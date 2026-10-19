-- Emberfall online social layer (players, friends, guilds, chat).
-- Run once in the Supabase SQL Editor for project msbumodfvmqllmpcfryk.
-- All writes go through SECURITY DEFINER functions that check a per-player secret,
-- so nobody can act as another player through the public anon key.

create table if not exists public.mmo_players(
 id uuid primary key default gen_random_uuid(),
 name text not null check (char_length(name) between 1 and 16),
 cls text default '', lv int default 1, look jsonb default '{}'::jsonb,
 guild_id uuid, last_seen timestamptz default now(), created_at timestamptz default now());
create unique index if not exists mmo_players_name_uq on public.mmo_players (lower(name));
create table if not exists public.mmo_secrets(id uuid primary key references public.mmo_players(id) on delete cascade, hash text not null);
create table if not exists public.mmo_guilds(
 id uuid primary key default gen_random_uuid(),
 name text not null check (char_length(name) between 3 and 20),
 tag text not null check (char_length(tag) between 2 and 4),
 owner uuid references public.mmo_players(id) on delete set null,
 motd text default 'Welcome to the guild!',
 created_at timestamptz default now());
create unique index if not exists mmo_guilds_name_uq on public.mmo_guilds (lower(name));
do $$ begin
 if not exists (select 1 from pg_constraint where conname = 'mmo_players_guild_fk') then
  alter table public.mmo_players add constraint mmo_players_guild_fk foreign key (guild_id) references public.mmo_guilds(id) on delete set null;
 end if; end $$;
create table if not exists public.mmo_friends(
 a uuid references public.mmo_players(id) on delete cascade,
 b uuid references public.mmo_players(id) on delete cascade,
 status text not null default 'pending' check (status in ('pending','accepted')),
 created_at timestamptz default now(), primary key(a,b), check (a<>b));
create table if not exists public.mmo_chat(
 id bigserial primary key, channel text not null, sender uuid references public.mmo_players(id) on delete cascade,
 name text not null, msg text not null check (char_length(msg) between 1 and 200), created_at timestamptz default now());
create index if not exists mmo_chat_ch_idx on public.mmo_chat(channel, id desc);

alter table public.mmo_players enable row level security;
alter table public.mmo_secrets enable row level security;
alter table public.mmo_guilds enable row level security;
alter table public.mmo_friends enable row level security;
alter table public.mmo_chat enable row level security;
drop policy if exists mmo_players_read on public.mmo_players;
drop policy if exists mmo_guilds_read on public.mmo_guilds;
drop policy if exists mmo_chat_read on public.mmo_chat;
create policy mmo_players_read on public.mmo_players for select to anon, authenticated using (true);
create policy mmo_guilds_read on public.mmo_guilds for select to anon, authenticated using (true);
create policy mmo_chat_read on public.mmo_chat for select to anon, authenticated using (channel = 'world' or channel like 'guild:%');

create or replace function public.mmo_ok(p_id uuid, p_secret text) returns boolean
language sql stable security definer set search_path = public, extensions as $$
 select exists(select 1 from mmo_secrets s where s.id = p_id and s.hash = encode(digest(p_secret,'sha256'),'hex'));
$$;
revoke execute on function public.mmo_ok(uuid,text) from public, anon, authenticated;

create or replace function public.mmo_register(p_name text, p_secret text) returns uuid
language plpgsql security definer set search_path = public, extensions as $$
declare v uuid;
begin
 if char_length(coalesce(p_secret,'')) < 24 then raise exception 'bad secret'; end if;
 insert into mmo_players(name) values (left(trim(p_name),16)) returning id into v;
 insert into mmo_secrets(id,hash) values (v, encode(digest(p_secret,'sha256'),'hex'));
 return v;
end $$;

create or replace function public.mmo_update(p_id uuid, p_secret text, p_cls text, p_lv int, p_look jsonb) returns void
language plpgsql security definer set search_path = public, extensions as $$
begin
 if not mmo_ok(p_id,p_secret) then raise exception 'auth'; end if;
 update mmo_players set cls = left(coalesce(p_cls,''),40), lv = greatest(1,least(coalesce(p_lv,1),999)), look = coalesce(p_look,'{}'::jsonb), last_seen = now() where id = p_id;
end $$;

create or replace function public.mmo_rename(p_id uuid, p_secret text, p_name text) returns void
language plpgsql security definer set search_path = public, extensions as $$
begin
 if not mmo_ok(p_id,p_secret) then raise exception 'auth'; end if;
 update mmo_players set name = left(trim(p_name),16) where id = p_id;
end $$;

create or replace function public.mmo_friend_request(p_id uuid, p_secret text, p_to uuid) returns text
language plpgsql security definer set search_path = public, extensions as $$
begin
 if not mmo_ok(p_id,p_secret) then raise exception 'auth'; end if;
 if p_id = p_to then return 'self'; end if;
 if exists(select 1 from mmo_friends where a = p_to and b = p_id) then
  update mmo_friends set status = 'accepted' where a = p_to and b = p_id; return 'accepted';
 end if;
 insert into mmo_friends(a,b) values (p_id,p_to) on conflict do nothing; return 'sent';
end $$;

create or replace function public.mmo_friend_respond(p_id uuid, p_secret text, p_from uuid, p_accept boolean) returns void
language plpgsql security definer set search_path = public, extensions as $$
begin
 if not mmo_ok(p_id,p_secret) then raise exception 'auth'; end if;
 if p_accept then update mmo_friends set status = 'accepted' where a = p_from and b = p_id;
 else delete from mmo_friends where a = p_from and b = p_id; end if;
end $$;

create or replace function public.mmo_friend_remove(p_id uuid, p_secret text, p_other uuid) returns void
language plpgsql security definer set search_path = public, extensions as $$
begin
 if not mmo_ok(p_id,p_secret) then raise exception 'auth'; end if;
 delete from mmo_friends where (a = p_id and b = p_other) or (a = p_other and b = p_id);
end $$;

create or replace function public.mmo_my_friends(p_id uuid, p_secret text)
returns table(other uuid, name text, lv int, cls text, last_seen timestamptz, status text, incoming boolean)
language plpgsql stable security definer set search_path = public, extensions as $$
begin
 if not mmo_ok(p_id,p_secret) then raise exception 'auth'; end if;
 return query select p.id, p.name, p.lv, p.cls, p.last_seen, f.status, (f.b = p_id)
  from mmo_friends f join mmo_players p on p.id = case when f.a = p_id then f.b else f.a end
  where f.a = p_id or f.b = p_id order by f.status, p.name;
end $$;

create or replace function public.mmo_guild_create(p_id uuid, p_secret text, p_name text, p_tag text) returns uuid
language plpgsql security definer set search_path = public, extensions as $$
declare g uuid;
begin
 if not mmo_ok(p_id,p_secret) then raise exception 'auth'; end if;
 if (select guild_id from mmo_players where id = p_id) is not null then raise exception 'already in a guild'; end if;
 insert into mmo_guilds(name,tag,owner) values (left(trim(p_name),20), upper(left(trim(p_tag),4)), p_id) returning id into g;
 update mmo_players set guild_id = g where id = p_id;
 return g;
end $$;

create or replace function public.mmo_guild_join(p_id uuid, p_secret text, p_guild uuid) returns void
language plpgsql security definer set search_path = public, extensions as $$
begin
 if not mmo_ok(p_id,p_secret) then raise exception 'auth'; end if;
 if (select guild_id from mmo_players where id = p_id) is not null then raise exception 'already in a guild'; end if;
 if not exists(select 1 from mmo_guilds where id = p_guild) then raise exception 'no such guild'; end if;
 update mmo_players set guild_id = p_guild where id = p_id;
end $$;

create or replace function public.mmo_guild_leave(p_id uuid, p_secret text) returns void
language plpgsql security definer set search_path = public, extensions as $$
declare g uuid; nxt uuid;
begin
 if not mmo_ok(p_id,p_secret) then raise exception 'auth'; end if;
 select guild_id into g from mmo_players where id = p_id;
 if g is null then return; end if;
 update mmo_players set guild_id = null where id = p_id;
 if (select owner from mmo_guilds where id = g) = p_id then
  select id into nxt from mmo_players where guild_id = g order by created_at limit 1;
  if nxt is null then delete from mmo_guilds where id = g; else update mmo_guilds set owner = nxt where id = g; end if;
 end if;
end $$;

create or replace function public.mmo_guild_motd(p_id uuid, p_secret text, p_motd text) returns void
language plpgsql security definer set search_path = public, extensions as $$
begin
 if not mmo_ok(p_id,p_secret) then raise exception 'auth'; end if;
 update mmo_guilds set motd = left(p_motd,140) where owner = p_id;
end $$;

create or replace function public.mmo_chat_post(p_id uuid, p_secret text, p_channel text, p_msg text) returns void
language plpgsql security definer set search_path = public, extensions as $$
declare nm text; g uuid;
begin
 if not mmo_ok(p_id,p_secret) then raise exception 'auth'; end if;
 select name, guild_id into nm, g from mmo_players where id = p_id;
 if p_channel <> 'world' and p_channel <> ('guild:' || coalesce(g::text,'-')) then raise exception 'channel'; end if;
 if (select count(*) from mmo_chat where sender = p_id and created_at > now() - interval '10 seconds') >= 5 then raise exception 'slow down'; end if;
 insert into mmo_chat(channel,sender,name,msg) values (p_channel,p_id,nm,left(trim(p_msg),200));
 delete from mmo_chat where channel = p_channel and id < (select min(id) from (select id from mmo_chat where channel = p_channel order by id desc limit 200) t);
end $$;

grant execute on function public.mmo_register(text,text), public.mmo_update(uuid,text,text,int,jsonb), public.mmo_rename(uuid,text,text),
 public.mmo_friend_request(uuid,text,uuid), public.mmo_friend_respond(uuid,text,uuid,boolean), public.mmo_friend_remove(uuid,text,uuid),
 public.mmo_my_friends(uuid,text), public.mmo_guild_create(uuid,text,text,text), public.mmo_guild_join(uuid,text,uuid),
 public.mmo_guild_leave(uuid,text), public.mmo_guild_motd(uuid,text,text), public.mmo_chat_post(uuid,text,text,text) to anon, authenticated;
