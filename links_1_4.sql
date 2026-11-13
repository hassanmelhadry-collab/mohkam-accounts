-- روابط الديمو (بنفس فكرة الموارد البشرية): رابط سري واحد باسم الشخص؛ تبدأ المدة من أول فتح ثم يُقفل
create table if not exists acc.demo_links (
  token text primary key, label text not null, hours int not null check (hours in (24, 48, 72, 168)), code text not null, pwd text not null,
  created_at timestamptz not null default now(), first_open timestamptz, expires_at timestamptz, opens int not null default 0, revoked boolean not null default false);
alter table acc.demo_links enable row level security;

create or replace function public.demo_link_create(p jsonb) returns jsonb language plpgsql security definer set search_path = public, app, acc as $$
declare nm text := trim(coalesce(p->>'label','')); h int := coalesce(nullif(p->>'hours','')::int, 48); code text; pwd text; tok text; alphabet text := 'abcdefghjkmnpqrstuvwxyz23456789'; i int;
begin
  perform app.demo_admin();
  if nm = '' or length(nm) > 80 then raise exception 'الاسم مطلوب (حتى 80 حرفًا)'; end if;
  if h not in (24, 48, 72, 168) then raise exception 'المدة: يوم أو يومان أو 3 أيام أو أسبوع'; end if;
  code := 'demo-'; for i in 1..5 loop code := code || substr(alphabet, 1 + floor(random() * length(alphabet))::int, 1); end loop;
  pwd := 'Dm'; for i in 1..8 loop pwd := pwd || substr(alphabet, 1 + floor(random() * length(alphabet))::int, 1); end loop; pwd := pwd || '#7';
  tok := 'k' || substr(replace(gen_random_uuid()::text || gen_random_uuid()::text, '-', ''), 1, 20);
  perform app.demo_seed(code, 'نسخة تجريبية — ' || nm, pwd, 7, nm);
  insert into acc.demo_links (token, label, hours, code, pwd) values (tok, nm, h, code, pwd);
  return jsonb_build_object('token', tok);
end $$;

-- يُستدعى من الرابط (بدون تسجيل دخول): يعيد بيانات الدخول إلى النسخة ويبدأ العدّ عند أول فتح
create or replace function public.demo_link_open(p jsonb) returns jsonb language plpgsql security definer set search_path = public, app, acc as $$
declare l acc.demo_links;
begin
  select * into l from acc.demo_links where token = coalesce(p->>'token', '') for update;
  if l.token is null or l.revoked then raise exception 'الرابط غير صالح أو أُلغي'; end if;
  if l.first_open is null then
    if l.created_at < now() - interval '7 days' then raise exception 'انتهت صلاحية الرابط'; end if;
    update acc.demo_links set first_open = now(), expires_at = now() + make_interval(hours => l.hours), opens = opens + 1 where token = l.token returning * into l;
    update acc.tenants set expires_at = (l.expires_at at time zone 'UTC')::date - 7 where code = l.code;
  else
    if l.expires_at < now() then raise exception 'انتهت مدة هذا الرابط — اطلب رابطًا جديدًا'; end if;
    update acc.demo_links set opens = opens + 1 where token = l.token;
  end if;
  return jsonb_build_object('code', l.code, 'username', 'owner', 'password', l.pwd, 'expires', l.expires_at);
end $$;

create or replace function public.demo_links_list(p jsonb default '{}') returns jsonb language plpgsql stable security definer set search_path = public, app, acc as $$
begin
  perform app.demo_admin();
  return coalesce((select jsonb_agg(jsonb_build_object('token', token, 'label', label, 'hours', hours, 'code', code, 'first_open', first_open, 'expires_at', expires_at, 'opens', opens, 'created_at', created_at,
    'state', case when revoked then 'revoked' when first_open is null then (case when created_at < now() - interval '7 days' then 'expired' else 'new' end) when expires_at < now() then 'expired' else 'active' end) order by created_at desc) from acc.demo_links), '[]'::jsonb);
end $$;

create or replace function public.demo_link_revoke(p jsonb) returns jsonb language plpgsql security definer set search_path = public, app, acc as $$
declare l acc.demo_links;
begin
  perform app.demo_admin();
  update acc.demo_links set revoked = true where token = p->>'token' returning * into l;
  if l.token is null then raise exception 'الرابط غير موجود'; end if;
  if exists (select 1 from acc.tenants where code = l.code and settings ? 'demo') then perform app.demo_wipe(l.code); end if;
  return jsonb_build_object('ok', true);
end $$;

revoke all on function public.demo_link_create(jsonb), public.demo_link_open(jsonb), public.demo_links_list(jsonb), public.demo_link_revoke(jsonb) from public, anon;
grant execute on function public.demo_link_create(jsonb), public.demo_links_list(jsonb), public.demo_link_revoke(jsonb) to authenticated;
grant execute on function public.demo_link_open(jsonb) to anon, authenticated;
create or replace function public.demo_link_delete(p jsonb) returns jsonb language plpgsql security definer set search_path = public, app, acc as $$
declare l acc.demo_links;
begin
  perform app.demo_admin();
  select * into l from acc.demo_links where token = p->>'token';
  if l.token is null then raise exception 'الرابط غير موجود'; end if;
  if exists (select 1 from acc.tenants where code = l.code and settings ? 'demo') then perform app.demo_wipe(l.code); end if;
  delete from acc.demo_links where token = l.token;
  return jsonb_build_object('ok', true);
end $$;
revoke all on function public.demo_link_delete(jsonb) from public, anon;
grant execute on function public.demo_link_delete(jsonb) to authenticated;
