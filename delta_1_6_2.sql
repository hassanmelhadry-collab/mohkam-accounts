-- مُحكَم للحسابات 1.6.2 — إنشاء رابط الديمو في أقل من ثانية: مخزون جاهز من شركات تجريبية مبذورة مسبقًا
-- رابط الديمو يحجز شركة جاهزة من المخزون (تسمية فقط) فيصير الإنشاء فوريًا؛ المخزون يُعاد ملؤه في الخلفية. إن فرغ يعمل البذر المباشر كما كان.
create table if not exists acc.demo_pool (code text primary key, pwd text not null, created_at timestamptz not null default now());
alter table acc.demo_pool enable row level security;

create or replace function app.demo_cleanup() returns int language plpgsql security definer set search_path = public, app, acc as $$
declare r record; n int := 0;
begin
  for r in select code from acc.tenants where settings ? 'demo' and code <> 'group5' and (settings->'demo'->>'days') is not null and expires_at + 7 < current_date - 30 and code not in (select code from acc.demo_pool) loop
    perform app.demo_wipe(r.code); n := n + 1; end loop;
  -- مخزون قديم جدًا (أكثر من 20 يومًا) يُستبدل بجديد
  for r in select code from acc.demo_pool where created_at < now() - interval '20 days' loop
    delete from acc.demo_pool where code = r.code; perform app.demo_wipe(r.code); n := n + 1; end loop;
  return n;
end $$;

-- ملء المخزون: شركة واحدة في كل استدعاء (تستغرق بضع ثوانٍ؛ تُستدعى من الخلفية). target = العدد المطلوب جاهزًا (1..5)
create or replace function public.demo_pool_fill(p jsonb default '{}') returns jsonb language plpgsql security definer set search_path = public, app, acc as $$
declare tg int := least(greatest(coalesce(nullif(p->>'target','')::int, 2), 1), 5); have int; vcode text; vpwd text; alphabet text := 'abcdefghjkmnpqrstuvwxyz23456789'; i int;
begin
  perform app.demo_admin();
  if not pg_try_advisory_xact_lock(7770148) then return jsonb_build_object('ready', (select count(*) from acc.demo_pool), 'busy', true); end if;
  select count(*) into have from acc.demo_pool;
  if have < tg then
    vcode := 'demo-'; for i in 1..5 loop vcode := vcode || substr(alphabet, 1 + floor(random() * length(alphabet))::int, 1); end loop;
    vpwd := 'Dm'; for i in 1..8 loop vpwd := vpwd || substr(alphabet, 1 + floor(random() * length(alphabet))::int, 1); end loop; vpwd := vpwd || '#7';
    perform app.demo_seed(vcode, 'نسخة تجريبية', vpwd, 7, '');
    insert into acc.demo_pool (code, pwd) values (vcode, vpwd); have := have + 1;
  end if;
  return jsonb_build_object('ready', have, 'target', tg, 'busy', false);
end $$;

create or replace function public.demo_link_create(p jsonb) returns jsonb language plpgsql security definer set search_path = public, app, acc as $$
declare nm text := trim(coalesce(p->>'label','')); h int := coalesce(nullif(p->>'hours','')::int, 48); vcode text; vpwd text; tok text; alphabet text := 'abcdefghjkmnpqrstuvwxyz23456789'; i int; pl record; fast boolean := false;
begin
  perform app.demo_admin();
  if nm = '' or length(nm) > 80 then raise exception 'الاسم مطلوب (حتى 80 حرفًا)'; end if;
  if h not in (24, 48, 72, 168, 336, 720) then raise exception 'المدة: يوم أو يومان أو 3 أيام أو أسبوع أو أسبوعان أو 30 يومًا'; end if;
  -- حجز شركة جاهزة (تخطّي الصفوف المحجوزة لدى طلب آخر متزامن)
  for pl in select * from acc.demo_pool order by created_at for update skip locked loop
    if exists (select 1 from acc.tenants t where t.code = pl.code) then
      vcode := pl.code; vpwd := pl.pwd; delete from acc.demo_pool where demo_pool.code = pl.code; fast := true; exit;
    else delete from acc.demo_pool where demo_pool.code = pl.code; end if;
  end loop;
  if fast then
    update acc.tenants set name = 'نسخة تجريبية — ' || nm, settings = jsonb_set(settings, '{demo,for}', to_jsonb(nm)) where acc.tenants.code = vcode;
  else
    vcode := 'demo-'; for i in 1..5 loop vcode := vcode || substr(alphabet, 1 + floor(random() * length(alphabet))::int, 1); end loop;
    vpwd := 'Dm'; for i in 1..8 loop vpwd := vpwd || substr(alphabet, 1 + floor(random() * length(alphabet))::int, 1); end loop; vpwd := vpwd || '#7';
    perform app.demo_seed(vcode, 'نسخة تجريبية — ' || nm, vpwd, 7, nm);
  end if;
  tok := 'k' || substr(replace(gen_random_uuid()::text || gen_random_uuid()::text, '-', ''), 1, 20);
  insert into acc.demo_links (token, label, hours, code, pwd) values (tok, nm, h, vcode, vpwd);
  perform app.padmin_log('demo_create', vcode, nm || ' / ' || h || ' ساعة' || case when fast then ' (جاهزة)' else '' end);
  return jsonb_build_object('token', tok, 'fast', fast);
end $$;

insert into app.schema_migrations (version, name) values ('1.6.2.0', 'مخزون الديمو الجاهز: إنشاء رابط الديمو فوري') on conflict (version) do nothing;
-- مُحكَم للحسابات — الصلاحيات: لا وصول مباشر للجداول، الواجهة عبر RPC فقط
do $$ begin
  begin revoke all on schema acc from public, anon, authenticated; exception when others then null; end;
  begin revoke all on schema app from public, anon, authenticated; exception when others then null; end;
  begin revoke all on all tables in schema acc from public, anon, authenticated; exception when others then null; end;
  begin revoke all on all sequences in schema acc from public, anon, authenticated; exception when others then null; end;
  begin revoke execute on all functions in schema app from public, anon, authenticated; exception when others then null; end;
  begin revoke execute on all functions in schema public from public, anon, authenticated; exception when others then null; end;
end $$;
-- كل دوال الواجهة (التي تأخذ jsonb) متاحة للمستخدم المسجَّل فقط
do $$ declare f record; begin
  for f in select p.oid::regprocedure as sig, p.proname from pg_proc p join pg_namespace n on n.oid = p.pronamespace where n.nspname = 'public' and p.prokind = 'f' and p.proowner = (select oid from pg_roles where rolname = current_user)
      and (p.proname in ('login_email','register_company','ingest_journal','api_call','api_catalog','signup_status','demo_link_open') or p.pronargs = 0 or p.proargtypes::text = (select oid::text from pg_type where typname = 'jsonb')) loop
    if f.proname in ('register_company','ingest_journal','api_call','api_catalog','login_email','signup_status','demo_link_open') then execute format('grant execute on function %s to anon, authenticated', f.sig);
    else execute format('grant execute on function %s to authenticated', f.sig); end if;
  end loop;
end $$;
alter default privileges in schema public revoke execute on functions from public, anon;

-- تشديد نهائي (آمن للتكرار): لا يصل الزائر أو المستخدم المسجّل مباشرة لأي دالة داخلية في app/acc
do $$ declare f record; begin
  for f in select p.oid::regprocedure as sig from pg_proc p join pg_namespace n on n.oid = p.pronamespace where n.nspname in ('app','acc') and p.prokind in ('f','p') loop
    begin execute format('revoke execute on function %s from public, anon, authenticated', f.sig); exception when others then null; end; end loop;
  for f in select p.oid::regprocedure as sig from pg_proc p join pg_namespace n on n.oid = p.pronamespace where n.nspname = 'public' and p.prokind = 'f' and p.proname not in ('login_email','register_company','ingest_journal','api_call','api_catalog','signup_status','demo_link_open') and pg_get_function_identity_arguments(p.oid) = 'p jsonb' loop
    begin execute format('revoke execute on function %s from public, anon', f.sig); execute format('grant execute on function %s to authenticated', f.sig); exception when others then null; end; end loop;
end $$;
