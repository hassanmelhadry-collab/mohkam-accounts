-- مُحكَم 1.5.0.5 — تأمين التخزين + مراقبة الأخطاء (آمن للتكرار، لا يمس الروابط ولا البيانات)
-- مُحكَم — تأمين التخزين خادمياً: الشركة فعّالة + المستخدم فعّال + نوع الملف + صلاحية/ميزة المرفقات (لا يعتمد على الواجهة)
-- لا يغيّر مسارات الملفات الحالية ولا الروابط؛ يشدّد الرفع والحذف فقط.
create or replace function public.storage_ok(p jsonb) returns boolean language plpgsql stable security definer set search_path = public, app, acc as $$
declare nm text := coalesce(p->>'name', ''); act text := coalesce(p->>'act', 'select'); t uuid := app.tenant(); parts text[] := string_to_array(nm, '/'); ot text;
begin
  if t is null or coalesce(parts[1], '') <> t::text or nm ~ '\.\.' or array_length(parts, 1) < 3 then return false; end if;
  if not app.tenant_ok(t) then return false; end if;
  if not exists (select 1 from acc.members m where m.user_id = auth.uid() and m.active) then return false; end if;
  ot := parts[2];
  if act = 'select' then return true; end if;
  if act = 'insert' then
    if lower(nm) !~ '\.(pdf|png|jpe?g|webp|gif|xlsx?|docx?|csv|txt|zip)$' then return false; end if;
    if ot = 'request' then return app.feat_on('portal', t); end if;
    return app.can('attachments', 'add');
  end if;
  if act = 'delete' then
    if ot = 'request' then return app.feat_on('portal', t); end if;
    return app.can('attachments', 'delete');
  end if;
  return false;
end $$;

do $$ begin
  if exists (select 1 from information_schema.schemata where schema_name = 'storage') then
    drop policy if exists acc_files_select on storage.objects; drop policy if exists acc_files_insert on storage.objects; drop policy if exists acc_files_delete on storage.objects;
    create policy acc_files_select on storage.objects for select to authenticated using (bucket_id = 'acc-files' and public.storage_ok(jsonb_build_object('name', name, 'act', 'select')));
    create policy acc_files_insert on storage.objects for insert to authenticated with check (bucket_id = 'acc-files' and public.storage_ok(jsonb_build_object('name', name, 'act', 'insert')));
    create policy acc_files_delete on storage.objects for delete to authenticated using (bucket_id = 'acc-files' and public.storage_ok(jsonb_build_object('name', name, 'act', 'delete')));
  end if;
end $$;
-- مُحكَم — مراقبة الأخطاء: سجل أخطاء المتصفح (بلا بيانات حساسة) + عرض للبائع + تنظيف دوري
create table if not exists acc.client_errors (
  id bigserial primary key, at timestamptz not null default now(), tenant_id uuid, user_id uuid, route text not null default '', message text not null, stack text not null default '', ua text not null default '', ver text not null default '');
alter table acc.client_errors enable row level security;
create index if not exists client_errors_at_idx on acc.client_errors (at desc);

-- تسجيل خطأ من مستخدم مسجّل فقط، بحد 30 سجلًا/ساعة للمستخدم، وبقصّ الأطوال
create or replace function public.log_client_error(p jsonb) returns jsonb language plpgsql security definer set search_path = public, app, acc as $$
declare m acc.members;
begin
  select * into m from acc.members where user_id = auth.uid();
  if m.user_id is null then return jsonb_build_object('ok', false); end if;
  if (select count(*) from acc.client_errors where user_id = m.user_id and at > now() - interval '1 hour') >= 30 then return jsonb_build_object('ok', false, 'limited', true); end if;
  insert into acc.client_errors (tenant_id, user_id, route, message, stack, ua, ver)
  values (m.tenant_id, m.user_id, left(coalesce(p->>'route',''), 200), left(coalesce(nullif(p->>'message',''), 'خطأ غير معروف'), 500), left(coalesce(p->>'stack',''), 3000), left(coalesce(p->>'ua',''), 200), left(coalesce(p->>'ver',''), 20));
  return jsonb_build_object('ok', true);
end $$;

-- للبائع: آخر 24 ساعة مجمّعة حسب الرسالة + آخر 50 سجلًا
create or replace function public.platform_errors(p jsonb default '{}') returns jsonb language plpgsql stable security definer set search_path = public, app, acc as $$
begin
  perform app.demo_admin();
  return jsonb_build_object(
    'total_24h', (select count(*) from acc.client_errors where at > now() - interval '24 hours'),
    'groups', coalesce((select jsonb_agg(g) from (select message, count(*) n, count(distinct user_id) users, max(at) last_at, max(route) route from acc.client_errors where at > now() - interval '24 hours' group by message order by n desc limit 30) g), '[]'::jsonb),
    'recent', coalesce((select jsonb_agg(r) from (select e.at, e.route, e.message, e.ver, (select t.code from acc.tenants t where t.id = e.tenant_id) code from acc.client_errors e order by e.at desc limit 50) r), '[]'::jsonb));
end $$;

create or replace function app.purge_client_errors() returns int language plpgsql security definer set search_path = public, app, acc as $$
declare n int; begin delete from acc.client_errors where at < now() - interval '30 days'; get diagnostics n = row_count; return n; end $$;

do $$ begin
  begin
    create extension if not exists pg_cron;
    perform cron.unschedule(jobid) from cron.job where jobname = 'mohkam-purge-errors';
    perform cron.schedule('mohkam-purge-errors', '45 21 * * *', 'select app.purge_client_errors()');
  exception when others then raise notice 'pg_cron غير متاح: تنظيف الأخطاء يدويًا (%).', sqlerrm; end;
end $$;

-- تشديد نهائي (آمن للتكرار): لا يصل الزائر أو المستخدم المسجّل مباشرة لأي دالة داخلية في app/acc
do $$ declare f record; begin
  for f in select p.oid::regprocedure as sig from pg_proc p join pg_namespace n on n.oid = p.pronamespace where n.nspname in ('app','acc') and p.prokind in ('f','p') loop
    begin execute format('revoke execute on function %s from public, anon, authenticated', f.sig); exception when others then null; end; end loop;
  for f in select p.oid::regprocedure as sig from pg_proc p join pg_namespace n on n.oid = p.pronamespace where n.nspname = 'public' and p.prokind = 'f' and p.proname not in ('login_email','register_company','ingest_journal','signup_status','demo_link_open') and pg_get_function_identity_arguments(p.oid) = 'p jsonb' loop
    begin execute format('revoke execute on function %s from public, anon', f.sig); execute format('grant execute on function %s to authenticated', f.sig); exception when others then null; end; end loop;
end $$;
