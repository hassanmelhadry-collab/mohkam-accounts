-- مُحكَم 1.5.0.8 — إنهاء العقد وشهادة الحذف + الدعم الفني + قائمة التهيئة (آمن للتكرار، لا يمس الروابط ولا البيانات)
-- مُحكَم للحسابات — إنهاء العقد: فترة إتاحة 30 يومًا للتصدير ثم حذف نهائي بشهادة حذف (لمدير المنصة فقط)
create table if not exists acc.deletion_certificates (
  id uuid primary key default gen_random_uuid(), code text not null, name text not null, deleted_at timestamptz not null default now(), deleted_by uuid,
  reason text not null default '', terminated_at timestamptz, export_until date, counts jsonb not null default '{}'::jsonb);
alter table acc.deletion_certificates enable row level security;

-- بناء نسخة احتياطية كاملة لشركة (داخلي) — تستخدمها النسخة الذاتية ونسخة مدير المنصة
create or replace function app.backup_build(t uuid) returns jsonb language plpgsql stable security definer set search_path = public, app, acc as $$
declare r jsonb := '{}'::jsonb; x record; j jsonb; n jsonb := '{}'::jsonb; c bigint; meta jsonb;
begin
  for x in select tb.table_name from information_schema.tables tb join information_schema.columns c on c.table_schema = tb.table_schema and c.table_name = tb.table_name and c.column_name = 'tenant_id'
           where tb.table_schema = 'acc' and tb.table_type = 'BASE TABLE' and tb.table_name not in ('api_keys', 'demo_links', 'ingest_log', 'client_errors') order by 1 loop
    execute format('select coalesce(jsonb_agg(to_jsonb(q)), ''[]''::jsonb), count(*) from acc.%I q where q.tenant_id = $1', x.table_name) into j, c using t;
    r := r || jsonb_build_object(x.table_name, j); n := n || jsonb_build_object(x.table_name, c);
  end loop;
  select to_jsonb(z) - 'id' - 'created_ip' into meta from acc.tenants z where z.id = t;
  return jsonb_build_object('app', 'mohkam-accounts', 'format', 1, 'exported_at', now(), 'tenant_id', t, 'tenant', meta, 'counts', n, 'tables', r);
end $$;

create or replace function public.backup_export(p jsonb default '{}') returns jsonb language plpgsql volatile security definer set search_path = public, app, acc as $$
declare t uuid := app.need_sys('backup');
begin
  perform app.audit('export', 'backup', t::text, 'تصدير نسخة احتياطية كاملة');
  return app.backup_build(t);
end $$;

-- تصدير نسخة شركة بواسطة مدير المنصة (لتسليمها للعميل عند الإنهاء)
create or replace function public.platform_backup_export(p jsonb) returns jsonb language plpgsql volatile security definer set search_path = public, app, acc as $$
declare t acc.tenants;
begin
  perform app.demo_admin();
  select * into t from acc.tenants where code = p->>'code' and not (settings ? 'demo');
  if t.id is null then raise exception 'الشركة غير موجودة'; end if;
  perform app.padmin_log('tenant_export', t.code, t.name);
  return app.backup_build(t.id);
end $$;

-- إنهاء العقد: إيقاف الشركة وتسجيل بدء فترة الإتاحة (30 يومًا افتراضيًا)
create or replace function public.platform_terminate(p jsonb) returns jsonb language plpgsql volatile security definer set search_path = public, app, acc as $$
declare t acc.tenants; mine uuid := (select tenant_id from app.me()); d int := least(greatest(coalesce(nullif(p->>'days', '')::int, 30), 1), 365); ex date;
begin
  perform app.demo_admin();
  select * into t from acc.tenants where code = p->>'code' and not (settings ? 'demo');
  if t.id is null then raise exception 'الشركة غير موجودة'; end if;
  if t.id = mine then raise exception 'لا يمكن إنهاء الشركة التي تدخل بها الآن'; end if;
  if length(trim(coalesce(p->>'reason', ''))) < 3 then raise exception 'سبب الإنهاء مطلوب'; end if;
  ex := current_date + d;
  update acc.tenants set status = 'suspended', suspend_msg = 'انتهى العقد — بياناتك متاحة للتصدير عبر المزوّد حتى ' || ex::text,
    settings = settings || jsonb_build_object('termination', jsonb_build_object('at', now(), 'export_until', ex, 'reason', left(trim(p->>'reason'), 300))) where id = t.id;
  perform app.padmin_log('tenant_terminate', t.code, 'حتى ' || ex::text || ' — ' || left(trim(p->>'reason'), 100));
  return jsonb_build_object('ok', true, 'export_until', ex);
end $$;

-- الحذف النهائي بشهادة: يلزم إنهاء سابق وانتهاء فترة الإتاحة، أو early=true صراحةً
create or replace function public.platform_tenant_delete(p jsonb) returns jsonb language plpgsql volatile security definer set search_path = public, app, acc as $$
declare t acc.tenants; mine uuid := (select tenant_id from app.me()); tm jsonb; cnt jsonb := '{}'::jsonb; x record; c bigint; cert uuid;
begin
  perform app.demo_admin();
  select * into t from acc.tenants where code = p->>'code' and not (settings ? 'demo');
  if t.id is null then raise exception 'الشركة غير موجودة'; end if;
  if t.id = mine then raise exception 'لا يمكن حذف الشركة التي تدخل بها الآن'; end if;
  if t.status <> 'suspended' then raise exception 'أوقف الشركة أولًا ثم احذفها'; end if;
  if coalesce(p->>'confirm', '') <> t.code then raise exception 'اكتب رمز الشركة للتأكيد'; end if;
  tm := t.settings->'termination';
  if (tm is null or (tm->>'export_until')::date >= current_date) and coalesce((p->>'early')::boolean, false) is not true then
    raise exception 'لم تنتهِ فترة الإتاحة للتصدير (أو لم يُسجَّل إنهاء العقد). للحذف المبكر أكّد ذلك صراحةً بعد تسليم العميل نسخته';
  end if;
  for x in select tb.table_name from information_schema.tables tb join information_schema.columns c on c.table_schema = tb.table_schema and c.table_name = tb.table_name and c.column_name = 'tenant_id'
           where tb.table_schema = 'acc' and tb.table_type = 'BASE TABLE' and tb.table_name in ('journals', 'journal_lines', 'invoices', 'payments', 'accounts', 'parties', 'attachments', 'members') order by 1 loop
    execute format('select count(*) from acc.%I where tenant_id = $1', x.table_name) into c using t.id; cnt := cnt || jsonb_build_object(x.table_name, c);
  end loop;
  insert into acc.deletion_certificates (code, name, deleted_by, reason, terminated_at, export_until, counts)
  values (t.code, t.name, auth.uid(), left(coalesce(p->>'reason', tm->>'reason', ''), 300), (tm->>'at')::timestamptz, (tm->>'export_until')::date, cnt) returning id into cert;
  perform app.padmin_log('tenant_delete', t.code, t.name);
  perform app.tenant_destroy(t.id);
  return jsonb_build_object('ok', true, 'certificate', cert);
end $$;

create or replace function public.platform_certificates(p jsonb default '{}') returns jsonb language plpgsql stable security definer set search_path = public, app, acc as $$
begin
  perform app.demo_admin();
  return coalesce((select jsonb_agg(to_jsonb(x) order by x.deleted_at desc) from (select id, code, name, deleted_at, reason, terminated_at, export_until, counts from acc.deletion_certificates order by deleted_at desc limit 200) x), '[]'::jsonb);
end $$;
-- مُحكَم للحسابات — الدعم الفني الداخلي: تذاكر العميل وردود فريق المنصة (بلا مرفقات؛ نص فقط)
create table if not exists acc.tickets (
  id uuid primary key default gen_random_uuid(), tenant_id uuid not null references acc.tenants(id) on delete cascade, no bigint generated always as identity,
  user_id uuid, username text, subject text not null, status text not null default 'open' check (status in ('open','answered','closed')),
  priority text not null default 'normal' check (priority in ('low','normal','high')), created_at timestamptz not null default now(), updated_at timestamptz not null default now());
create table if not exists acc.ticket_msgs (
  id uuid primary key default gen_random_uuid(), ticket_id uuid not null references acc.tickets(id) on delete cascade, tenant_id uuid not null references acc.tenants(id) on delete cascade,
  by_support boolean not null default false, author text not null default '', body text not null, at timestamptz not null default now());
alter table acc.tickets enable row level security; alter table acc.ticket_msgs enable row level security;
create index if not exists tickets_t_idx on acc.tickets (tenant_id, updated_at desc);
create index if not exists tickets_status_idx on acc.tickets (status, updated_at desc);
create index if not exists ticket_msgs_idx on acc.ticket_msgs (ticket_id, at);

create or replace function public.ticket_create(p jsonb) returns jsonb language plpgsql volatile security definer set search_path = public, app, acc as $$
declare m acc.members; t uuid; sj text := trim(coalesce(p->>'subject', '')); bd text := trim(coalesce(p->>'body', '')); pr text := coalesce(nullif(p->>'priority', ''), 'normal'); id uuid;
begin
  select * into m from acc.members where user_id = auth.uid(); t := m.tenant_id;
  if t is null or not app.tenant_ok(t) then raise exception 'يجب تسجيل الدخول'; end if;
  if length(sj) < 3 or length(sj) > 150 then raise exception 'عنوان التذكرة من 3 إلى 150 حرفًا'; end if;
  if length(bd) < 5 or length(bd) > 4000 then raise exception 'نص التذكرة من 5 إلى 4000 حرف'; end if;
  if pr not in ('low','normal','high') then pr := 'normal'; end if;
  if (select count(*) from acc.tickets where user_id = m.user_id and created_at > now() - interval '1 day') >= 10 then raise exception 'تجاوزت الحد اليومي للتذاكر — أضف رسالة على تذكرة قائمة'; end if;
  insert into acc.tickets (tenant_id, user_id, username, subject, priority) values (t, m.user_id, m.username, sj, pr) returning acc.tickets.id into id;
  insert into acc.ticket_msgs (ticket_id, tenant_id, by_support, author, body) values (id, t, false, coalesce(m.name, m.username), bd);
  return jsonb_build_object('id', id);
end $$;

create or replace function public.ticket_list(p jsonb default '{}') returns jsonb language plpgsql stable security definer set search_path = public, app, acc as $$
declare t uuid := app.tenant(); mine boolean := not app.is_admin_like();
begin
  if t is null then raise exception 'يجب تسجيل الدخول'; end if;
  -- مدير الحساب يرى تذاكر شركته كلها، وغيره يرى تذاكره فقط
  return coalesce((select jsonb_agg(to_jsonb(x) order by x.updated_at desc) from (select id, no, subject, status, priority, username, created_at, updated_at from acc.tickets where tenant_id = t and (not mine or user_id = auth.uid()) order by updated_at desc limit 200) x), '[]'::jsonb);
end $$;

create or replace function public.ticket_get(p jsonb) returns jsonb language plpgsql stable security definer set search_path = public, app, acc as $$
declare t uuid := app.tenant(); k acc.tickets;
begin
  if t is null then raise exception 'يجب تسجيل الدخول'; end if;
  select * into k from acc.tickets where id = (p->>'id')::uuid and tenant_id = t and (app.is_admin_like() or user_id = auth.uid());
  if k.id is null then raise exception 'التذكرة غير موجودة'; end if;
  return jsonb_build_object('ticket', to_jsonb(k) - 'tenant_id' - 'user_id', 'msgs', coalesce((select jsonb_agg(jsonb_build_object('by_support', by_support, 'author', author, 'body', body, 'at', at) order by at) from acc.ticket_msgs where ticket_id = k.id), '[]'::jsonb));
end $$;

create or replace function public.ticket_reply(p jsonb) returns jsonb language plpgsql volatile security definer set search_path = public, app, acc as $$
declare m acc.members; k acc.tickets; bd text := trim(coalesce(p->>'body', ''));
begin
  select * into m from acc.members where user_id = auth.uid();
  if m.user_id is null or not app.tenant_ok(m.tenant_id) then raise exception 'يجب تسجيل الدخول'; end if;
  select * into k from acc.tickets where id = (p->>'id')::uuid and tenant_id = m.tenant_id and (app.is_admin_like() or user_id = auth.uid());
  if k.id is null then raise exception 'التذكرة غير موجودة'; end if;
  if length(bd) < 2 or length(bd) > 4000 then raise exception 'نص الرد من حرفين إلى 4000 حرف'; end if;
  if (select count(*) from acc.ticket_msgs where ticket_id = k.id and not by_support and at > now() - interval '1 hour') >= 20 then raise exception 'رسائل كثيرة — حاول لاحقًا'; end if;
  insert into acc.ticket_msgs (ticket_id, tenant_id, by_support, author, body) values (k.id, k.tenant_id, false, coalesce(m.name, m.username), bd);
  update acc.tickets set status = 'open', updated_at = now() where id = k.id;
  return jsonb_build_object('ok', true);
end $$;

create or replace function public.ticket_close(p jsonb) returns jsonb language plpgsql volatile security definer set search_path = public, app, acc as $$
declare m acc.members;
begin
  select * into m from acc.members where user_id = auth.uid();
  if m.user_id is null then raise exception 'يجب تسجيل الدخول'; end if;
  update acc.tickets set status = 'closed', updated_at = now() where id = (p->>'id')::uuid and tenant_id = m.tenant_id and (app.is_admin_like() or user_id = auth.uid());
  return jsonb_build_object('ok', found);
end $$;

-- جانب المنصة
create or replace function public.platform_tickets(p jsonb default '{}') returns jsonb language plpgsql stable security definer set search_path = public, app, acc as $$
declare st text := nullif(p->>'status', '');
begin
  perform app.demo_admin();
  return coalesce((select jsonb_agg(to_jsonb(x) order by x.updated_at desc) from (select k.id, k.no, k.subject, k.status, k.priority, k.username, k.created_at, k.updated_at, t.code, t.name from acc.tickets k join acc.tenants t on t.id = k.tenant_id
    where (st is null or k.status = st) order by (k.status = 'open') desc, k.updated_at desc limit 200) x), '[]'::jsonb);
end $$;

create or replace function public.platform_ticket_get(p jsonb) returns jsonb language plpgsql stable security definer set search_path = public, app, acc as $$
declare k acc.tickets; t acc.tenants;
begin
  perform app.demo_admin();
  select * into k from acc.tickets where id = (p->>'id')::uuid; if k.id is null then raise exception 'التذكرة غير موجودة'; end if;
  select * into t from acc.tenants where id = k.tenant_id;
  return jsonb_build_object('ticket', to_jsonb(k) - 'tenant_id' - 'user_id', 'company', jsonb_build_object('code', t.code, 'name', t.name),
    'msgs', coalesce((select jsonb_agg(jsonb_build_object('by_support', by_support, 'author', author, 'body', body, 'at', at) order by at) from acc.ticket_msgs where ticket_id = k.id), '[]'::jsonb));
end $$;

create or replace function public.platform_ticket_reply(p jsonb) returns jsonb language plpgsql volatile security definer set search_path = public, app, acc as $$
declare k acc.tickets; bd text := trim(coalesce(p->>'body', '')); close_it boolean := coalesce((p->>'close')::boolean, false);
begin
  perform app.demo_admin();
  select * into k from acc.tickets where id = (p->>'id')::uuid; if k.id is null then raise exception 'التذكرة غير موجودة'; end if;
  if length(bd) < 2 or length(bd) > 4000 then raise exception 'نص الرد من حرفين إلى 4000 حرف'; end if;
  insert into acc.ticket_msgs (ticket_id, tenant_id, by_support, author, body) values (k.id, k.tenant_id, true, 'فريق الدعم', bd);
  update acc.tickets set status = case when close_it then 'closed' else 'answered' end, updated_at = now() where id = k.id;
  perform app.padmin_log('ticket_reply', (select code from acc.tenants where id = k.tenant_id), '#' || k.no::text);
  return jsonb_build_object('ok', true);
end $$;
-- مُحكَم للحسابات — قائمة تهيئة الشركة الجديدة (تُحسب من بيانات الشركة نفسها؛ لا تخزين)
create or replace function public.onboarding_status(p jsonb default '{}') returns jsonb language plpgsql stable security definer set search_path = public, app, acc as $$
declare t uuid := app.tenant(); x acc.tenants;
begin
  if t is null then raise exception 'يجب تسجيل الدخول'; end if;
  select * into x from acc.tenants where id = t;
  return jsonb_build_array(
    jsonb_build_object('key', 'profile', 'done', coalesce(x.vat_no, '') <> '' or coalesce(x.cr, '') <> ''),
    jsonb_build_object('key', 'parties', 'done', exists (select 1 from acc.parties where tenant_id = t)),
    jsonb_build_object('key', 'journal', 'done', exists (select 1 from acc.journals where tenant_id = t and status = 'posted')),
    jsonb_build_object('key', 'invoice', 'done', exists (select 1 from acc.invoices where tenant_id = t and status = 'issued')),
    jsonb_build_object('key', 'users', 'done', (select count(*) from acc.members where tenant_id = t) > 1),
    jsonb_build_object('key', 'backup', 'done', exists (select 1 from acc.audit where tenant_id = t and action = 'export' and entity = 'backup')),
    jsonb_build_object('key', 'mfa', 'done', exists (select 1 from auth.mfa_factors where user_id = auth.uid() and status = 'verified')),
    jsonb_build_object('key', 'agreement', 'done', exists (select 1 from acc.agreement_acceptance where tenant_id = t)));
end $$;

-- تشديد نهائي (آمن للتكرار): لا يصل الزائر أو المستخدم المسجّل مباشرة لأي دالة داخلية في app/acc
do $$ declare f record; begin
  for f in select p.oid::regprocedure as sig from pg_proc p join pg_namespace n on n.oid = p.pronamespace where n.nspname in ('app','acc') and p.prokind in ('f','p') loop
    begin execute format('revoke execute on function %s from public, anon, authenticated', f.sig); exception when others then null; end; end loop;
  for f in select p.oid::regprocedure as sig from pg_proc p join pg_namespace n on n.oid = p.pronamespace where n.nspname = 'public' and p.prokind = 'f' and p.proname not in ('login_email','register_company','ingest_journal','signup_status','demo_link_open') and pg_get_function_identity_arguments(p.oid) = 'p jsonb' loop
    begin execute format('revoke execute on function %s from public, anon', f.sig); execute format('grant execute on function %s to authenticated', f.sig); exception when others then null; end; end loop;
end $$;
