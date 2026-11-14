-- مُحكَم 1.5.0.9 — بوابة API الموحّدة + سجل إصدارات القاعدة (آمن للتكرار، لا يمس الروابط ولا البيانات)
-- مُحكَم للحسابات — بوابة API الموحّدة v1 (للربط مع أي نظام): مفتاح ↔ مستخدم خدمة بدور محدود، فتسري كل الصلاحيات والتدقيق وإيقاف المزايا كما هي
-- نقطة واحدة: POST /rest/v1/rpc/api_call  {"p": {"key": "mk_…", "op": "invoices.list", "args": {…}, "idem": "اختياري للكتابة"}}
alter table acc.api_keys add column if not exists kind text not null default 'ingest' check (kind in ('ingest','api'));
alter table acc.api_keys add column if not exists member_id uuid;
alter table acc.api_keys add column if not exists role text;

-- قائمة العمليات المسموحة (بيانات لا شيفرة: التوسعة بإضافة صف)
create table if not exists app.api_ops (op text primary key, fn text not null, writes boolean not null default false, descr text not null default '');
insert into app.api_ops (op, fn, writes, descr) values
 ('accounts.list','coa_list',false,'دليل الحسابات'),('entities.list','entity_list',false,'الكيانات'),('parties.list','party_list',false,'العملاء والموردون'),('party.get','party_get',false,'طرف بتفاصيله'),
 ('invoices.list','inv_list',false,'الفواتير'),('invoice.get','inv_get',false,'فاتورة بتفاصيلها'),('payments.list','pay_list',false,'المدفوعات'),('payment.get','pay_get',false,'سند'),
 ('journals.list','je_list',false,'القيود'),('journal.get','je_get',false,'قيد بأسطره'),('items.list','item_list',false,'الأصناف'),('tax.list','tax_list',false,'رموز الضريبة'),('fx.rates','fx_rate_list',false,'أسعار الصرف'),
 ('report.trial_balance','rpt_trial_balance',false,'ميزان المراجعة'),('report.ledger','rpt_ledger',false,'الأستاذ'),('report.aging','rpt_aging',false,'أعمار الديون'),('report.income','rpt_income',false,'قائمة الدخل'),
 ('report.balance_sheet','rpt_balance_sheet',false,'المركز المالي'),('report.cashflow','rpt_cashflow',false,'التدفقات النقدية'),('report.vat','rpt_vat',false,'إقرار ضريبة القيمة المضافة'),('dashboard','dashboard',false,'مؤشرات لوحة التحكم'),
 ('party.upsert','party_upsert',true,'إنشاء/تعديل طرف'),('item.upsert','item_upsert',true,'إنشاء/تعديل صنف'),('invoice.save','inv_save',true,'حفظ فاتورة (مسودة)'),('invoice.submit','inv_submit',true,'إرسال فاتورة للاعتماد'),
 ('invoice.issue','inv_issue',true,'إصدار فاتورة'),('payment.save','pay_save',true,'حفظ سند'),('payment.submit','pay_submit',true,'إرسال سند للاعتماد'),('journal.save','je_save',true,'حفظ قيد (مسودة)'),('journal.submit','je_submit',true,'إرسال قيد للاعتماد'),
 ('fx.set','fx_rate_set',true,'تسجيل سعر صرف')
on conflict (op) do update set fn = excluded.fn, writes = excluded.writes, descr = excluded.descr;

create table if not exists acc.api_rate (key_id uuid not null, minute timestamptz not null, n int not null default 0, primary key (key_id, minute));
create table if not exists acc.api_idem (key_id uuid not null, idem text not null, result jsonb, at timestamptz not null default now(), primary key (key_id, idem));
alter table acc.api_rate enable row level security; alter table acc.api_idem enable row level security;

-- إنشاء مفتاح API: يُنشئ مستخدم خدمة (لا يستطيع الدخول) بدور محدّد لا يملك صلاحيات نظام
create or replace function public.api_key_create(p jsonb) returns jsonb language plpgsql volatile security definer set search_path = public, app, acc, auth as $$
declare t uuid := app.need('connectors','add'); nm text := trim(coalesce(p->>'name','')); rl text := trim(coalesce(p->>'role','')); r acc.roles; e uuid := nullif(p->>'entity','')::uuid; secret text; pre text; v_id uuid := gen_random_uuid(); uid uuid; un text; tcode text; slug text;
begin
  if nm = '' or length(nm) > 80 then raise exception 'اسم المفتاح مطلوب'; end if;
  select * into r from acc.roles where tenant_id = t and id = rl; if r.id is null then raise exception 'الدور غير موجود'; end if;
  if r.locked or jsonb_array_length(coalesce(r.sys, '[]'::jsonb)) > 0 then raise exception 'لا يجوز ربط مفتاح بدور إداري أو بصلاحيات نظام — أنشئ دورًا مخصصًا بالصلاحيات اللازمة فقط'; end if;
  if e is not null then perform app.entity_ok(t, e); else e := (select id from acc.entities where tenant_id = t order by created_at limit 1); end if;
  select x.code into tcode from acc.tenants x where x.id = t;
  pre := substr(replace(gen_random_uuid()::text, '-', ''), 1, 8); secret := 'mk_' || pre || '_' || replace(gen_random_uuid()::text || gen_random_uuid()::text, '-', '');
  slug := substr(pre, 1, 6); un := 'api.' || slug;
  uid := app.make_auth_user(app.login_email(tcode, un), replace(gen_random_uuid()::text || gen_random_uuid()::text, '-', ''), 'مفتاح API: ' || nm);
  insert into acc.members (user_id, tenant_id, username, name, role, entities) values (uid, t, un, 'مفتاح API: ' || nm, rl, case when nullif(p->>'entity','') is null then null else array[e] end);
  insert into acc.api_keys (tenant_id, id, name, prefix, key_hash, entity_id, scopes, kind, member_id, role, expires_at, created_by)
  values (t, v_id, nm, pre, encode(sha256(convert_to(secret, 'UTF8')), 'hex'), e, array['api'], 'api', uid, rl, nullif(p->>'expires_at','')::timestamptz, auth.uid());
  perform app.audit('create', 'connector', v_id::text, 'مفتاح API ' || nm || ' — الدور ' || rl);
  return jsonb_build_object('id', v_id, 'key', secret, 'note', 'احفظ المفتاح الآن — لا يظهر مرة أخرى');
end $$;

create or replace function public.connector_key_list(p jsonb default '{}') returns jsonb language plpgsql stable security definer set search_path = public, app, acc as $$
declare t uuid := app.need('connectors','view');
begin return coalesce((select jsonb_agg(jsonb_build_object('id', k.id, 'name', k.name, 'prefix', k.prefix, 'entity_id', k.entity_id, 'active', k.active, 'expires_at', k.expires_at, 'last_used_at', k.last_used_at, 'use_count', k.use_count, 'created_at', k.created_at, 'kind', k.kind, 'role', k.role) order by k.created_at desc) from acc.api_keys k where k.tenant_id = t), '[]'::jsonb); end $$;

create or replace function public.connector_key_revoke(p jsonb) returns jsonb language plpgsql volatile security definer set search_path = public, app, acc as $$
declare t uuid := app.need('connectors','delete'); k acc.api_keys;
begin
  update acc.api_keys set active = false where tenant_id = t and id = (p->>'id')::uuid returning * into k; if k.id is null then raise exception 'المفتاح غير موجود'; end if;
  if k.member_id is not null then update acc.members set active = false where user_id = k.member_id and tenant_id = t; end if;
  perform app.audit('revoke', 'connector', p->>'id', 'إلغاء مفتاح ' || k.name); return jsonb_build_object('ok', true);
end $$;

-- كتالوج العمليات (علني للتوثيق الذاتي)
create or replace function public.api_catalog(p jsonb default '{}') returns jsonb language sql stable security definer set search_path = public, app, acc as $$
  select jsonb_build_object('version', 'v1', 'rate_limit_per_minute', 300, 'ops', coalesce((select jsonb_agg(jsonb_build_object('op', op, 'writes', writes, 'descr', descr) order by op) from app.api_ops), '[]'::jsonb)) $$;

-- نقطة الدخول: تُصادَق بالمفتاح فقط
create or replace function public.api_call(p jsonb) returns jsonb language plpgsql volatile security definer set search_path = public, app, acc as $$
declare k acc.api_keys; h text := encode(sha256(convert_to(coalesce(p->>'key', ''), 'UTF8')), 'hex'); o app.api_ops; opn text := coalesce(p->>'op', ''); args jsonb := coalesce(p->'args', '{}'::jsonb); idm text := nullif(trim(coalesce(p->>'idem', '')), ''); cnt int; res jsonb; prev jsonb; m acc.members;
begin
  if jsonb_typeof(args) <> 'object' then raise exception 'args يجب أن تكون كائنًا'; end if;
  if length(args::text) > 400000 then raise exception 'الطلب كبير جدًا'; end if;
  select * into k from acc.api_keys where key_hash = h and active and kind = 'api' and (expires_at is null or expires_at > now());
  if k.id is null then raise exception 'مفتاح غير صالح'; end if;
  select * into m from acc.members where user_id = k.member_id and tenant_id = k.tenant_id and active;
  if m.user_id is null or not app.tenant_ok(k.tenant_id) then raise exception 'الخدمة غير متاحة لهذه الشركة'; end if;
  insert into acc.api_rate (key_id, minute, n) values (k.id, date_trunc('minute', now()), 1) on conflict (key_id, minute) do update set n = acc.api_rate.n + 1 returning n into cnt;
  if cnt > 300 then raise exception 'تجاوزت حد الطلبات (300 في الدقيقة) — أعد المحاولة بعد قليل'; end if;
  if random() < 0.02 then delete from acc.api_rate where minute < now() - interval '1 hour'; delete from acc.api_idem where at < now() - interval '7 days'; end if;
  select * into o from app.api_ops where api_ops.op = opn; if o.op is null then raise exception 'عملية غير معروفة: %', left(opn, 60); end if;
  if not app.feat_on('connectors', k.tenant_id) then raise exception 'ميزة الموصّلات غير مفعّلة لهذه الشركة'; end if;
  if o.writes and idm is not null then
    select result into prev from acc.api_idem where key_id = k.id and api_idem.idem = idm;
    if found then return jsonb_build_object('ok', true, 'duplicate', true, 'result', prev); end if;
  end if;
  perform set_config('request.jwt.claim.sub', m.user_id::text, true);
  perform set_config('request.jwt.claims', jsonb_build_object('sub', m.user_id, 'role', 'authenticated', 'aal', 'aal2', 'api', true)::text, true);
  execute format('select public.%I($1)', o.fn) into res using args;
  update acc.api_keys set last_used_at = now(), use_count = use_count + 1 where id = k.id and tenant_id = k.tenant_id;
  if o.writes and idm is not null then insert into acc.api_idem (key_id, idem, result) values (k.id, idm, res) on conflict do nothing; end if;
  return jsonb_build_object('ok', true, 'result', res);
end $$;
-- مُحكَم للحسابات — سجل إصدارات قاعدة البيانات: يعرف مدير المنصة أي تحديث طُبّق، وينبّه إن كان التطبيق أحدث من القاعدة
create table if not exists app.schema_migrations (version text primary key check (version ~ '^[0-9]+(\.[0-9]+){2,3}$'), name text not null default '', applied_at timestamptz not null default now());
insert into app.schema_migrations (version, name) values
  ('1.5.0.5', 'تأمين التخزين + مراقبة الأخطاء'), ('1.5.0.6', 'استرجاع الكوارث'), ('1.5.0.7', 'حماية مدير المنصة + القبول الإلكتروني + أداء التدفقات'),
  ('1.5.0.8', 'إنهاء العقد + الدعم الفني + قائمة التهيئة'), ('1.5.0.9', 'بوابة API الموحّدة + سجل الإصدارات')
on conflict (version) do nothing;

create or replace function public.platform_system_info(p jsonb default '{}') returns jsonb language plpgsql stable security definer set search_path = public, app, acc as $$
begin
  perform app.demo_admin();
  return jsonb_build_object('versions', coalesce((select jsonb_agg(jsonb_build_object('version', version, 'name', name, 'applied_at', applied_at) order by string_to_array(version, '.')::int[] desc) from app.schema_migrations), '[]'::jsonb),
    'db_version', (select version from app.schema_migrations order by string_to_array(version, '.')::int[] desc limit 1),
    'tenants', (select count(*) from acc.tenants where not (settings ? 'demo')), 'latest_release', app.latest_release());
end $$;

-- تشديد نهائي (آمن للتكرار): لا يصل الزائر أو المستخدم المسجّل مباشرة لأي دالة داخلية في app/acc
do $$ declare f record; begin
  for f in select p.oid::regprocedure as sig from pg_proc p join pg_namespace n on n.oid = p.pronamespace where n.nspname in ('app','acc') and p.prokind in ('f','p') loop
    begin execute format('revoke execute on function %s from public, anon, authenticated', f.sig); exception when others then null; end; end loop;
  for f in select p.oid::regprocedure as sig from pg_proc p join pg_namespace n on n.oid = p.pronamespace where n.nspname = 'public' and p.prokind = 'f' and p.proname not in ('login_email','register_company','ingest_journal','signup_status','demo_link_open') and pg_get_function_identity_arguments(p.oid) = 'p jsonb' loop
    begin execute format('revoke execute on function %s from public, anon', f.sig); execute format('grant execute on function %s to authenticated', f.sig); exception when others then null; end; end loop;
end $$;
