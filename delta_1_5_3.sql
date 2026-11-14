-- مُحكَم للحسابات 1.5.0.3 — لوحة البائع + روابط ديمو ثابتة + التحكم بالمزايا والإصدارات (آمن للتكرار)
-- مُحكَم للحسابات — لوحة البائع: إدارة الشركات (تعديل/تجديد/إيقاف/حذف) + تمديد روابط الديمو بنفس الرابط والبيانات
-- مبدأ الديمو: الرابط ثابت لا يتغير، وبيانات العميل تبقى كما هي، ولا يُقفل إلا بانتهاء مدته؛ والبائع وحده يمدّه.

-- المدد المسموحة لرابط الديمو: يوم/يومان/3 أيام/أسبوع/أسبوعان/30 يومًا
do $$ declare c record; begin
  for c in select conname from pg_constraint where conrelid = 'acc.demo_links'::regclass and contype = 'c' and pg_get_constraintdef(oid) ilike '%hours%' loop
    execute format('alter table acc.demo_links drop constraint %I', c.conname); end loop;
  alter table acc.demo_links add constraint demo_links_hours_chk check (hours in (24, 48, 72, 168, 336, 720));
end $$;

alter table acc.tenants add column if not exists release int not null default 1;
alter table acc.tenants add column if not exists features_off text[] not null default '{}';
create or replace function app.latest_release() returns int language sql immutable as $$ select 1 $$;
create index if not exists tenants_status_exp_idx on acc.tenants (status, expires_at);
create index if not exists tenants_created_idx on acc.tenants (created_at desc);
create index if not exists demo_links_code_idx on acc.demo_links (code);

-- سجل عمليات البائع (لا يظهر لأي شركة)
create table if not exists acc.platform_audit (
  id bigserial primary key, at timestamptz not null default now(), admin_id uuid, action text not null, code text not null default '', details text not null default '');
alter table acc.platform_audit enable row level security;
create or replace function app.padmin_log(a text, c text, d text) returns void language sql security definer set search_path = public, app, acc as $$
  insert into acc.platform_audit (admin_id, action, code, details) values (auth.uid(), a, coalesce(c, ''), coalesce(d, '')) $$;

-- إغلاق الشركة التجريبية فور انتهاء مدة الرابط (بالدقيقة وليس باليوم)
create or replace function app.tenant_ok(t uuid) returns boolean language sql stable security definer set search_path = public, acc as
$$ select exists (select 1 from acc.tenants x where x.id = t and x.status in ('trial','active') and x.expires_at + 7 >= current_date
     and (jsonb_typeof(x.settings->'demo') is distinct from 'object' or (x.settings->'demo'->>'until') is null or (x.settings->'demo'->>'until')::timestamptz >= now())
     and (not x.require_mfa or (x.mfa_scope = 'admin' and not app.is_admin_like()) or coalesce(auth.jwt()->>'aal','aal1') = 'aal2')) $$;

-- حذف شركة كاملة (داخلي): كل جداولها ثم مستخدموها ثم الشركة
create or replace function app.tenant_destroy(t uuid) returns void language plpgsql security definer set search_path = public, app, acc as $$
declare r record; done boolean; pass int; uids uuid[];
begin
  if t is null then return; end if;
  perform set_config('app.demo_wipe', '1', true);
  uids := array(select user_id from acc.members where tenant_id = t);
  for pass in 1..10 loop
    done := true;
    for r in select c.table_name from information_schema.columns c join information_schema.tables x on x.table_schema = c.table_schema and x.table_name = c.table_name and x.table_type = 'BASE TABLE'
      where c.table_schema = 'acc' and c.column_name = 'tenant_id' and c.table_name not in ('tenants') loop
      begin execute format('delete from acc.%I where tenant_id = $1', r.table_name) using t;
      exception when foreign_key_violation then done := false; end;
    end loop;
    exit when done;
  end loop;
  delete from auth.users where id = any(uids);
  delete from acc.tenants where id = t;
  perform set_config('app.demo_wipe', '0', true);
end $$;

-- تنظيف النسخ المُصدرة المنتهية: تُحفظ بيانات العميل 30 يومًا بعد الانتهاء ليتمكن البائع من التمديد
create or replace function app.demo_cleanup() returns int language plpgsql security definer set search_path = public, app, acc as $$
declare r record; n int := 0;
begin
  for r in select code from acc.tenants where settings ? 'demo' and code <> 'group5' and (settings->'demo'->>'days') is not null and expires_at + 7 < current_date - 30 loop
    perform app.demo_wipe(r.code); n := n + 1; end loop;
  return n;
end $$;

create or replace function public.demo_link_create(p jsonb) returns jsonb language plpgsql security definer set search_path = public, app, acc as $$
declare nm text := trim(coalesce(p->>'label','')); h int := coalesce(nullif(p->>'hours','')::int, 48); code text; pwd text; tok text; alphabet text := 'abcdefghjkmnpqrstuvwxyz23456789'; i int;
begin
  perform app.demo_admin();
  if nm = '' or length(nm) > 80 then raise exception 'الاسم مطلوب (حتى 80 حرفًا)'; end if;
  if h not in (24, 48, 72, 168, 336, 720) then raise exception 'المدة: يوم أو يومان أو 3 أيام أو أسبوع أو أسبوعان أو 30 يومًا'; end if;
  code := 'demo-'; for i in 1..5 loop code := code || substr(alphabet, 1 + floor(random() * length(alphabet))::int, 1); end loop;
  pwd := 'Dm'; for i in 1..8 loop pwd := pwd || substr(alphabet, 1 + floor(random() * length(alphabet))::int, 1); end loop; pwd := pwd || '#7';
  tok := 'k' || substr(replace(gen_random_uuid()::text || gen_random_uuid()::text, '-', ''), 1, 20);
  perform app.demo_seed(code, 'نسخة تجريبية — ' || nm, pwd, 7, nm);
  insert into acc.demo_links (token, label, hours, code, pwd) values (tok, nm, h, code, pwd);
  perform app.padmin_log('demo_create', code, nm || ' / ' || h || ' ساعة');
  return jsonb_build_object('token', tok);
end $$;

-- فتح الرابط: ثابت لا يتغير. تبدأ المدة عند أول فتح، وبعد الانتهاء يُرفض (يمدّه البائع من لوحته فيعود بنفس البيانات)
create or replace function public.demo_link_open(p jsonb) returns jsonb language plpgsql security definer set search_path = public, app, acc as $$
declare l acc.demo_links;
begin
  select * into l from acc.demo_links where token = coalesce(p->>'token', '') for update;
  if l.token is null or l.revoked then raise exception 'الرابط غير صالح أو أُلغي'; end if;
  if l.first_open is null then
    if l.created_at < now() - interval '60 days' then raise exception 'انتهت صلاحية الرابط — تواصل مع البائع'; end if;
    update acc.demo_links set first_open = now(), expires_at = now() + make_interval(hours => l.hours), opens = opens + 1 where token = l.token returning * into l;
    update acc.tenants set expires_at = (l.expires_at at time zone 'UTC')::date - 7,
      settings = case when jsonb_typeof(settings->'demo') = 'object' then settings || jsonb_build_object('demo', (settings->'demo') || jsonb_build_object('until', l.expires_at)) else settings end
      where code = l.code;
  else
    if l.expires_at < now() then raise exception 'انتهت مدة هذا الرابط — تواصل مع البائع للتمديد'; end if;
    update acc.demo_links set opens = opens + 1 where token = l.token;
  end if;
  return jsonb_build_object('code', l.code, 'username', 'owner', 'password', l.pwd, 'expires', l.expires_at);
end $$;

-- حالة الرابط: new / active / expired / revoked
create or replace function public.demo_links_list(p jsonb default '{}') returns jsonb language plpgsql stable security definer set search_path = public, app, acc as $$
begin
  perform app.demo_admin();
  return coalesce((select jsonb_agg(jsonb_build_object('token', token, 'label', label, 'hours', hours, 'code', code, 'first_open', first_open, 'expires_at', expires_at, 'opens', opens, 'created_at', created_at,
    'has_data', exists (select 1 from acc.tenants t where t.code = d.code),
    'state', case when revoked then 'revoked' when first_open is null then (case when created_at < now() - interval '60 days' then 'expired' else 'new' end) when expires_at < now() then 'expired' else 'active' end) order by created_at desc)
    from acc.demo_links d), '[]'::jsonb);
end $$;

-- تمديد نفس الرابط ونفس البيانات: {token, hours}. لا رابط جديد ولا فقد بيانات.
create or replace function public.demo_link_extend(p jsonb) returns jsonb language plpgsql security definer set search_path = public, app, acc as $$
declare l acc.demo_links; h int := coalesce(nullif(p->>'hours','')::int, 0); ne timestamptz;
begin
  perform app.demo_admin();
  if h not in (24, 48, 72, 168, 336, 720) then raise exception 'مدة التمديد: يوم أو يومان أو 3 أيام أو أسبوع أو أسبوعان أو 30 يومًا'; end if;
  select * into l from acc.demo_links where token = coalesce(p->>'token', '') for update;
  if l.token is null then raise exception 'الرابط غير موجود'; end if;
  if l.revoked then raise exception 'الرابط مُلغى — أنشئ رابطًا جديدًا'; end if;
  if not exists (select 1 from acc.tenants where code = l.code) then raise exception 'حُذفت بيانات هذه النسخة بعد انتهاء مدة الاحتفاظ — أنشئ رابطًا جديدًا'; end if;
  if l.first_open is null then
    update acc.demo_links set created_at = now() where token = l.token;  -- لم يُفتح بعد: تُجدَّد صلاحية الفتح، وتبدأ المدة عند أول فتح
    perform app.padmin_log('demo_extend', l.code, 'رابط لم يُفتح: تجديد صلاحية الفتح');
    return jsonb_build_object('state', 'new', 'expires_at', null);
  end if;
  ne := greatest(l.expires_at, now()) + make_interval(hours => h);
  update acc.demo_links set expires_at = ne where token = l.token;
  update acc.tenants set status = 'active', expires_at = (ne at time zone 'UTC')::date - 7,
    settings = case when jsonb_typeof(settings->'demo') = 'object' then settings || jsonb_build_object('demo', (settings->'demo') || jsonb_build_object('until', ne)) else settings end
    where code = l.code;
  perform app.padmin_log('demo_extend', l.code, l.label || ' +' || h || ' ساعة');
  return jsonb_build_object('state', 'active', 'expires_at', ne);
end $$;

create or replace function public.demo_link_revoke(p jsonb) returns jsonb language plpgsql security definer set search_path = public, app, acc as $$
declare l acc.demo_links;
begin
  perform app.demo_admin();
  update acc.demo_links set revoked = true where token = p->>'token' returning * into l;
  if l.token is null then raise exception 'الرابط غير موجود'; end if;
  if exists (select 1 from acc.tenants where code = l.code and settings ? 'demo') then perform app.demo_wipe(l.code); end if;
  perform app.padmin_log('demo_revoke', l.code, l.label);
  return jsonb_build_object('ok', true);
end $$;

-- الشركات المشتركة: بحث وترقيم صفحات (يصلح لآلاف الشركات)
create or replace function public.platform_tenants_page(p jsonb default '{}') returns jsonb language plpgsql stable security definer set search_path = public, app, acc as $$
declare q text := nullif(trim(coalesce(p->>'q','')), ''); lim int := least(greatest(coalesce(nullif(p->>'limit','')::int, 50), 1), 200); off int := greatest(coalesce(nullif(p->>'offset','')::int, 0), 0);
  st text := nullif(p->>'status',''); mine uuid := (select tenant_id from app.me()); tot bigint;
begin
  perform app.demo_admin();
  select count(*) into tot from acc.tenants t where not (t.settings ? 'demo') and (st is null or t.status = st) and (q is null or t.name ilike '%' || q || '%' or t.code ilike '%' || q || '%' or t.contact_phone ilike '%' || q || '%');
  return jsonb_build_object('total', tot, 'rows', coalesce((select jsonb_agg(x) from (
    select jsonb_build_object('code', t.code, 'name', t.name, 'plan', t.plan, 'status', t.status, 'expires_at', t.expires_at::text, 'created_at', t.created_at, 'contact_phone', t.contact_phone, 'contact_email', t.contact_email, 'suspend_msg', t.suspend_msg, 'release', t.release, 'latest', app.latest_release(), 'off', cardinality(t.features_off),
      'users', (select count(*) from acc.members m where m.tenant_id = t.id), 'max_users', t.max_users, 'entities', (select count(*) from acc.entities e where e.tenant_id = t.id), 'max_entities', t.max_entities,
      'last_login', (select max(m.last_login) from acc.members m where m.tenant_id = t.id), 'mine', t.id = mine) x
    from acc.tenants t where not (t.settings ? 'demo') and (st is null or t.status = st) and (q is null or t.name ilike '%' || q || '%' or t.code ilike '%' || q || '%' or t.contact_phone ilike '%' || q || '%')
    order by t.created_at desc limit lim offset off) s), '[]'::jsonb),
    'stats', jsonb_build_object('all', (select count(*) from acc.tenants where not (settings ? 'demo')), 'active', (select count(*) from acc.tenants where not (settings ? 'demo') and status in ('trial','active') and expires_at + 7 >= current_date),
      'soon', (select count(*) from acc.tenants where not (settings ? 'demo') and status <> 'suspended' and expires_at between current_date and current_date + 30)));
end $$;

-- تعديل شركة: الاسم، الباقة، الحدود، الانتهاء، الإيقاف ورسالته
create or replace function public.platform_tenant_save(p jsonb) returns jsonb language plpgsql security definer set search_path = public, app, acc as $$
declare t acc.tenants; mine uuid := (select tenant_id from app.me()); st text := coalesce(nullif(p->>'status',''), null); mu int; me int;
begin
  perform app.demo_admin();
  select * into t from acc.tenants where code = p->>'code' and not (settings ? 'demo') for update;
  if t.id is null then raise exception 'الشركة غير موجودة'; end if;
  if st is not null and st not in ('trial','active','suspended') then raise exception 'حالة غير صحيحة'; end if;
  if st = 'suspended' and t.id = mine then raise exception 'لا يمكن إيقاف الشركة التي تدخل بها الآن'; end if;
  if p ? 'name' and length(trim(p->>'name')) < 2 then raise exception 'اسم الشركة مطلوب'; end if;
  mu := case when p ? 'max_users' then nullif(p->>'max_users','')::int else t.max_users end; me := case when p ? 'max_entities' then nullif(p->>'max_entities','')::int else t.max_entities end;
  if (mu is not null and mu < 1) or (me is not null and me < 1) then raise exception 'الحدود أرقام موجبة (أو فارغة = بلا حد)'; end if;
  update acc.tenants set name = coalesce(nullif(trim(p->>'name'), ''), name), plan = coalesce(nullif(p->>'plan', ''), plan), status = coalesce(st, status),
    expires_at = coalesce(nullif(p->>'expires_at', '')::date, expires_at), max_users = mu, max_entities = me,
    contact_phone = case when p ? 'contact_phone' then left(coalesce(p->>'contact_phone', ''), 40) else contact_phone end,
    suspend_msg = case when p ? 'suspend_msg' then left(coalesce(p->>'suspend_msg', ''), 300) else suspend_msg end
    where id = t.id;
  perform app.padmin_log('tenant_save', t.code, left(p::text, 400));
  return jsonb_build_object('ok', true);
end $$;

-- حذف شركة نهائيًا: مشروط بأن تكون موقوفة، وليست التي تدخل بها، ويلزم تأكيد رمزها
create or replace function public.platform_tenant_delete(p jsonb) returns jsonb language plpgsql security definer set search_path = public, app, acc as $$
declare t acc.tenants; mine uuid := (select tenant_id from app.me());
begin
  perform app.demo_admin();
  select * into t from acc.tenants where code = p->>'code' and not (settings ? 'demo');
  if t.id is null then raise exception 'الشركة غير موجودة'; end if;
  if t.id = mine then raise exception 'لا يمكن حذف الشركة التي تدخل بها الآن'; end if;
  if t.status <> 'suspended' then raise exception 'أوقف الشركة أولًا ثم احذفها'; end if;
  if coalesce(p->>'confirm', '') <> t.code then raise exception 'اكتب رمز الشركة للتأكيد'; end if;
  perform app.padmin_log('tenant_delete', t.code, t.name);
  perform app.tenant_destroy(t.id);
  return jsonb_build_object('ok', true);
end $$;
-- مُحكَم للحسابات — التحكم بالمزايا لكل شركة + إصدارات التحديث (رابط الشركة لا يتغير أبدًا)
-- المبدأ: كل ميزة تُفتح/تُقفل للشركة من لوحة البائع (حسب العقد). والمزايا الجديدة في الإصدارات القادمة لا تصل لشركة
-- إلا بضغط البائع «تحديث إلى آخر إصدار». الحجب يُنفَّذ في الخادم (قاعدة البيانات) لا في الواجهة فقط.

alter table acc.tenants add column if not exists features_off text[] not null default '{}';
alter table acc.tenants add column if not exists contract jsonb not null default '{}'::jsonb;

create table if not exists app.feature_cat (key text primary key, name text not null, grp text not null, core boolean not null default false, since int not null default 1, sort int not null default 0);
alter table app.feature_cat enable row level security;
insert into app.feature_cat (key, name, grp, core, since, sort) values
 ('dashboard', 'لوحة التحكم', 'أساسية', true, 1, 1), ('coa', 'دليل الحسابات', 'أساسية', true, 1, 2), ('journals', 'القيود اليومية والأرصدة الافتتاحية', 'أساسية', true, 1, 3),
 ('sales', 'فواتير المبيعات', 'المبيعات والمشتريات', false, 1, 10), ('purchases', 'فواتير المشتريات', 'المبيعات والمشتريات', false, 1, 11),
 ('parties', 'العملاء والموردون', 'المبيعات والمشتريات', false, 1, 12), ('payments', 'سندات القبض والصرف', 'المبيعات والمشتريات', false, 1, 13),
 ('bank', 'البنوك والتسوية', 'المالية', false, 1, 20), ('inventory', 'المخزون والأصناف', 'المالية', false, 1, 21), ('assets', 'الأصول الثابتة', 'المالية', false, 1, 22),
 ('budgets', 'الموازنات', 'المالية', false, 1, 23), ('costcenters', 'مراكز التكلفة والمشاريع', 'المالية', false, 1, 24),
 ('reports', 'التقارير والتحليل المالي والمفتش', 'التقارير والامتثال', false, 1, 30), ('tax', 'الإقرار الضريبي', 'التقارير والامتثال', false, 1, 31),
 ('periods', 'الفترات والإقفال السنوي', 'التقارير والامتثال', false, 1, 32), ('controls', 'الرقابة الداخلية', 'التقارير والامتثال', false, 1, 33),
 ('portal', 'بوابة الخدمة الذاتية (طلباتي)', 'الخدمة الذاتية', false, 1, 40), ('requests', 'صندوق الطلبات', 'الخدمة الذاتية', false, 1, 41),
 ('attachments', 'مركز المستندات والمرفقات', 'أدوات', false, 1, 50), ('import', 'الاستيراد من Excel', 'أدوات', false, 1, 51),
 ('connectors', 'الموصّلات (API) والربط الخارجي', 'أدوات', false, 1, 52), ('backup', 'النسخ الاحتياطي من داخل البرنامج', 'أدوات', false, 1, 53)
on conflict (key) do update set name = excluded.name, grp = excluded.grp, core = excluded.core, sort = excluded.sort;

-- آخر إصدار للبرنامج (يُرفع هنا عند نشر مزايا جديدة وتُسجَّل في feature_cat بقيمة since الجديدة)
create or replace function app.latest_release() returns int language sql immutable as $$ select 1 $$;
alter table acc.tenants add column if not exists release int not null default 1;
alter table acc.tenants alter column release set default 1;  -- الشركات الجديدة تبدأ بآخر إصدار عند نشره: يُعدَّل هذا الافتراضي مع latest_release

create or replace function app.feat_on(k text, t uuid default null) returns boolean language sql stable security definer set search_path = public, acc, app as $$
  select coalesce((select not (k = any(x.features_off)) and coalesce((select c.since from app.feature_cat c where c.key = k), 1) <= x.release from acc.tenants x where x.id = coalesce(t, app.tenant())), true) $$;

create or replace function app.features_off(t uuid) returns jsonb language sql stable security definer set search_path = public, acc, app as $$
  select coalesce((select jsonb_agg(c.key order by c.sort) from app.feature_cat c, acc.tenants x where x.id = t and not c.core and (c.key = any(x.features_off) or c.since > x.release)), '[]'::jsonb) $$;

-- بوابة الخادم: الصلاحية لا تكفي إن كانت الميزة مقفلة للشركة (حتى للمالك)
create or replace function app.can(module text, action text) returns boolean language sql stable security definer set search_path = public, acc, app as
$$ select app.feat_on(module) and (coalesce((app.role_def()->>'locked')::boolean, false) or coalesce(jsonb_exists(app.role_def()->'perms'->module, action), false)) $$;
create or replace function app.sys(p text) returns boolean language sql stable security definer set search_path = public, acc, app as
$$ select (p <> 'backup' or app.feat_on('backup')) and (coalesce((app.role_def()->>'locked')::boolean, false) or coalesce(jsonb_exists(app.role_def()->'sys', p), false)) $$;

create or replace function public.my_profile(p jsonb default '{}') returns jsonb language plpgsql stable security definer set search_path = public, app, acc as $$
declare m acc.members; t acc.tenants;
begin
  select * into m from acc.members where user_id = auth.uid();
  if m.user_id is null then return jsonb_build_object('member', null, 'platform_admin', app.is_platform_admin(), 'aal', coalesce(auth.jwt()->>'aal','aal1')); end if;
  select * into t from acc.tenants where id = m.tenant_id;
  return jsonb_build_object('member', to_jsonb(m), 'tenant', to_jsonb(t) - 'created_ip', 'role', (select jsonb_build_object('id', r.id, 'name', r.name, 'locked', r.locked, 'perms', r.perms, 'sys', r.sys) from acc.roles r where r.tenant_id = m.tenant_id and r.id = m.role),
    'entities', (select coalesce(jsonb_agg(to_jsonb(e) order by e.code), '[]'::jsonb) from acc.entities e where e.tenant_id = m.tenant_id and e.active and (m.entities is null or e.id = any(m.entities))),
    'policy', jsonb_build_object('journals', app.policy('journals'), 'invoices', app.policy('invoices'), 'payments', app.policy('payments')),
    'platform_admin', app.is_platform_admin(), 'aal', coalesce(auth.jwt()->>'aal','aal1'), 'ok', app.tenant_ok(m.tenant_id), 'features_off', app.features_off(m.tenant_id));
end $$;
-- الإدخال الخارجي: يلتزم بحالة الاشتراك وبميزة الموصّلات
create or replace function public.ingest_journal(p jsonb) returns jsonb language plpgsql security definer set search_path = public, app, acc as $$
declare k acc.api_keys; h text := encode(sha256(convert_to(coalesce(p->>'key',''), 'UTF8')), 'hex'); jid uuid := gen_random_uuid(); d date := (p->>'date')::date; src text := coalesce(nullif(trim(p->>'source'),''), 'external'); ext text := trim(coalesce(p->>'external_id',''));
  per acc.periods; dr numeric; cr numeric; ex uuid; l jsonb; tot numeric;
begin
  select * into k from acc.api_keys where key_hash = h and active and (expires_at is null or expires_at > now());
  if k.id is null or not ('ingest_journal' = any(k.scopes)) then raise exception 'مفتاح غير صالح'; end if;
  if not app.tenant_ok(k.tenant_id) or not app.feat_on('connectors', k.tenant_id) then raise exception 'الخدمة غير مفعّلة لهذه الشركة'; end if;
  if ext = '' or length(ext) > 100 or length(src) > 40 then raise exception 'المعرّف الخارجي والمصدر مطلوبان'; end if;
  if d is null then raise exception 'التاريخ مطلوب'; end if;
  if jsonb_array_length(coalesce(p->'lines','[]'::jsonb)) < 2 or jsonb_array_length(p->'lines') > 500 then raise exception 'سطران إلى 500 سطر'; end if;
  select journal_id into ex from acc.ingest_log where tenant_id = k.tenant_id and source = src and external_id = ext;
  if found then return jsonb_build_object('duplicate', true, 'journal_id', ex); end if;
  select * into per from acc.periods where tenant_id = k.tenant_id and entity_id = k.entity_id and d between start_date and end_date; if per.id is null or per.status = 'closed' then raise exception 'لا توجد فترة مفتوحة للتاريخ %', d; end if;
  select coalesce(sum(coalesce(nullif(x->>'debit','')::numeric,0)),0), coalesce(sum(coalesce(nullif(x->>'credit','')::numeric,0)),0) into dr, cr from jsonb_array_elements(p->'lines') x;
  if round(dr,2) <> round(cr,2) or dr = 0 then raise exception 'القيد غير متوازن (مدين % / دائن %)', dr, cr; end if;
  insert into acc.journals (tenant_id, id, entity_id, type, date, description, reference, status, source, created_by, submitted_at, total)
  values (k.tenant_id, jid, k.entity_id, 'GJ', d, left(coalesce(p->>'description','قيد من ' || src), 500), left(ext, 100), 'pending', 'connector', null, now(), round(dr, 2));
  perform app.put_lines(k.tenant_id, jid, k.entity_id, d, p->'lines');
  insert into acc.ingest_log (tenant_id, key_id, source, external_id, journal_id) values (k.tenant_id, k.id, src, ext, jid);
  update acc.api_keys set last_used_at = now(), use_count = use_count + 1 where id = k.id and tenant_id = k.tenant_id;
  perform app.audit_for(k.tenant_id, null, 'connector:' || k.name, 'ingest', 'journal', jid::text, src || ' / ' || ext || ' — ' || round(dr,2));
  return jsonb_build_object('journal_id', jid, 'status', 'pending');
end $$;

-- لوحة البائع: حالة مزايا شركة
create or replace function public.platform_features_get(p jsonb) returns jsonb language plpgsql stable security definer set search_path = public, app, acc as $$
declare t acc.tenants;
begin
  perform app.demo_admin();
  select * into t from acc.tenants where code = p->>'code' and not (settings ? 'demo');
  if t.id is null then raise exception 'الشركة غير موجودة'; end if;
  return jsonb_build_object('code', t.code, 'name', t.name, 'release', t.release, 'latest', app.latest_release(), 'contract', t.contract,
    'features', (select jsonb_agg(jsonb_build_object('key', c.key, 'name', c.name, 'grp', c.grp, 'core', c.core, 'since', c.since,
       'on', c.core or not (c.key = any(t.features_off)), 'locked_by_release', c.since > t.release) order by c.sort) from app.feature_cat c));
end $$;

-- حفظ المزايا والعقد: {code, off: [keys], contract: {price, currency, notes, agreed_at}} — لا يمس رابط الشركة ولا بياناتها
create or replace function public.platform_features_save(p jsonb) returns jsonb language plpgsql security definer set search_path = public, app, acc as $$
declare t acc.tenants; off text[]; bad text; c jsonb;
begin
  perform app.demo_admin();
  select * into t from acc.tenants where code = p->>'code' and not (settings ? 'demo') for update;
  if t.id is null then raise exception 'الشركة غير موجودة'; end if;
  off := coalesce(array(select jsonb_array_elements_text(coalesce(p->'off', '[]'::jsonb))), '{}');
  select k into bad from unnest(off) k where not exists (select 1 from app.feature_cat c where c.key = k and not c.core) limit 1;
  if bad is not null then raise exception 'ميزة غير معروفة أو أساسية لا تُقفل: %', bad; end if;
  c := coalesce(p->'contract', t.contract);
  if jsonb_typeof(c) <> 'object' or length(c::text) > 4000 then raise exception 'بيانات العقد غير صالحة'; end if;
  update acc.tenants set features_off = off, contract = c where id = t.id;
  perform app.padmin_log('features_save', t.code, 'قبل: ' || array_to_string(t.features_off, ',') || ' | بعد: ' || array_to_string(off, ',') || ' | عقد: ' || left(c::text, 300));
  return jsonb_build_object('ok', true);
end $$;

-- زر «تحديث إلى آخر إصدار»: تصل الشركة المزايا الجديدة (المقفولة منها عقديًا تبقى مقفولة)
create or replace function public.platform_release_push(p jsonb) returns jsonb language plpgsql security definer set search_path = public, app, acc as $$
declare t acc.tenants;
begin
  perform app.demo_admin();
  select * into t from acc.tenants where code = p->>'code' and not (settings ? 'demo') for update;
  if t.id is null then raise exception 'الشركة غير موجودة'; end if;
  update acc.tenants set release = app.latest_release() where id = t.id;
  perform app.padmin_log('release_push', t.code, 'من إصدار ' || t.release || ' إلى ' || app.latest_release());
  return jsonb_build_object('ok', true, 'release', app.latest_release());
end $$;


-- المخزون: إن أُقفلت الميزة تبقى قراءة الأصناف متاحة لشاشات الفواتير فقط، وتُمنع الإضافة والتعديل والحذف وحركات المخزون
create or replace function app.need_inv(action text) returns uuid language plpgsql stable security definer set search_path = public, acc, app as $$
declare t uuid := app.need(null, null);
begin
  if not app.feat_on('inventory') then
    if action = 'view' and (app.can('purchases','view') or app.can('sales','view')) then return t; end if;
    raise exception 'ميزة المخزون غير مفعّلة لشركتكم';
  end if;
  if app.can('inventory', action) or (action = 'view' and (app.can('purchases','view') or app.can('sales','view'))) or (action in ('add','edit') and app.can('purchases','add')) or (action = 'delete' and app.can('purchases','delete')) then return t; end if;
  raise exception 'ليست لديك صلاحية المخزون (%)', action;
end $$;

do $$ declare f record; begin
  for f in select p.oid::regprocedure as sig, p.proname from pg_proc p join pg_namespace n on n.oid = p.pronamespace where n.nspname = 'public' and p.prokind = 'f' and p.proowner = (select oid from pg_roles where rolname = current_user)
      and (p.proname in ('login_email','register_company','ingest_journal','signup_status','demo_link_open') or p.pronargs = 0 or p.proargtypes::text = (select oid::text from pg_type where typname = 'jsonb')) loop
    if f.proname in ('register_company','ingest_journal','login_email','signup_status','demo_link_open') then execute format('grant execute on function %s to anon, authenticated', f.sig);
    else execute format('grant execute on function %s to authenticated', f.sig); end if;
  end loop;
end $$;
alter default privileges in schema public revoke execute on functions from public, anon;

-- تشديد نهائي (آمن للتكرار): لا يصل الزائر أو المستخدم المسجّل مباشرة لأي دالة داخلية في app/acc
do $$ declare f record; begin
  for f in select p.oid::regprocedure as sig from pg_proc p join pg_namespace n on n.oid = p.pronamespace where n.nspname in ('app','acc') and p.prokind in ('f','p') loop
    begin execute format('revoke execute on function %s from public, anon, authenticated', f.sig); exception when others then null; end; end loop;
  for f in select p.oid::regprocedure as sig from pg_proc p join pg_namespace n on n.oid = p.pronamespace where n.nspname = 'public' and p.prokind = 'f' and p.proname not in ('login_email','register_company','ingest_journal','signup_status','demo_link_open') and pg_get_function_identity_arguments(p.oid) = 'p jsonb' loop
    begin execute format('revoke execute on function %s from public, anon', f.sig); execute format('grant execute on function %s to authenticated', f.sig); exception when others then null; end; end loop;
end $$;
