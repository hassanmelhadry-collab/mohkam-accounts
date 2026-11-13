-- مُحكَم للحسابات — install.sql (generated)
-- ===== sql/001_core.sql =====
-- مُحكَم للحسابات — النواة: الشركات، المستخدمون، الأدوار، سجل التدقيق المتسلسل، دوال الصلاحيات
-- معمارية الأمان: كل الجداول في مخطط acc (غير مكشوف) وRLS مفعّل بلا أي سياسة أو منح = لا وصول مباشر إطلاقًا.
-- الوصول الوحيد عبر دوال public (SECURITY DEFINER) تتحقق من الهوية والشركة والصلاحية والنطاق. (RPC-only)
create schema if not exists app;
create schema if not exists acc;
do $$ begin create extension if not exists pgcrypto with schema extensions; exception when others then null; end $$;

create table if not exists acc.tenants (
  id uuid primary key default gen_random_uuid(),
  code text unique not null check (code ~ '^[a-z0-9][a-z0-9-]{2,30}$'),
  name text not null, name_en text not null default '', cr text not null default '', vat_no text not null default '',
  country text not null default 'SA', currency text not null default 'SAR',
  contact_phone text not null default '', contact_email text not null default '', address text not null default '',
  plan text not null default 'P', max_users int, max_entities int,
  status text not null default 'trial' check (status in ('trial','active','suspended')),
  expires_at date not null default (current_date + 14), suspend_msg text not null default '',
  require_mfa boolean not null default false, mfa_scope text not null default 'all' check (mfa_scope in ('all','admin')),
  settings jsonb not null default '{}'::jsonb check (jsonb_typeof(settings) = 'object'),
  created_ip text, created_at timestamptz not null default now()
);
create table if not exists acc.members (
  user_id uuid primary key references auth.users(id) on delete cascade,
  tenant_id uuid not null references acc.tenants(id) on delete cascade,
  username text not null, name text not null default '', role text not null,
  entities uuid[],                                   -- null = كل الكيانات
  active boolean not null default true, must_change boolean not null default false,
  created_at timestamptz not null default now(), last_login timestamptz,
  unique (tenant_id, username)
);
create table if not exists acc.roles (
  tenant_id uuid not null references acc.tenants(id) on delete cascade,
  id text not null check (id ~ '^[a-z0-9_]{2,30}$'), name text not null, description text not null default '',
  locked boolean not null default false, perms jsonb not null default '{}'::jsonb, sys jsonb not null default '[]'::jsonb,
  primary key (tenant_id, id)
);
create table if not exists acc.platform_admins (user_id uuid primary key references auth.users(id) on delete cascade);
create table if not exists acc.seq (
  tenant_id uuid not null, entity_id uuid, key text not null, yr int not null default 0, last bigint not null default 0
);
create unique index if not exists seq_u on acc.seq (tenant_id, coalesce(entity_id, '00000000-0000-0000-0000-000000000000'::uuid), key, yr);

-- سجل التدقيق: إضافة فقط + تسلسل تجزئة (أي حذف أو تعديل يكسر السلسلة ويظهر في التحقق)
create table if not exists acc.audit (
  id bigserial primary key, tenant_id uuid not null references acc.tenants(id) on delete cascade,
  at timestamptz not null default clock_timestamp(), user_id uuid, username text, action text not null, entity text, ref text, details text,
  prev_hash text, hash text not null
);
create index if not exists audit_t on acc.audit (tenant_id, id desc);
create index if not exists audit_ref on acc.audit (tenant_id, entity, ref);

alter table acc.tenants enable row level security; alter table acc.members enable row level security; alter table acc.roles enable row level security;
alter table acc.platform_admins enable row level security; alter table acc.seq enable row level security; alter table acc.audit enable row level security;

create table if not exists acc.entities (
  tenant_id uuid not null references acc.tenants(id) on delete cascade, id uuid not null default gen_random_uuid(),
  code text not null, name text not null, name_en text not null default '', vat_no text not null default '', cr text not null default '', address text not null default '',
  active boolean not null default true, created_at timestamptz not null default now(),
  primary key (tenant_id, id), unique (tenant_id, code)
);
alter table acc.entities enable row level security;

-- ===== دوال مساعدة =====
create or replace function app.me() returns acc.members language sql stable security definer set search_path = public, acc as
$$ select m.* from acc.members m where m.user_id = auth.uid() and m.active $$;
create or replace function app.tenant() returns uuid language sql stable security definer set search_path = public, acc as
$$ select tenant_id from app.me() $$;
create or replace function app.is_platform_admin() returns boolean language sql stable security definer set search_path = public, acc as
$$ select exists (select 1 from acc.platform_admins where user_id = auth.uid()) $$;

create or replace function app.role_def() returns jsonb language sql stable security definer set search_path = public, acc as
$$ select coalesce((select jsonb_build_object('locked', r.locked, 'perms', r.perms, 'sys', r.sys) from acc.roles r where r.tenant_id = app.tenant() and r.id = (select role from app.me())), '{}'::jsonb) $$;
create or replace function app.can(module text, action text) returns boolean language sql stable security definer set search_path = public, acc as
$$ select coalesce((app.role_def()->>'locked')::boolean, false) or coalesce(jsonb_exists(app.role_def()->'perms'->module, action), false) $$;
create or replace function app.sys(p text) returns boolean language sql stable security definer set search_path = public, acc as
$$ select coalesce((app.role_def()->>'locked')::boolean, false) or coalesce(jsonb_exists(app.role_def()->'sys', p), false) $$;
create or replace function app.is_admin_like() returns boolean language sql stable security definer set search_path = public, acc as
$$ select coalesce((app.role_def()->>'locked')::boolean, false) or coalesce(jsonb_array_length(app.role_def()->'sys'), 0) > 0 $$;

create or replace function app.tenant_ok(t uuid) returns boolean language sql stable security definer set search_path = public, acc as
$$ select exists (select 1 from acc.tenants x where x.id = t and x.status in ('trial','active') and x.expires_at + 7 >= current_date
     and (not x.require_mfa or (x.mfa_scope = 'admin' and not app.is_admin_like()) or coalesce(auth.jwt()->>'aal','aal1') = 'aal2')) $$;

-- بوابة كل دالة: مستخدم فعّال + شركة فعّالة + صلاحية
create or replace function app.need(module text, action text) returns uuid language plpgsql stable security definer set search_path = public, acc as $$
declare t uuid := app.tenant();
begin
  if t is null then raise exception 'يجب تسجيل الدخول'; end if;
  if not app.tenant_ok(t) then raise exception 'الاشتراك غير فعّال أو يتطلب التحقق الثنائي'; end if;
  if module is not null and not app.can(module, action) then raise exception 'ليست لديك صلاحية (%/%)', module, action; end if;
  return t;
end $$;
create or replace function app.need_sys(p text) returns uuid language plpgsql stable security definer set search_path = public, acc as $$
declare t uuid := app.tenant();
begin
  if t is null then raise exception 'يجب تسجيل الدخول'; end if;
  if not app.tenant_ok(t) then raise exception 'الاشتراك غير فعّال أو يتطلب التحقق الثنائي'; end if;
  if not app.sys(p) then raise exception 'ليست لديك صلاحية النظام (%)', p; end if;
  return t;
end $$;

create or replace function app.setting(path text[], dflt jsonb default null) returns jsonb language sql stable security definer set search_path = public, acc as
$$ select coalesce((select settings #> path from acc.tenants where id = app.tenant()), dflt) $$;

-- كيانات المستخدم المسموحة
create or replace function app.ents(p jsonb default '{}'::jsonb) returns uuid[] language plpgsql stable security definer set search_path = public, acc as $$
declare m uuid[]; t uuid;
begin
  select x.tenant_id, x.entities into t, m from app.me() x;
  if t is null then return '{}'::uuid[]; end if;
  return coalesce((select array_agg(e.id) from acc.entities e where e.tenant_id = t and e.active and (m is null or e.id = any(m))), '{}'::uuid[]);
end $$;

-- ===== سجل التدقيق =====
create or replace function app.audit_for(t uuid, uid uuid, uname text, p_action text, p_entity text, p_ref text, p_details text default '') returns void language plpgsql security definer set search_path = public, acc as $$
declare prev text; ts timestamptz := clock_timestamp(); h text;
begin
  perform pg_advisory_xact_lock(hashtextextended(t::text, 7));
  select hash into prev from acc.audit where tenant_id = t order by id desc limit 1;
  h := encode(sha256(convert_to(coalesce(prev,'') || '|' || t::text || '|' || to_char(ts at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US') || '|' || coalesce(uname,'') || '|' || p_action || '|' || coalesce(p_entity,'') || '|' || coalesce(p_ref,'') || '|' || coalesce(p_details,''), 'UTF8')), 'hex');
  insert into acc.audit (tenant_id, at, user_id, username, action, entity, ref, details, prev_hash, hash) values (t, ts, uid, uname, p_action, p_entity, p_ref, p_details, prev, h);
end $$;
create or replace function app.audit(p_action text, p_entity text, p_ref text, p_details text default '') returns void language plpgsql security definer set search_path = public, acc as $$
declare m acc.members;
begin select * into m from app.me(); if m.tenant_id is null then return; end if;
  perform app.audit_for(m.tenant_id, m.user_id, m.username, p_action, p_entity, p_ref, p_details); end $$;

create or replace function app.audit_guard() returns trigger language plpgsql as $$
begin raise exception 'سجل التدقيق للإضافة فقط — لا يجوز التعديل أو الحذف'; end $$;
drop trigger if exists audit_noupd on acc.audit;
create trigger audit_noupd before update or delete on acc.audit for each row execute function app.audit_guard();
-- حذف الشركة بالكامل مسموح (cascade) عبر تعطيل المشغّل داخل دالة المنصة فقط

create or replace function app.next_no(t uuid, e uuid, k text, y int default 0) returns bigint language plpgsql security definer set search_path = public, acc as $$
declare n bigint;
begin
  insert into acc.seq (tenant_id, entity_id, key, yr, last) values (t, e, k, y, 1)
  on conflict (tenant_id, coalesce(entity_id, '00000000-0000-0000-0000-000000000000'::uuid), key, yr) do update set last = acc.seq.last + 1
  returning last into n;
  return n;
end $$;

create or replace function app.check_pw(p text) returns void language plpgsql immutable as $$
begin if length(coalesce(p,'')) < 10 or p !~ '[0-9]' or p !~ '[A-Za-z؀-ۿ]' then raise exception 'كلمة المرور 10 أحرف على الأقل وتحتوي حروفًا وأرقامًا'; end if; end $$;
create or replace function app.login_email(p_code text, p_user text) returns text language sql immutable as
$$ select lower(trim(p_user)) || '@' || lower(trim(p_code)) || '.accounts.mohkam.app' $$;
create or replace function app.client_ip() returns text language plpgsql stable as $$
declare h text; ip text;
begin
  begin h := current_setting('request.headers', true); exception when others then h := null; end;
  if h is null or h = '' then return 'unknown'; end if;
  ip := trim(split_part(coalesce((h::json)->>'x-forwarded-for', (h::json)->>'cf-connecting-ip', ''), ',', 1));
  return coalesce(nullif(ip, ''), 'unknown');
exception when others then return 'unknown'; end $$;

create or replace function app.make_auth_user(p_email text, p_password text, p_name text) returns uuid language plpgsql security definer set search_path = public, auth, extensions as $$
declare uid uuid := gen_random_uuid();
begin
  if exists (select 1 from auth.users where email = p_email) then raise exception 'اسم الدخول مستخدم من قبل'; end if;
  insert into auth.users (instance_id, id, aud, role, email, encrypted_password, email_confirmed_at, raw_app_meta_data, raw_user_meta_data,
    created_at, updated_at, confirmation_token, recovery_token, email_change_token_new, email_change, email_change_token_current, phone_change, phone_change_token, reauthentication_token)
  values ('00000000-0000-0000-0000-000000000000', uid, 'authenticated', 'authenticated', p_email, crypt(p_password, gen_salt('bf')), now(),
    '{"provider":"email","providers":["email"]}', jsonb_build_object('name', p_name), now(), now(), '', '', '', '', '', '', '', '');
  insert into auth.identities (id, provider_id, user_id, identity_data, provider, last_sign_in_at, created_at, updated_at)
  values (gen_random_uuid(), uid::text, uid, jsonb_build_object('sub', uid::text, 'email', p_email, 'email_verified', true), 'email', now(), now(), now());
  return uid;
end $$;

-- ===== الأدوار الافتراضية (فريق محاسبة كامل مع فصل المهام) =====
create or replace function app.seed_roles(t uuid) returns void language plpgsql security definer set search_path = public, acc as $$
declare allm jsonb := '{
 "dashboard":["view"],"coa":["view","add","edit","delete","export"],"journals":["view","add","edit","delete","approve","post","reverse","export"],
 "sales":["view","add","edit","delete","approve","post","export"],"purchases":["view","add","edit","delete","approve","post","export"],
 "payments":["view","add","edit","delete","approve","post","export"],"parties":["view","add","edit","delete","export"],
 "bank":["view","add","edit","reconcile","export"],"assets":["view","add","edit","delete","post","export"],"budgets":["view","add","edit","delete","approve","export"],
 "tax":["view","export"],"reports":["view","export"],"periods":["view","close","reopen"],"attachments":["view","add","delete"],
 "connectors":["view","add","edit","delete"],"controls":["view"],"import":["add"],"costcenters":["view","add","edit","delete"],"requests":["view","approve","pay","manage"],"portal":["view","add"]}'::jsonb;
begin
  insert into acc.roles (tenant_id, id, name, description, locked, perms, sys) values
  (t,'owner','المالك (مدير النظام)','كل الصلاحيات — لا يمكن تعديله', true, allm, '["settings","users","backup","audit","gm"]'),
  (t,'cfo','المدير المالي','كل الوحدات والاعتماد والإقفال وإعادة الفتح، بدون إدارة المستخدمين', false, allm, '["settings","backup","audit"]'),
  (t,'chief','رئيس الحسابات','القيود والاعتماد والترحيل والعكس والإقفال الشهري والتقارير', false, allm - 'connectors' - 'import' - 'periods' || '{"periods":["view","close"]}', '["audit"]'),
  (t,'acct','محاسب عام','إعداد القيود والفواتير والسندات بدون اعتماد أو ترحيل أو إقفال', false,
     '{"dashboard":["view"],"coa":["view","export"],"journals":["view","add","edit","delete","export"],"sales":["view","add","edit","export"],"purchases":["view","add","edit","export"],"payments":["view","add","edit","export"],"parties":["view","add","edit","export"],"bank":["view","add","edit","export"],"assets":["view","add","edit","export"],"tax":["view","export"],"reports":["view","export"],"attachments":["view","add"],"costcenters":["view"],"periods":["view"]}', '[]'),
  (t,'ar','محاسب عملاء (مبيعات)','فواتير المبيعات والمقبوضات والعملاء', false,
     '{"dashboard":["view"],"coa":["view"],"sales":["view","add","edit","export"],"payments":["view","add","edit","export"],"parties":["view","add","edit","export"],"reports":["view","export"],"attachments":["view","add"],"tax":["view"]}', '[]'),
  (t,'ap','محاسب موردين (مشتريات)','فواتير المشتريات والمدفوعات والموردين', false,
     '{"dashboard":["view"],"coa":["view"],"purchases":["view","add","edit","export"],"payments":["view","add","edit","export"],"parties":["view","add","edit","export"],"reports":["view","export"],"attachments":["view","add"],"tax":["view"]}', '[]'),
  (t,'cashier','أمين صندوق / بنوك','سندات القبض والصرف والبنوك والتسوية البنكية', false,
     '{"dashboard":["view"],"coa":["view"],"payments":["view","add","edit","export"],"bank":["view","add","edit","reconcile","export"],"parties":["view"],"reports":["view"],"attachments":["view","add"],"requests":["view","pay"]}', '[]'),
  (t,'gm','المدير العام','اطلاع كامل وتصدير والاعتماد النهائي بدون تعديل', false,
     '{"dashboard":["view"],"coa":["view","export"],"journals":["view","approve","export"],"sales":["view","approve","export"],"purchases":["view","approve","export"],"payments":["view","approve","export"],"parties":["view","export"],"bank":["view","export"],"assets":["view","export"],"budgets":["view","approve","export"],"tax":["view","export"],"reports":["view","export"],"attachments":["view"],"controls":["view"],"periods":["view"],"costcenters":["view"]}', '["gm","audit"]'),
  (t,'auditor','مراجع / رقابة داخلية','اطلاع فقط على كل شيء مع سجل التدقيق والاستثناءات، بلا أي تعديل', false,
     '{"dashboard":["view"],"coa":["view","export"],"journals":["view","export"],"sales":["view","export"],"purchases":["view","export"],"payments":["view","export"],"parties":["view","export"],"bank":["view","export"],"assets":["view","export"],"budgets":["view","export"],"tax":["view","export"],"reports":["view","export"],"attachments":["view"],"controls":["view"],"periods":["view"],"costcenters":["view"]}', '["audit"]'),
  (t,'employee','موظف (بوابة الموظف)','يرى طلباته ومطالباته ويرفع طلبات للمالية فقط', false, '{"portal":["view","add"]}', '[]'),
  (t,'viewer','اطلاع محدود','لوحة التحكم والتقارير فقط', false, '{"dashboard":["view"],"reports":["view"]}', '[]')
  on conflict (tenant_id, id) do nothing;
end $$;
-- ===== sql/002_ledger.sql =====
-- مُحكَم للحسابات — دفتر الأستاذ: شجرة الحسابات، الفترات، القيود، المرفقات (قيد مزدوج بقيود قاعدة البيانات)

create table if not exists acc.accounts (
  tenant_id uuid not null references acc.tenants(id) on delete cascade, id uuid not null default gen_random_uuid(),
  code text not null check (code ~ '^[0-9A-Za-z._-]{1,20}$'), name text not null, name_en text not null default '',
  parent_id uuid, type text not null check (type in ('asset','liability','equity','revenue','expense')),
  subtype text not null default 'general', is_group boolean not null default false,
  normal text generated always as (case when type in ('asset','expense') then 'D' else 'C' end) stored,
  cf_class text not null default 'operating' check (cf_class in ('operating','investing','financing','cash','none')),
  requires_party boolean not null default false, requires_cc boolean not null default false,
  system_key text, active boolean not null default true, note text not null default '',
  created_at timestamptz not null default now(), created_by uuid,
  primary key (tenant_id, id), unique (tenant_id, code),
  foreign key (tenant_id, parent_id) references acc.accounts (tenant_id, id)
);
create unique index if not exists accounts_syskey on acc.accounts (tenant_id, system_key) where system_key is not null;
create index if not exists accounts_parent on acc.accounts (tenant_id, parent_id);

create table if not exists acc.dims (   -- مراكز التكلفة والمشاريع
  tenant_id uuid not null references acc.tenants(id) on delete cascade, id uuid not null default gen_random_uuid(),
  kind text not null check (kind in ('cc','project')), code text not null, name text not null, parent_id uuid,
  active boolean not null default true, note text not null default '', created_at timestamptz not null default now(),
  primary key (tenant_id, id), unique (tenant_id, kind, code), foreign key (tenant_id, parent_id) references acc.dims (tenant_id, id)
);

create table if not exists acc.parties (
  tenant_id uuid not null references acc.tenants(id) on delete cascade, id uuid not null default gen_random_uuid(),
  kind text not null check (kind in ('customer','supplier','both','employee','other')), code text not null,
  name text not null, name_en text not null default '', vat_no text not null default '', cr text not null default '',
  phone text not null default '', email text not null default '', address text not null default '', city text not null default '', country text not null default 'SA',
  contact text not null default '', credit_limit numeric(18,2) not null default 0, terms_days int not null default 30,
  active boolean not null default true, note text not null default '', created_at timestamptz not null default now(), created_by uuid,
  primary key (tenant_id, id), unique (tenant_id, code)
);

create table if not exists acc.tax_codes (
  tenant_id uuid not null references acc.tenants(id) on delete cascade, code text not null check (code ~ '^[A-Za-z0-9_-]{1,12}$'),
  name text not null, rate numeric(7,4) not null default 0 check (rate >= 0 and rate <= 100),
  kind text not null check (kind in ('output','input','zero_out','zero_in','exempt','oos')),
  account_id uuid, active boolean not null default true,
  primary key (tenant_id, code), foreign key (tenant_id, account_id) references acc.accounts (tenant_id, id)
);

create table if not exists acc.fiscal_years (
  tenant_id uuid not null references acc.tenants(id) on delete cascade, entity_id uuid not null, id uuid not null default gen_random_uuid(),
  name text not null, start_date date not null, end_date date not null, status text not null default 'open' check (status in ('open','closed')),
  closed_at timestamptz, closed_by uuid, closing_journal_id uuid,
  primary key (tenant_id, id), foreign key (tenant_id, entity_id) references acc.entities (tenant_id, id),
  check (end_date > start_date), unique (tenant_id, entity_id, start_date)
);
create table if not exists acc.periods (
  tenant_id uuid not null references acc.tenants(id) on delete cascade, entity_id uuid not null, id uuid not null default gen_random_uuid(),
  fy_id uuid not null, no int not null, start_date date not null, end_date date not null,
  status text not null default 'open' check (status in ('open','soft','closed')),
  changed_at timestamptz, changed_by uuid,
  primary key (tenant_id, id), foreign key (tenant_id, fy_id) references acc.fiscal_years (tenant_id, id) on delete cascade,
  unique (tenant_id, entity_id, start_date)
);
create index if not exists periods_lookup on acc.periods (tenant_id, entity_id, start_date, end_date);

create table if not exists acc.journals (
  tenant_id uuid not null references acc.tenants(id) on delete cascade, id uuid not null default gen_random_uuid(), entity_id uuid not null,
  type text not null check (type in ('GJ','ADJ','OB','PAY','SI','PI','SC','PD','RV','PV','DEP','AST','CL','REV')),
  number text, date date not null, period_id uuid, description text not null default '', reference text not null default '',
  status text not null default 'draft' check (status in ('draft','pending','approved','posted','reversed')),
  source text not null default 'manual', source_id uuid, total numeric(18,2) not null default 0,
  reversal_of uuid, reversed_by uuid, rejected_note text not null default '',
  created_by uuid, created_at timestamptz not null default now(), updated_at timestamptz not null default now(),
  submitted_by uuid, submitted_at timestamptz, approved_by uuid, approved_at timestamptz, posted_by uuid, posted_at timestamptz,
  chain_no bigint, prev_hash text, hash text,
  primary key (tenant_id, id), foreign key (tenant_id, entity_id) references acc.entities (tenant_id, id),
  foreign key (tenant_id, period_id) references acc.periods (tenant_id, id)
);
create unique index if not exists journals_number on acc.journals (tenant_id, entity_id, number) where number is not null;
create index if not exists journals_q on acc.journals (tenant_id, entity_id, date desc, created_at desc);
create index if not exists journals_src on acc.journals (tenant_id, source, source_id);
create index if not exists journals_status on acc.journals (tenant_id, status);

create table if not exists acc.journal_lines (
  tenant_id uuid not null references acc.tenants(id) on delete cascade, id uuid not null default gen_random_uuid(),
  journal_id uuid not null, entity_id uuid not null, line_no int not null, date date not null,
  account_id uuid not null, debit numeric(18,2) not null default 0 check (debit >= 0), credit numeric(18,2) not null default 0 check (credit >= 0),
  currency text, fc_amount numeric(18,2), rate numeric(18,6),
  party_id uuid, cost_center_id uuid, project_id uuid, description text not null default '',
  tax_code text, tax_base numeric(18,2), due_date date, posted boolean not null default false, reconciled_id uuid,
  primary key (tenant_id, id),
  foreign key (tenant_id, journal_id) references acc.journals (tenant_id, id) on delete cascade,
  foreign key (tenant_id, account_id) references acc.accounts (tenant_id, id),
  foreign key (tenant_id, party_id) references acc.parties (tenant_id, id),
  foreign key (tenant_id, cost_center_id) references acc.dims (tenant_id, id),
  foreign key (tenant_id, project_id) references acc.dims (tenant_id, id),
  check (not (debit > 0 and credit > 0))
);
create index if not exists jl_journal on acc.journal_lines (tenant_id, journal_id, line_no);
create index if not exists jl_acct on acc.journal_lines (tenant_id, entity_id, account_id, date) where posted;
create index if not exists jl_party on acc.journal_lines (tenant_id, party_id, date) where posted and party_id is not null;

create table if not exists acc.tax_lines (   -- أساس الإقرار الضريبي (يُنشأ مع الترحيل فقط)
  tenant_id uuid not null references acc.tenants(id) on delete cascade, id uuid not null default gen_random_uuid(),
  entity_id uuid not null, journal_id uuid not null, date date not null, tax_code text not null,
  direction text not null check (direction in ('out','in')), base numeric(18,2) not null, tax numeric(18,2) not null,
  party_id uuid, doc_type text, doc_id uuid, primary key (tenant_id, id),
  foreign key (tenant_id, journal_id) references acc.journals (tenant_id, id) on delete cascade
);
create index if not exists tax_lines_q on acc.tax_lines (tenant_id, entity_id, date);

create table if not exists acc.attachments (
  tenant_id uuid not null references acc.tenants(id) on delete cascade, id uuid not null default gen_random_uuid(), entity_id uuid,
  owner_type text not null check (owner_type in ('journal','invoice','payment','asset','party','bank','request','other')), owner_id uuid not null,
  path text not null, filename text not null, mime text not null default '', size bigint not null default 0, sha256 text not null default '', note text not null default '',
  uploaded_by uuid, uploaded_at timestamptz not null default now(), primary key (tenant_id, id), unique (tenant_id, path)
);
create index if not exists att_owner on acc.attachments (tenant_id, owner_type, owner_id);

do $$ declare t text; begin
  foreach t in array array['accounts','dims','parties','tax_codes','fiscal_years','periods','journals','journal_lines','tax_lines','attachments'] loop
    execute format('alter table acc.%I enable row level security', t);
  end loop; end $$;

-- ===== مشغّلات السلامة =====
create or replace function app.accounts_guard() returns trigger language plpgsql as $$
declare pt text; has_post boolean;
begin
  if new.parent_id is not null then
    select type into pt from acc.accounts where tenant_id = new.tenant_id and id = new.parent_id;
    if pt is distinct from new.type then raise exception 'نوع الحساب يجب أن يطابق نوع الحساب الأب'; end if;
    if new.parent_id = new.id then raise exception 'الحساب لا يكون أبًا لنفسه'; end if;
    if exists (select 1 from acc.journal_lines where tenant_id = new.tenant_id and account_id = new.parent_id limit 1) then raise exception 'الحساب الأب عليه حركات — لا يجوز إضافة حسابات فرعية تحته'; end if;
    update acc.accounts set is_group = true where tenant_id = new.tenant_id and id = new.parent_id and not is_group and tg_op <> 'xx';
  end if;
  if tg_op = 'UPDATE' then
    select exists (select 1 from acc.journal_lines where tenant_id = old.tenant_id and account_id = old.id limit 1) into has_post;
    if has_post and (new.type is distinct from old.type) then raise exception 'لا يجوز تغيير نوع حساب عليه حركات'; end if;
    if has_post and new.is_group and not old.is_group then raise exception 'لا يجوز تحويل حساب عليه حركات إلى حساب تجميعي'; end if;
    if new.parent_id is distinct from old.parent_id then
      -- منع الحلقات: الأب الجديد ليس من أبناء الحساب
      if exists (with recursive d as (select id from acc.accounts where tenant_id = old.tenant_id and parent_id = old.id union all select a.id from acc.accounts a join d on a.parent_id = d.id where a.tenant_id = old.tenant_id) select 1 from d where id = new.parent_id) then
        raise exception 'لا يجوز نقل الحساب تحت أحد أبنائه'; end if;
    end if;
  end if;
  return new;
end $$;
drop trigger if exists accounts_guard on acc.accounts;
create trigger accounts_guard before insert or update on acc.accounts for each row execute function app.accounts_guard();

create or replace function app.lines_guard() returns trigger language plpgsql as $$
begin
  if tg_op = 'INSERT' then
    if exists (select 1 from acc.journals j where j.tenant_id = new.tenant_id and j.id = new.journal_id and j.status in ('posted','reversed')) then
      raise exception 'القيد مرحّل — لا يجوز إضافة أسطر'; end if;
    return new;
  elsif tg_op = 'UPDATE' then
    if old.posted and (to_jsonb(new) - 'reconciled_id') is distinct from (to_jsonb(old) - 'reconciled_id') then raise exception 'القيد مرحّل ولا يجوز تعديل أسطره'; end if;
    return new;
  else
    if old.posted then raise exception 'القيد مرحّل ولا يجوز حذف أسطره'; end if;
    return old;
  end if;
end $$;
drop trigger if exists lines_guard on acc.journal_lines;
create trigger lines_guard before insert or update or delete on acc.journal_lines for each row execute function app.lines_guard();

create or replace function app.journals_guard() returns trigger language plpgsql as $$
declare d numeric; c numeric;
begin
  if tg_op = 'DELETE' then
    if old.status <> 'draft' then raise exception 'لا يجوز حذف قيد غير مسودة'; end if;
    return old;
  end if;
  if old.status in ('posted','reversed') then
    if old.status = 'posted' and new.status = 'reversed' and new.reversed_by is not null
       and (to_jsonb(new) - 'status' - 'reversed_by' - 'updated_at') = (to_jsonb(old) - 'status' - 'reversed_by' - 'updated_at') then return new; end if;
    raise exception 'القيد مرحّل ولا يجوز تعديله — استخدم عكس القيد';
  end if;
  if new.status = 'posted' then
    select coalesce(sum(debit),0), coalesce(sum(credit),0) into d, c from acc.journal_lines where tenant_id = new.tenant_id and journal_id = new.id;
    if d <> c or d = 0 then raise exception 'القيد غير متوازن (مدين % / دائن %)', d, c; end if;
    if new.number is null or new.period_id is null or new.hash is null then raise exception 'بيانات الترحيل ناقصة'; end if;
  end if;
  return new;
end $$;
drop trigger if exists journals_guard on acc.journals;
create trigger journals_guard before update or delete on acc.journals for each row execute function app.journals_guard();

-- فترة مالية لتاريخ
create or replace function app.period_for(t uuid, e uuid, d date) returns acc.periods language sql stable security definer set search_path = public, acc as
$$ select p.* from acc.periods p where p.tenant_id = t and p.entity_id = e and d between p.start_date and p.end_date limit 1 $$;

create or replace function app.entity_ok(t uuid, e uuid) returns void language plpgsql stable security definer set search_path = public, acc as $$
begin
  if e is null or not (e = any(app.ents())) then raise exception 'الكيان غير موجود أو غير مسموح لك به'; end if;
end $$;

create or replace function app.acct_id(t uuid, ref text) returns uuid language plpgsql stable security definer set search_path = public, acc as $$
declare r uuid;
begin
  if ref is null or ref = '' then return null; end if;
  if ref ~* '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$' then select id into r from acc.accounts where tenant_id = t and id = ref::uuid;
  else select id into r from acc.accounts where tenant_id = t and code = ref; end if;
  return r;
end $$;
create or replace function app.sysacct(t uuid, k text) returns uuid language plpgsql stable security definer set search_path = public, acc as $$
declare r uuid;
begin select id into r from acc.accounts where tenant_id = t and system_key = k and active;
  if r is null then raise exception 'لم يُحدَّد الحساب الافتراضي (%) — اربطه من الإعدادات ← ربط الحسابات', k; end if; return r; end $$;

create or replace function app.type_prefix(ty text) returns text language sql immutable as
$$ select case ty when 'GJ' then 'JV' when 'ADJ' then 'AJ' when 'OB' then 'OB' when 'PAY' then 'PY' when 'SI' then 'INV' when 'PI' then 'BILL' when 'SC' then 'CN' when 'PD' then 'DN'
  when 'RV' then 'RV' when 'PV' then 'PV' when 'DEP' then 'DEP' when 'AST' then 'AST' when 'CL' then 'CL' when 'REV' then 'RJ' else ty end $$;

-- بصمة القيد (تجزئة مسلسلة): تغيّر أي بيان في قيد مرحّل يكشفه التحقق
create or replace function app.journal_hash(jr acc.journals, prev text) returns text language sql stable security definer set search_path = public, acc as $$
  select encode(sha256(convert_to(coalesce(prev,'') || '|' || jr.id::text || '|' || jr.tenant_id::text || '|' || jr.entity_id::text || '|' || jr.type || '|' || coalesce(jr.number,'') || '|' || jr.date::text || '|' ||
    coalesce(jr.description,'') || '|' || coalesce(jr.reference,'') || '|' || coalesce(jr.posted_by::text,'') || '|' || to_char(jr.posted_at at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US') || '|' ||
    coalesce((select string_agg(l.line_no || ':' || l.account_id::text || ':' || l.debit::text || ':' || l.credit::text || ':' || coalesce(l.party_id::text,'') || ':' || coalesce(l.cost_center_id::text,'') || ':' || coalesce(l.project_id::text,'') || ':' || coalesce(l.tax_code,''), ';' order by l.line_no, l.id)
      from acc.journal_lines l where l.tenant_id = jr.tenant_id and l.journal_id = jr.id), ''), 'UTF8')), 'hex')
$$;

-- التحقق قبل الاعتماد/الترحيل: توازن، حسابات صالحة، اشتراطات العميل/مركز التكلفة، فترة مفتوحة
create or replace function app.validate_journal(j uuid) returns jsonb language plpgsql security definer set search_path = public, acc as $$
declare jr acc.journals; n int; d numeric; c numeric; r record; per acc.periods;
begin
  select * into jr from acc.journals where id = j and tenant_id = app.tenant();
  if jr.id is null then raise exception 'القيد غير موجود'; end if;
  select count(*), coalesce(sum(debit),0), coalesce(sum(credit),0) into n, d, c from acc.journal_lines where tenant_id = jr.tenant_id and journal_id = j;
  if n < 2 then raise exception 'القيد يحتاج سطرين على الأقل'; end if;
  if d <> c then raise exception 'القيد غير متوازن: مدين % ≠ دائن %', d, c; end if;
  if d = 0 then raise exception 'قيمة القيد صفر'; end if;
  for r in select l.line_no, l.party_id, l.cost_center_id, l.debit, l.credit, a.code, a.name, a.is_group, a.active, a.requires_party, a.requires_cc, a.subtype
           from acc.journal_lines l join acc.accounts a on a.tenant_id = l.tenant_id and a.id = l.account_id where l.tenant_id = jr.tenant_id and l.journal_id = j loop
    if r.debit = 0 and r.credit = 0 then raise exception 'السطر % بلا مبلغ', r.line_no; end if;
    if r.is_group then raise exception 'الحساب % - % حساب تجميعي لا تُرحَّل عليه حركات', r.code, r.name; end if;
    if not r.active then raise exception 'الحساب % - % موقوف', r.code, r.name; end if;
    if (r.requires_party or r.subtype in ('receivable','payable')) and r.party_id is null then raise exception 'السطر %: الحساب % يتطلب تحديد العميل/المورد', r.line_no, r.code; end if;
    if r.requires_cc and r.cost_center_id is null then raise exception 'السطر %: الحساب % يتطلب مركز تكلفة', r.line_no, r.code; end if;
  end loop;
  per := app.period_for(jr.tenant_id, jr.entity_id, jr.date);
  if per.id is null then raise exception 'لا توجد فترة مالية للتاريخ % — أنشئ السنة المالية أولًا', jr.date; end if;
  if per.status = 'closed' then raise exception 'الفترة المالية (%) مقفلة', per.no; end if;
  if per.status = 'soft' and not app.can('periods','close') then raise exception 'الفترة المالية (%) مقفلة مبدئيًا — يلزم صلاحية الإقفال للترحيل فيها', per.no; end if;
  return jsonb_build_object('debit', d, 'credit', c, 'period_id', per.id);
end $$;

-- ===== الترحيل (داخلي): كل القيود تمر من هنا =====
create or replace function app.post_journal(j uuid) returns acc.journals language plpgsql security definer set search_path = public, acc as $$
declare jr acc.journals; d numeric; per uuid; v jsonb; num bigint; prev text; cn bigint; me uuid := auth.uid();
begin
  select * into jr from acc.journals where id = j and tenant_id = app.tenant() for update;
  if jr.id is null then raise exception 'القيد غير موجود'; end if;
  if jr.status in ('posted','reversed') then raise exception 'القيد مرحّل مسبقًا'; end if;
  perform pg_advisory_xact_lock(hashtextextended(jr.tenant_id::text, 11));
  v := app.validate_journal(j); d := (v->>'debit')::numeric; per := (v->>'period_id')::uuid;
  num := app.next_no(jr.tenant_id, jr.entity_id, jr.type, extract(year from jr.date)::int);
  cn := app.next_no(jr.tenant_id, null, 'chain', 0);
  select hash into prev from acc.journals where tenant_id = jr.tenant_id and chain_no = cn - 1;
  jr.number := app.type_prefix(jr.type) || '-' || extract(year from jr.date)::int || '-' || lpad(num::text, 5, '0');
  jr.posted_by := me; jr.posted_at := clock_timestamp(); jr.status := 'posted';
  update acc.journal_lines set posted = true, date = jr.date where tenant_id = jr.tenant_id and journal_id = j;
  update acc.journals set number = jr.number, period_id = per, total = d, posted_by = jr.posted_by, posted_at = jr.posted_at, chain_no = cn, prev_hash = prev,
    updated_at = now(), hash = app.journal_hash(jr, prev), status = 'posted' where id = j and tenant_id = jr.tenant_id;
  -- ضريبة القيود اليدوية: أسطر عليها رمز ضريبة وأساس
  if jr.source = 'manual' then
    insert into acc.tax_lines (tenant_id, entity_id, journal_id, date, tax_code, direction, base, tax, party_id, doc_type, doc_id)
    select l.tenant_id, l.entity_id, l.journal_id, l.date, l.tax_code, case when tc.kind in ('output','zero_out') then 'out' else 'in' end, coalesce(l.tax_base,0),
      case when tc.kind in ('output','zero_out') then l.credit - l.debit else l.debit - l.credit end, l.party_id, 'journal', l.journal_id
    from acc.journal_lines l join acc.tax_codes tc on tc.tenant_id = l.tenant_id and tc.code = l.tax_code
    where l.tenant_id = jr.tenant_id and l.journal_id = j and l.tax_code is not null and tc.kind in ('output','input','zero_out','zero_in');
  end if;
  select * into jr from acc.journals where id = j and tenant_id = jr.tenant_id;
  return jr;
end $$;

-- عكس قيد مرحّل (داخلي): ينشئ قيدًا معاكسًا مرحّلًا ويعلّم الأصل «معكوس»
create or replace function app.reverse_journal(orig uuid, d date, reason text) returns acc.journals language plpgsql security definer set search_path = public, acc as $$
declare o acc.journals; nj uuid := gen_random_uuid(); me uuid := auth.uid(); r acc.journals;
begin
  select * into o from acc.journals where id = orig and tenant_id = app.tenant() for update;
  if o.id is null then raise exception 'القيد غير موجود'; end if;
  if o.status <> 'posted' then raise exception 'يمكن عكس القيود المرحّلة غير المعكوسة فقط'; end if;
  if o.type = 'REV' then raise exception 'لا يجوز عكس قيد عكسي'; end if;
  if d < o.date then raise exception 'تاريخ العكس يجب ألا يسبق تاريخ القيد الأصلي'; end if;
  insert into acc.journals (tenant_id, id, entity_id, type, date, description, reference, status, source, source_id, reversal_of, created_by)
  values (o.tenant_id, nj, o.entity_id, 'REV', d, 'عكس القيد ' || o.number || coalesce(' — ' || nullif(reason,''), ''), o.number, 'draft', 'reversal', o.id, o.id, me);
  insert into acc.journal_lines (tenant_id, journal_id, entity_id, line_no, date, account_id, debit, credit, currency, fc_amount, rate, party_id, cost_center_id, project_id, description, tax_code, tax_base, due_date)
  select tenant_id, nj, entity_id, line_no, d, account_id, credit, debit, currency, case when fc_amount is null then null else -fc_amount end, rate, party_id, cost_center_id, project_id, description, tax_code, tax_base, due_date
  from acc.journal_lines where tenant_id = o.tenant_id and journal_id = o.id;
  r := app.post_journal(nj);
  insert into acc.tax_lines (tenant_id, entity_id, journal_id, date, tax_code, direction, base, tax, party_id, doc_type, doc_id)
  select tenant_id, entity_id, nj, d, tax_code, direction, -base, -tax, party_id, doc_type, doc_id from acc.tax_lines where tenant_id = o.tenant_id and journal_id = o.id;
  update acc.journals set status = 'reversed', reversed_by = nj, updated_at = now() where id = o.id and tenant_id = o.tenant_id;
  perform app.audit('reverse', 'journal', o.id::text, 'عكس القيد ' || o.number || ' بالقيد ' || r.number || coalesce(' — ' || nullif(reason,''), ''));
  return r;
end $$;
-- ===== sql/003_api_ledger.sql =====
-- مُحكَم للحسابات — واجهة الدوال (RPC) للدفتر: الكيانات، الشجرة، السنوات والفترات، القيود، المرفقات، الأطراف، الإعدادات
-- كل دالة تأخذ وسيطًا واحدًا jsonb وتعيد jsonb. التحقق من الهوية والشركة والصلاحية داخل كل دالة.

create or replace function app.pick_ents(p jsonb) returns uuid[] language plpgsql stable security definer set search_path = public, acc as $$
declare allowed uuid[] := app.ents(); want uuid[];
begin
  if jsonb_typeof(p->'entities') = 'array' and jsonb_array_length(p->'entities') > 0 then
    select array_agg(x::uuid) into want from jsonb_array_elements_text(p->'entities') x;
    return coalesce((select array_agg(u) from unnest(want) u where u = any(allowed)), '{}'::uuid[]);
  elsif nullif(p->>'entity','') is not null then
    if (p->>'entity')::uuid = any(allowed) then return array[(p->>'entity')::uuid]; end if;
    raise exception 'الكيان غير موجود أو غير مسموح لك به';
  end if;
  return allowed;
end $$;

create or replace function app.jsonb_merge(a jsonb, b jsonb) returns jsonb language sql immutable as $$
  select case when jsonb_typeof(a) = 'object' and jsonb_typeof(b) = 'object'
    then coalesce((select jsonb_object_agg(k, case when a ? k and b ? k then app.jsonb_merge(a->k, b->k) when b ? k then b->k else a->k end) from (select jsonb_object_keys(a) k union select jsonb_object_keys(b)) z), '{}'::jsonb)
    else b end $$;

create or replace function app.setting_num(path text[]) returns numeric language sql stable security definer set search_path = public, acc as
$$ select nullif(nullif(app.setting(path)::text, 'null'), '')::numeric $$;

create or replace function app.policy(kind text) returns jsonb language plpgsql stable security definer set search_path = public, acc as $$
declare s jsonb := coalesce(app.setting(array['approval']), '{}'::jsonb); solo boolean := (select count(*) from acc.members where tenant_id = app.tenant() and active) <= 1;
begin
  return jsonb_build_object('required', coalesce((s->kind->>'required')::boolean, true) and not solo,
    'threshold', coalesce((s->kind->>'threshold')::numeric, 0), 'sod', coalesce((s->>'sod')::boolean, true) and not solo, 'solo', solo);
end $$;

-- ===== الكيانات (الشركات التابعة) =====
create or replace function public.entity_list(p jsonb default '{}') returns jsonb language plpgsql stable security definer set search_path = public, app, acc as $$
declare t uuid := app.need(null, null);
begin return coalesce((select jsonb_agg(to_jsonb(e) order by e.code) from acc.entities e where e.tenant_id = t and e.id = any(app.ents())), '[]'::jsonb); end $$;

create or replace function public.entity_upsert(p jsonb) returns jsonb language plpgsql security definer set search_path = public, app, acc as $$
declare t uuid := app.need_sys('settings'); v_id uuid := nullif(p->>'id','')::uuid; mx int; n int;
begin
  if coalesce(trim(p->>'name'),'') = '' or coalesce(trim(p->>'code'),'') = '' then raise exception 'رمز واسم الكيان مطلوبان'; end if;
  if v_id is null then
    select max_entities into mx from acc.tenants x where x.id = t; select count(*) into n from acc.entities where tenant_id = t;
    if mx is not null and n >= mx then raise exception 'باقتك تسمح بـ % كيانات', mx; end if;
    v_id := gen_random_uuid();
    insert into acc.entities (tenant_id, id, code, name, name_en, vat_no, cr, address) values (t, v_id, trim(p->>'code'), trim(p->>'name'), coalesce(p->>'name_en',''), coalesce(p->>'vat_no',''), coalesce(p->>'cr',''), coalesce(p->>'address',''));
    perform app.audit('create','entity',v_id::text,'إنشاء كيان ' || (p->>'name'));
  else
    update acc.entities set code = trim(p->>'code'), name = trim(p->>'name'), name_en = coalesce(p->>'name_en',''), vat_no = coalesce(p->>'vat_no',''), cr = coalesce(p->>'cr',''),
      address = coalesce(p->>'address',''), active = coalesce((p->>'active')::boolean, active) where tenant_id = t and acc.entities.id = v_id;
    perform app.audit('update','entity',v_id::text,'تعديل كيان ' || (p->>'name'));
  end if;
  return jsonb_build_object('id', v_id);
end $$;

-- ===== شجرة الحسابات =====
create or replace function app.default_cf(ty text, sub text) returns text language sql immutable as $$
  select case when ty in ('revenue','expense') then 'none' when sub in ('cash','bank') then 'cash' when sub in ('fixed_asset','accum_dep','intangible','investment') then 'investing'
    when sub in ('loan','capital','retained_earnings','equity','dividends') or ty = 'equity' then 'financing' else 'operating' end $$;

create or replace function public.coa_list(p jsonb default '{}') returns jsonb language plpgsql stable security definer set search_path = public, app, acc as $$
declare t uuid := app.need('coa', 'view'); ents uuid[] := app.pick_ents(p); asof date := coalesce(nullif(p->>'to','')::date, current_date + 36500);
  fromd date := nullif(p->>'from','')::date; with_bal boolean := coalesce((p->>'balances')::boolean, false);
begin
  return coalesce((select jsonb_agg(jsonb_build_object('id', a.id, 'code', a.code, 'name', a.name, 'name_en', a.name_en, 'parent_id', a.parent_id, 'type', a.type, 'subtype', a.subtype,
      'is_group', a.is_group, 'normal', a.normal, 'cf_class', a.cf_class, 'requires_party', a.requires_party, 'requires_cc', a.requires_cc, 'system_key', a.system_key, 'active', a.active, 'note', a.note,
      'balance', case when with_bal then coalesce(b.bal, 0) end, 'has_postings', coalesce(b.n, 0) > 0) order by a.code)
    from acc.accounts a left join (select account_id, sum(debit - credit) bal, count(*) n from acc.journal_lines where tenant_id = t and posted and entity_id = any(ents) and date <= asof and (fromd is null or date >= fromd) group by 1) b on b.account_id = a.id
    where a.tenant_id = t), '[]'::jsonb);
end $$;

create or replace function public.coa_upsert(p jsonb) returns jsonb language plpgsql security definer set search_path = public, app, acc as $$
declare t uuid; v_id uuid := nullif(p->>'id','')::uuid; par uuid := app.acct_id(app.tenant(), coalesce(nullif(p->>'parent_id',''), nullif(p->>'parent_code',''))); ty text := p->>'type'; sub text := coalesce(nullif(p->>'subtype',''),'general');
  sk text := nullif(p->>'system_key',''); isg boolean := coalesce((p->>'is_group')::boolean, false); old acc.accounts; rp boolean; rc boolean;
begin
  t := app.need('coa', case when nullif(p->>'id','') is null then 'add' else 'edit' end);
  if coalesce(trim(p->>'code'),'') = '' or coalesce(trim(p->>'name'),'') = '' then raise exception 'رمز واسم الحساب مطلوبان'; end if;
  if par is not null then select type into ty from acc.accounts where tenant_id = t and id = par; end if;
  if ty is null then raise exception 'نوع الحساب مطلوب (أصل/التزام/حقوق ملكية/إيراد/مصروف)'; end if;
  rp := coalesce((p->>'requires_party')::boolean, sub in ('receivable','payable')); rc := coalesce((p->>'requires_cc')::boolean, false);
  if sk is not null then
    if isg then raise exception 'الحساب الافتراضي النظامي يجب أن يكون حسابًا فرعيًا (غير تجميعي)'; end if;
    update acc.accounts a2 set system_key = null where a2.tenant_id = t and a2.system_key = sk and a2.id is distinct from (nullif(p->>'id','')::uuid);
  end if;
  if v_id is null then
    v_id := gen_random_uuid();
    insert into acc.accounts (tenant_id, id, code, name, name_en, parent_id, type, subtype, is_group, cf_class, requires_party, requires_cc, system_key, active, note, created_by)
    values (t, v_id, trim(p->>'code'), trim(p->>'name'), coalesce(p->>'name_en',''), par, ty, sub, isg, coalesce(nullif(p->>'cf_class',''), app.default_cf(ty, sub)), rp, rc, sk, coalesce((p->>'active')::boolean, true), coalesce(p->>'note',''), auth.uid());
    perform app.audit('create','account',v_id::text,'إنشاء حساب ' || (p->>'code') || ' ' || (p->>'name'));
  else
    select * into old from acc.accounts where tenant_id = t and acc.accounts.id = v_id;
    if old.id is null then raise exception 'الحساب غير موجود'; end if;
    update acc.accounts set code = trim(p->>'code'), name = trim(p->>'name'), name_en = coalesce(p->>'name_en',''), parent_id = par, type = ty, subtype = sub, is_group = isg,
      cf_class = coalesce(nullif(p->>'cf_class',''), app.default_cf(ty, sub)), requires_party = rp, requires_cc = rc, system_key = sk, active = coalesce((p->>'active')::boolean, active), note = coalesce(p->>'note','')
    where tenant_id = t and acc.accounts.id = v_id;
    perform app.audit('update','account',v_id::text,'تعديل حساب ' || (p->>'code') || ' ' || (p->>'name'));
  end if;
  return jsonb_build_object('id', v_id);
end $$;

create or replace function public.coa_delete(p jsonb) returns jsonb language plpgsql security definer set search_path = public, app, acc as $$
declare t uuid := app.need('coa','delete'); v_id uuid := (p->>'id')::uuid; a acc.accounts;
begin
  select * into a from acc.accounts where tenant_id = t and acc.accounts.id = v_id; if a.id is null then raise exception 'الحساب غير موجود'; end if;
  if exists (select 1 from acc.journal_lines where tenant_id = t and account_id = v_id limit 1) then raise exception 'عليه حركات — أوقفه بدل الحذف'; end if;
  if exists (select 1 from acc.accounts where tenant_id = t and parent_id = v_id) then raise exception 'له حسابات فرعية — انقلها أو احذفها أولًا'; end if;
  if a.system_key is not null then raise exception 'حساب افتراضي نظامي (%) — غيّر الربط أولًا', a.system_key; end if;
  delete from acc.accounts where tenant_id = t and acc.accounts.id = v_id;
  perform app.audit('delete','account',v_id::text,'حذف حساب ' || a.code || ' ' || a.name);
  return jsonb_build_object('ok', true);
end $$;

-- استيراد شجرة حسابات (Excel/CSV بعد تحويله في الواجهة إلى صفوف). dry=true للمعاينة والتحقق فقط.
create or replace function public.coa_import(p jsonb) returns jsonb language plpgsql security definer set search_path = public, app, acc as $$
declare t uuid := app.need('coa','add'); r jsonb; i int := 0; errs jsonb := '[]'::jsonb; dry boolean := coalesce((p->>'dry')::boolean, false); created int := 0; updated int := 0;
  v_code text; ty text; par text; pass int; todo jsonb := coalesce(p->'rows','[]'::jsonb); left_ jsonb; progressed boolean; pid uuid; nm text; isg boolean;
  codes text[] := '{}'; pars text[] := '{}'; rowsd jsonb := '[]'::jsonb; ex acc.accounts; sub text;
begin
  perform app.need('import','add');
  if jsonb_array_length(todo) = 0 then raise exception 'الملف فارغ'; end if;
  if jsonb_array_length(todo) > 5000 then raise exception 'الحد الأقصى 5000 حساب في المرة'; end if;
  -- فحص أولي
  for r in select * from jsonb_array_elements(todo) loop
    i := i + 1; v_code := trim(coalesce(r->>'code','')); nm := trim(coalesce(r->>'name',''));
    if v_code = '' or nm = '' then errs := errs || jsonb_build_object('row', i, 'msg', 'الرمز والاسم مطلوبان'); continue; end if;
    if v_code !~ '^[0-9A-Za-z._-]{1,20}$' then errs := errs || jsonb_build_object('row', i, 'msg', 'رمز غير صالح: ' || v_code); continue; end if;
    if v_code = any(codes) then errs := errs || jsonb_build_object('row', i, 'msg', 'رمز مكرر في الملف: ' || v_code); continue; end if;
    codes := codes || v_code; par := nullif(trim(coalesce(r->>'parent_code','')), ''); pars := pars || coalesce(par, '');
    if par is not null and par = v_code then errs := errs || jsonb_build_object('row', i, 'msg', 'حساب أب لنفسه: ' || v_code); end if;
    ty := nullif(r->>'type','');
    if ty is not null and ty not in ('asset','liability','equity','revenue','expense') then errs := errs || jsonb_build_object('row', i, 'msg', 'نوع غير صالح: ' || ty); end if;
    if par is null and ty is null then errs := errs || jsonb_build_object('row', i, 'msg', 'الحساب الرئيسي ' || v_code || ' يحتاج نوعًا'); end if;
    if par is not null and not (par = any(codes) or exists (select 1 from jsonb_array_elements(todo) x where trim(x->>'code') = par) or exists (select 1 from acc.accounts where tenant_id = t and acc.accounts.code = par)) then
      errs := errs || jsonb_build_object('row', i, 'msg', 'الحساب الأب غير موجود: ' || par); end if;
  end loop;
  if jsonb_array_length(errs) > 0 or dry then return jsonb_build_object('ok', jsonb_array_length(errs) = 0, 'errors', errs, 'count', jsonb_array_length(todo)); end if;
  -- إدخال متعدد الجولات: الآباء أولًا
  left_ := todo;
  for pass in 1..12 loop
    progressed := false;
    for r in select * from jsonb_array_elements(left_) loop
      v_code := trim(r->>'code'); par := nullif(trim(coalesce(r->>'parent_code','')), '');
      pid := null;
      if par is not null then select a3.id into pid from acc.accounts a3 where a3.tenant_id = t and a3.code = par; if pid is null then continue; end if; end if;
      ty := coalesce(nullif(r->>'type',''), (select a4.type from acc.accounts a4 where a4.tenant_id = t and a4.id = pid));
      sub := coalesce(nullif(r->>'subtype',''), 'general');
      isg := coalesce((r->>'is_group')::boolean, exists (select 1 from jsonb_array_elements(todo) x where trim(coalesce(x->>'parent_code','')) = v_code));
      select * into ex from acc.accounts a5 where a5.tenant_id = t and a5.code = v_code;
      if ex.id is null then
        insert into acc.accounts (tenant_id, code, name, name_en, parent_id, type, subtype, is_group, cf_class, requires_party, requires_cc, system_key, created_by)
        values (t, v_code, trim(r->>'name'), coalesce(r->>'name_en',''), pid, ty, sub, isg, coalesce(nullif(r->>'cf_class',''), app.default_cf(ty, sub)),
          coalesce((r->>'requires_party')::boolean, sub in ('receivable','payable')), coalesce((r->>'requires_cc')::boolean, false), nullif(r->>'system_key',''), auth.uid());
        created := created + 1;
      else
        update acc.accounts a6 set name = trim(r->>'name'), name_en = coalesce(r->>'name_en', a6.name_en), parent_id = pid, subtype = sub, is_group = isg where a6.tenant_id = t and a6.id = ex.id;
        updated := updated + 1;
      end if;
      left_ := (select coalesce(jsonb_agg(x), '[]'::jsonb) from jsonb_array_elements(left_) x where trim(x->>'code') <> v_code);
      progressed := true;
    end loop;
    exit when jsonb_array_length(left_) = 0 or not progressed;
  end loop;
  if jsonb_array_length(left_) > 0 then raise exception 'تعذّر ترتيب % حسابًا (حلقة أو أب مفقود)', jsonb_array_length(left_); end if;
  perform app.audit('import','account','', 'استيراد شجرة حسابات: ' || created || ' جديد، ' || updated || ' محدّث');
  return jsonb_build_object('ok', true, 'created', created, 'updated', updated, 'errors', '[]'::jsonb);
end $$;

create table if not exists app.coa_templates (key text primary key, name text not null, description text not null default '', rows jsonb not null);
create or replace function public.coa_templates(p jsonb default '{}') returns jsonb language plpgsql stable security definer set search_path = public, app, acc as $$
begin perform app.need(null, null); return coalesce((select jsonb_agg(jsonb_build_object('key', key, 'name', name, 'description', description, 'count', jsonb_array_length(rows)) order by key) from app.coa_templates), '[]'::jsonb); end $$;
create or replace function public.coa_template_rows(p jsonb) returns jsonb language plpgsql stable security definer set search_path = public, app, acc as $$
begin perform app.need('coa','view'); return coalesce((select rows from app.coa_templates where key = p->>'key'), '[]'::jsonb); end $$;

-- ===== السنوات والفترات =====
create or replace function public.fy_create(p jsonb) returns jsonb language plpgsql security definer set search_path = public, app, acc as $$
declare t uuid := app.need('periods','close'); e uuid := (p->>'entity')::uuid; sd date := (p->>'start_date')::date; ed date; fid uuid := gen_random_uuid(); i int; nm text;
begin
  perform app.entity_ok(t, e);
  if sd is null then raise exception 'تاريخ بداية السنة مطلوب'; end if;
  ed := (sd + interval '1 year' - interval '1 day')::date;
  if exists (select 1 from acc.fiscal_years where tenant_id = t and entity_id = e and daterange(start_date, end_date, '[]') && daterange(sd, ed, '[]')) then raise exception 'تتداخل مع سنة مالية قائمة'; end if;
  nm := coalesce(nullif(p->>'name',''), 'السنة المالية ' || extract(year from sd)::int || case when extract(month from sd) <> 1 then '/' || (extract(year from sd)::int + 1) else '' end);
  insert into acc.fiscal_years (tenant_id, entity_id, id, name, start_date, end_date) values (t, e, fid, nm, sd, ed);
  for i in 0..11 loop
    insert into acc.periods (tenant_id, entity_id, fy_id, no, start_date, end_date)
    values (t, e, fid, i + 1, (sd + (i || ' month')::interval)::date, (sd + ((i + 1) || ' month')::interval - interval '1 day')::date);
  end loop;
  perform app.audit('create','fiscal_year',fid::text,'إنشاء ' || nm);
  return jsonb_build_object('id', fid);
end $$;

create or replace function public.fy_list(p jsonb default '{}') returns jsonb language plpgsql stable security definer set search_path = public, app, acc as $$
declare t uuid := app.need('periods','view'); ents uuid[] := app.pick_ents(p);
begin
  return coalesce((select jsonb_agg(to_jsonb(f) || jsonb_build_object('periods', (select jsonb_agg(to_jsonb(x) order by x.no) from acc.periods x where x.tenant_id = t and x.fy_id = f.id),
      'drafts', (select count(*) from acc.journals j where j.tenant_id = t and j.entity_id = f.entity_id and j.status in ('draft','pending','approved') and j.date between f.start_date and f.end_date)) order by f.entity_id, f.start_date desc)
    from acc.fiscal_years f where f.tenant_id = t and f.entity_id = any(ents)), '[]'::jsonb);
end $$;

create or replace function public.period_set(p jsonb) returns jsonb language plpgsql security definer set search_path = public, app, acc as $$
declare t uuid; pid uuid := (p->>'id')::uuid; st text := p->>'status'; per acc.periods; fy acc.fiscal_years; pend int;
begin
  if st not in ('open','soft','closed') then raise exception 'حالة غير صالحة'; end if;
  select * into per from acc.periods where tenant_id = app.tenant() and id = pid; if per.id is null then raise exception 'الفترة غير موجودة'; end if;
  t := app.need('periods', case when per.status = 'closed' and st <> 'closed' then 'reopen' else 'close' end);
  perform app.entity_ok(t, per.entity_id);
  select * into fy from acc.fiscal_years where tenant_id = t and id = per.fy_id;
  if fy.status = 'closed' and st <> 'closed' then raise exception 'السنة المالية مقفلة — أعد فتح السنة أولًا'; end if;
  if st = 'closed' then
    select count(*) into pend from acc.journals where tenant_id = t and entity_id = per.entity_id and status in ('draft','pending','approved') and date between per.start_date and per.end_date;
    if pend > 0 then raise exception 'يوجد % قيد غير مرحّل في هذه الفترة — رحّلها أو احذفها أو انقلها قبل الإقفال', pend; end if;
    if exists (select 1 from acc.periods where tenant_id = t and entity_id = per.entity_id and fy_id = per.fy_id and no < per.no and status <> 'closed') then raise exception 'أقفل الفترات السابقة أولًا (الإقفال بالتسلسل)'; end if;
  end if;
  update acc.periods set status = st, changed_at = now(), changed_by = auth.uid() where tenant_id = t and id = pid;
  perform app.audit('period','period',pid::text, 'الفترة ' || per.no || ' (' || per.start_date || ') ← ' || st);
  return jsonb_build_object('ok', true);
end $$;
-- ===== sql/004_api_journals.sql =====
-- مُحكَم للحسابات — دورة القيد: مسودة ← رفع ← اعتماد ← ترحيل ← (عكس) مع فصل المهام والاشتراطات الرقابية

create or replace function app.line_party_ok(t uuid, pid uuid) returns void language plpgsql stable security definer set search_path = public, acc as $$
begin if pid is not null and not exists (select 1 from acc.parties where tenant_id = t and id = pid) then raise exception 'العميل/المورد غير موجود'; end if; end $$;
create or replace function app.line_dim_ok(t uuid, did uuid, k text) returns void language plpgsql stable security definer set search_path = public, acc as $$
begin if did is not null and not exists (select 1 from acc.dims where tenant_id = t and id = did and kind = k) then raise exception 'مركز التكلفة/المشروع غير موجود'; end if; end $$;

-- يضيف أسطر القيد من jsonb (يُستخدم من الحفظ اليدوي والاستيراد)
create or replace function app.put_lines(t uuid, jid uuid, e uuid, d date, lines jsonb) returns void language plpgsql security definer set search_path = public, acc as $$
declare l jsonb; i int := 0; aid uuid; pid uuid; cc uuid; pr uuid; dr numeric; cr numeric;
begin
  for l in select * from jsonb_array_elements(coalesce(lines, '[]'::jsonb)) loop
    i := i + 1;
    aid := coalesce(app.acct_id(t, nullif(l->>'account','')), app.acct_id(t, nullif(l->>'account_code','')));
    if aid is null then raise exception 'السطر %: الحساب غير موجود', i; end if;
    pid := nullif(l->>'party','')::uuid; cc := nullif(l->>'cost_center','')::uuid; pr := nullif(l->>'project','')::uuid;
    perform app.line_party_ok(t, pid); perform app.line_dim_ok(t, cc, 'cc'); perform app.line_dim_ok(t, pr, 'project');
    dr := round(coalesce(nullif(l->>'debit','')::numeric, 0), 2); cr := round(coalesce(nullif(l->>'credit','')::numeric, 0), 2);
    if dr < 0 or cr < 0 then raise exception 'السطر %: لا مبالغ سالبة', i; end if;
    if dr > 0 and cr > 0 then raise exception 'السطر %: مبلغ في المدين والدائن معًا', i; end if;
    if nullif(l->>'tax_code','') is not null and not exists (select 1 from acc.tax_codes where tenant_id = t and code = l->>'tax_code') then raise exception 'السطر %: رمز الضريبة غير موجود', i; end if;
    insert into acc.journal_lines (tenant_id, journal_id, entity_id, line_no, date, account_id, debit, credit, currency, fc_amount, rate, party_id, cost_center_id, project_id, description, tax_code, tax_base, due_date)
    values (t, jid, e, i, d, aid, dr, cr, nullif(l->>'currency',''), nullif(l->>'fc_amount','')::numeric, nullif(l->>'rate','')::numeric, pid, cc, pr, coalesce(l->>'description',''),
      nullif(l->>'tax_code',''), nullif(l->>'tax_base','')::numeric, nullif(l->>'due_date','')::date);
  end loop;
end $$;

create or replace function public.je_save(p jsonb) returns jsonb language plpgsql security definer set search_path = public, app, acc as $$
declare t uuid; jid uuid := nullif(p->>'id','')::uuid; e uuid := nullif(p->>'entity','')::uuid; jr acc.journals; ty text := coalesce(nullif(p->>'type',''), 'GJ'); d date := nullif(p->>'date','')::date; me uuid := auth.uid(); bd int;
begin
  t := app.need('journals', case when jid is null then 'add' else 'edit' end);
  if ty not in ('GJ','ADJ','OB','PAY') then raise exception 'نوع القيد غير مسموح يدويًا'; end if;
  if d is null then raise exception 'تاريخ القيد مطلوب'; end if;
  bd := app.setting_num(array['controls','backdate_days'])::int;
  if bd is not null and d < current_date - bd and not app.can('periods','close') then raise exception 'لا يجوز القيد بتاريخ أقدم من % يومًا دون صلاحية الإقفال', bd; end if;
  if jid is not null then
    select * into jr from acc.journals where tenant_id = t and id = jid for update;
    if jr.id is null then raise exception 'القيد غير موجود'; end if;
    perform app.entity_ok(t, jr.entity_id);
    if jr.status <> 'draft' then raise exception 'يمكن تعديل المسودات فقط (الحالة: %)', jr.status; end if;
    if jr.source <> 'manual' then raise exception 'قيد ناتج عن مستند — عدّل المستند'; end if;
    update acc.journals set date = d, type = ty, description = coalesce(p->>'description',''), reference = coalesce(p->>'reference',''), rejected_note = '', updated_at = now() where tenant_id = t and id = jid;
    delete from acc.journal_lines where tenant_id = t and journal_id = jid;
    e := jr.entity_id;
  else
    perform app.entity_ok(t, e);
    jid := gen_random_uuid();
    insert into acc.journals (tenant_id, id, entity_id, type, date, description, reference, status, source, created_by) values (t, jid, e, ty, d, coalesce(p->>'description',''), coalesce(p->>'reference',''), 'draft', 'manual', me);
  end if;
  perform app.put_lines(t, jid, e, d, p->'lines');
  perform app.audit(case when p->>'id' is null then 'create' else 'update' end, 'journal', jid::text, 'مسودة قيد ' || d || ' — ' || coalesce(p->>'description',''));
  return jsonb_build_object('id', jid);
end $$;

create or replace function public.je_delete(p jsonb) returns jsonb language plpgsql security definer set search_path = public, app, acc as $$
declare t uuid := app.need('journals','delete'); jr acc.journals;
begin
  select * into jr from acc.journals where tenant_id = t and id = (p->>'id')::uuid for update;
  if jr.id is null then raise exception 'القيد غير موجود'; end if;
  perform app.entity_ok(t, jr.entity_id);
  if jr.status <> 'draft' then raise exception 'لا يُحذف إلا القيد المسودة'; end if;
  if jr.source <> 'manual' then raise exception 'قيد ناتج عن مستند — لا يُحذف يدويًا'; end if;
  delete from acc.attachments where tenant_id = t and owner_type = 'journal' and owner_id = jr.id;
  delete from acc.journals where tenant_id = t and id = jr.id;
  perform app.audit('delete','journal',jr.id::text,'حذف مسودة قيد ' || jr.date || ' — ' || jr.description);
  return jsonb_build_object('ok', true);
end $$;

-- عدد المرفقات على قيد (أو على المستند المصدر)
create or replace function app.journal_att_count(t uuid, jid uuid) returns int language sql stable security definer set search_path = public, acc as $$
  select (select count(*) from acc.attachments a where a.tenant_id = t and a.owner_type = 'journal' and a.owner_id = jid)::int
       + (select count(*) from acc.attachments a join acc.journals j on j.tenant_id = a.tenant_id and j.id = jid and j.source_id = a.owner_id and a.owner_type in ('invoice','payment','asset') where a.tenant_id = t)::int $$;


-- المرفقات المطلوبة: القيمة = الحد الأدنى للمبلغ الذي يلزم عنده مرفق (0 = دائمًا، -1 = غير مطلوب)
create or replace function app.attach_over(k text) returns numeric language sql stable security definer set search_path = public, acc as $$
  select coalesce(app.setting_num(array['controls','attach',k]), -1) $$;
create or replace function app.need_attach(t uuid, k text, owner_type text, owner_id uuid, amount numeric, what text) returns void language plpgsql security definer set search_path = public, acc as $$
declare o numeric := app.attach_over(k);
begin
  if o >= 0 and amount >= o and not exists (select 1 from acc.attachments a where a.tenant_id = t and a.owner_type = need_attach.owner_type and a.owner_id = need_attach.owner_id) then
    raise exception 'يلزم إرفاق المستند الداعم (%) قبل المتابعة%', what, case when o > 0 then ' — للمبالغ ' || o || ' فأكثر' else '' end; end if;
end $$;

create or replace function public.je_submit(p jsonb) returns jsonb language plpgsql security definer set search_path = public, app, acc as $$
declare t uuid := app.need(null, null); jr acc.journals; v jsonb; pol jsonb := app.policy('journals'); tot numeric; req numeric; st text;
begin
  if not (app.can('journals','add') or app.can('journals','edit')) then raise exception 'ليست لديك صلاحية إعداد القيود'; end if;
  select * into jr from acc.journals where tenant_id = t and id = (p->>'id')::uuid for update;
  if jr.id is null then raise exception 'القيد غير موجود'; end if;
  perform app.entity_ok(t, jr.entity_id);
  if jr.status <> 'draft' then raise exception 'يُرفع القيد من حالة المسودة فقط'; end if;
  v := app.validate_journal(jr.id); tot := (v->>'debit')::numeric;
  req := nullif(app.attach_over('journal'), -1);
  if req is not null and tot >= req and app.journal_att_count(t, jr.id) = 0 then raise exception 'القيود بقيمة % فأكثر تتطلب إرفاق مستند داعم', req; end if;
  st := case when (pol->>'required')::boolean and tot >= (pol->>'threshold')::numeric then 'pending' else 'approved' end;
  update acc.journals set status = st, submitted_by = auth.uid(), submitted_at = now(), total = tot, updated_at = now() where tenant_id = t and id = jr.id;
  perform app.audit('submit','journal',jr.id::text, case when st = 'pending' then 'رفع للاعتماد' else 'جاهز للترحيل (لا يتطلب اعتمادًا)' end || ' — ' || tot);
  return jsonb_build_object('status', st);
end $$;

create or replace function public.je_approve(p jsonb) returns jsonb language plpgsql security definer set search_path = public, app, acc as $$
declare t uuid := app.need('journals','approve'); jr acc.journals; pol jsonb := app.policy('journals');
begin
  select * into jr from acc.journals where tenant_id = t and id = (p->>'id')::uuid for update;
  if jr.id is null then raise exception 'القيد غير موجود'; end if;
  perform app.entity_ok(t, jr.entity_id);
  if jr.status <> 'pending' then raise exception 'القيد ليس بانتظار الاعتماد'; end if;
  if (pol->>'sod')::boolean and (jr.created_by = auth.uid() or jr.submitted_by = auth.uid()) then raise exception 'فصل المهام: لا يجوز اعتماد قيد أعددته أو رفعته بنفسك'; end if;
  update acc.journals set status = 'approved', approved_by = auth.uid(), approved_at = now(), updated_at = now() where tenant_id = t and id = jr.id;
  perform app.audit('approve','journal',jr.id::text,'اعتماد القيد ' || coalesce(nullif(p->>'note',''), ''));
  return jsonb_build_object('status', 'approved');
end $$;

create or replace function public.je_reject(p jsonb) returns jsonb language plpgsql security definer set search_path = public, app, acc as $$
declare t uuid := app.need('journals','approve'); jr acc.journals;
begin
  if coalesce(trim(p->>'note'),'') = '' then raise exception 'سبب الرفض مطلوب'; end if;
  select * into jr from acc.journals where tenant_id = t and id = (p->>'id')::uuid for update;
  if jr.id is null then raise exception 'القيد غير موجود'; end if;
  perform app.entity_ok(t, jr.entity_id);
  if jr.status not in ('pending','approved') then raise exception 'لا يمكن رفض هذه الحالة'; end if;
  update acc.journals set status = 'draft', rejected_note = trim(p->>'note'), updated_at = now() where tenant_id = t and id = jr.id;
  perform app.audit('reject','journal',jr.id::text,'إعادة للمسودة: ' || trim(p->>'note'));
  return jsonb_build_object('status', 'draft');
end $$;

create or replace function public.je_post(p jsonb) returns jsonb language plpgsql security definer set search_path = public, app, acc as $$
declare t uuid := app.need('journals','post'); jr acc.journals; pol jsonb := app.policy('journals'); r acc.journals; tot numeric; req numeric;
begin
  select * into jr from acc.journals where tenant_id = t and id = (p->>'id')::uuid for update;
  if jr.id is null then raise exception 'القيد غير موجود'; end if;
  perform app.entity_ok(t, jr.entity_id);
  if jr.source <> 'manual' then raise exception 'قيد ناتج عن مستند — يُرحَّل بإصدار المستند'; end if;
  if jr.status not in ('draft','pending','approved') then raise exception 'حالة القيد لا تسمح بالترحيل'; end if;
  tot := (app.validate_journal(jr.id)->>'debit')::numeric;
  if (pol->>'required')::boolean and tot >= (pol->>'threshold')::numeric and jr.status <> 'approved' then raise exception 'القيد يتطلب اعتمادًا قبل الترحيل'; end if;
  if (pol->>'sod')::boolean and jr.status <> 'approved' and jr.created_by = auth.uid() and tot >= (pol->>'threshold')::numeric then raise exception 'فصل المهام: لا ترحّل قيدًا أعددته دون اعتماد'; end if;
  req := nullif(app.attach_over('journal'), -1);
  if req is not null and tot >= req and app.journal_att_count(t, jr.id) = 0 then raise exception 'القيود بقيمة % فأكثر تتطلب إرفاق مستند داعم', req; end if;
  r := app.post_journal(jr.id);
  perform app.audit('post','journal',jr.id::text,'ترحيل ' || r.number || ' — ' || r.total);
  return jsonb_build_object('number', r.number, 'status', r.status);
end $$;

create or replace function public.je_reverse(p jsonb) returns jsonb language plpgsql security definer set search_path = public, app, acc as $$
declare t uuid := app.need('journals','reverse'); jr acc.journals; r acc.journals; d date := coalesce(nullif(p->>'date','')::date, current_date);
begin
  select * into jr from acc.journals where tenant_id = t and id = (p->>'id')::uuid;
  if jr.id is null then raise exception 'القيد غير موجود'; end if;
  perform app.entity_ok(t, jr.entity_id);
  if jr.source not in ('manual') and coalesce((p->>'internal')::boolean, false) = false then raise exception 'قيد ناتج عن مستند — ألغِ المستند نفسه ليُعكس قيده'; end if;
  if coalesce(trim(p->>'reason'),'') = '' then raise exception 'سبب العكس مطلوب'; end if;
  r := app.reverse_journal(jr.id, d, trim(p->>'reason'));
  return jsonb_build_object('id', r.id, 'number', r.number);
end $$;

create or replace function public.je_get(p jsonb) returns jsonb language plpgsql stable security definer set search_path = public, app, acc as $$
declare t uuid := app.need('journals','view'); jr acc.journals; src jsonb;
begin
  select * into jr from acc.journals where tenant_id = t and id = (p->>'id')::uuid;
  if jr.id is null or not (jr.entity_id = any(app.ents())) then raise exception 'القيد غير موجود'; end if;
  src := case jr.source
    when 'invoice' then (select jsonb_build_object('kind', 'invoice', 'id', i.id, 'number', i.number, 'type', i.kind) from acc.invoices i where i.tenant_id = t and i.id = jr.source_id)
    when 'payment' then (select jsonb_build_object('kind', 'payment', 'id', x.id, 'number', x.number, 'type', x.kind) from acc.payments x where x.tenant_id = t and x.id = jr.source_id)
    when 'asset' then (select jsonb_build_object('kind', 'asset_run', 'id', jr.source_id) )
    when 'reversal' then (select jsonb_build_object('kind', 'journal', 'id', o.id, 'number', o.number) from acc.journals o where o.tenant_id = t and o.id = jr.source_id)
    else null end;
  return to_jsonb(jr) - 'prev_hash' || jsonb_build_object(
    'created_by_name', (select name from acc.members where user_id = jr.created_by), 'posted_by_name', (select name from acc.members where user_id = jr.posted_by),
    'approved_by_name', (select name from acc.members where user_id = jr.approved_by), 'submitted_by_name', (select name from acc.members where user_id = jr.submitted_by),
    'entity_name', (select name from acc.entities where tenant_id = t and id = jr.entity_id),
    'reversed_by_number', (select number from acc.journals where tenant_id = t and id = jr.reversed_by),
    'source_doc', src,
    'lines', coalesce((select jsonb_agg(jsonb_build_object('id', l.id, 'line_no', l.line_no, 'account_id', l.account_id, 'account_code', a.code, 'account_name', a.name, 'debit', l.debit, 'credit', l.credit,
        'party_id', l.party_id, 'party_name', pa.name, 'cost_center_id', l.cost_center_id, 'cc_name', cc.name, 'project_id', l.project_id, 'project_name', pr.name, 'description', l.description,
        'tax_code', l.tax_code, 'tax_base', l.tax_base, 'due_date', l.due_date, 'currency', l.currency, 'fc_amount', l.fc_amount, 'rate', l.rate) order by l.line_no)
      from acc.journal_lines l join acc.accounts a on a.tenant_id = l.tenant_id and a.id = l.account_id
      left join acc.parties pa on pa.tenant_id = l.tenant_id and pa.id = l.party_id left join acc.dims cc on cc.tenant_id = l.tenant_id and cc.id = l.cost_center_id left join acc.dims pr on pr.tenant_id = l.tenant_id and pr.id = l.project_id
      where l.tenant_id = t and l.journal_id = jr.id), '[]'::jsonb),
    'attachments', coalesce((select jsonb_agg(jsonb_build_object('id', x.id, 'filename', x.filename, 'mime', x.mime, 'size', x.size, 'path', x.path, 'owner_type', x.owner_type, 'uploaded_at', x.uploaded_at,
        'by', (select name from acc.members where user_id = x.uploaded_by)) order by x.uploaded_at)
      from acc.attachments x where x.tenant_id = t and ((x.owner_type = 'journal' and x.owner_id = jr.id) or (jr.source_id is not null and x.owner_id = jr.source_id and x.owner_type in ('invoice','payment','asset')))), '[]'::jsonb),
    'history', coalesce((select jsonb_agg(jsonb_build_object('at', h.at, 'by', h.username, 'action', h.action, 'details', h.details) order by h.id) from acc.audit h where h.tenant_id = t and h.entity = 'journal' and h.ref = jr.id::text), '[]'::jsonb));
end $$;

create or replace function public.je_list(p jsonb default '{}') returns jsonb language plpgsql stable security definer set search_path = public, app, acc as $$
declare t uuid := app.need('journals','view'); ents uuid[] := app.pick_ents(p); lim int := least(coalesce(nullif(p->>'limit','')::int, 50), 500); off int := coalesce(nullif(p->>'offset','')::int, 0); q text := nullif(trim(coalesce(p->>'q','')), '');
  res jsonb;
begin
  select jsonb_build_object('total', coalesce(max(x.cnt), 0), 'rows', coalesce(jsonb_agg(jsonb_build_object('id', x.id, 'entity_id', x.entity_id, 'type', x.type, 'number', x.number, 'date', x.date, 'description', x.description, 'reference', x.reference,
      'status', x.status, 'total', x.total, 'source', x.source, 'created_by_name', x.cname, 'posted_at', x.posted_at, 'atts', x.atts, 'created_at', x.created_at) order by x.rn), '[]'::jsonb)) into res
  from (select j.*, (select name from acc.members where user_id = j.created_by) cname, app.journal_att_count(t, j.id) atts, count(*) over() cnt, row_number() over (order by j.date desc, j.created_at desc, j.id) rn
    from acc.journals j where j.tenant_id = t and j.entity_id = any(ents)
      and (nullif(p->>'status','') is null or j.status = p->>'status') and (nullif(p->>'type','') is null or j.type = p->>'type') and (nullif(p->>'source','') is null or j.source = p->>'source')
      and (nullif(p->>'from','') is null or j.date >= (p->>'from')::date) and (nullif(p->>'to','') is null or j.date <= (p->>'to')::date)
      and (nullif(p->>'created_by','') is null or j.created_by = (p->>'created_by')::uuid)
      and (nullif(p->>'min','') is null or j.total >= (p->>'min')::numeric) and (nullif(p->>'max','') is null or j.total <= (p->>'max')::numeric)
      and (q is null or j.description ilike '%' || q || '%' or j.reference ilike '%' || q || '%' or j.number ilike '%' || q || '%')
      and (nullif(p->>'account','') is null or exists (select 1 from acc.journal_lines l where l.tenant_id = t and l.journal_id = j.id and l.account_id = (p->>'account')::uuid))
      and (nullif(p->>'party','') is null or exists (select 1 from acc.journal_lines l where l.tenant_id = t and l.journal_id = j.id and l.party_id = (p->>'party')::uuid))
    order by j.date desc, j.created_at desc, j.id limit lim offset off) x;
  return res;
end $$;

-- ===== المرفقات (البيانات الوصفية؛ الملف نفسه في Storage بمسار يبدأ برقم الشركة) =====
create or replace function public.att_register(p jsonb) returns jsonb language plpgsql security definer set search_path = public, app, acc as $$
declare t uuid := app.need('attachments','add'); ot text := p->>'owner_type'; oid uuid := (p->>'owner_id')::uuid; id uuid := gen_random_uuid(); path text := p->>'path'; ok boolean := false; ent uuid;
begin
  if split_part(path, '/', 1) <> t::text then raise exception 'مسار المرفق غير صالح'; end if;
  if path ~ '\.\.' then raise exception 'مسار المرفق غير صالح'; end if;
  if coalesce((p->>'size')::bigint, 0) > 10485760 then raise exception 'الحد الأقصى للمرفق 10 ميجابايت'; end if;
  if ot = 'journal' then select entity_id into ent from acc.journals where tenant_id = t and acc.journals.id = oid; ok := ent is not null;
  elsif ot = 'invoice' then select entity_id into ent from acc.invoices where tenant_id = t and acc.invoices.id = oid; ok := ent is not null;
  elsif ot = 'payment' then select entity_id into ent from acc.payments where tenant_id = t and acc.payments.id = oid; ok := ent is not null;
  elsif ot = 'asset' then select entity_id into ent from acc.assets where tenant_id = t and acc.assets.id = oid; ok := ent is not null;
  elsif ot = 'party' then ok := exists (select 1 from acc.parties where tenant_id = t and acc.parties.id = oid);
  elsif ot = 'bank' then select entity_id into ent from acc.bank_accounts where tenant_id = t and acc.bank_accounts.id = oid; ok := ent is not null;
  else ok := false; end if;
  if not ok then raise exception 'المستند المرتبط غير موجود'; end if;
  if ent is not null then perform app.entity_ok(t, ent); end if;
  insert into acc.attachments (tenant_id, id, entity_id, owner_type, owner_id, path, filename, mime, size, sha256, note, uploaded_by)
  values (t, id, ent, ot, oid, path, coalesce(nullif(p->>'filename',''), 'file'), coalesce(p->>'mime',''), coalesce((p->>'size')::bigint, 0), coalesce(p->>'sha256',''), coalesce(p->>'note',''), auth.uid());
  perform app.audit('attach', case when ot = 'journal' then 'journal' else ot end, oid::text, 'إرفاق ' || coalesce(p->>'filename',''));
  return jsonb_build_object('id', id);
end $$;

create or replace function public.att_list(p jsonb) returns jsonb language plpgsql stable security definer set search_path = public, app, acc as $$
declare t uuid := app.need('attachments','view');
begin
  return coalesce((select jsonb_agg(jsonb_build_object('id', x.id, 'filename', x.filename, 'mime', x.mime, 'size', x.size, 'path', x.path, 'uploaded_at', x.uploaded_at, 'by', (select name from acc.members where user_id = x.uploaded_by)) order by x.uploaded_at)
    from acc.attachments x where x.tenant_id = t and x.owner_type = p->>'owner_type' and x.owner_id = (p->>'owner_id')::uuid and (x.entity_id is null or x.entity_id = any(app.ents()))), '[]'::jsonb);
end $$;

create or replace function public.att_delete(p jsonb) returns jsonb language plpgsql security definer set search_path = public, app, acc as $$
declare t uuid := app.need('attachments','delete'); a acc.attachments; locked boolean := false;
begin
  select * into a from acc.attachments where tenant_id = t and id = (p->>'id')::uuid;
  if a.id is null then raise exception 'المرفق غير موجود'; end if;
  if a.owner_type = 'journal' then locked := exists (select 1 from acc.journals where tenant_id = t and id = a.owner_id and status in ('posted','reversed','approved')); end if;
  if a.owner_type in ('invoice','payment') then locked := true; end if;
  if locked then raise exception 'المرفق مرتبط بقيد/مستند معتمد أو مرحّل — لا يُحذف (للحفظ والتدقيق)'; end if;
  delete from acc.attachments where tenant_id = t and id = a.id;
  perform app.audit('detach', a.owner_type, a.owner_id::text, 'حذف مرفق ' || a.filename);
  return jsonb_build_object('ok', true, 'path', a.path);
end $$;
-- ===== sql/005_api_admin.sql =====
-- مُحكَم للحسابات — الشركات والمستخدمون والأدوار والإعدادات والتدقيق

create or replace function app.default_settings() returns jsonb language sql immutable as $$ select jsonb_build_object(
  'approval', jsonb_build_object('journals', jsonb_build_object('required', true, 'threshold', 0), 'invoices', jsonb_build_object('required', false, 'threshold', 0), 'payments', jsonb_build_object('required', false, 'threshold', 0), 'sod', true),
  'controls', jsonb_build_object('flag_weekend', true, 'flag_round', true, 'flag_manual_control', true, 'attach', jsonb_build_object('journal', 10000, 'purchase', 0, 'sales', -1, 'payment', 10000, 'receipt', 10000)),
  'format', jsonb_build_object('decimals', 2),
  'invoice', jsonb_build_object('terms', '', 'footer', 'شكرًا لتعاملكم معنا', 'show_stamp', true, 'show_signature', true),
  'brand', '{}'::jsonb) $$;

create or replace function app.make_fy(t uuid, e uuid, sd date, nm text default null) returns uuid language plpgsql security definer set search_path = public, acc as $$
declare fid uuid := gen_random_uuid(); ed date := (sd + interval '1 year' - interval '1 day')::date; i int;
begin
  insert into acc.fiscal_years (tenant_id, entity_id, id, name, start_date, end_date) values (t, e, fid, coalesce(nm, 'السنة المالية ' || extract(year from sd)::int), sd, ed);
  for i in 0..11 loop
    insert into acc.periods (tenant_id, entity_id, fy_id, no, start_date, end_date) values (t, e, fid, i + 1, (sd + (i || ' month')::interval)::date, (sd + ((i + 1) || ' month')::interval - interval '1 day')::date);
  end loop;
  return fid;
end $$;

create or replace function app.seed_tax(t uuid, country text) returns void language plpgsql security definer set search_path = public, acc as $$
declare r numeric := case country when 'SA' then 15 when 'AE' then 5 when 'BH' then 10 when 'OM' then 5 when 'EG' then 14 when 'JO' then 16 else 0 end; vo uuid; vi uuid;
begin
  select id into vo from acc.accounts where tenant_id = t and system_key = 'VAT_OUT'; select id into vi from acc.accounts where tenant_id = t and system_key = 'VAT_IN';
  insert into acc.tax_codes (tenant_id, code, name, rate, kind, account_id) values
   (t, 'S',  'مبيعات خاضعة للضريبة بالنسبة الأساسية', r, 'output', vo), (t, 'Z', 'مبيعات بنسبة صفر', 0, 'zero_out', null), (t, 'SE', 'مبيعات معفاة', 0, 'exempt', null),
   (t, 'PS', 'مشتريات خاضعة للضريبة بالنسبة الأساسية', r, 'input', vi), (t, 'PZ', 'مشتريات بنسبة صفر', 0, 'zero_in', null), (t, 'PE', 'مشتريات معفاة', 0, 'exempt', null),
   (t, 'O',  'خارج نطاق الضريبة', 0, 'oos', null)
  on conflict (tenant_id, code) do nothing;
end $$;

create or replace function app.apply_template(t uuid, k text) returns int language plpgsql security definer set search_path = public, acc as $$
declare r jsonb; pid uuid; n int := 0; ty text; sub text; isg boolean; rows jsonb;
begin
  select tpl.rows into rows from app.coa_templates tpl where tpl.key = k; if rows is null then return 0; end if;
  for r in select * from jsonb_array_elements(rows) loop
    pid := null; if nullif(r->>'parent_code','') is not null then select a.id into pid from acc.accounts a where a.tenant_id = t and a.code = r->>'parent_code'; end if;
    ty := coalesce(r->>'type', (select a.type from acc.accounts a where a.tenant_id = t and a.id = pid)); sub := coalesce(nullif(r->>'subtype',''), 'general'); isg := coalesce((r->>'is_group')::boolean, false);
    insert into acc.accounts (tenant_id, code, name, name_en, parent_id, type, subtype, is_group, cf_class, requires_party, requires_cc, system_key)
    values (t, r->>'code', r->>'name', coalesce(r->>'name_en',''), pid, ty, sub, isg, coalesce(nullif(r->>'cf_class',''), app.default_cf(ty, sub)), sub in ('receivable','payable'), false, nullif(r->>'system_key',''));
    n := n + 1;
  end loop;
  return n;
end $$;

create or replace function public.login_email(p jsonb) returns text language sql stable security definer set search_path = public, app as $$ select app.login_email(p->>'code', p->>'username') $$;

create or replace function public.register_company(p jsonb) returns jsonb language plpgsql security definer set search_path = public, app, acc as $$
declare t uuid := gen_random_uuid(); u uuid; c text := lower(trim(coalesce(p->>'code',''))); ip text := app.client_ip(); un text := lower(trim(coalesce(p->>'username',''))); e uuid := gen_random_uuid();
  country text := upper(coalesce(nullif(p->>'country',''), 'SA')); cur text := upper(coalesce(nullif(p->>'currency',''), 'SAR')); tpl text := coalesce(nullif(p->>'template',''), 'general'); fy date := coalesce(nullif(p->>'fy_start','')::date, make_date(extract(year from current_date)::int, 1, 1));
begin
  if c !~ '^[a-z0-9][a-z0-9-]{2,30}$' then raise exception 'رمز الشركة: 3 إلى 31 حرفًا إنجليزيًا صغيرًا أو أرقامًا أو شرطة'; end if;
  if exists (select 1 from acc.tenants where code = c) then raise exception 'رمز الشركة مستخدم — اختر رمزًا آخر'; end if;
  if coalesce(trim(p->>'name'),'') = '' or un = '' then raise exception 'اسم الشركة واسم الدخول مطلوبان'; end if;
  if un !~ '^[a-z0-9._-]{3,40}$' then raise exception 'اسم الدخول بالإنجليزية (حروف وأرقام ونقطة وشرطة)'; end if;
  perform app.check_pw(p->>'password');
  if (select count(*) from acc.tenants where created_at > now() - interval '1 hour') > 60 then raise exception 'محاولات كثيرة — حاول لاحقًا'; end if;
  if ip <> 'unknown' and (select count(*) from acc.tenants where created_ip = ip and created_at > now() - interval '1 hour') >= 5 then raise exception 'محاولات كثيرة من نفس الجهاز — حاول لاحقًا'; end if;
  insert into acc.tenants (id, code, name, name_en, cr, vat_no, country, currency, contact_phone, contact_email, plan, max_users, max_entities, created_ip, settings)
  values (t, c, trim(p->>'name'), coalesce(p->>'name_en',''), coalesce(p->>'cr',''), coalesce(p->>'vat_no',''), country, cur, coalesce(p->>'phone',''), coalesce(p->>'email',''), 'P', 200, 100, ip, app.default_settings());
  insert into acc.entities (tenant_id, id, code, name, name_en, vat_no, cr) values (t, e, 'E1', trim(p->>'name'), coalesce(p->>'name_en',''), coalesce(p->>'vat_no',''), coalesce(p->>'cr',''));
  perform app.seed_roles(t);
  if tpl <> 'none' then perform app.apply_template(t, tpl); end if;
  perform app.seed_tax(t, country);
  perform app.make_fy(t, e, fy);
  u := app.make_auth_user(app.login_email(c, un), p->>'password', coalesce(nullif(p->>'display',''), un));
  insert into acc.members (user_id, tenant_id, username, name, role) values (u, t, un, coalesce(nullif(trim(p->>'display'),''), un), 'owner');
  perform app.audit_for(t, u, un, 'system', 'tenant', t::text, 'تسجيل الشركة وبدء التجربة');
  return jsonb_build_object('tenant', t, 'email', app.login_email(c, un));
end $$;

create or replace function public.my_profile(p jsonb default '{}') returns jsonb language plpgsql stable security definer set search_path = public, app, acc as $$
declare m acc.members; t acc.tenants;
begin
  select * into m from acc.members where user_id = auth.uid();
  if m.user_id is null then return jsonb_build_object('member', null, 'platform_admin', app.is_platform_admin(), 'aal', coalesce(auth.jwt()->>'aal','aal1')); end if;
  select * into t from acc.tenants where id = m.tenant_id;
  return jsonb_build_object('member', to_jsonb(m), 'tenant', to_jsonb(t) - 'created_ip', 'role', (select jsonb_build_object('id', r.id, 'name', r.name, 'locked', r.locked, 'perms', r.perms, 'sys', r.sys) from acc.roles r where r.tenant_id = m.tenant_id and r.id = m.role),
    'entities', (select coalesce(jsonb_agg(to_jsonb(e) order by e.code), '[]'::jsonb) from acc.entities e where e.tenant_id = m.tenant_id and e.active and (m.entities is null or e.id = any(m.entities))),
    'policy', jsonb_build_object('journals', app.policy('journals'), 'invoices', app.policy('invoices'), 'payments', app.policy('payments')),
    'platform_admin', app.is_platform_admin(), 'aal', coalesce(auth.jwt()->>'aal','aal1'), 'ok', app.tenant_ok(m.tenant_id));
end $$;

create or replace function public.touch_login(p jsonb default '{}') returns jsonb language plpgsql security definer set search_path = public, acc as $$
begin update acc.members set last_login = now() where user_id = auth.uid(); perform app.audit('login','user',auth.uid()::text,'تسجيل دخول'); return '{}'::jsonb; end $$;
create or replace function public.clear_must_change(p jsonb default '{}') returns jsonb language plpgsql security definer set search_path = public, acc as $$
begin update acc.members set must_change = false where user_id = auth.uid(); return '{}'::jsonb; end $$;

-- ===== المستخدمون =====
create or replace function public.members_list(p jsonb default '{}') returns jsonb language plpgsql stable security definer set search_path = public, app, acc as $$
declare t uuid := app.need(null, null);
begin
  if not (app.sys('users') or app.sys('audit')) then raise exception 'ليست لديك صلاحية'; end if;
  return coalesce((select jsonb_agg(jsonb_build_object('user_id', m.user_id, 'username', m.username, 'name', m.name, 'role', m.role, 'entities', m.entities, 'active', m.active, 'must_change', m.must_change,
    'last_login', m.last_login, 'created_at', m.created_at, 'mfa', exists (select 1 from auth.mfa_factors f where f.user_id = m.user_id and f.status = 'verified')) order by m.created_at) from acc.members m where m.tenant_id = t), '[]'::jsonb);
exception when undefined_table then
  return coalesce((select jsonb_agg(jsonb_build_object('user_id', m.user_id, 'username', m.username, 'name', m.name, 'role', m.role, 'entities', m.entities, 'active', m.active, 'must_change', m.must_change, 'last_login', m.last_login, 'created_at', m.created_at, 'mfa', false) order by m.created_at) from acc.members m where m.tenant_id = t), '[]'::jsonb);
end $$;

create or replace function public.admin_create_users(p jsonb) returns jsonb language plpgsql security definer set search_path = public, app, acc as $$
declare me acc.members; t acc.tenants; u jsonb; uid uuid; n int := 0; cnt int; users jsonb := coalesce(p->'users', '[]'::jsonb); un text;
begin
  perform app.need_sys('users'); select * into me from app.me(); select * into t from acc.tenants where id = me.tenant_id;
  select count(*) into cnt from acc.members where tenant_id = t.id and active;
  if t.max_users is not null and cnt + jsonb_array_length(users) > t.max_users then raise exception 'باقتك تسمح بـ % مستخدمين', t.max_users; end if;
  for u in select * from jsonb_array_elements(users) loop
    un := lower(trim(u->>'username'));
    if un !~ '^[a-z0-9._-]{2,40}$' then raise exception 'اسم الدخول % غير صالح (إنجليزي بدون مسافات)', u->>'username'; end if;
    if not exists (select 1 from acc.roles where tenant_id = t.id and id = coalesce(u->>'role','viewer')) then raise exception 'الدور غير موجود'; end if;
    if u->>'role' = 'owner' and me.role <> 'owner' then raise exception 'المالك فقط يضيف مالكًا'; end if;
    perform app.check_pw(u->>'password');
    if exists (select 1 from acc.members where tenant_id = t.id and username = un) then raise exception 'اسم الدخول % مستخدم من قبل', un; end if;
    uid := app.make_auth_user(app.login_email(t.code, un), u->>'password', u->>'name');
    insert into acc.members (user_id, tenant_id, username, name, role, entities, must_change)
    values (uid, t.id, un, coalesce(nullif(u->>'name',''), un), coalesce(u->>'role','viewer'),
      case when jsonb_typeof(u->'entities') = 'array' and jsonb_array_length(u->'entities') > 0 then (select array_agg(x::uuid) from jsonb_array_elements_text(u->'entities') x) end, coalesce((u->>'must_change')::boolean, true));
    perform app.audit('create','user',uid::text,'إنشاء مستخدم ' || un || ' بدور ' || coalesce(u->>'role','viewer'));
    n := n + 1;
  end loop;
  return jsonb_build_object('created', n);
end $$;

create or replace function public.member_update(p jsonb) returns jsonb language plpgsql security definer set search_path = public, app, acc as $$
declare t uuid := app.need_sys('users'); m acc.members; me acc.members := (select x from app.me() x); newrole text := p->>'role'; nact boolean := (p->>'active')::boolean;
begin
  select * into m from acc.members where tenant_id = t and user_id = (p->>'user_id')::uuid; if m.user_id is null then raise exception 'المستخدم غير موجود'; end if;
  if m.user_id = auth.uid() and ((newrole is not null and newrole <> m.role) or nact is false) then raise exception 'غير مسموح بتغيير دورك أو تعطيل حسابك بنفسك'; end if;
  if (m.role = 'owner' or newrole = 'owner') and me.role <> 'owner' then raise exception 'تعديل دور المالك للمالك فقط'; end if;
  if newrole is not null and not exists (select 1 from acc.roles where tenant_id = t and id = newrole) then raise exception 'الدور غير موجود'; end if;
  if (m.role = 'owner' and (newrole is distinct from 'owner' and newrole is not null or nact is false)) and (select count(*) from acc.members where tenant_id = t and role = 'owner' and active) <= 1 then raise exception 'يجب أن يبقى مالك فعّال واحد'; end if;
  update acc.members set name = coalesce(nullif(p->>'name',''), name), role = coalesce(newrole, role), active = coalesce(nact, active),
    entities = case when p ? 'entities' then (case when jsonb_typeof(p->'entities') = 'array' and jsonb_array_length(p->'entities') > 0 then (select array_agg(x::uuid) from jsonb_array_elements_text(p->'entities') x) end) else entities end
  where tenant_id = t and user_id = m.user_id;
  perform app.audit('update','user',m.user_id::text,'تعديل مستخدم ' || m.username);
  return jsonb_build_object('ok', true);
end $$;

create or replace function public.admin_set_password(p jsonb) returns jsonb language plpgsql security definer set search_path = public, app, acc, auth, extensions as $$
declare t uuid := app.need_sys('users'); uid uuid := (p->>'user_id')::uuid;
begin
  if not exists (select 1 from acc.members where user_id = uid and tenant_id = t) then raise exception 'غير مسموح'; end if;
  perform app.check_pw(p->>'password');
  update auth.users set encrypted_password = crypt(p->>'password', gen_salt('bf')), updated_at = now() where id = uid;
  update acc.members set must_change = true where user_id = uid;
  perform app.audit('password','user',uid::text,'إعادة تعيين كلمة مرور'); return jsonb_build_object('ok', true);
end $$;
create or replace function public.admin_reset_mfa(p jsonb) returns jsonb language plpgsql security definer set search_path = public, app, acc, auth as $$
declare t uuid := app.need_sys('users'); uid uuid := (p->>'user_id')::uuid;
begin
  if not exists (select 1 from acc.members where user_id = uid and tenant_id = t) then raise exception 'غير مسموح'; end if;
  delete from auth.mfa_factors where user_id = uid; perform app.audit('mfa_reset','user',uid::text,'إعادة ضبط التحقق الثنائي'); return jsonb_build_object('ok', true);
exception when undefined_table then return jsonb_build_object('ok', true);
end $$;
create or replace function public.admin_delete_user(p jsonb) returns jsonb language plpgsql security definer set search_path = public, app, acc, auth as $$
declare t uuid := app.need_sys('users'); uid uuid := (p->>'user_id')::uuid; m acc.members;
begin
  select * into m from acc.members where user_id = uid and tenant_id = t;
  if m.user_id is null or uid = auth.uid() then raise exception 'غير مسموح'; end if;
  if m.role = 'owner' and (select count(*) from acc.members where tenant_id = t and role = 'owner' and active) <= 1 then raise exception 'يجب أن يبقى مالك واحد'; end if;
  -- لا يُحذف مستخدم له قيود (يُعطَّل بدل ذلك للحفاظ على أثر المساءلة)
  if exists (select 1 from acc.journals where tenant_id = t and (created_by = uid or posted_by = uid or approved_by = uid)) then
    update acc.members set active = false where user_id = uid; perform app.audit('deactivate','user',uid::text,'تعطيل مستخدم له قيود: ' || m.username);
    return jsonb_build_object('ok', true, 'deactivated', true);
  end if;
  delete from auth.users where id = uid; perform app.audit('delete','user',uid::text,'حذف مستخدم ' || m.username);
  return jsonb_build_object('ok', true);
end $$;

create or replace function public.set_require_mfa(p jsonb) returns jsonb language plpgsql security definer set search_path = public, app, acc as $$
begin
  if (select role from app.me()) is distinct from 'owner' then raise exception 'المالك فقط'; end if;
  if coalesce(p->>'scope','all') not in ('all','admin') then raise exception 'نطاق غير صحيح'; end if;
  update acc.tenants set require_mfa = coalesce((p->>'on')::boolean, false), mfa_scope = coalesce(p->>'scope','all') where id = app.tenant();
  perform app.audit('security','tenant',app.tenant()::text,'إلزام التحقق الثنائي: ' || coalesce(p->>'on','false') || ' / ' || coalesce(p->>'scope','all')); return jsonb_build_object('ok', true);
end $$;

-- ===== الأدوار =====
create or replace function public.role_list(p jsonb default '{}') returns jsonb language plpgsql stable security definer set search_path = public, app, acc as $$
declare t uuid := app.need(null, null);
begin
  if not (app.sys('users') or app.sys('audit')) then raise exception 'ليست لديك صلاحية'; end if;
  return coalesce((select jsonb_agg(jsonb_build_object('id', r.id, 'name', r.name, 'description', r.description, 'locked', r.locked, 'perms', r.perms, 'sys', r.sys, 'users', (select count(*) from acc.members m where m.tenant_id = t and m.role = r.id and m.active)) order by r.locked desc, r.name) from acc.roles r where r.tenant_id = t), '[]'::jsonb);
end $$;
create or replace function public.role_upsert(p jsonb) returns jsonb language plpgsql security definer set search_path = public, app, acc as $$
declare t uuid := app.need_sys('users'); rid text := p->>'id'; old acc.roles;
begin
  if rid !~ '^[a-z0-9_]{2,30}$' then raise exception 'رمز الدور: حروف إنجليزية صغيرة وأرقام و_'; end if;
  if jsonb_typeof(p->'perms') <> 'object' or jsonb_typeof(coalesce(p->'sys','[]'::jsonb)) <> 'array' then raise exception 'صيغة الصلاحيات غير صحيحة'; end if;
  select * into old from acc.roles where tenant_id = t and id = rid;
  if old.locked then raise exception 'دور المالك لا يُعدَّل'; end if;
  if (select role from app.me()) <> 'owner' and exists (select 1 from jsonb_array_elements_text(coalesce(p->'sys','[]'::jsonb)) s where s in ('users','settings','backup','gm') and not app.sys(s)) then raise exception 'لا تمنح صلاحيات نظام لا تملكها'; end if;
  insert into acc.roles (tenant_id, id, name, description, perms, sys) values (t, rid, coalesce(nullif(trim(p->>'name'),''), rid), coalesce(p->>'description',''), p->'perms', coalesce(p->'sys','[]'::jsonb))
  on conflict (tenant_id, id) do update set name = excluded.name, description = excluded.description, perms = excluded.perms, sys = excluded.sys;
  perform app.audit('role','role',rid,'حفظ الدور ' || coalesce(p->>'name',rid)); return jsonb_build_object('ok', true);
end $$;
create or replace function public.role_delete(p jsonb) returns jsonb language plpgsql security definer set search_path = public, app, acc as $$
declare t uuid := app.need_sys('users');
begin
  if exists (select 1 from acc.roles where tenant_id = t and id = p->>'id' and locked) then raise exception 'دور المالك لا يُحذف'; end if;
  if exists (select 1 from acc.members where tenant_id = t and role = p->>'id') then raise exception 'الدور مستخدم — انقل مستخدميه أولًا'; end if;
  delete from acc.roles where tenant_id = t and id = p->>'id'; perform app.audit('role_delete','role',p->>'id','حذف دور'); return jsonb_build_object('ok', true);
end $$;

-- ===== الإعدادات =====
create or replace function public.settings_get(p jsonb default '{}') returns jsonb language plpgsql stable security definer set search_path = public, app, acc as $$
declare t uuid := app.need(null, null);
begin return (select to_jsonb(x) - 'created_ip' - 'id' || jsonb_build_object('settings', app.jsonb_merge(app.default_settings(), x.settings)) from acc.tenants x where x.id = t); end $$;

create or replace function public.settings_set(p jsonb) returns jsonb language plpgsql security definer set search_path = public, app, acc as $$
declare t uuid := app.need_sys('settings'); s jsonb := coalesce(p->'settings','{}'::jsonb); k text; cur jsonb;
begin
  for k in select jsonb_object_keys(s) loop if k not in ('approval','controls','format','invoice','brand','tax','locale','consol') then raise exception 'إعداد غير مسموح: %', k; end if; end loop;
  if s ? 'brand' then
    if length(coalesce(s->'brand'->>'logo','')) > 450000 or length(coalesce(s->'brand'->>'stamp','')) > 450000 or length(coalesce(s->'brand'->>'signature','')) > 450000 then raise exception 'الصورة كبيرة — الحد 300 كيلوبايت تقريبًا'; end if;
    if exists (select 1 from jsonb_each_text(s->'brand') b where b.value is not null and b.value <> '' and b.value !~ '^data:image/(png|jpeg|webp|svg\+xml);base64,[A-Za-z0-9+/=]+$') then raise exception 'صيغة الصورة غير مدعومة (PNG/JPG/WebP/SVG)'; end if;
  end if;
  select settings into cur from acc.tenants where id = t;
  update acc.tenants set settings = app.jsonb_merge(cur, s),
    name = coalesce(nullif(trim(p->>'name'),''), name), name_en = coalesce(p->>'name_en', name_en), cr = coalesce(p->>'cr', cr), vat_no = coalesce(p->>'vat_no', vat_no),
    address = coalesce(p->>'address', address), contact_phone = coalesce(p->>'contact_phone', contact_phone), contact_email = coalesce(p->>'contact_email', contact_email) where id = t;
  perform app.audit('settings','tenant',t::text,'تعديل الإعدادات: ' || (select string_agg(x, '، ') from jsonb_object_keys(s) x)); return jsonb_build_object('ok', true);
end $$;

-- ===== التدقيق والتحقق من السلسلة =====
create or replace function public.audit_list(p jsonb default '{}') returns jsonb language plpgsql stable security definer set search_path = public, app, acc as $$
declare t uuid := app.need_sys('audit'); lim int := least(coalesce(nullif(p->>'limit','')::int, 100), 1000); off int := coalesce(nullif(p->>'offset','')::int, 0);
begin
  return (select jsonb_build_object('total', (select count(*) from acc.audit where tenant_id = t), 'rows', coalesce(jsonb_agg(jsonb_build_object('id', a.id, 'at', a.at, 'user', a.username, 'action', a.action, 'entity', a.entity, 'ref', a.ref, 'details', a.details) order by a.id desc), '[]'::jsonb))
    from (select * from acc.audit a where a.tenant_id = t and (nullif(p->>'entity','') is null or a.entity = p->>'entity') and (nullif(p->>'user','') is null or a.username = p->>'user') and (nullif(p->>'action','') is null or a.action = p->>'action')
      and (nullif(p->>'q','') is null or a.details ilike '%' || (p->>'q') || '%') order by a.id desc limit lim offset off) a);
end $$;

create or replace function public.chain_verify(p jsonb default '{}') returns jsonb language plpgsql stable security definer set search_path = public, app, acc as $$
declare t uuid := app.need_sys('audit'); r record; prev text := null; bad jsonb := '[]'::jsonb; n int := 0; h text; jn int := 0; pj text := null; jr acc.journals;
begin
  for r in select * from acc.audit where tenant_id = t order by id loop
    n := n + 1;
    h := encode(sha256(convert_to(coalesce(prev,'') || '|' || t::text || '|' || to_char(r.at at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US') || '|' || coalesce(r.username,'') || '|' || r.action || '|' || coalesce(r.entity,'') || '|' || coalesce(r.ref,'') || '|' || coalesce(r.details,''), 'UTF8')), 'hex');
    if r.hash <> h or r.prev_hash is distinct from prev then bad := bad || jsonb_build_object('kind', 'audit', 'id', r.id); end if;
    prev := r.hash;
  end loop;
  for jr in select * from acc.journals where tenant_id = t and chain_no is not null order by chain_no loop
    jn := jn + 1;
    if jr.prev_hash is distinct from pj or jr.hash is distinct from app.journal_hash(jr, pj) then bad := bad || jsonb_build_object('kind', 'journal', 'id', jr.id, 'number', jr.number); end if;
    pj := jr.hash;
  end loop;
  return jsonb_build_object('ok', jsonb_array_length(bad) = 0, 'audit_rows', n, 'journals', jn, 'broken', bad);
end $$;
-- ===== sql/006_docs.sql =====
-- مُحكَم للحسابات — الأطراف، مراكز التكلفة، الضرائب، الفواتير، السندات والتسويات (كلها تولّد قيودًا مرحّلة)

create table if not exists acc.invoices (
  tenant_id uuid not null references acc.tenants(id) on delete cascade, id uuid not null default gen_random_uuid(), entity_id uuid not null,
  kind text not null check (kind in ('sales','purchase','sales_credit','purchase_debit')), number text, supplier_ref text not null default '',
  party_id uuid not null, date date not null, due_date date, currency text not null default 'SAR', rate numeric(18,6) not null default 1 check (rate > 0),
  subtotal numeric(18,2) not null default 0, discount_total numeric(18,2) not null default 0, tax_total numeric(18,2) not null default 0, total numeric(18,2) not null default 0, total_base numeric(18,2) not null default 0,
  status text not null default 'draft' check (status in ('draft','pending','approved','issued','void')), journal_id uuid, related_id uuid,
  notes text not null default '', terms text not null default '', void_reason text not null default '',
  created_by uuid, created_at timestamptz not null default now(), updated_at timestamptz not null default now(),
  submitted_by uuid, submitted_at timestamptz, approved_by uuid, approved_at timestamptz, issued_by uuid, issued_at timestamptz,
  primary key (tenant_id, id), foreign key (tenant_id, entity_id) references acc.entities (tenant_id, id), foreign key (tenant_id, party_id) references acc.parties (tenant_id, id),
  foreign key (tenant_id, journal_id) references acc.journals (tenant_id, id)
);
create unique index if not exists invoices_number on acc.invoices (tenant_id, entity_id, number) where number is not null;
create unique index if not exists invoices_supref on acc.invoices (tenant_id, entity_id, party_id, supplier_ref) where kind = 'purchase' and supplier_ref <> '' and status <> 'void';
create index if not exists invoices_q on acc.invoices (tenant_id, entity_id, date desc);
create index if not exists invoices_party on acc.invoices (tenant_id, party_id);
create table if not exists acc.invoice_lines (
  tenant_id uuid not null, id uuid not null default gen_random_uuid(), invoice_id uuid not null, line_no int not null, description text not null default '',
  qty numeric(18,4) not null default 1, unit_price numeric(18,4) not null default 0, discount numeric(18,2) not null default 0, tax_code text, account_id uuid not null,
  cost_center_id uuid, project_id uuid, net numeric(18,2) not null default 0, tax numeric(18,2) not null default 0,
  primary key (tenant_id, id), foreign key (tenant_id, invoice_id) references acc.invoices (tenant_id, id) on delete cascade, foreign key (tenant_id, account_id) references acc.accounts (tenant_id, id),
  foreign key (tenant_id, cost_center_id) references acc.dims (tenant_id, id), foreign key (tenant_id, project_id) references acc.dims (tenant_id, id)
);
create table if not exists acc.payments (
  tenant_id uuid not null references acc.tenants(id) on delete cascade, id uuid not null default gen_random_uuid(), entity_id uuid not null,
  kind text not null check (kind in ('receipt','payment')), number text, date date not null, party_id uuid, method text not null default 'bank' check (method in ('cash','bank','cheque','transfer','card')),
  cash_account_id uuid not null, amount numeric(18,2) not null check (amount > 0), on_account numeric(18,2) not null default 0, reference text not null default '', cheque_no text not null default '', cheque_date date,
  status text not null default 'draft' check (status in ('draft','pending','approved','posted','void')), journal_id uuid, notes text not null default '', void_reason text not null default '',
  created_by uuid, created_at timestamptz not null default now(), updated_at timestamptz not null default now(), submitted_by uuid, submitted_at timestamptz, approved_by uuid, approved_at timestamptz, posted_by uuid, posted_at timestamptz,
  primary key (tenant_id, id), foreign key (tenant_id, entity_id) references acc.entities (tenant_id, id), foreign key (tenant_id, party_id) references acc.parties (tenant_id, id),
  foreign key (tenant_id, cash_account_id) references acc.accounts (tenant_id, id), foreign key (tenant_id, journal_id) references acc.journals (tenant_id, id)
);
create unique index if not exists payments_number on acc.payments (tenant_id, entity_id, number) where number is not null;
create index if not exists payments_q on acc.payments (tenant_id, entity_id, date desc);
create table if not exists acc.payment_lines (
  tenant_id uuid not null, id uuid not null default gen_random_uuid(), payment_id uuid not null, line_no int not null, account_id uuid not null, description text not null default '',
  amount numeric(18,2) not null check (amount > 0), tax_code text, tax numeric(18,2) not null default 0, cost_center_id uuid, project_id uuid,
  primary key (tenant_id, id), foreign key (tenant_id, payment_id) references acc.payments (tenant_id, id) on delete cascade, foreign key (tenant_id, account_id) references acc.accounts (tenant_id, id),
  foreign key (tenant_id, cost_center_id) references acc.dims (tenant_id, id), foreign key (tenant_id, project_id) references acc.dims (tenant_id, id)
);
create table if not exists acc.allocations (   -- تسوية دفعة أو إشعار دائن/مدين على فاتورة
  tenant_id uuid not null, id uuid not null default gen_random_uuid(), entity_id uuid not null, source_kind text not null check (source_kind in ('payment','credit')), source_id uuid not null,
  invoice_id uuid not null, amount numeric(18,2) not null check (amount > 0), date date not null, active boolean not null default false, created_by uuid, created_at timestamptz not null default now(),
  primary key (tenant_id, id), foreign key (tenant_id, invoice_id) references acc.invoices (tenant_id, id)
);
create index if not exists alloc_inv on acc.allocations (tenant_id, invoice_id) where active;
create index if not exists alloc_src on acc.allocations (tenant_id, source_kind, source_id);
do $$ declare t text; begin foreach t in array array['invoices','invoice_lines','payments','payment_lines','allocations'] loop execute format('alter table acc.%I enable row level security', t); end loop; end $$;

-- ===== الأطراف =====
create or replace function public.party_list(p jsonb default '{}') returns jsonb language plpgsql stable security definer set search_path = public, app, acc as $$
declare t uuid := app.need('parties','view'); ents uuid[] := app.ents(); q text := nullif(trim(coalesce(p->>'q','')), ''); lim int := least(coalesce(nullif(p->>'limit','')::int, 200), 2000);
begin
  return coalesce((select jsonb_agg(jsonb_build_object('id', x.id, 'code', x.code, 'kind', x.kind, 'name', x.name, 'name_en', x.name_en, 'vat_no', x.vat_no, 'phone', x.phone, 'email', x.email, 'city', x.city, 'credit_limit', x.credit_limit,
      'terms_days', x.terms_days, 'active', x.active, 'ar', coalesce(b.ar, 0), 'ap', coalesce(b.ap, 0)) order by x.code)
    from (select * from acc.parties where tenant_id = t and (nullif(p->>'kind','') is null or kind = p->>'kind' or kind = 'both' and p->>'kind' in ('customer','supplier')) and (q is null or name ilike '%' || q || '%' or code ilike '%' || q || '%' or vat_no ilike '%' || q || '%' or phone ilike '%' || q || '%')
      and (nullif(p->>'active','') is null or active = (p->>'active')::boolean) order by code limit lim) x
    left join (select l.party_id, sum(case when a.subtype = 'receivable' then l.debit - l.credit else 0 end) ar, sum(case when a.subtype = 'payable' then l.credit - l.debit else 0 end) ap
      from acc.journal_lines l join acc.accounts a on a.tenant_id = l.tenant_id and a.id = l.account_id where l.tenant_id = t and l.posted and l.party_id is not null and l.entity_id = any(ents) group by 1) b on b.party_id = x.id), '[]'::jsonb);
end $$;

create or replace function public.party_upsert(p jsonb) returns jsonb language plpgsql security definer set search_path = public, app, acc as $$
declare t uuid; v_id uuid := nullif(p->>'id','')::uuid; k text := coalesce(nullif(p->>'kind',''), 'customer'); c text := nullif(trim(coalesce(p->>'code','')), '');
begin
  t := app.need('parties', case when v_id is null then 'add' else 'edit' end);
  if coalesce(trim(p->>'name'),'') = '' then raise exception 'اسم العميل/المورد مطلوب'; end if;
  if k not in ('customer','supplier','both','employee','other') then raise exception 'نوع غير صالح'; end if;
  if nullif(p->>'vat_no','') is not null and (p->>'vat_no') !~ '^[0-9A-Za-z-]{5,20}$' then raise exception 'الرقم الضريبي غير صالح'; end if;
  if v_id is null then
    v_id := gen_random_uuid();
    if c is null then c := case when k = 'supplier' then 'S-' when k = 'employee' then 'EMP-' else 'C-' end || lpad(app.next_no(t, null, 'party_' || k, 0)::text, 5, '0'); end if;
    insert into acc.parties (tenant_id, id, kind, code, name, name_en, vat_no, cr, phone, email, address, city, country, contact, credit_limit, terms_days, note, created_by)
    values (t, v_id, k, c, trim(p->>'name'), coalesce(p->>'name_en',''), coalesce(p->>'vat_no',''), coalesce(p->>'cr',''), coalesce(p->>'phone',''), coalesce(p->>'email',''), coalesce(p->>'address',''), coalesce(p->>'city',''),
      coalesce(nullif(p->>'country',''), 'SA'), coalesce(p->>'contact',''), coalesce(nullif(p->>'credit_limit','')::numeric, 0), coalesce(nullif(p->>'terms_days','')::int, 30), coalesce(p->>'note',''), auth.uid());
    perform app.audit('create','party',v_id::text,'إنشاء ' || c || ' ' || (p->>'name'));
  else
    update acc.parties set kind = k, code = coalesce(c, code), name = trim(p->>'name'), name_en = coalesce(p->>'name_en',''), vat_no = coalesce(p->>'vat_no',''), cr = coalesce(p->>'cr',''), phone = coalesce(p->>'phone',''),
      email = coalesce(p->>'email',''), address = coalesce(p->>'address',''), city = coalesce(p->>'city',''), country = coalesce(nullif(p->>'country',''), country), contact = coalesce(p->>'contact',''),
      credit_limit = coalesce(nullif(p->>'credit_limit','')::numeric, 0), terms_days = coalesce(nullif(p->>'terms_days','')::int, 30), active = coalesce((p->>'active')::boolean, active), note = coalesce(p->>'note','')
    where tenant_id = t and acc.parties.id = v_id;
    if not found then raise exception 'الطرف غير موجود'; end if;
    perform app.audit('update','party',v_id::text,'تعديل ' || (p->>'name'));
  end if;
  return jsonb_build_object('id', v_id, 'code', (select code from acc.parties where tenant_id = t and acc.parties.id = v_id));
end $$;

create or replace function public.party_delete(p jsonb) returns jsonb language plpgsql security definer set search_path = public, app, acc as $$
declare t uuid := app.need('parties','delete'); v_id uuid := (p->>'id')::uuid;
begin
  if exists (select 1 from acc.journal_lines where tenant_id = t and party_id = v_id limit 1) or exists (select 1 from acc.invoices where tenant_id = t and party_id = v_id limit 1) or exists (select 1 from acc.payments where tenant_id = t and party_id = v_id limit 1)
  then raise exception 'للطرف حركات — أوقفه بدل الحذف'; end if;
  delete from acc.parties where tenant_id = t and acc.parties.id = v_id; perform app.audit('delete','party',v_id::text,'حذف طرف'); return jsonb_build_object('ok', true);
end $$;

create or replace function public.party_get(p jsonb) returns jsonb language plpgsql stable security definer set search_path = public, app, acc as $$
declare t uuid := app.need('parties','view'); r acc.parties;
begin
  select * into r from acc.parties where tenant_id = t and id = (p->>'id')::uuid; if r.id is null then raise exception 'الطرف غير موجود'; end if;
  return to_jsonb(r) || jsonb_build_object('attachments', coalesce((select jsonb_agg(jsonb_build_object('id', x.id, 'filename', x.filename, 'path', x.path, 'size', x.size)) from acc.attachments x where x.tenant_id = t and x.owner_type = 'party' and x.owner_id = r.id), '[]'::jsonb));
end $$;

-- ===== مراكز التكلفة والمشاريع =====
create or replace function public.dim_list(p jsonb default '{}') returns jsonb language plpgsql stable security definer set search_path = public, app, acc as $$
declare t uuid := app.need(null, null);
begin return coalesce((select jsonb_agg(to_jsonb(d) - 'tenant_id' order by d.kind, d.code) from acc.dims d where d.tenant_id = t and (nullif(p->>'kind','') is null or d.kind = p->>'kind')), '[]'::jsonb); end $$;
create or replace function public.dim_upsert(p jsonb) returns jsonb language plpgsql security definer set search_path = public, app, acc as $$
declare t uuid; v_id uuid := nullif(p->>'id','')::uuid;
begin
  t := app.need('costcenters', case when v_id is null then 'add' else 'edit' end);
  if p->>'kind' not in ('cc','project') or coalesce(trim(p->>'code'),'') = '' or coalesce(trim(p->>'name'),'') = '' then raise exception 'النوع والرمز والاسم مطلوبة'; end if;
  if v_id is null then v_id := gen_random_uuid();
    insert into acc.dims (tenant_id, id, kind, code, name, parent_id, note) values (t, v_id, p->>'kind', trim(p->>'code'), trim(p->>'name'), nullif(p->>'parent_id','')::uuid, coalesce(p->>'note',''));
  else update acc.dims set code = trim(p->>'code'), name = trim(p->>'name'), parent_id = nullif(p->>'parent_id','')::uuid, active = coalesce((p->>'active')::boolean, active), note = coalesce(p->>'note','') where tenant_id = t and acc.dims.id = v_id; end if;
  perform app.audit('upsert','dim',v_id::text,(p->>'code') || ' ' || (p->>'name')); return jsonb_build_object('id', v_id);
end $$;
create or replace function public.dim_delete(p jsonb) returns jsonb language plpgsql security definer set search_path = public, app, acc as $$
declare t uuid := app.need('costcenters','delete'); v_id uuid := (p->>'id')::uuid;
begin
  if exists (select 1 from acc.journal_lines where tenant_id = t and (cost_center_id = v_id or project_id = v_id) limit 1) then raise exception 'عليه حركات — أوقفه بدل الحذف'; end if;
  delete from acc.dims where tenant_id = t and acc.dims.id = v_id; return jsonb_build_object('ok', true);
end $$;

-- ===== رموز الضريبة =====
create or replace function public.tax_list(p jsonb default '{}') returns jsonb language plpgsql stable security definer set search_path = public, app, acc as $$
declare t uuid := app.need(null, null);
begin return coalesce((select jsonb_agg(jsonb_build_object('code', c.code, 'name', c.name, 'rate', c.rate, 'kind', c.kind, 'account_id', c.account_id, 'active', c.active) order by c.code) from acc.tax_codes c where c.tenant_id = t), '[]'::jsonb); end $$;
create or replace function public.tax_upsert(p jsonb) returns jsonb language plpgsql security definer set search_path = public, app, acc as $$
declare t uuid := app.need_sys('settings'); acct uuid := nullif(p->>'account_id','')::uuid;
begin
  if (p->>'kind') not in ('output','input','zero_out','zero_in','exempt','oos') then raise exception 'نوع رمز الضريبة غير صالح'; end if;
  if (p->>'kind') in ('output','input') and acct is null then raise exception 'حدّد حساب الضريبة'; end if;
  insert into acc.tax_codes (tenant_id, code, name, rate, kind, account_id, active) values (t, trim(p->>'code'), trim(p->>'name'), coalesce(nullif(p->>'rate','')::numeric, 0), p->>'kind', acct, coalesce((p->>'active')::boolean, true))
  on conflict (tenant_id, code) do update set name = excluded.name, rate = excluded.rate, kind = excluded.kind, account_id = excluded.account_id, active = excluded.active;
  perform app.audit('upsert','tax',p->>'code', 'رمز ضريبة ' || (p->>'code') || ' ' || coalesce(p->>'rate','0') || '%'); return jsonb_build_object('ok', true);
end $$;

-- ===== الفواتير =====
create or replace function app.inv_module(k text) returns text language sql immutable as $$ select case when k in ('sales','sales_credit') then 'sales' else 'purchases' end $$;
create or replace function app.inv_paid(t uuid, inv uuid) returns numeric language sql stable security definer set search_path = public, acc as $$
  select coalesce(sum(amount), 0) from acc.allocations where tenant_id = t and invoice_id = inv and active $$;

create or replace function public.inv_save(p jsonb) returns jsonb language plpgsql security definer set search_path = public, app, acc as $$
declare t uuid; v_id uuid := nullif(p->>'id','')::uuid; e uuid := nullif(p->>'entity','')::uuid; k text := p->>'kind'; inv acc.invoices; pid uuid := nullif(p->>'party','')::uuid; pr acc.parties; d date := nullif(p->>'date','')::date;
  l jsonb; i int := 0; aid uuid; tc acc.tax_codes; q numeric; up numeric; dc numeric; net numeric; tx numeric; sub numeric := 0; disc numeric := 0; taxt numeric := 0; fx numeric := coalesce(nullif(p->>'rate','')::numeric, 1); cur text; tcode text; defk text;
begin
  if k not in ('sales','purchase','sales_credit','purchase_debit') then raise exception 'نوع الفاتورة غير صالح'; end if;
  t := app.need(app.inv_module(k), case when v_id is null then 'add' else 'edit' end);
  if d is null then raise exception 'تاريخ الفاتورة مطلوب'; end if;
  select * into pr from acc.parties where tenant_id = t and id = pid; if pr.id is null then raise exception 'اختر العميل/المورد'; end if;
  if not pr.active then raise exception 'الطرف موقوف'; end if;
  if k in ('sales','sales_credit') and pr.kind not in ('customer','both') then raise exception 'الطرف المحدد ليس عميلًا'; end if;
  if k in ('purchase','purchase_debit') and pr.kind not in ('supplier','both') then raise exception 'الطرف المحدد ليس موردًا'; end if;
  select currency into cur from acc.tenants x where x.id = t;
  if v_id is not null then
    select * into inv from acc.invoices where tenant_id = t and acc.invoices.id = v_id for update;
    if inv.id is null then raise exception 'الفاتورة غير موجودة'; end if; perform app.entity_ok(t, inv.entity_id);
    if inv.status <> 'draft' then raise exception 'تُعدَّل المسودات فقط'; end if; e := inv.entity_id; k := inv.kind;
    delete from acc.invoice_lines where tenant_id = t and invoice_id = v_id;
  else perform app.entity_ok(t, e); v_id := gen_random_uuid();
    insert into acc.invoices (tenant_id, id, entity_id, kind, party_id, date, currency, created_by) values (t, v_id, e, k, pid, d, cur, auth.uid()); end if;
  defk := case when k in ('sales','sales_credit') then 'SALES' else 'PURCHASES' end;
  for l in select * from jsonb_array_elements(coalesce(p->'lines','[]'::jsonb)) loop
    i := i + 1; q := coalesce(nullif(l->>'qty','')::numeric, 1); up := coalesce(nullif(l->>'unit_price','')::numeric, 0); dc := coalesce(nullif(l->>'discount','')::numeric, 0);
    if q <= 0 or up < 0 or dc < 0 or dc > q * up then raise exception 'السطر %: كمية/سعر/خصم غير صالح', i; end if;
    aid := coalesce(app.acct_id(t, nullif(l->>'account','')), app.acct_id(t, nullif(l->>'account_code','')), app.acct_id(t, (select code from acc.accounts where tenant_id = t and system_key = defk)));
    if aid is null then raise exception 'السطر %: حدّد الحساب (أو اربط الحساب الافتراضي %)', i, defk; end if;
    tcode := nullif(l->>'tax_code','');
    net := round(q * up - dc, 2); tx := 0;
    if tcode is not null then
      select * into tc from acc.tax_codes where tenant_id = t and code = tcode and active; if tc.code is null then raise exception 'السطر %: رمز الضريبة غير موجود', i; end if;
      if k in ('sales','sales_credit') and tc.kind not in ('output','zero_out','exempt','oos') then raise exception 'السطر %: رمز ضريبة مشتريات على فاتورة مبيعات', i; end if;
      if k in ('purchase','purchase_debit') and tc.kind not in ('input','zero_in','exempt','oos') then raise exception 'السطر %: رمز ضريبة مبيعات على فاتورة مشتريات', i; end if;
      tx := round(net * tc.rate / 100, 2);
    end if;
    perform app.line_dim_ok(t, nullif(l->>'cost_center','')::uuid, 'cc'); perform app.line_dim_ok(t, nullif(l->>'project','')::uuid, 'project');
    insert into acc.invoice_lines (tenant_id, invoice_id, line_no, description, qty, unit_price, discount, tax_code, account_id, cost_center_id, project_id, net, tax)
    values (t, v_id, i, coalesce(l->>'description',''), q, up, dc, tcode, aid, nullif(l->>'cost_center','')::uuid, nullif(l->>'project','')::uuid, net, tx);
    sub := sub + net; taxt := taxt + tx; disc := disc + dc;
  end loop;
  if i = 0 then raise exception 'أضف بندًا واحدًا على الأقل'; end if;
  update acc.invoices set party_id = pid, date = d, due_date = coalesce(nullif(p->>'due_date','')::date, d + pr.terms_days), supplier_ref = coalesce(trim(p->>'supplier_ref'), ''), currency = coalesce(nullif(p->>'currency',''), cur), rate = case when coalesce(nullif(p->>'currency',''), cur) = cur then 1 else fx end,
    subtotal = sub, discount_total = disc, tax_total = taxt, total = sub + taxt, notes = coalesce(p->>'notes',''), terms = coalesce(p->>'terms',''), related_id = nullif(p->>'related_id','')::uuid, updated_at = now() where tenant_id = t and acc.invoices.id = v_id;
  perform app.audit('save','invoice',v_id::text,'مسودة فاتورة (' || k || ') ' || pr.name || ' — ' || (sub + taxt));
  return jsonb_build_object('id', v_id, 'total', sub + taxt);
end $$;

-- بناء القيد المرحّل للفاتورة
create or replace function app.inv_post(inv_id uuid) returns acc.journals language plpgsql security definer set search_path = public, app, acc as $$
declare t uuid := app.tenant(); inv acc.invoices; jid uuid := gen_random_uuid(); ty text; sale boolean; credit boolean; ctl uuid; fx numeric; lines jsonb := '[]'::jsonb; r record; amt numeric; tot numeric := 0; j acc.journals; vat uuid; dirn text; sg int;
begin
  select * into inv from acc.invoices where tenant_id = t and id = inv_id for update;
  sale := inv.kind in ('sales','sales_credit'); credit := inv.kind in ('sales_credit','purchase_debit'); fx := inv.rate;
  ty := case inv.kind when 'sales' then 'SI' when 'purchase' then 'PI' when 'sales_credit' then 'SC' else 'PD' end;
  ctl := app.sysacct(t, case when sale then 'AR' else 'AP' end);
  insert into acc.journals (tenant_id, id, entity_id, type, date, description, reference, status, source, source_id, created_by)
  values (t, jid, inv.entity_id, ty, inv.date, (case inv.kind when 'sales' then 'فاتورة مبيعات' when 'purchase' then 'فاتورة مشتريات' when 'sales_credit' then 'إشعار دائن' else 'إشعار مدين' end) || ' — ' || (select name from acc.parties where tenant_id = t and id = inv.party_id), inv.supplier_ref, 'draft', 'invoice', inv.id, auth.uid());
  -- بنود الإيراد/المصروف
  for r in select account_id, cost_center_id, project_id, sum(net) net from acc.invoice_lines where tenant_id = t and invoice_id = inv.id group by 1, 2, 3 order by 1 loop
    amt := round(r.net * fx, 2); if amt = 0 then continue; end if;
    lines := lines || jsonb_build_object('account', r.account_id, 'cost_center', r.cost_center_id, 'project', r.project_id, case when (sale and not credit) or (not sale and credit) then 'credit' else 'debit' end, amt, 'description', 'بنود ' || case when sale then 'المبيعات' else 'المشتريات' end);
    tot := tot + case when (sale and not credit) or (not sale and credit) then amt else amt end;
  end loop;
  -- الضريبة
  for r in select l.tax_code, c.kind, c.account_id, sum(l.tax) tx, sum(l.net) base from acc.invoice_lines l join acc.tax_codes c on c.tenant_id = l.tenant_id and c.code = l.tax_code where l.tenant_id = t and l.invoice_id = inv.id and l.tax_code is not null group by 1, 2, 3 loop
    amt := round(r.tx * fx, 2);
    if amt > 0 then
      vat := coalesce(r.account_id, app.sysacct(t, case when sale then 'VAT_OUT' else 'VAT_IN' end));
      lines := lines || jsonb_build_object('account', vat, case when (sale and not credit) or (not sale and credit) then 'credit' else 'debit' end, amt, 'description', 'ضريبة ' || r.tax_code);
      tot := tot + amt;
    end if;
  end loop;
  -- حساب الذمم (طرف مقابل)
  lines := lines || jsonb_build_object('account', ctl, 'party', inv.party_id, case when (sale and not credit) or (not sale and credit) then 'debit' else 'credit' end, tot, 'due_date', inv.due_date,
    'currency', case when inv.rate <> 1 then inv.currency end, 'fc_amount', case when inv.rate <> 1 then inv.total end, 'rate', case when inv.rate <> 1 then inv.rate end, 'description', 'ذمم ' || coalesce(inv.supplier_ref,''));
  perform app.put_lines(t, jid, inv.entity_id, inv.date, lines);
  j := app.post_journal(jid);
  -- أساس الإقرار الضريبي
  sg := case when credit then -1 else 1 end; dirn := case when sale then 'out' else 'in' end;
  for r in select l.tax_code, c.kind, sum(l.net) base, sum(l.tax) tx from acc.invoice_lines l join acc.tax_codes c on c.tenant_id = l.tenant_id and c.code = l.tax_code where l.tenant_id = t and l.invoice_id = inv.id and l.tax_code is not null and c.kind <> 'oos' group by 1, 2 loop
    insert into acc.tax_lines (tenant_id, entity_id, journal_id, date, tax_code, direction, base, tax, party_id, doc_type, doc_id)
    values (t, inv.entity_id, j.id, inv.date, r.tax_code, dirn, sg * round(r.base * fx, 2), sg * round(r.tx * fx, 2), inv.party_id, 'invoice', inv.id);
  end loop;
  update acc.invoices set total_base = tot, journal_id = j.id, number = j.number, status = 'issued', issued_by = auth.uid(), issued_at = now(), updated_at = now() where tenant_id = t and id = inv.id;
  return j;
end $$;

create or replace function public.inv_issue(p jsonb) returns jsonb language plpgsql security definer set search_path = public, app, acc as $$
declare t uuid; inv acc.invoices; pol jsonb := app.policy('invoices'); j acc.journals; lim numeric; pr acc.parties; bal numeric;
begin
  select * into inv from acc.invoices where tenant_id = app.tenant() and id = (p->>'id')::uuid for update; if inv.id is null then raise exception 'الفاتورة غير موجودة'; end if;
  t := app.need(app.inv_module(inv.kind), 'post'); perform app.entity_ok(t, inv.entity_id);
  if inv.status not in ('draft','pending','approved') then raise exception 'الفاتورة صادرة مسبقًا أو ملغاة'; end if;
  if (pol->>'required')::boolean and inv.total >= (pol->>'threshold')::numeric and inv.status <> 'approved' then raise exception 'الفاتورة تتطلب اعتمادًا قبل الإصدار'; end if;
  if inv.total <= 0 then raise exception 'إجمالي الفاتورة يجب أن يكون أكبر من صفر'; end if;
  if inv.status = 'draft' then perform app.need_attach(t, case when inv.kind like 'purchase%' then 'purchase' else 'sales' end, 'invoice', inv.id, inv.total, 'صورة فاتورة المورد أو العقد/أمر التوريد'); end if;
  -- حد ائتمان العميل (تحذير نظامي: يمنع الإصدار إذا تجاوز ما لم يملك المستخدم صلاحية الاعتماد)
  if inv.kind = 'sales' then
    select * into pr from acc.parties where tenant_id = t and id = inv.party_id;
    if pr.credit_limit > 0 then
      select coalesce(sum(l.debit - l.credit), 0) into bal from acc.journal_lines l join acc.accounts a on a.tenant_id = l.tenant_id and a.id = l.account_id where l.tenant_id = t and l.posted and l.party_id = pr.id and a.subtype = 'receivable';
      if bal + inv.total > pr.credit_limit and not app.can('sales','approve') then raise exception 'تجاوز حد الائتمان للعميل (% + % > %) — يلزم اعتماد', bal, inv.total, pr.credit_limit; end if;
    end if;
  end if;
  j := app.inv_post(inv.id);
  perform app.audit('issue','invoice',inv.id::text,'إصدار ' || j.number || ' — ' || inv.total);
  return jsonb_build_object('number', j.number, 'journal_id', j.id);
end $$;

create or replace function public.inv_void(p jsonb) returns jsonb language plpgsql security definer set search_path = public, app, acc as $$
declare t uuid; inv acc.invoices; d date := coalesce(nullif(p->>'date','')::date, current_date); r acc.journals;
begin
  select * into inv from acc.invoices where tenant_id = app.tenant() and id = (p->>'id')::uuid for update; if inv.id is null then raise exception 'الفاتورة غير موجودة'; end if;
  t := app.need(app.inv_module(inv.kind), 'delete'); perform app.entity_ok(t, inv.entity_id);
  if coalesce(trim(p->>'reason'),'') = '' then raise exception 'سبب الإلغاء مطلوب'; end if;
  if inv.status = 'draft' or inv.status = 'pending' or inv.status = 'approved' then
    delete from acc.attachments where tenant_id = t and owner_type = 'invoice' and owner_id = inv.id;
    delete from acc.invoices where tenant_id = t and id = inv.id; perform app.audit('delete','invoice',inv.id::text,'حذف مسودة فاتورة'); return jsonb_build_object('deleted', true);
  end if;
  if inv.status <> 'issued' then raise exception 'الفاتورة ملغاة مسبقًا'; end if;
  if app.inv_paid(t, inv.id) > 0 then raise exception 'عليها تسويات (سدادات/إشعارات) — ألغِ التسويات أولًا أو أصدر إشعارًا دائنًا/مدينًا'; end if;
  if exists (select 1 from acc.invoices where tenant_id = t and related_id = inv.id and status = 'issued') then raise exception 'لها إشعارات صادرة — ألغِها أولًا'; end if;
  r := app.reverse_journal(inv.journal_id, d, trim(p->>'reason'));
  update acc.invoices set status = 'void', void_reason = trim(p->>'reason'), updated_at = now() where tenant_id = t and id = inv.id;
  perform app.audit('void','invoice',inv.id::text,'إلغاء ' || inv.number || ' بقيد ' || r.number || ': ' || trim(p->>'reason'));
  return jsonb_build_object('reversal', r.number);
end $$;

create or replace function public.inv_get(p jsonb) returns jsonb language plpgsql stable security definer set search_path = public, app, acc as $$
declare t uuid := app.need(null, null); inv acc.invoices; paid numeric;
begin
  select * into inv from acc.invoices where tenant_id = t and id = (p->>'id')::uuid; if inv.id is null then raise exception 'الفاتورة غير موجودة'; end if;
  if not app.can(app.inv_module(inv.kind), 'view') or not (inv.entity_id = any(app.ents())) then raise exception 'ليست لديك صلاحية'; end if;
  paid := app.inv_paid(t, inv.id);
  return to_jsonb(inv) || jsonb_build_object('paid', paid, 'balance', case when inv.status = 'issued' then inv.total_base - paid else 0 end,
    'party', (select jsonb_build_object('id', x.id, 'code', x.code, 'name', x.name, 'name_en', x.name_en, 'vat_no', x.vat_no, 'address', x.address, 'city', x.city, 'phone', x.phone) from acc.parties x where x.tenant_id = t and x.id = inv.party_id),
    'entity', (select jsonb_build_object('name', e.name, 'name_en', e.name_en, 'vat_no', e.vat_no, 'cr', e.cr, 'address', e.address) from acc.entities e where e.tenant_id = t and e.id = inv.entity_id),
    'journal_number', (select number from acc.journals where tenant_id = t and id = inv.journal_id),
    'created_by_name', (select name from acc.members where user_id = inv.created_by), 'issued_by_name', (select name from acc.members where user_id = inv.issued_by),
    'lines', coalesce((select jsonb_agg(jsonb_build_object('id', l.id, 'line_no', l.line_no, 'description', l.description, 'qty', l.qty, 'unit_price', l.unit_price, 'discount', l.discount, 'tax_code', l.tax_code, 'account_id', l.account_id,
        'account_name', a.code || ' - ' || a.name, 'cost_center_id', l.cost_center_id, 'project_id', l.project_id, 'net', l.net, 'tax', l.tax) order by l.line_no) from acc.invoice_lines l join acc.accounts a on a.tenant_id = l.tenant_id and a.id = l.account_id where l.tenant_id = t and l.invoice_id = inv.id), '[]'::jsonb),
    'allocations', coalesce((select jsonb_agg(jsonb_build_object('id', x.id, 'kind', x.source_kind, 'source_id', x.source_id, 'amount', x.amount, 'date', x.date,
        'number', case when x.source_kind = 'payment' then (select number from acc.payments where tenant_id = t and id = x.source_id) else (select number from acc.invoices where tenant_id = t and id = x.source_id) end) order by x.date) from acc.allocations x where x.tenant_id = t and x.invoice_id = inv.id and x.active), '[]'::jsonb),
    'attachments', coalesce((select jsonb_agg(jsonb_build_object('id', x.id, 'filename', x.filename, 'mime', x.mime, 'size', x.size, 'path', x.path, 'uploaded_at', x.uploaded_at)) from acc.attachments x where x.tenant_id = t and x.owner_type = 'invoice' and x.owner_id = inv.id), '[]'::jsonb),
    'history', coalesce((select jsonb_agg(jsonb_build_object('at', h.at, 'by', h.username, 'action', h.action, 'details', h.details) order by h.id) from acc.audit h where h.tenant_id = t and h.entity = 'invoice' and h.ref = inv.id::text), '[]'::jsonb));
end $$;

create or replace function public.inv_list(p jsonb default '{}') returns jsonb language plpgsql stable security definer set search_path = public, app, acc as $$
declare t uuid; ents uuid[] := app.pick_ents(p); lim int := least(coalesce(nullif(p->>'limit','')::int, 50), 500); off int := coalesce(nullif(p->>'offset','')::int, 0); q text := nullif(trim(coalesce(p->>'q','')), ''); k text := p->>'kind'; st text := nullif(p->>'status','');
begin
  t := app.need(case when k is null then null else app.inv_module(k) end, 'view');
  if k is null and not (app.can('sales','view') or app.can('purchases','view')) then raise exception 'ليست لديك صلاحية'; end if;
  return (select jsonb_build_object('total', coalesce(max(x.cnt), 0), 'rows', coalesce(jsonb_agg(jsonb_build_object('id', x.id, 'entity_id', x.entity_id, 'kind', x.kind, 'number', x.number, 'supplier_ref', x.supplier_ref, 'party_id', x.party_id, 'party_name', x.pname, 'date', x.date, 'due_date', x.due_date,
      'total', x.total, 'tax_total', x.tax_total, 'status', x.status, 'paid', x.paid, 'balance', case when x.status = 'issued' then x.total_base - x.paid else 0 end,
      'overdue_days', case when x.status = 'issued' and x.total_base - x.paid > 0 and x.due_date < current_date then current_date - x.due_date else 0 end) order by x.rn), '[]'::jsonb))
    from (select i.*, pa.name pname, app.inv_paid(t, i.id) paid, count(*) over() cnt, row_number() over (order by i.date desc, i.created_at desc, i.id) rn
      from acc.invoices i join acc.parties pa on pa.tenant_id = i.tenant_id and pa.id = i.party_id
      where i.tenant_id = t and i.entity_id = any(ents) and (k is null or i.kind = k) and (k is not null or app.can(app.inv_module(i.kind), 'view'))
        and (st is null or (st = 'open' and i.status = 'issued' and i.total_base > app.inv_paid(t, i.id)) or (st = 'paid' and i.status = 'issued' and i.total_base <= app.inv_paid(t, i.id)) or (st = 'overdue' and i.status = 'issued' and i.total_base > app.inv_paid(t, i.id) and i.due_date < current_date) or i.status = st)
        and (nullif(p->>'party','') is null or i.party_id = (p->>'party')::uuid) and (nullif(p->>'from','') is null or i.date >= (p->>'from')::date) and (nullif(p->>'to','') is null or i.date <= (p->>'to')::date)
        and (q is null or i.number ilike '%' || q || '%' or i.supplier_ref ilike '%' || q || '%' or pa.name ilike '%' || q || '%')
      order by i.date desc, i.created_at desc, i.id limit lim offset off) x);
end $$;

-- ===== التسويات (إشعار دائن/مدين على فاتورة) =====
create or replace function public.credit_apply(p jsonb) returns jsonb language plpgsql security definer set search_path = public, app, acc as $$
declare t uuid; cn acc.invoices; inv acc.invoices; amt numeric := (p->>'amount')::numeric; cn_left numeric; inv_left numeric; d date := coalesce(nullif(p->>'date','')::date, current_date);
begin
  select * into cn from acc.invoices where tenant_id = app.tenant() and id = (p->>'credit_id')::uuid for update;
  select * into inv from acc.invoices where tenant_id = app.tenant() and id = (p->>'invoice_id')::uuid for update;
  if cn.id is null or inv.id is null then raise exception 'المستند غير موجود'; end if;
  t := app.need(app.inv_module(cn.kind), 'post'); perform app.entity_ok(t, cn.entity_id);
  if cn.kind not in ('sales_credit','purchase_debit') or cn.status <> 'issued' then raise exception 'يجب اختيار إشعار صادر'; end if;
  if inv.status <> 'issued' or inv.party_id <> cn.party_id or inv.entity_id <> cn.entity_id or (cn.kind = 'sales_credit' and inv.kind <> 'sales') or (cn.kind = 'purchase_debit' and inv.kind <> 'purchase') then raise exception 'الفاتورة لا تطابق الإشعار (الطرف/النوع/الكيان)'; end if;
  if amt is null or amt <= 0 then raise exception 'المبلغ غير صالح'; end if;
  cn_left := cn.total_base - app.inv_paid(t, cn.id);
  inv_left := inv.total_base - app.inv_paid(t, inv.id);
  if amt > cn_left or amt > inv_left then raise exception 'المبلغ يتجاوز المتاح (الإشعار: %، الفاتورة: %)', cn_left, inv_left; end if;
  insert into acc.allocations (tenant_id, entity_id, source_kind, source_id, invoice_id, amount, date, active, created_by) values (t, cn.entity_id, 'credit', cn.id, inv.id, amt, d, true, auth.uid());
  -- يُغلق رصيد الإشعار بنفس القيمة (يُعامل كأنه مسدَّد)
  insert into acc.allocations (tenant_id, entity_id, source_kind, source_id, invoice_id, amount, date, active, created_by) values (t, cn.entity_id, 'credit', inv.id, cn.id, amt, d, true, auth.uid());
  perform app.audit('apply','invoice',inv.id::text,'تسوية ' || amt || ' من ' || cn.number); return jsonb_build_object('ok', true);
end $$;

-- ===== مسار الاعتماد العام للفواتير والسندات =====
create or replace function app.doc_transition(tbl text, doc uuid, action text, note text) returns text language plpgsql security definer set search_path = public, app, acc as $$
declare t uuid := app.tenant(); ent uuid; st text; cby uuid; sby uuid; tot numeric; kind text; modn text; pol jsonb; ns text; ok text;
begin
  if tbl not in ('invoices','payments') then raise exception 'مستند غير معروف'; end if;
  execute format('select entity_id, status, created_by, submitted_by, %s, kind from acc.%I where tenant_id = $1 and id = $2 for update', case when tbl = 'invoices' then 'total' else 'amount' end, tbl) into ent, st, cby, sby, tot, kind using t, doc;
  if ent is null then raise exception 'المستند غير موجود'; end if; perform app.entity_ok(t, ent);
  modn := case when tbl = 'payments' then 'payments' else app.inv_module(kind) end;
  pol := app.policy(tbl);
  if action = 'submit' then
    if not (app.can(modn, 'add') or app.can(modn, 'edit')) then raise exception 'ليست لديك صلاحية'; end if;
    if st <> 'draft' then raise exception 'يُرفع من المسودة فقط'; end if;
    perform app.need_attach(t, case when tbl = 'payments' then kind else case when kind like 'purchase%' then 'purchase' else 'sales' end end, case when tbl = 'payments' then 'payment' else 'invoice' end, doc, tot, case when tbl = 'payments' then 'إيصال/إشعار التحويل/الشيك' else 'صورة فاتورة المورد أو العقد/أمر التوريد' end);
    ns := case when (pol->>'required')::boolean and tot >= (pol->>'threshold')::numeric then 'pending' else 'approved' end;
    execute format('update acc.%I set status = $3, submitted_by = auth.uid(), submitted_at = now(), updated_at = now() where tenant_id = $1 and id = $2', tbl) using t, doc, ns;
  elsif action = 'approve' then
    if not app.can(modn, 'approve') then raise exception 'ليست لديك صلاحية الاعتماد'; end if;
    if st <> 'pending' then raise exception 'ليس بانتظار الاعتماد'; end if;
    if (pol->>'sod')::boolean and (cby = auth.uid() or sby = auth.uid()) then raise exception 'فصل المهام: لا يجوز اعتماد مستند أعددته أو رفعته بنفسك'; end if;
    ns := 'approved'; execute format('update acc.%I set status = $3, approved_by = auth.uid(), approved_at = now(), updated_at = now() where tenant_id = $1 and id = $2', tbl) using t, doc, ns;
  elsif action = 'reject' then
    if not app.can(modn, 'approve') then raise exception 'ليست لديك صلاحية'; end if;
    if st not in ('pending','approved') then raise exception 'لا يمكن الرفض'; end if;
    ns := 'draft'; execute format('update acc.%I set status = $3, updated_at = now() where tenant_id = $1 and id = $2', tbl) using t, doc, ns;
  else raise exception 'إجراء غير معروف'; end if;
  perform app.audit(action, case when tbl = 'invoices' then 'invoice' else 'payment' end, doc::text, action || coalesce(': ' || nullif(note, ''), ''));
  return ns;
end $$;
create or replace function public.inv_submit(p jsonb) returns jsonb language sql security definer set search_path = public, app, acc as $$ select jsonb_build_object('status', app.doc_transition('invoices', (p->>'id')::uuid, 'submit', p->>'note')) $$;
create or replace function public.inv_approve(p jsonb) returns jsonb language sql security definer set search_path = public, app, acc as $$ select jsonb_build_object('status', app.doc_transition('invoices', (p->>'id')::uuid, 'approve', p->>'note')) $$;
create or replace function public.inv_reject(p jsonb) returns jsonb language sql security definer set search_path = public, app, acc as $$ select jsonb_build_object('status', app.doc_transition('invoices', (p->>'id')::uuid, 'reject', p->>'note')) $$;
create or replace function public.pay_submit(p jsonb) returns jsonb language sql security definer set search_path = public, app, acc as $$ select jsonb_build_object('status', app.doc_transition('payments', (p->>'id')::uuid, 'submit', p->>'note')) $$;
create or replace function public.pay_approve(p jsonb) returns jsonb language sql security definer set search_path = public, app, acc as $$ select jsonb_build_object('status', app.doc_transition('payments', (p->>'id')::uuid, 'approve', p->>'note')) $$;
create or replace function public.pay_reject(p jsonb) returns jsonb language sql security definer set search_path = public, app, acc as $$ select jsonb_build_object('status', app.doc_transition('payments', (p->>'id')::uuid, 'reject', p->>'note')) $$;

-- ===== سندات القبض والصرف =====
create or replace function public.pay_save(p jsonb) returns jsonb language plpgsql security definer set search_path = public, app, acc as $$
declare t uuid; v_id uuid := nullif(p->>'id','')::uuid; e uuid := nullif(p->>'entity','')::uuid; k text := p->>'kind'; pay acc.payments; pid uuid := nullif(p->>'party','')::uuid; amt numeric := round((p->>'amount')::numeric, 2);
  l jsonb; i int := 0; alloc numeric := 0; direct numeric := 0; inv acc.invoices; aid uuid; tc acc.tax_codes; net numeric; tx numeric; ca acc.accounts; d date := nullif(p->>'date','')::date; onacc numeric;
begin
  if k not in ('receipt','payment') then raise exception 'نوع السند غير صالح'; end if;
  t := app.need('payments', case when v_id is null then 'add' else 'edit' end);
  if d is null or amt is null or amt <= 0 then raise exception 'التاريخ والمبلغ مطلوبان'; end if;
  select * into ca from acc.accounts where tenant_id = t and id = app.acct_id(t, coalesce(nullif(p->>'cash_account',''), '')); if ca.id is null or ca.subtype not in ('cash','bank','general') or ca.is_group or ca.type <> 'asset' then raise exception 'اختر حساب الصندوق/البنك'; end if;
  if pid is not null then perform app.line_party_ok(t, pid); end if;
  if v_id is not null then
    select * into pay from acc.payments where tenant_id = t and acc.payments.id = v_id for update; if pay.id is null then raise exception 'السند غير موجود'; end if; perform app.entity_ok(t, pay.entity_id);
    if pay.status <> 'draft' then raise exception 'تُعدَّل المسودات فقط'; end if; e := pay.entity_id; k := pay.kind;
    delete from acc.payment_lines where tenant_id = t and payment_id = v_id; delete from acc.allocations where tenant_id = t and source_kind = 'payment' and source_id = v_id;
  else perform app.entity_ok(t, e); v_id := gen_random_uuid();
    insert into acc.payments (tenant_id, id, entity_id, kind, date, cash_account_id, amount, created_by) values (t, v_id, e, k, d, ca.id, amt, auth.uid()); end if;
  for l in select * from jsonb_array_elements(coalesce(p->'allocations','[]'::jsonb)) loop
    if pid is null then raise exception 'حدّد الطرف لتسوية الفواتير'; end if;
    select * into inv from acc.invoices where tenant_id = t and id = (l->>'invoice')::uuid;
    if inv.id is null or inv.party_id <> pid or inv.entity_id <> e or inv.status <> 'issued' or (k = 'receipt' and inv.kind <> 'sales') or (k = 'payment' and inv.kind <> 'purchase') then raise exception 'فاتورة غير صالحة للتسوية'; end if;
    if (l->>'amount')::numeric <= 0 then raise exception 'مبلغ تسوية غير صالح'; end if;
    insert into acc.allocations (tenant_id, entity_id, source_kind, source_id, invoice_id, amount, date, active, created_by) values (t, e, 'payment', v_id, inv.id, round((l->>'amount')::numeric, 2), d, false, auth.uid());
    alloc := alloc + round((l->>'amount')::numeric, 2);
  end loop;
  for l in select * from jsonb_array_elements(coalesce(p->'lines','[]'::jsonb)) loop
    i := i + 1; aid := coalesce(app.acct_id(t, nullif(l->>'account','')), app.acct_id(t, nullif(l->>'account_code','')));
    if aid is null then raise exception 'بند %: الحساب غير موجود', i; end if;
    net := round((l->>'amount')::numeric, 2); tx := 0;
    if nullif(l->>'tax_code','') is not null then
      select * into tc from acc.tax_codes where tenant_id = t and code = l->>'tax_code' and active; if tc.code is null then raise exception 'بند %: رمز الضريبة غير موجود', i; end if;
      tx := round(net * tc.rate / 100, 2);
    end if;
    insert into acc.payment_lines (tenant_id, payment_id, line_no, account_id, description, amount, tax_code, tax, cost_center_id, project_id)
    values (t, v_id, i, aid, coalesce(l->>'description',''), net, nullif(l->>'tax_code',''), tx, nullif(l->>'cost_center','')::uuid, nullif(l->>'project','')::uuid);
    direct := direct + net + tx;
  end loop;
  onacc := amt - alloc - direct;
  if onacc < 0 then raise exception 'مجموع التسويات والبنود (%) يتجاوز مبلغ السند (%)', alloc + direct, amt; end if;
  if onacc > 0 and pid is null then raise exception 'المبلغ المتبقي % بلا طرف — حدّد العميل/المورد أو وزّعه على بنود', onacc; end if;
  update acc.payments set date = d, party_id = pid, method = coalesce(nullif(p->>'method',''), 'bank'), cash_account_id = ca.id, amount = amt, on_account = onacc, reference = coalesce(p->>'reference',''),
    cheque_no = coalesce(p->>'cheque_no',''), cheque_date = nullif(p->>'cheque_date','')::date, notes = coalesce(p->>'notes',''), updated_at = now() where tenant_id = t and acc.payments.id = v_id;
  perform app.audit('save','payment',v_id::text,'مسودة سند ' || k || ' — ' || amt);
  return jsonb_build_object('id', v_id, 'on_account', onacc);
end $$;

create or replace function public.pay_post(p jsonb) returns jsonb language plpgsql security definer set search_path = public, app, acc as $$
declare t uuid := app.need('payments','post'); pay acc.payments; pol jsonb := app.policy('payments'); jid uuid := gen_random_uuid(); lines jsonb := '[]'::jsonb; rcpt boolean; ctl uuid; r record; j acc.journals; a numeric; inv acc.invoices; ty text; party_amt numeric;
begin
  select * into pay from acc.payments where tenant_id = t and id = (p->>'id')::uuid for update; if pay.id is null then raise exception 'السند غير موجود'; end if; perform app.entity_ok(t, pay.entity_id);
  if pay.status not in ('draft','pending','approved') then raise exception 'السند مرحّل أو ملغى'; end if;
  if pay.status = 'draft' then perform app.need_attach(t, pay.kind, 'payment', pay.id, pay.amount, 'إيصال/إشعار التحويل/الشيك'); end if;
  if (pol->>'required')::boolean and pay.amount >= (pol->>'threshold')::numeric and pay.status <> 'approved' then raise exception 'السند يتطلب اعتمادًا قبل الترحيل'; end if;
  rcpt := pay.kind = 'receipt';
  -- إعادة التحقق من أرصدة الفواتير تحت القفل
  for r in select al.id, al.invoice_id, al.amount from acc.allocations al where al.tenant_id = t and al.source_kind = 'payment' and al.source_id = pay.id loop
    select * into inv from acc.invoices where tenant_id = t and id = r.invoice_id for update;
    if inv.status <> 'issued' or r.amount > inv.total_base - app.inv_paid(t, inv.id) then raise exception 'تسوية على الفاتورة % تتجاوز رصيدها المفتوح', inv.number; end if;
  end loop;
  -- جهة النقد
  lines := lines || jsonb_build_object('account', pay.cash_account_id, case when rcpt then 'debit' else 'credit' end, pay.amount, 'description', coalesce(nullif(pay.reference,''), 'سند'));
  party_amt := pay.amount - coalesce((select sum(amount + tax) from acc.payment_lines where tenant_id = t and payment_id = pay.id), 0);
  if party_amt > 0 then
    ctl := app.sysacct(t, case when rcpt then 'AR' else 'AP' end);
    lines := lines || jsonb_build_object('account', ctl, 'party', pay.party_id, case when rcpt then 'credit' else 'debit' end, party_amt, 'description', case when pay.on_account > 0 then 'سداد ودفعة على الحساب' else 'سداد' end);
  end if;
  for r in select l.account_id, l.description, l.amount, l.tax_code, l.tax, l.cost_center_id, l.project_id, c.account_id tax_acct from acc.payment_lines l left join acc.tax_codes c on c.tenant_id = l.tenant_id and c.code = l.tax_code where l.tenant_id = t and l.payment_id = pay.id order by l.line_no loop
    lines := lines || jsonb_build_object('account', r.account_id, 'cost_center', r.cost_center_id, 'project', r.project_id, case when rcpt then 'credit' else 'debit' end, r.amount, 'description', r.description);
    if r.tax > 0 then lines := lines || jsonb_build_object('account', coalesce(r.tax_acct, app.sysacct(t, case when rcpt then 'VAT_OUT' else 'VAT_IN' end)), case when rcpt then 'credit' else 'debit' end, r.tax, 'description', 'ضريبة ' || r.tax_code); end if;
  end loop;
  ty := case when rcpt then 'RV' else 'PV' end;
  insert into acc.journals (tenant_id, id, entity_id, type, date, description, reference, status, source, source_id, created_by)
  values (t, jid, pay.entity_id, ty, pay.date, (case when rcpt then 'سند قبض' else 'سند صرف' end) || coalesce(' — ' || (select name from acc.parties where tenant_id = t and id = pay.party_id), ''), pay.reference, 'draft', 'payment', pay.id, auth.uid());
  perform app.put_lines(t, jid, pay.entity_id, pay.date, lines);
  j := app.post_journal(jid);
  insert into acc.tax_lines (tenant_id, entity_id, journal_id, date, tax_code, direction, base, tax, party_id, doc_type, doc_id)
  select t, pay.entity_id, j.id, pay.date, l.tax_code, case when rcpt then 'out' else 'in' end, l.amount, l.tax, pay.party_id, 'payment', pay.id from acc.payment_lines l where l.tenant_id = t and l.payment_id = pay.id and l.tax_code is not null;
  update acc.allocations set active = true where tenant_id = t and source_kind = 'payment' and source_id = pay.id;
  update acc.payments set status = 'posted', number = j.number, journal_id = j.id, posted_by = auth.uid(), posted_at = now(), updated_at = now() where tenant_id = t and id = pay.id;
  perform app.audit('post','payment',pay.id::text,'ترحيل ' || j.number || ' — ' || pay.amount);
  return jsonb_build_object('number', j.number, 'journal_id', j.id);
end $$;

create or replace function public.pay_void(p jsonb) returns jsonb language plpgsql security definer set search_path = public, app, acc as $$
declare t uuid := app.need('payments','delete'); pay acc.payments; d date := coalesce(nullif(p->>'date','')::date, current_date); r acc.journals;
begin
  select * into pay from acc.payments where tenant_id = t and id = (p->>'id')::uuid for update; if pay.id is null then raise exception 'السند غير موجود'; end if; perform app.entity_ok(t, pay.entity_id);
  if pay.status in ('draft','pending','approved') then
    delete from acc.allocations where tenant_id = t and source_kind = 'payment' and source_id = pay.id; delete from acc.attachments where tenant_id = t and owner_type = 'payment' and owner_id = pay.id;
    delete from acc.payments where tenant_id = t and id = pay.id; perform app.audit('delete','payment',pay.id::text,'حذف مسودة سند'); return jsonb_build_object('deleted', true);
  end if;
  if pay.status <> 'posted' then raise exception 'السند ملغى مسبقًا'; end if;
  if coalesce(trim(p->>'reason'),'') = '' then raise exception 'سبب الإلغاء مطلوب'; end if;
  if exists (select 1 from acc.journal_lines where tenant_id = t and journal_id = pay.journal_id and reconciled_id is not null) then raise exception 'السند مطابق مع كشف البنك — فكّ المطابقة أولًا'; end if;
  r := app.reverse_journal(pay.journal_id, d, trim(p->>'reason'));
  update acc.allocations set active = false where tenant_id = t and source_kind = 'payment' and source_id = pay.id;
  update acc.payments set status = 'void', void_reason = trim(p->>'reason'), updated_at = now() where tenant_id = t and id = pay.id;
  perform app.audit('void','payment',pay.id::text,'إلغاء ' || pay.number || ' بقيد ' || r.number || ': ' || trim(p->>'reason')); return jsonb_build_object('reversal', r.number);
end $$;

create or replace function public.pay_get(p jsonb) returns jsonb language plpgsql stable security definer set search_path = public, app, acc as $$
declare t uuid := app.need('payments','view'); pay acc.payments;
begin
  select * into pay from acc.payments where tenant_id = t and id = (p->>'id')::uuid; if pay.id is null or not (pay.entity_id = any(app.ents())) then raise exception 'السند غير موجود'; end if;
  return to_jsonb(pay) || jsonb_build_object('party', (select jsonb_build_object('id', x.id, 'code', x.code, 'name', x.name) from acc.parties x where x.tenant_id = t and x.id = pay.party_id),
    'cash_account', (select code || ' - ' || name from acc.accounts where tenant_id = t and id = pay.cash_account_id), 'journal_number', (select number from acc.journals where tenant_id = t and id = pay.journal_id),
    'entity', (select jsonb_build_object('name', e.name, 'name_en', e.name_en, 'vat_no', e.vat_no, 'address', e.address) from acc.entities e where e.tenant_id = t and e.id = pay.entity_id),
    'created_by_name', (select name from acc.members where user_id = pay.created_by),
    'allocations', coalesce((select jsonb_agg(jsonb_build_object('id', a.id, 'invoice_id', a.invoice_id, 'number', i.number, 'supplier_ref', i.supplier_ref, 'amount', a.amount) order by i.date) from acc.allocations a join acc.invoices i on i.tenant_id = a.tenant_id and i.id = a.invoice_id where a.tenant_id = t and a.source_kind = 'payment' and a.source_id = pay.id), '[]'::jsonb),
    'lines', coalesce((select jsonb_agg(jsonb_build_object('line_no', l.line_no, 'account_id', l.account_id, 'account_name', a.code || ' - ' || a.name, 'description', l.description, 'amount', l.amount, 'tax_code', l.tax_code, 'tax', l.tax, 'cost_center_id', l.cost_center_id, 'project_id', l.project_id) order by l.line_no)
      from acc.payment_lines l join acc.accounts a on a.tenant_id = l.tenant_id and a.id = l.account_id where l.tenant_id = t and l.payment_id = pay.id), '[]'::jsonb),
    'attachments', coalesce((select jsonb_agg(jsonb_build_object('id', x.id, 'filename', x.filename, 'mime', x.mime, 'size', x.size, 'path', x.path, 'uploaded_at', x.uploaded_at)) from acc.attachments x where x.tenant_id = t and x.owner_type = 'payment' and x.owner_id = pay.id), '[]'::jsonb),
    'history', coalesce((select jsonb_agg(jsonb_build_object('at', h.at, 'by', h.username, 'action', h.action, 'details', h.details) order by h.id) from acc.audit h where h.tenant_id = t and h.entity = 'payment' and h.ref = pay.id::text), '[]'::jsonb));
end $$;

create or replace function public.pay_list(p jsonb default '{}') returns jsonb language plpgsql stable security definer set search_path = public, app, acc as $$
declare t uuid := app.need('payments','view'); ents uuid[] := app.pick_ents(p); lim int := least(coalesce(nullif(p->>'limit','')::int, 50), 500); off int := coalesce(nullif(p->>'offset','')::int, 0); q text := nullif(trim(coalesce(p->>'q','')), '');
begin
  return (select jsonb_build_object('total', coalesce(max(x.cnt), 0), 'rows', coalesce(jsonb_agg(jsonb_build_object('id', x.id, 'entity_id', x.entity_id, 'kind', x.kind, 'number', x.number, 'date', x.date, 'party_id', x.party_id, 'party_name', x.pname, 'method', x.method,
      'amount', x.amount, 'on_account', x.on_account, 'status', x.status, 'reference', x.reference, 'cash_account', x.cname) order by x.rn), '[]'::jsonb))
    from (select y.*, pa.name pname, ca.name cname, count(*) over() cnt, row_number() over (order by y.date desc, y.created_at desc, y.id) rn from acc.payments y left join acc.parties pa on pa.tenant_id = y.tenant_id and pa.id = y.party_id join acc.accounts ca on ca.tenant_id = y.tenant_id and ca.id = y.cash_account_id
      where y.tenant_id = t and y.entity_id = any(ents) and (nullif(p->>'kind','') is null or y.kind = p->>'kind') and (nullif(p->>'status','') is null or y.status = p->>'status')
        and (nullif(p->>'party','') is null or y.party_id = (p->>'party')::uuid) and (nullif(p->>'from','') is null or y.date >= (p->>'from')::date) and (nullif(p->>'to','') is null or y.date <= (p->>'to')::date)
        and (q is null or y.number ilike '%' || q || '%' or y.reference ilike '%' || q || '%' or pa.name ilike '%' || q || '%') order by y.date desc, y.created_at desc, y.id limit lim offset off) x);
end $$;

-- الفواتير المفتوحة لطرف (لشاشة التسوية)
create or replace function public.open_invoices(p jsonb) returns jsonb language plpgsql stable security definer set search_path = public, app, acc as $$
declare t uuid := app.need(null, null); sale boolean := p->>'kind' = 'receipt';
begin
  if not app.can('payments','view') then raise exception 'ليست لديك صلاحية'; end if;
  return coalesce((select jsonb_agg(jsonb_build_object('id', i.id, 'number', i.number, 'supplier_ref', i.supplier_ref, 'date', i.date, 'due_date', i.due_date, 'total', i.total_base, 'balance', i.total_base - app.inv_paid(t, i.id)) order by i.date)
    from acc.invoices i where i.tenant_id = t and i.party_id = (p->>'party')::uuid and i.entity_id = (p->>'entity')::uuid and i.entity_id = any(app.ents()) and i.status = 'issued' and i.kind = case when sale then 'sales' else 'purchase' end and i.total_base > app.inv_paid(t, i.id)), '[]'::jsonb);
end $$;
-- ===== sql/007_reports.sql =====
-- مُحكَم للحسابات — التقارير والقوائم المالية (قراءة فقط، من الأستاذ المرحّل)

-- أرصدة الحسابات: افتتاحي قبل from، حركة بين from و to
create or replace function app.tb_rows(t uuid, ents uuid[], d_from date, d_to date, incl_cl boolean default true, cc uuid default null, pj uuid default null)
returns table (account_id uuid, opening numeric, debit numeric, credit numeric) language sql stable security definer set search_path = public, acc as $$
  select l.account_id,
    coalesce(sum(l.debit - l.credit) filter (where d_from is not null and l.date < d_from), 0),
    coalesce(sum(l.debit) filter (where (d_from is null or l.date >= d_from) and l.date <= d_to), 0),
    coalesce(sum(l.credit) filter (where (d_from is null or l.date >= d_from) and l.date <= d_to), 0)
  from acc.journal_lines l join acc.journals j on j.tenant_id = l.tenant_id and j.id = l.journal_id
  where l.tenant_id = t and l.posted and l.entity_id = any(ents) and l.date <= d_to
    and (incl_cl or not (j.type = 'CL' or exists (select 1 from acc.journals o where o.tenant_id = j.tenant_id and o.id = j.reversal_of and o.type = 'CL'))) and (cc is null or l.cost_center_id = cc) and (pj is null or l.project_id = pj)
  group by l.account_id $$;

-- تجميع الأرصدة صعودًا في الشجرة
create or replace function app.rollup(t uuid, base jsonb) returns table (account_id uuid, opening numeric, debit numeric, credit numeric) language sql stable security definer set search_path = public, acc as $$
  with recursive anc(id, a) as (select a.id, a.id from acc.accounts a where a.tenant_id = t union all select anc.id, p.parent_id from anc join acc.accounts p on p.tenant_id = t and p.id = anc.a where p.parent_id is not null),
  b as (select (x->>'account_id')::uuid id, (x->>'opening')::numeric o, (x->>'debit')::numeric d, (x->>'credit')::numeric c from jsonb_array_elements(base) x)
  select anc.a, sum(b.o), sum(b.d), sum(b.c) from anc join b on b.id = anc.id group by anc.a $$;

create or replace function public.rpt_trial_balance(p jsonb default '{}') returns jsonb language plpgsql stable security definer set search_path = public, app, acc as $$
declare t uuid := app.need('reports','view'); ents uuid[] := app.pick_ents(p); df date := nullif(p->>'from','')::date; dt date := coalesce(nullif(p->>'to','')::date, current_date); base jsonb; rows jsonb; zero boolean := coalesce((p->>'with_zero')::boolean, false);
  tot jsonb;
begin
  select coalesce(jsonb_agg(jsonb_build_object('account_id', r.account_id, 'opening', r.opening, 'debit', r.debit, 'credit', r.credit)), '[]') into base
    from app.tb_rows(t, ents, df, dt, true, nullif(p->>'cost_center','')::uuid, nullif(p->>'project','')::uuid) r;
  select coalesce(jsonb_agg(jsonb_build_object('id', a.id, 'code', a.code, 'name', a.name, 'name_en', a.name_en, 'type', a.type, 'is_group', a.is_group, 'parent_id', a.parent_id,
      'opening', r.opening, 'debit', r.debit, 'credit', r.credit, 'closing', r.opening + r.debit - r.credit) order by a.code), '[]') into rows
  from app.rollup(t, base) r join acc.accounts a on a.tenant_id = t and a.id = r.account_id
  where (zero or r.opening <> 0 or r.debit <> 0 or r.credit <> 0);
  -- المجاميع من الحسابات الورقية فقط (تجنب التكرار)
  select jsonb_build_object('opening', coalesce(sum(r.opening),0), 'debit', coalesce(sum(r.debit),0), 'credit', coalesce(sum(r.credit),0), 'closing', coalesce(sum(r.opening + r.debit - r.credit),0)) into tot from (select (x->>'opening')::numeric opening, (x->>'debit')::numeric debit, (x->>'credit')::numeric credit from jsonb_array_elements(base) x) r;
  return jsonb_build_object('rows', rows, 'totals', tot, 'from', df, 'to', dt);
end $$;

-- دفتر الأستاذ لحساب (أو طرف) مع رصيد جارٍ
create or replace function public.rpt_ledger(p jsonb) returns jsonb language plpgsql stable security definer set search_path = public, app, acc as $$
declare t uuid := app.need('reports','view'); ents uuid[] := app.pick_ents(p); a uuid := app.acct_id(t, nullif(p->>'account','')); pt uuid := nullif(p->>'party','')::uuid; df date := coalesce(nullif(p->>'from','')::date, date '1900-01-01'); dt date := coalesce(nullif(p->>'to','')::date, current_date);
  op numeric; lim int := least(coalesce(nullif(p->>'limit','')::int, 5000), 20000); rows jsonb;
begin
  if a is null and pt is null then raise exception 'حدّد الحساب أو الطرف'; end if;
  select coalesce(sum(l.debit - l.credit), 0) into op from acc.journal_lines l where l.tenant_id = t and l.posted and l.entity_id = any(ents) and l.date < df and (a is null or l.account_id = a) and (pt is null or l.party_id = pt);
  select coalesce(jsonb_agg(jsonb_build_object('date', x.date, 'journal_id', x.journal_id, 'number', x.number, 'type', x.type, 'description', coalesce(nullif(x.ldesc, ''), x.jdesc), 'reference', x.reference, 'account', x.acode, 'party', x.pname,
      'debit', x.debit, 'credit', x.credit, 'balance', op + x.run, 'source', x.source, 'source_id', x.source_id) order by x.date, x.chain_no, x.line_no), '[]') into rows
  from (select l.date, l.journal_id, j.number, j.type, l.description ldesc, j.description jdesc, j.reference, ac.code acode, pa.name pname, l.debit, l.credit, j.source, j.source_id, j.chain_no, l.line_no,
      sum(l.debit - l.credit) over (order by l.date, j.chain_no, l.line_no) run
    from acc.journal_lines l join acc.journals j on j.tenant_id = l.tenant_id and j.id = l.journal_id join acc.accounts ac on ac.tenant_id = l.tenant_id and ac.id = l.account_id left join acc.parties pa on pa.tenant_id = l.tenant_id and pa.id = l.party_id
    where l.tenant_id = t and l.posted and l.entity_id = any(ents) and l.date between df and dt and (a is null or l.account_id = a) and (pt is null or l.party_id = pt) order by l.date, j.chain_no, l.line_no limit lim) x;
  return jsonb_build_object('opening', op, 'rows', rows, 'closing', op + (select coalesce(sum(l.debit - l.credit), 0) from acc.journal_lines l where l.tenant_id = t and l.posted and l.entity_id = any(ents) and l.date between df and dt and (a is null or l.account_id = a) and (pt is null or l.party_id = pt)), 'truncated', jsonb_array_length(rows) >= lim);
end $$;

-- قائمة الدخل (مع مقارنة اختيارية بفترة أخرى). تستثني قيود الإقفال لتظهر بعد إقفال السنة.
create or replace function public.rpt_income(p jsonb default '{}') returns jsonb language plpgsql stable security definer set search_path = public, app, acc as $$
declare t uuid := app.need('reports','view'); ents uuid[] := app.pick_ents(p); df date := (p->>'from')::date; dt date := (p->>'to')::date; cf date := nullif(p->>'cmp_from','')::date; ct date := nullif(p->>'cmp_to','')::date; cc uuid := nullif(p->>'cost_center','')::uuid; pj uuid := nullif(p->>'project','')::uuid;
  base jsonb; cbase jsonb; rows jsonb;
begin
  if df is null or dt is null then raise exception 'حدّد الفترة'; end if;
  select coalesce(jsonb_agg(jsonb_build_object('account_id', r.account_id, 'opening', 0, 'debit', r.debit, 'credit', r.credit)), '[]') into base from app.tb_rows(t, ents, df, dt, false, cc, pj) r where r.debit <> 0 or r.credit <> 0;
  if cf is not null and ct is not null then select coalesce(jsonb_agg(jsonb_build_object('account_id', r.account_id, 'opening', 0, 'debit', r.debit, 'credit', r.credit)), '[]') into cbase from app.tb_rows(t, ents, cf, ct, false, cc, pj) r where r.debit <> 0 or r.credit <> 0; else cbase := '[]'; end if;
  select coalesce(jsonb_agg(jsonb_build_object('id', a.id, 'code', a.code, 'name', a.name, 'name_en', a.name_en, 'type', a.type, 'subtype', a.subtype, 'is_group', a.is_group, 'parent_id', a.parent_id,
      'amount', case when a.type = 'revenue' then coalesce(r.credit - r.debit, 0) else coalesce(r.debit - r.credit, 0) end,
      'cmp', case when a.type = 'revenue' then coalesce(c.credit - c.debit, 0) else coalesce(c.debit - c.credit, 0) end) order by a.code), '[]') into rows
  from acc.accounts a left join app.rollup(t, base) r on r.account_id = a.id left join app.rollup(t, cbase) c on c.account_id = a.id
  where a.tenant_id = t and a.type in ('revenue','expense') and (r.account_id is not null or c.account_id is not null);
  return jsonb_build_object('rows', rows, 'from', df, 'to', dt, 'cmp_from', cf, 'cmp_to', ct, 'revenue', (select coalesce(sum(case when a.type='revenue' then (x->>'credit')::numeric - (x->>'debit')::numeric end), 0) from jsonb_array_elements(base) x join acc.accounts a on a.tenant_id = t and a.id = (x->>'account_id')::uuid),
    'expense', (select coalesce(sum(case when a.type='expense' then (x->>'debit')::numeric - (x->>'credit')::numeric end), 0) from jsonb_array_elements(base) x join acc.accounts a on a.tenant_id = t and a.id = (x->>'account_id')::uuid),
    'cmp_revenue', (select coalesce(sum(case when a.type='revenue' then (x->>'credit')::numeric - (x->>'debit')::numeric end), 0) from jsonb_array_elements(cbase) x join acc.accounts a on a.tenant_id = t and a.id = (x->>'account_id')::uuid),
    'cmp_expense', (select coalesce(sum(case when a.type='expense' then (x->>'debit')::numeric - (x->>'credit')::numeric end), 0) from jsonb_array_elements(cbase) x join acc.accounts a on a.tenant_id = t and a.id = (x->>'account_id')::uuid));
end $$;

-- المركز المالي في تاريخ معيّن (الأرباح غير المقفلة تُضاف لحقوق الملكية كبند مستقل)
create or replace function public.rpt_balance_sheet(p jsonb default '{}') returns jsonb language plpgsql stable security definer set search_path = public, app, acc as $$
declare t uuid := app.need('reports','view'); ents uuid[] := app.pick_ents(p); dt date := coalesce(nullif(p->>'asof','')::date, current_date); cd date := nullif(p->>'cmp_asof','')::date; base jsonb; cbase jsonb; rows jsonb; ni numeric; cni numeric;
begin
  select coalesce(jsonb_agg(jsonb_build_object('account_id', r.account_id, 'opening', 0, 'debit', r.debit, 'credit', r.credit)), '[]') into base from app.tb_rows(t, ents, null, dt, true) r where r.debit <> r.credit;
  if cd is not null then select coalesce(jsonb_agg(jsonb_build_object('account_id', r.account_id, 'opening', 0, 'debit', r.debit, 'credit', r.credit)), '[]') into cbase from app.tb_rows(t, ents, null, cd, true) r where r.debit <> r.credit; else cbase := '[]'; end if;
  select coalesce(sum(case when a.type in ('revenue','expense') then (x->>'credit')::numeric - (x->>'debit')::numeric end), 0) into ni from jsonb_array_elements(base) x join acc.accounts a on a.tenant_id = t and a.id = (x->>'account_id')::uuid;
  select coalesce(sum(case when a.type in ('revenue','expense') then (x->>'credit')::numeric - (x->>'debit')::numeric end), 0) into cni from jsonb_array_elements(cbase) x join acc.accounts a on a.tenant_id = t and a.id = (x->>'account_id')::uuid;
  select coalesce(jsonb_agg(jsonb_build_object('id', a.id, 'code', a.code, 'name', a.name, 'name_en', a.name_en, 'type', a.type, 'subtype', a.subtype, 'is_group', a.is_group, 'parent_id', a.parent_id,
      'amount', case when a.type = 'asset' then coalesce(r.debit - r.credit, 0) else coalesce(r.credit - r.debit, 0) end,
      'cmp', case when a.type = 'asset' then coalesce(c.debit - c.credit, 0) else coalesce(c.credit - c.debit, 0) end) order by a.code), '[]') into rows
  from acc.accounts a left join app.rollup(t, base) r on r.account_id = a.id left join app.rollup(t, cbase) c on c.account_id = a.id
  where a.tenant_id = t and a.type in ('asset','liability','equity') and (r.account_id is not null or c.account_id is not null);
  return jsonb_build_object('rows', rows, 'asof', dt, 'cmp_asof', cd, 'unclosed_income', ni, 'cmp_unclosed_income', cni,
    'assets', (select coalesce(sum((x->>'debit')::numeric - (x->>'credit')::numeric), 0) from jsonb_array_elements(base) x join acc.accounts a on a.tenant_id = t and a.id = (x->>'account_id')::uuid where a.type = 'asset'),
    'liabilities', (select coalesce(sum((x->>'credit')::numeric - (x->>'debit')::numeric), 0) from jsonb_array_elements(base) x join acc.accounts a on a.tenant_id = t and a.id = (x->>'account_id')::uuid where a.type = 'liability'),
    'equity', (select coalesce(sum((x->>'credit')::numeric - (x->>'debit')::numeric), 0) from jsonb_array_elements(base) x join acc.accounts a on a.tenant_id = t and a.id = (x->>'account_id')::uuid where a.type = 'equity') + ni,
    'cmp_assets', (select coalesce(sum((x->>'debit')::numeric - (x->>'credit')::numeric), 0) from jsonb_array_elements(cbase) x join acc.accounts a on a.tenant_id = t and a.id = (x->>'account_id')::uuid where a.type = 'asset'),
    'cmp_liabilities', (select coalesce(sum((x->>'credit')::numeric - (x->>'debit')::numeric), 0) from jsonb_array_elements(cbase) x join acc.accounts a on a.tenant_id = t and a.id = (x->>'account_id')::uuid where a.type = 'liability'),
    'cmp_equity', (select coalesce(sum((x->>'credit')::numeric - (x->>'debit')::numeric), 0) from jsonb_array_elements(cbase) x join acc.accounts a on a.tenant_id = t and a.id = (x->>'account_id')::uuid where a.type = 'equity') + cni);
end $$;

-- التدفقات النقدية (الطريقة المباشرة): حركة النقدية مصنفة حسب نوع الحساب المقابل
create or replace function public.rpt_cashflow(p jsonb default '{}') returns jsonb language plpgsql stable security definer set search_path = public, app, acc as $$
declare t uuid := app.need('reports','view'); ents uuid[] := app.pick_ents(p); df date := (p->>'from')::date; dt date := (p->>'to')::date; op numeric; cl numeric; rows jsonb;
begin
  if df is null or dt is null then raise exception 'حدّد الفترة'; end if;
  select coalesce(sum(l.debit - l.credit) filter (where l.date < df), 0), coalesce(sum(l.debit - l.credit), 0) into op, cl
    from acc.journal_lines l join acc.accounts a on a.tenant_id = l.tenant_id and a.id = l.account_id where l.tenant_id = t and l.posted and l.entity_id = any(ents) and l.date <= dt and a.subtype in ('cash','bank');
  select coalesce(jsonb_agg(jsonb_build_object('section', s.section, 'account_id', s.account_id, 'code', s.code, 'name', s.name, 'amount', s.amt) order by s.section, s.code), '[]') into rows
  from (select case when a.cf_class in ('investing','financing') then a.cf_class else 'operating' end section, a.id account_id, a.code, a.name, -sum(l.debit - l.credit) amt
    from acc.journal_lines l join acc.accounts a on a.tenant_id = l.tenant_id and a.id = l.account_id
    where l.tenant_id = t and l.posted and l.entity_id = any(ents) and l.date between df and dt and a.subtype not in ('cash','bank')
      and l.journal_id in (select l2.journal_id from acc.journal_lines l2 join acc.accounts a2 on a2.tenant_id = l2.tenant_id and a2.id = l2.account_id where l2.tenant_id = t and l2.posted and l2.entity_id = any(ents) and l2.date between df and dt and a2.subtype in ('cash','bank'))
    group by 1, 2, 3, 4 having sum(l.debit - l.credit) <> 0) s;
  return jsonb_build_object('opening_cash', op, 'closing_cash', cl, 'rows', rows, 'net_change', cl - op,
    'operating', (select coalesce(sum((r->>'amount')::numeric), 0) from jsonb_array_elements(rows) r where r->>'section' = 'operating'),
    'investing', (select coalesce(sum((r->>'amount')::numeric), 0) from jsonb_array_elements(rows) r where r->>'section' = 'investing'),
    'financing', (select coalesce(sum((r->>'amount')::numeric), 0) from jsonb_array_elements(rows) r where r->>'section' = 'financing'));
end $$;

-- أعمار الديون: مبنية على الفواتير المفتوحة + "غير مطبّق" (دفعات مقدمة/قيود يدوية) لتطابق الأستاذ
create or replace function public.rpt_aging(p jsonb) returns jsonb language plpgsql stable security definer set search_path = public, app, acc as $$
declare t uuid := app.need('reports','view'); ents uuid[] := app.pick_ents(p); sale boolean := coalesce(p->>'kind','ar') = 'ar'; asof date := coalesce(nullif(p->>'asof','')::date, current_date); rows jsonb;
begin
  select coalesce(jsonb_agg(jsonb_build_object('party_id', y.pid, 'code', y.pcode, 'name', y.pname, 'current', y.cur, 'd30', y.d30, 'd60', y.d60, 'd90', y.d90, 'd90p', y.d90p, 'unapplied', y.unapplied, 'total', y.gl) order by y.gl desc), '[]') into rows
  from (select pa.id pid, pa.code pcode, pa.name pname,
      coalesce(sum(o.bal) filter (where asof <= o.due), 0) cur, coalesce(sum(o.bal) filter (where asof - o.due between 1 and 30), 0) d30, coalesce(sum(o.bal) filter (where asof - o.due between 31 and 60), 0) d60,
      coalesce(sum(o.bal) filter (where asof - o.due between 61 and 90), 0) d90, coalesce(sum(o.bal) filter (where asof - o.due > 90), 0) d90p,
      g.gl - coalesce(sum(o.bal), 0) unapplied, g.gl
    from acc.parties pa
    join (select l.party_id, sum(case when sale then l.debit - l.credit else l.credit - l.debit end) gl from acc.journal_lines l join acc.accounts a on a.tenant_id = l.tenant_id and a.id = l.account_id
          where l.tenant_id = t and l.posted and l.entity_id = any(ents) and l.date <= asof and a.subtype = case when sale then 'receivable' else 'payable' end and l.party_id is not null group by 1 having sum(l.debit - l.credit) <> 0) g on g.party_id = pa.id
    left join (select i.party_id, coalesce(i.due_date, i.date) due, i.total_base - coalesce((select sum(al.amount) from acc.allocations al where al.tenant_id = t and al.invoice_id = i.id and al.active and al.date <= asof), 0) bal
          from acc.invoices i where i.tenant_id = t and i.entity_id = any(ents) and i.status = 'issued' and i.date <= asof and i.kind = case when sale then 'sales' else 'purchase' end) o on o.party_id = pa.id and o.bal > 0
    where pa.tenant_id = t group by pa.id, pa.code, pa.name, g.gl) y;
  return jsonb_build_object('rows', rows, 'asof', asof, 'kind', case when sale then 'ar' else 'ap' end);
end $$;

-- كشف حساب طرف (عميل/مورد)
create or replace function public.rpt_party_statement(p jsonb) returns jsonb language plpgsql stable security definer set search_path = public, app, acc as $$
begin
  perform app.need('reports','view');
  return public.rpt_ledger(jsonb_build_object('party', p->>'party', 'from', p->>'from', 'to', p->>'to', 'entities', p->'entities', 'entity', p->>'entity', 'account', p->>'account'));
end $$;

-- إقرار ضريبة القيمة المضافة
create or replace function public.rpt_vat(p jsonb) returns jsonb language plpgsql stable security definer set search_path = public, app, acc as $$
declare t uuid := app.need('tax','view'); ents uuid[] := app.pick_ents(p); df date := (p->>'from')::date; dt date := (p->>'to')::date; rows jsonb;
begin
  if df is null or dt is null then raise exception 'حدّد الفترة'; end if;
  select coalesce(jsonb_agg(jsonb_build_object('code', x.tax_code, 'name', c.name, 'rate', c.rate, 'kind', c.kind, 'direction', x.direction, 'base', x.base, 'tax', x.tax, 'count', x.n) order by x.direction desc, x.tax_code), '[]') into rows
  from (select tax_code, direction, sum(base) base, sum(tax) tax, count(*) n from acc.tax_lines where tenant_id = t and entity_id = any(ents) and date between df and dt group by 1, 2) x left join acc.tax_codes c on c.tenant_id = t and c.code = x.tax_code;
  return jsonb_build_object('rows', rows, 'from', df, 'to', dt,
    'output_base', (select coalesce(sum(base), 0) from acc.tax_lines where tenant_id = t and entity_id = any(ents) and date between df and dt and direction = 'out'),
    'output_tax', (select coalesce(sum(tax), 0) from acc.tax_lines where tenant_id = t and entity_id = any(ents) and date between df and dt and direction = 'out'),
    'input_base', (select coalesce(sum(base), 0) from acc.tax_lines where tenant_id = t and entity_id = any(ents) and date between df and dt and direction = 'in'),
    'input_tax', (select coalesce(sum(tax), 0) from acc.tax_lines where tenant_id = t and entity_id = any(ents) and date between df and dt and direction = 'in'),
    'net_payable', (select coalesce(sum(case when direction = 'out' then tax else -tax end), 0) from acc.tax_lines where tenant_id = t and entity_id = any(ents) and date between df and dt));
end $$;

-- ربحية مراكز التكلفة / المشاريع
create or replace function public.rpt_dim_pl(p jsonb) returns jsonb language plpgsql stable security definer set search_path = public, app, acc as $$
declare t uuid := app.need('reports','view'); ents uuid[] := app.pick_ents(p); df date := (p->>'from')::date; dt date := (p->>'to')::date; k text := coalesce(p->>'kind','cc');
begin
  return jsonb_build_object('rows', coalesce((select jsonb_agg(jsonb_build_object('id', d.id, 'code', d.code, 'name', d.name, 'revenue', coalesce(z.rev, 0), 'expense', coalesce(z.exp, 0), 'net', coalesce(z.rev, 0) - coalesce(z.exp, 0)) order by d.code)
    from acc.dims d left join (select case when k = 'cc' then l.cost_center_id else l.project_id end did, sum(case when a.type = 'revenue' then l.credit - l.debit else 0 end) rev, sum(case when a.type = 'expense' then l.debit - l.credit else 0 end) exp
      from acc.journal_lines l join acc.journals j on j.tenant_id = l.tenant_id and j.id = l.journal_id join acc.accounts a on a.tenant_id = l.tenant_id and a.id = l.account_id
      where l.tenant_id = t and l.posted and not (j.type = 'CL' or exists (select 1 from acc.journals o where o.tenant_id = j.tenant_id and o.id = j.reversal_of and o.type = 'CL')) and l.entity_id = any(ents) and l.date between df and dt and a.type in ('revenue','expense') group by 1) z on z.did = d.id where d.tenant_id = t and d.kind = k), '[]'));
end $$;
-- ===== sql/008_close_dash.sql =====
-- مُحكَم للحسابات — الإقفال السنوي وفتح السنة الجديدة، لوحة المؤشرات، الرقابة والاستثناءات

create or replace function public.fy_close(p jsonb) returns jsonb language plpgsql security definer set search_path = public, app, acc as $$
declare t uuid := app.need('periods','close'); fy acc.fiscal_years; jid uuid := gen_random_uuid(); lines jsonb := '[]'::jsonb; r record; net numeric := 0; re uuid; j acc.journals; nfy uuid; pend int; unp int;
begin
  select * into fy from acc.fiscal_years where tenant_id = t and id = (p->>'id')::uuid for update; if fy.id is null then raise exception 'السنة المالية غير موجودة'; end if;
  perform app.entity_ok(t, fy.entity_id);
  if fy.status = 'closed' then raise exception 'السنة مقفلة مسبقًا'; end if;
  if exists (select 1 from acc.fiscal_years where tenant_id = t and entity_id = fy.entity_id and end_date < fy.start_date and status = 'open') then raise exception 'أقفل السنوات السابقة أولًا'; end if;
  select count(*) into pend from acc.journals where tenant_id = t and entity_id = fy.entity_id and status in ('draft','pending','approved') and date between fy.start_date and fy.end_date;
  if pend > 0 then raise exception 'يوجد % قيد غير مرحّل في السنة — رحّلها أو احذفها قبل الإقفال', pend; end if;
  select count(*) into unp from acc.invoices where tenant_id = t and entity_id = fy.entity_id and status in ('draft','pending','approved') and date between fy.start_date and fy.end_date;
  select count(*) + unp into unp from acc.payments where tenant_id = t and entity_id = fy.entity_id and status in ('draft','pending','approved') and date between fy.start_date and fy.end_date;
  if unp > 0 then raise exception 'يوجد % فاتورة/سند غير مرحّل في السنة', unp; end if;
  re := app.sysacct(t, 'RE');
  -- تصفير الإيرادات والمصروفات إلى الأرباح المبقاة
  for r in select l.account_id, sum(l.debit - l.credit) bal from acc.journal_lines l join acc.accounts a on a.tenant_id = l.tenant_id and a.id = l.account_id
      where l.tenant_id = t and l.posted and l.entity_id = fy.entity_id and l.date between fy.start_date and fy.end_date and a.type in ('revenue','expense') group by 1 having sum(l.debit - l.credit) <> 0 loop
    lines := lines || jsonb_build_object('account', r.account_id, case when r.bal > 0 then 'credit' else 'debit' end, abs(r.bal), 'description', 'إقفال حساب النتيجة');
    net := net + r.bal;
  end loop;
  if jsonb_array_length(lines) > 0 then
    lines := lines || jsonb_build_object('account', re, case when net > 0 then 'debit' else 'credit' end, abs(net), 'description', case when net > 0 then 'صافي خسارة السنة' else 'صافي ربح السنة' end);
    insert into acc.journals (tenant_id, id, entity_id, type, date, description, status, source, source_id, created_by)
    values (t, jid, fy.entity_id, 'CL', fy.end_date, 'قيد إقفال ' || fy.name, 'draft', 'closing', fy.id, auth.uid());
    perform app.put_lines(t, jid, fy.entity_id, fy.end_date, lines);
    j := app.post_journal(jid);
  end if;
  update acc.periods set status = 'closed', changed_at = now(), changed_by = auth.uid() where tenant_id = t and fy_id = fy.id;
  update acc.fiscal_years set status = 'closed', closed_at = now(), closed_by = auth.uid(), closing_journal_id = j.id where tenant_id = t and id = fy.id;
  -- فتح السنة الجديدة تلقائيًا (الأرصدة الافتتاحية تنتقل بالاستمرارية في الأستاذ)
  select id into nfy from acc.fiscal_years where tenant_id = t and entity_id = fy.entity_id and start_date = fy.end_date + 1;
  if nfy is null then nfy := app.make_fy(t, fy.entity_id, fy.end_date + 1); end if;
  perform app.audit('close','fiscal_year',fy.id::text,'إقفال ' || fy.name || ' — صافي ' || (-net) || coalesce(' قيد ' || j.number, ''));
  return jsonb_build_object('net_income', -net, 'closing_journal', j.number, 'new_fy', nfy);
end $$;

create or replace function public.fy_reopen(p jsonb) returns jsonb language plpgsql security definer set search_path = public, app, acc as $$
declare t uuid := app.need('periods','reopen'); fy acc.fiscal_years; r acc.journals;
begin
  if coalesce(trim(p->>'reason'),'') = '' then raise exception 'سبب إعادة الفتح مطلوب'; end if;
  select * into fy from acc.fiscal_years where tenant_id = t and id = (p->>'id')::uuid for update; if fy.id is null then raise exception 'السنة غير موجودة'; end if;
  perform app.entity_ok(t, fy.entity_id);
  if fy.status <> 'closed' then raise exception 'السنة غير مقفلة'; end if;
  if exists (select 1 from acc.fiscal_years where tenant_id = t and entity_id = fy.entity_id and start_date > fy.start_date and status = 'closed') then raise exception 'توجد سنة لاحقة مقفلة — أعد فتحها أولًا'; end if;
  update acc.periods set status = 'open', changed_at = now(), changed_by = auth.uid() where tenant_id = t and fy_id = fy.id;
  if fy.closing_journal_id is not null then r := app.reverse_journal(fy.closing_journal_id, fy.end_date, 'إعادة فتح السنة: ' || trim(p->>'reason')); end if;
  update acc.fiscal_years set status = 'open', closed_at = null, closed_by = null, closing_journal_id = null where tenant_id = t and id = fy.id;
  perform app.audit('reopen','fiscal_year',fy.id::text,'إعادة فتح ' || fy.name || ': ' || trim(p->>'reason'));
  return jsonb_build_object('reversal', r.number);
end $$;

-- لوحة المؤشرات
create or replace function public.dashboard(p jsonb default '{}') returns jsonb language plpgsql stable security definer set search_path = public, app, acc as $$
declare t uuid := app.need('dashboard','view'); ents uuid[] := app.pick_ents(p); d date := current_date; ys date := date_trunc('year', d)::date; ms date := date_trunc('month', d)::date; res jsonb;
begin
  select jsonb_build_object(
    'cash', (select coalesce(sum(l.debit - l.credit), 0) from acc.journal_lines l join acc.accounts a on a.tenant_id = l.tenant_id and a.id = l.account_id where l.tenant_id = t and l.posted and l.entity_id = any(ents) and a.subtype in ('cash','bank')),
    'ar', (select coalesce(sum(l.debit - l.credit), 0) from acc.journal_lines l join acc.accounts a on a.tenant_id = l.tenant_id and a.id = l.account_id where l.tenant_id = t and l.posted and l.entity_id = any(ents) and a.subtype = 'receivable'),
    'ap', (select coalesce(sum(l.credit - l.debit), 0) from acc.journal_lines l join acc.accounts a on a.tenant_id = l.tenant_id and a.id = l.account_id where l.tenant_id = t and l.posted and l.entity_id = any(ents) and a.subtype = 'payable'),
    'revenue_ytd', (select coalesce(sum(l.credit - l.debit), 0) from acc.journal_lines l join acc.accounts a on a.tenant_id = l.tenant_id and a.id = l.account_id join acc.journals j on j.tenant_id = l.tenant_id and j.id = l.journal_id where l.tenant_id = t and l.posted and l.entity_id = any(ents) and l.date >= ys and a.type = 'revenue' and j.type <> 'CL'),
    'expense_ytd', (select coalesce(sum(l.debit - l.credit), 0) from acc.journal_lines l join acc.accounts a on a.tenant_id = l.tenant_id and a.id = l.account_id join acc.journals j on j.tenant_id = l.tenant_id and j.id = l.journal_id where l.tenant_id = t and l.posted and l.entity_id = any(ents) and l.date >= ys and a.type = 'expense' and j.type <> 'CL'),
    'revenue_mtd', (select coalesce(sum(l.credit - l.debit), 0) from acc.journal_lines l join acc.accounts a on a.tenant_id = l.tenant_id and a.id = l.account_id join acc.journals j on j.tenant_id = l.tenant_id and j.id = l.journal_id where l.tenant_id = t and l.posted and l.entity_id = any(ents) and l.date >= ms and a.type = 'revenue' and j.type <> 'CL'),
    'expense_mtd', (select coalesce(sum(l.debit - l.credit), 0) from acc.journal_lines l join acc.accounts a on a.tenant_id = l.tenant_id and a.id = l.account_id join acc.journals j on j.tenant_id = l.tenant_id and j.id = l.journal_id where l.tenant_id = t and l.posted and l.entity_id = any(ents) and l.date >= ms and a.type = 'expense' and j.type <> 'CL'),
    'overdue_ar', (select coalesce(sum(i.total_base - app.inv_paid(t, i.id)), 0) from acc.invoices i where i.tenant_id = t and i.entity_id = any(ents) and i.kind = 'sales' and i.status = 'issued' and i.due_date < d and i.total_base > app.inv_paid(t, i.id)),
    'due_ap_7d', (select coalesce(sum(i.total_base - app.inv_paid(t, i.id)), 0) from acc.invoices i where i.tenant_id = t and i.entity_id = any(ents) and i.kind = 'purchase' and i.status = 'issued' and i.due_date <= d + 7 and i.total_base > app.inv_paid(t, i.id)),
    'pending', jsonb_build_object('journals', (select count(*) from acc.journals where tenant_id = t and entity_id = any(ents) and status = 'pending'),
      'invoices', (select count(*) from acc.invoices where tenant_id = t and entity_id = any(ents) and status = 'pending'), 'payments', (select count(*) from acc.payments where tenant_id = t and entity_id = any(ents) and status = 'pending'),
      'drafts', (select count(*) from acc.journals where tenant_id = t and entity_id = any(ents) and status = 'draft')),
    'series', coalesce((select jsonb_agg(jsonb_build_object('month', to_char(m.ms, 'YYYY-MM'), 'revenue', coalesce(z.rev, 0), 'expense', coalesce(z.exp, 0)) order by m.ms)
      from generate_series(date_trunc('month', d) - interval '11 month', date_trunc('month', d), interval '1 month') m(ms)
      left join (select date_trunc('month', l.date)::date mm, sum(case when a.type = 'revenue' then l.credit - l.debit else 0 end) rev, sum(case when a.type = 'expense' then l.debit - l.credit else 0 end) exp
        from acc.journal_lines l join acc.accounts a on a.tenant_id = l.tenant_id and a.id = l.account_id join acc.journals j on j.tenant_id = l.tenant_id and j.id = l.journal_id
        where l.tenant_id = t and l.posted and l.entity_id = any(ents) and l.date >= date_trunc('month', d) - interval '11 month' and a.type in ('revenue','expense') and j.type <> 'CL' group by 1) z on z.mm = m.ms::date), '[]'::jsonb),
    'top_customers', coalesce((select jsonb_agg(x) from (select jsonb_build_object('name', pa.name, 'amount', sum(l.credit - l.debit)) x from acc.journal_lines l join acc.accounts a on a.tenant_id = l.tenant_id and a.id = l.account_id join acc.parties pa on pa.tenant_id = l.tenant_id and pa.id = l.party_id
        where l.tenant_id = t and l.posted and l.entity_id = any(ents) and l.date >= ys and a.type = 'revenue' and l.party_id is not null group by pa.name order by sum(l.credit - l.debit) desc limit 5) q), '[]'::jsonb)
  ) into res;
  -- الصلاحيات: الأرقام المالية الحساسة تُخفى عمّن لا يرى التقارير
  if not app.can('reports','view') then res := res - 'revenue_ytd' - 'expense_ytd' - 'revenue_mtd' - 'expense_mtd' - 'series' - 'top_customers'; end if;
  return res;
end $$;

-- الرقابة الداخلية والاستثناءات
create or replace function public.controls_report(p jsonb default '{}') returns jsonb language plpgsql stable security definer set search_path = public, app, acc as $$
declare t uuid := app.need('controls','view'); ents uuid[] := app.pick_ents(p); res jsonb := '[]'::jsonb; n bigint; cl jsonb := '[]'::jsonb;
begin
  select count(*) into n from acc.journals where tenant_id = t and entity_id = any(ents) and status = 'posted' and approved_by is not null and approved_by = created_by;
  res := res || jsonb_build_object('code','sod_violation','severity','high','count',n,'title','قيود اعتمدها معدّها نفسه');
  select count(*) into n from acc.journals where tenant_id = t and entity_id = any(ents) and status in ('draft','pending') and created_at < now() - interval '14 days';
  res := res || jsonb_build_object('code','stale_drafts','severity','medium','count',n,'title','مسودات/قيود معلّقة أكثر من 14 يومًا');
  select count(*) into n from acc.journals where tenant_id = t and entity_id = any(ents) and status in ('posted','reversed') and posted_at::date - date > 30 and type in ('GJ','ADJ');
  res := res || jsonb_build_object('code','backdated','severity','medium','count',n,'title','قيود يدوية رُحّلت بعد أكثر من 30 يومًا من تاريخها');
  select count(*) into n from acc.journals j where j.tenant_id = t and j.entity_id = any(ents) and j.status in ('posted','reversed') and j.type in ('GJ','ADJ') and j.total >= coalesce(app.setting_num(array['controls','attachment_threshold']), 10000) and app.journal_att_count(t, j.id) = 0;
  res := res || jsonb_build_object('code','no_attachment','severity','medium','count',n,'title','قيود يدوية كبيرة بلا مرفقات');
  select count(*) into n from acc.journals where tenant_id = t and entity_id = any(ents) and status in ('posted','reversed') and extract(isodow from date) in (5,6) and type in ('GJ','ADJ') and extract(isodow from posted_at) in (5,6);
  res := res || jsonb_build_object('code','weekend_posting','severity','low','count',n,'title','قيود يدوية رُحّلت في عطلة نهاية الأسبوع');
  select count(*) into n from acc.journals where tenant_id = t and entity_id = any(ents) and status in ('posted','reversed') and type = 'REV';
  res := res || jsonb_build_object('code','reversals','severity','low','count',n,'title','قيود عكسية (للمراجعة)');
  select count(*) into n from (select l.party_id from acc.journal_lines l join acc.accounts a on a.tenant_id = l.tenant_id and a.id = l.account_id where l.tenant_id = t and l.posted and l.entity_id = any(ents) and a.subtype = 'receivable' group by 1 having sum(l.debit - l.credit) < 0) q;
  res := res || jsonb_build_object('code','ar_credit_balance','severity','medium','count',n,'title','عملاء برصيد دائن');
  select count(*) into n from (select l.party_id from acc.journal_lines l join acc.accounts a on a.tenant_id = l.tenant_id and a.id = l.account_id where l.tenant_id = t and l.posted and l.entity_id = any(ents) and a.subtype = 'payable' group by 1 having sum(l.credit - l.debit) < 0) q;
  res := res || jsonb_build_object('code','ap_debit_balance','severity','medium','count',n,'title','موردون برصيد مدين');
  select count(*) into n from (select pa.id from acc.parties pa join acc.journal_lines l on l.tenant_id = pa.tenant_id and l.party_id = pa.id and l.posted join acc.accounts a on a.tenant_id = l.tenant_id and a.id = l.account_id and a.subtype = 'receivable'
      where pa.tenant_id = t and pa.credit_limit > 0 and l.entity_id = any(ents) group by pa.id, pa.credit_limit having sum(l.debit - l.credit) > pa.credit_limit) q;
  res := res || jsonb_build_object('code','over_credit','severity','high','count',n,'title','عملاء تجاوزوا حد الائتمان');
  select count(*) into n from acc.invoices i where i.tenant_id = t and i.entity_id = any(ents) and i.kind = 'sales' and i.status = 'issued' and i.due_date < current_date - 90 and i.total_base > app.inv_paid(t, i.id);
  res := res || jsonb_build_object('code','overdue_90','severity','high','count',n,'title','فواتير مبيعات متأخرة أكثر من 90 يومًا');
  select count(*) into n from (select l.account_id from acc.journal_lines l join acc.accounts a on a.tenant_id = l.tenant_id and a.id = l.account_id where l.tenant_id = t and l.posted and l.entity_id = any(ents) and a.system_key = 'SUSPENSE' group by 1 having sum(l.debit - l.credit) <> 0) q;
  res := res || jsonb_build_object('code','suspense','severity','high','count',n,'title','رصيد غير مصفّى في حساب معلّق');
  select count(*) into n from (select a.id from acc.accounts a join acc.journal_lines l on l.tenant_id = a.tenant_id and l.account_id = a.id and l.posted where a.tenant_id = t and l.entity_id = any(ents) and a.type = 'asset' and a.subtype in ('cash','bank') group by a.id having sum(l.debit - l.credit) < 0) q;
  res := res || jsonb_build_object('code','negative_cash','severity','high','count',n,'title','نقدية/بنك برصيد سالب');
  select count(*) into n from acc.journals where tenant_id = t and entity_id = any(ents) and status = 'posted' and date > current_date + 31;
  res := res || jsonb_build_object('code','future_dated','severity','low','count',n,'title','قيود مرحّلة بتاريخ مستقبلي');
  select count(*) into n from acc.periods where tenant_id = t and entity_id = any(ents) and status = 'open' and end_date < current_date - 45;
  res := res || jsonb_build_object('code','periods_not_closed','severity','medium','count',n,'title','فترات منتهية لم تُقفل بعد (أكثر من 45 يومًا)');
  -- ميزان المراجعة والتكامل
  select jsonb_build_object('debit', coalesce(sum(debit),0), 'credit', coalesce(sum(credit),0)) into cl from acc.journal_lines where tenant_id = t and posted and entity_id = any(ents);
  res := res || jsonb_build_object('code','tb_balanced','severity', case when (cl->>'debit') = (cl->>'credit') then 'ok' else 'critical' end,'count', case when (cl->>'debit') = (cl->>'credit') then 0 else 1 end,'title','توازن الأستاذ العام (مدين = دائن)');
  return jsonb_build_object('items', res, 'generated_at', now());
end $$;
-- ===== sql/009_bank_assets_budget.sql =====
-- مُحكَم للحسابات — البنوك والتسوية البنكية، الأصول الثابتة والإهلاك، الموازنات

create table if not exists acc.bank_accounts (
  tenant_id uuid not null references acc.tenants(id) on delete cascade, id uuid not null default gen_random_uuid(), entity_id uuid not null, account_id uuid not null,
  name text not null, iban text not null default '', bank_name text not null default '', currency text not null default 'SAR', active boolean not null default true, created_at timestamptz not null default now(),
  primary key (tenant_id, id), unique (tenant_id, account_id), foreign key (tenant_id, entity_id) references acc.entities (tenant_id, id), foreign key (tenant_id, account_id) references acc.accounts (tenant_id, id)
);
create table if not exists acc.bank_lines (
  tenant_id uuid not null, id uuid not null default gen_random_uuid(), bank_account_id uuid not null, date date not null, description text not null default '', reference text not null default '',
  amount numeric(18,2) not null check (amount <> 0), dedupe text not null, matched_line_id uuid, matched_at timestamptz, matched_by uuid, created_by uuid, created_at timestamptz not null default now(),
  primary key (tenant_id, id), unique (tenant_id, bank_account_id, dedupe), foreign key (tenant_id, bank_account_id) references acc.bank_accounts (tenant_id, id)
);
create index if not exists bank_lines_q on acc.bank_lines (tenant_id, bank_account_id, date);

create table if not exists acc.assets (
  tenant_id uuid not null references acc.tenants(id) on delete cascade, id uuid not null default gen_random_uuid(), entity_id uuid not null, code text not null, name text not null, category text not null default '',
  acquisition_date date not null, cost numeric(18,2) not null check (cost > 0), salvage numeric(18,2) not null default 0 check (salvage >= 0), life_months int not null default 60 check (life_months >= 0),
  method text not null default 'sl' check (method in ('sl','none')), asset_account_id uuid not null, accum_account_id uuid, expense_account_id uuid, cost_center_id uuid,
  accumulated numeric(18,2) not null default 0, dep_through date, status text not null default 'active' check (status in ('active','disposed')),
  disposal_date date, disposal_proceeds numeric(18,2), disposal_journal_id uuid, serial text not null default '', location text not null default '', note text not null default '', acquisition_journal_id uuid,
  created_by uuid, created_at timestamptz not null default now(),
  primary key (tenant_id, id), unique (tenant_id, entity_id, code), foreign key (tenant_id, entity_id) references acc.entities (tenant_id, id), foreign key (tenant_id, asset_account_id) references acc.accounts (tenant_id, id),
  foreign key (tenant_id, accum_account_id) references acc.accounts (tenant_id, id), foreign key (tenant_id, expense_account_id) references acc.accounts (tenant_id, id), foreign key (tenant_id, cost_center_id) references acc.dims (tenant_id, id),
  check (salvage < cost)
);
create table if not exists acc.asset_deps (
  tenant_id uuid not null, id uuid not null default gen_random_uuid(), asset_id uuid not null, upto date not null, months int not null, amount numeric(18,2) not null, journal_id uuid,
  primary key (tenant_id, id), foreign key (tenant_id, asset_id) references acc.assets (tenant_id, id), foreign key (tenant_id, journal_id) references acc.journals (tenant_id, id)
);
create table if not exists acc.budgets (
  tenant_id uuid not null references acc.tenants(id) on delete cascade, id uuid not null default gen_random_uuid(), entity_id uuid not null, fy_id uuid not null, name text not null,
  status text not null default 'draft' check (status in ('draft','approved')), created_by uuid, approved_by uuid, approved_at timestamptz, created_at timestamptz not null default now(), note text not null default '',
  primary key (tenant_id, id), foreign key (tenant_id, entity_id) references acc.entities (tenant_id, id), foreign key (tenant_id, fy_id) references acc.fiscal_years (tenant_id, id)
);
create table if not exists acc.budget_lines (
  tenant_id uuid not null, budget_id uuid not null, account_id uuid not null, month int not null check (month between 1 and 12), amount numeric(18,2) not null default 0,
  primary key (tenant_id, budget_id, account_id, month), foreign key (tenant_id, budget_id) references acc.budgets (tenant_id, id) on delete cascade, foreign key (tenant_id, account_id) references acc.accounts (tenant_id, id)
);
do $$ declare t text; begin foreach t in array array['bank_accounts','bank_lines','assets','asset_deps','budgets','budget_lines'] loop execute format('alter table acc.%I enable row level security', t); end loop; end $$;

-- ===== البنوك =====
create or replace function public.bank_upsert(p jsonb) returns jsonb language plpgsql security definer set search_path = public, app, acc as $$
declare t uuid; v_id uuid := nullif(p->>'id','')::uuid; e uuid := nullif(p->>'entity','')::uuid; a acc.accounts;
begin
  t := app.need('bank', case when v_id is null then 'add' else 'edit' end);
  if coalesce(trim(p->>'name'),'') = '' then raise exception 'اسم الحساب البنكي مطلوب'; end if;
  select * into a from acc.accounts where tenant_id = t and id = app.acct_id(t, p->>'account'); if a.id is null or a.type <> 'asset' or a.is_group then raise exception 'اختر حساب بنك من الأصول (غير تجميعي)'; end if;
  if v_id is null then perform app.entity_ok(t, e); v_id := gen_random_uuid();
    insert into acc.bank_accounts (tenant_id, id, entity_id, account_id, name, iban, bank_name, currency) values (t, v_id, e, a.id, trim(p->>'name'), coalesce(p->>'iban',''), coalesce(p->>'bank_name',''), coalesce(nullif(p->>'currency',''), 'SAR'));
  else update acc.bank_accounts set name = trim(p->>'name'), iban = coalesce(p->>'iban',''), bank_name = coalesce(p->>'bank_name',''), active = coalesce((p->>'active')::boolean, active) where tenant_id = t and acc.bank_accounts.id = v_id;
    if not found then raise exception 'الحساب البنكي غير موجود'; end if; end if;
  update acc.accounts set subtype = 'bank' where tenant_id = t and acc.accounts.id = a.id and subtype = 'general';
  perform app.audit('upsert','bank',v_id::text,'حساب بنكي ' || (p->>'name')); return jsonb_build_object('id', v_id);
end $$;

create or replace function public.bank_list(p jsonb default '{}') returns jsonb language plpgsql stable security definer set search_path = public, app, acc as $$
declare t uuid := app.need('bank','view'); ents uuid[] := app.pick_ents(p);
begin
  return coalesce((select jsonb_agg(jsonb_build_object('id', b.id, 'entity_id', b.entity_id, 'name', b.name, 'iban', b.iban, 'bank_name', b.bank_name, 'currency', b.currency, 'active', b.active, 'account', a.code || ' - ' || a.name, 'account_id', a.id,
      'gl_balance', coalesce((select sum(l.debit - l.credit) from acc.journal_lines l where l.tenant_id = t and l.account_id = a.id and l.posted), 0),
      'unmatched_stmt', (select count(*) from acc.bank_lines x where x.tenant_id = t and x.bank_account_id = b.id and x.matched_line_id is null),
      'unmatched_gl', (select count(*) from acc.journal_lines l where l.tenant_id = t and l.account_id = a.id and l.posted and l.reconciled_id is null)) order by b.name)
    from acc.bank_accounts b join acc.accounts a on a.tenant_id = b.tenant_id and a.id = b.account_id where b.tenant_id = t and b.entity_id = any(ents)), '[]'::jsonb);
end $$;

create or replace function public.bank_import(p jsonb) returns jsonb language plpgsql security definer set search_path = public, app, acc as $$
declare t uuid := app.need('bank','add'); b acc.bank_accounts; r jsonb; n int := 0; dup int := 0; amt numeric; dd date; ded text; ok int;
begin
  select * into b from acc.bank_accounts where tenant_id = t and id = (p->>'bank')::uuid; if b.id is null then raise exception 'الحساب البنكي غير موجود'; end if; perform app.entity_ok(t, b.entity_id);
  if jsonb_array_length(coalesce(p->'rows','[]'::jsonb)) > 5000 then raise exception 'الحد الأقصى 5000 سطر في المرة'; end if;
  for r in select * from jsonb_array_elements(coalesce(p->'rows','[]'::jsonb)) loop
    dd := (r->>'date')::date; amt := coalesce(nullif(r->>'amount','')::numeric, coalesce(nullif(r->>'credit','')::numeric, 0) - coalesce(nullif(r->>'debit','')::numeric, 0));
    if dd is null or amt is null or amt = 0 then raise exception 'سطر غير صالح (التاريخ/المبلغ): %', r::text; end if;
    ded := encode(sha256(convert_to(dd::text || '|' || amt::text || '|' || coalesce(r->>'reference','') || '|' || coalesce(r->>'description','') || '|' || coalesce(r->>'seq', ''), 'UTF8')), 'hex');
    insert into acc.bank_lines (tenant_id, bank_account_id, date, description, reference, amount, dedupe, created_by) values (t, b.id, dd, coalesce(r->>'description',''), coalesce(r->>'reference',''), amt, ded, auth.uid()) on conflict do nothing;
    get diagnostics ok = row_count; if ok = 1 then n := n + 1; else dup := dup + 1; end if;
  end loop;
  perform app.audit('import','bank',b.id::text,'استيراد كشف بنك: ' || n || ' سطر، مكرر ' || dup); return jsonb_build_object('imported', n, 'duplicates', dup);
end $$;

create or replace function public.bank_workspace(p jsonb) returns jsonb language plpgsql stable security definer set search_path = public, app, acc as $$
declare t uuid := app.need('bank','view'); b acc.bank_accounts;
begin
  select * into b from acc.bank_accounts where tenant_id = t and id = (p->>'bank')::uuid; if b.id is null then raise exception 'الحساب البنكي غير موجود'; end if; perform app.entity_ok(t, b.entity_id);
  return jsonb_build_object('statement', coalesce((select jsonb_agg(jsonb_build_object('id', x.id, 'date', x.date, 'description', x.description, 'reference', x.reference, 'amount', x.amount, 'matched_line_id', x.matched_line_id) order by x.date, x.created_at) from acc.bank_lines x where x.tenant_id = t and x.bank_account_id = b.id and (x.matched_line_id is null or coalesce((p->>'all')::boolean, false))), '[]'::jsonb),
    'ledger', coalesce((select jsonb_agg(jsonb_build_object('id', l.id, 'date', l.date, 'journal_id', l.journal_id, 'number', j.number, 'description', coalesce(nullif(l.description,''), j.description), 'amount', l.debit - l.credit, 'reconciled_id', l.reconciled_id) order by l.date, j.chain_no)
      from acc.journal_lines l join acc.journals j on j.tenant_id = l.tenant_id and j.id = l.journal_id where l.tenant_id = t and l.account_id = b.account_id and l.posted and (l.reconciled_id is null or coalesce((p->>'all')::boolean, false))), '[]'::jsonb),
    'gl_balance', (select coalesce(sum(debit - credit), 0) from acc.journal_lines where tenant_id = t and account_id = b.account_id and posted),
    'stmt_balance', (select coalesce(sum(amount), 0) from acc.bank_lines where tenant_id = t and bank_account_id = b.id));
end $$;

create or replace function public.bank_match(p jsonb) returns jsonb language plpgsql security definer set search_path = public, app, acc as $$
declare t uuid := app.need('bank','reconcile'); bl acc.bank_lines; jl acc.journal_lines; b acc.bank_accounts;
begin
  select * into bl from acc.bank_lines where tenant_id = t and id = (p->>'bank_line')::uuid for update; select * into jl from acc.journal_lines where tenant_id = t and id = (p->>'ledger_line')::uuid for update;
  if bl.id is null or jl.id is null then raise exception 'السطر غير موجود'; end if;
  select * into b from acc.bank_accounts where tenant_id = t and id = bl.bank_account_id; perform app.entity_ok(t, b.entity_id);
  if jl.account_id <> b.account_id or not jl.posted or jl.entity_id <> b.entity_id then raise exception 'سطر الأستاذ لا يخص هذا الحساب البنكي'; end if;
  if bl.matched_line_id is not null or jl.reconciled_id is not null then raise exception 'أحد السطرين مطابق مسبقًا'; end if;
  if jl.debit - jl.credit <> bl.amount then raise exception 'المبلغان غير متطابقين (كشف % / أستاذ %)', bl.amount, jl.debit - jl.credit; end if;
  update acc.bank_lines set matched_line_id = jl.id, matched_at = now(), matched_by = auth.uid() where tenant_id = t and id = bl.id;
  update acc.journal_lines set reconciled_id = bl.id where tenant_id = t and id = jl.id;
  return jsonb_build_object('ok', true);
end $$;

create or replace function public.bank_unmatch(p jsonb) returns jsonb language plpgsql security definer set search_path = public, app, acc as $$
declare t uuid := app.need('bank','reconcile'); bl acc.bank_lines; b acc.bank_accounts;
begin
  select * into bl from acc.bank_lines where tenant_id = t and id = (p->>'bank_line')::uuid for update; if bl.id is null or bl.matched_line_id is null then raise exception 'السطر غير مطابق'; end if;
  select * into b from acc.bank_accounts where tenant_id = t and id = bl.bank_account_id; perform app.entity_ok(t, b.entity_id);
  update acc.journal_lines set reconciled_id = null where tenant_id = t and id = bl.matched_line_id;
  update acc.bank_lines set matched_line_id = null, matched_at = null, matched_by = null where tenant_id = t and id = bl.id; perform app.audit('unmatch','bank',bl.id::text,'فكّ مطابقة'); return jsonb_build_object('ok', true);
end $$;

-- مطابقة تلقائية: نفس المبلغ وتاريخ ضمن N يوم وتطابق وحيد
create or replace function public.bank_auto_match(p jsonb) returns jsonb language plpgsql security definer set search_path = public, app, acc as $$
declare t uuid := app.need('bank','reconcile'); b acc.bank_accounts; r record; c uuid[]; n int := 0; days int := least(coalesce(nullif(p->>'days','')::int, 5), 30);
begin
  select * into b from acc.bank_accounts where tenant_id = t and id = (p->>'bank')::uuid; if b.id is null then raise exception 'الحساب البنكي غير موجود'; end if; perform app.entity_ok(t, b.entity_id);
  for r in select * from acc.bank_lines where tenant_id = t and bank_account_id = b.id and matched_line_id is null order by date loop
    select array_agg(l.id) into c from acc.journal_lines l where l.tenant_id = t and l.account_id = b.account_id and l.posted and l.reconciled_id is null and l.debit - l.credit = r.amount and abs(l.date - r.date) <= days;
    if c is not null and array_length(c, 1) = 1 then
      update acc.bank_lines set matched_line_id = c[1], matched_at = now(), matched_by = auth.uid() where tenant_id = t and id = r.id; update acc.journal_lines set reconciled_id = r.id where tenant_id = t and id = c[1]; n := n + 1;
    end if;
  end loop;
  perform app.audit('automatch','bank',b.id::text,'مطابقة تلقائية: ' || n); return jsonb_build_object('matched', n);
end $$;

-- تقرير التسوية البنكية
create or replace function public.bank_recon_report(p jsonb) returns jsonb language plpgsql stable security definer set search_path = public, app, acc as $$
declare t uuid := app.need('bank','view'); b acc.bank_accounts; asof date := coalesce(nullif(p->>'asof','')::date, current_date); gl numeric; st numeric; ul numeric; us numeric;
begin
  select * into b from acc.bank_accounts where tenant_id = t and id = (p->>'bank')::uuid; if b.id is null then raise exception 'الحساب البنكي غير موجود'; end if; perform app.entity_ok(t, b.entity_id);
  select coalesce(sum(debit - credit), 0) into gl from acc.journal_lines where tenant_id = t and account_id = b.account_id and posted and date <= asof;
  select coalesce(sum(amount), 0) into st from acc.bank_lines where tenant_id = t and bank_account_id = b.id and date <= asof;
  select coalesce(sum(debit - credit), 0) into ul from acc.journal_lines where tenant_id = t and account_id = b.account_id and posted and date <= asof and reconciled_id is null;
  select coalesce(sum(amount), 0) into us from acc.bank_lines where tenant_id = t and bank_account_id = b.id and date <= asof and matched_line_id is null;
  return jsonb_build_object('asof', asof, 'gl_balance', gl, 'statement_balance', st, 'ledger_unmatched', ul, 'statement_unmatched', us, 'difference', (gl - ul) - (st - us),
    'unmatched_ledger', coalesce((select jsonb_agg(jsonb_build_object('date', l.date, 'number', j.number, 'amount', l.debit - l.credit, 'description', l.description) order by l.date) from acc.journal_lines l join acc.journals j on j.tenant_id = l.tenant_id and j.id = l.journal_id where l.tenant_id = t and l.account_id = b.account_id and l.posted and l.date <= asof and l.reconciled_id is null), '[]'::jsonb),
    'unmatched_statement', coalesce((select jsonb_agg(jsonb_build_object('date', x.date, 'reference', x.reference, 'amount', x.amount, 'description', x.description) order by x.date) from acc.bank_lines x where x.tenant_id = t and x.bank_account_id = b.id and x.date <= asof and x.matched_line_id is null), '[]'::jsonb));
end $$;

-- ===== الأصول الثابتة =====
create or replace function public.asset_upsert(p jsonb) returns jsonb language plpgsql security definer set search_path = public, app, acc as $$
declare t uuid; v_id uuid := nullif(p->>'id','')::uuid; e uuid := nullif(p->>'entity','')::uuid; a acc.assets; ac uuid; cu uuid; ex uuid; v_cost numeric := (p->>'cost')::numeric; sal numeric := coalesce(nullif(p->>'salvage','')::numeric, 0); lm int := coalesce(nullif(p->>'life_months','')::int, 60); m text := coalesce(nullif(p->>'method',''), 'sl');
begin
  t := app.need('assets', case when v_id is null then 'add' else 'edit' end);
  if coalesce(trim(p->>'name'),'') = '' or coalesce(trim(p->>'code'),'') = '' or nullif(p->>'acquisition_date','') is null or v_cost is null or v_cost <= 0 then raise exception 'الرمز والاسم وتاريخ الاقتناء والتكلفة مطلوبة'; end if;
  if sal < 0 or sal >= v_cost then raise exception 'القيمة التخريدية يجب أن تكون أقل من التكلفة'; end if; if m = 'sl' and lm < 1 then raise exception 'العمر الإنتاجي بالأشهر مطلوب'; end if;
  ac := app.acct_id(t, p->>'asset_account'); cu := app.acct_id(t, nullif(p->>'accum_account','')); ex := app.acct_id(t, nullif(p->>'expense_account',''));
  if ac is null then raise exception 'حساب الأصل مطلوب'; end if; if m = 'sl' and (cu is null or ex is null) then raise exception 'حساب مجمع الإهلاك ومصروف الإهلاك مطلوبان'; end if;
  if v_id is null then perform app.entity_ok(t, e); v_id := gen_random_uuid();
    insert into acc.assets (tenant_id, id, entity_id, code, name, category, acquisition_date, cost, salvage, life_months, method, asset_account_id, accum_account_id, expense_account_id, cost_center_id, accumulated, dep_through, serial, location, note, acquisition_journal_id, created_by)
    values (t, v_id, e, trim(p->>'code'), trim(p->>'name'), coalesce(p->>'category',''), (p->>'acquisition_date')::date, v_cost, sal, lm, m, ac, cu, ex, nullif(p->>'cost_center','')::uuid, coalesce(nullif(p->>'opening_accumulated','')::numeric, 0), nullif(p->>'opening_through','')::date,
      coalesce(p->>'serial',''), coalesce(p->>'location',''), coalesce(p->>'note',''), nullif(p->>'acquisition_journal','')::uuid, auth.uid());
  else select * into a from acc.assets where tenant_id = t and acc.assets.id = v_id for update; if a.id is null then raise exception 'الأصل غير موجود'; end if; perform app.entity_ok(t, a.entity_id);
    if a.status <> 'active' then raise exception 'أصل مستبعد'; end if;
    if exists (select 1 from acc.asset_deps where tenant_id = t and asset_id = v_id) and (v_cost <> a.cost or lm <> a.life_months or sal <> a.salvage or m <> a.method or ac <> a.asset_account_id) then raise exception 'عليه إهلاك مرحّل — لا يجوز تغيير التكلفة/العمر/الطريقة'; end if;
    update acc.assets set name = trim(p->>'name'), category = coalesce(p->>'category',''), cost = v_cost, salvage = sal, life_months = lm, method = m, asset_account_id = ac, accum_account_id = cu, expense_account_id = ex, cost_center_id = nullif(p->>'cost_center','')::uuid, serial = coalesce(p->>'serial',''), location = coalesce(p->>'location',''), note = coalesce(p->>'note','')
    where tenant_id = t and acc.assets.id = v_id; end if;
  perform app.audit('upsert','asset',v_id::text,(p->>'code') || ' ' || (p->>'name')); return jsonb_build_object('id', v_id);
end $$;

create or replace function public.asset_list(p jsonb default '{}') returns jsonb language plpgsql stable security definer set search_path = public, app, acc as $$
declare t uuid := app.need('assets','view'); ents uuid[] := app.pick_ents(p);
begin
  return coalesce((select jsonb_agg(to_jsonb(a) - 'tenant_id' || jsonb_build_object('nbv', a.cost - a.accumulated, 'asset_account', (select code || ' - ' || name from acc.accounts where tenant_id = t and id = a.asset_account_id)) order by a.code)
    from acc.assets a where a.tenant_id = t and a.entity_id = any(ents) and (nullif(p->>'status','') is null or a.status = p->>'status')), '[]'::jsonb);
end $$;

-- تشغيل الإهلاك حتى آخر نهاية شهر ≤ upto (قيد واحد مجمّع لكل كيان)
create or replace function public.asset_depreciate(p jsonb) returns jsonb language plpgsql security definer set search_path = public, app, acc as $$
declare t uuid := app.need('assets','post'); e uuid := (p->>'entity')::uuid; upto date := (date_trunc('month', (p->>'upto')::date + 1) - interval '1 day')::date; me date; a acc.assets; jid uuid := gen_random_uuid(); lines jsonb := '[]'::jsonb;
  from_m date; k int; amt numeric; monthly numeric; base numeric; tot numeric := 0; cnt int := 0; j acc.journals; ids uuid[] := '{}'; ms int[] := '{}'; ams numeric[] := '{}'; i int;
begin
  perform app.entity_ok(t, e);
  if (p->>'upto')::date <> (date_trunc('month', (p->>'upto')::date + 1) - interval '1 day')::date then upto := (date_trunc('month', (p->>'upto')::date) - interval '1 day')::date; end if;
  for a in select * from acc.assets where tenant_id = t and entity_id = e and status = 'active' and method = 'sl' order by code for update loop
    from_m := coalesce((date_trunc('month', a.dep_through + 1))::date, date_trunc('month', a.acquisition_date)::date);
    if a.dep_through is not null then from_m := (date_trunc('month', a.dep_through) + interval '1 month')::date; end if;
    if upto < (from_m + interval '1 month' - interval '1 day')::date then continue; end if;
    k := (extract(year from age(upto + 1, from_m)) * 12 + extract(month from age(upto + 1, from_m)))::int;
    base := a.cost - a.salvage; monthly := round(base / a.life_months, 2);
    amt := least(round(base / a.life_months * k, 2), base - a.accumulated); if amt <= 0 then continue; end if;
    lines := lines || jsonb_build_object('account', a.expense_account_id, 'cost_center', a.cost_center_id, 'debit', amt, 'description', 'إهلاك ' || a.code || ' ' || a.name)
                   || jsonb_build_object('account', a.accum_account_id, 'credit', amt, 'description', 'مجمع إهلاك ' || a.code);
    ids := ids || a.id; ms := ms || k; ams := ams || amt; tot := tot + amt; cnt := cnt + 1;
  end loop;
  if cnt = 0 then return jsonb_build_object('assets', 0, 'total', 0); end if;
  insert into acc.journals (tenant_id, id, entity_id, type, date, description, status, source, created_by) values (t, jid, e, 'DEP', upto, 'إهلاك الأصول الثابتة حتى ' || upto, 'draft', 'assets', auth.uid());
  perform app.put_lines(t, jid, e, upto, lines); j := app.post_journal(jid);
  for i in 1..cnt loop
    insert into acc.asset_deps (tenant_id, asset_id, upto, months, amount, journal_id) values (t, ids[i], upto, ms[i], ams[i], j.id);
    update acc.assets set accumulated = accumulated + ams[i], dep_through = upto where tenant_id = t and id = ids[i];
  end loop;
  perform app.audit('depreciate','asset',j.id::text,'إهلاك ' || cnt || ' أصل بإجمالي ' || tot); return jsonb_build_object('assets', cnt, 'total', tot, 'journal', j.number, 'journal_id', j.id);
end $$;

create or replace function public.asset_dispose(p jsonb) returns jsonb language plpgsql security definer set search_path = public, app, acc as $$
declare t uuid := app.need('assets','post'); a acc.assets; d date := (p->>'date')::date; proceeds numeric := coalesce(nullif(p->>'proceeds','')::numeric, 0); cash uuid := app.acct_id(t, nullif(p->>'cash_account','')); jid uuid := gen_random_uuid(); lines jsonb := '[]'::jsonb; gl numeric; j acc.journals;
begin
  select * into a from acc.assets where tenant_id = t and id = (p->>'id')::uuid for update; if a.id is null then raise exception 'الأصل غير موجود'; end if; perform app.entity_ok(t, a.entity_id);
  if a.status <> 'active' then raise exception 'الأصل مستبعد مسبقًا'; end if; if d is null or d < a.acquisition_date then raise exception 'تاريخ الاستبعاد غير صالح'; end if;
  if a.method = 'sl' and a.accumulated < least(a.cost - a.salvage, round((a.cost - a.salvage) / a.life_months * ((extract(year from age(date_trunc('month', d)::date, date_trunc('month', a.acquisition_date)::date)) * 12 + extract(month from age(date_trunc('month', d)::date, date_trunc('month', a.acquisition_date)::date)))::int), 2)) - 0.05
    then raise exception 'شغّل الإهلاك حتى نهاية الشهر السابق للاستبعاد أولًا'; end if;
  if proceeds > 0 and cash is null then raise exception 'حدّد حساب النقدية/البنك للمتحصلات'; end if;
  gl := proceeds - (a.cost - a.accumulated);
  if proceeds > 0 then lines := lines || jsonb_build_object('account', cash, 'debit', proceeds, 'description', 'متحصلات بيع ' || a.code); end if;
  if a.accumulated > 0 then lines := lines || jsonb_build_object('account', a.accum_account_id, 'debit', a.accumulated, 'description', 'إقفال مجمع إهلاك ' || a.code); end if;
  lines := lines || jsonb_build_object('account', a.asset_account_id, 'credit', a.cost, 'description', 'استبعاد ' || a.code);
  if gl > 0 then lines := lines || jsonb_build_object('account', app.sysacct(t, 'ASSET_GAIN'), 'credit', gl, 'description', 'ربح بيع أصل'); elsif gl < 0 then lines := lines || jsonb_build_object('account', app.sysacct(t, 'ASSET_LOSS'), 'debit', -gl, 'description', 'خسارة بيع أصل'); end if;
  insert into acc.journals (tenant_id, id, entity_id, type, date, description, status, source, source_id, created_by) values (t, jid, a.entity_id, 'AST', d, 'استبعاد أصل ' || a.code || ' ' || a.name, 'draft', 'assets', a.id, auth.uid());
  perform app.put_lines(t, jid, a.entity_id, d, lines); j := app.post_journal(jid);
  update acc.assets set status = 'disposed', disposal_date = d, disposal_proceeds = proceeds, disposal_journal_id = j.id where tenant_id = t and id = a.id;
  perform app.audit('dispose','asset',a.id::text,'استبعاد ' || a.code || ' — ربح/خسارة ' || gl); return jsonb_build_object('journal', j.number, 'gain_loss', gl);
end $$;

-- ===== الموازنات =====
create or replace function public.budget_save(p jsonb) returns jsonb language plpgsql security definer set search_path = public, app, acc as $$
declare t uuid; v_id uuid := nullif(p->>'id','')::uuid; e uuid := nullif(p->>'entity','')::uuid; fy uuid := nullif(p->>'fy','')::uuid; l jsonb; a uuid; i int; b acc.budgets;
begin
  t := app.need('budgets', case when v_id is null then 'add' else 'edit' end);
  if coalesce(trim(p->>'name'),'') = '' then raise exception 'اسم الموازنة مطلوب'; end if;
  if v_id is null then perform app.entity_ok(t, e); if not exists (select 1 from acc.fiscal_years where tenant_id = t and id = fy and entity_id = e) then raise exception 'السنة المالية غير صالحة'; end if; v_id := gen_random_uuid();
    insert into acc.budgets (tenant_id, id, entity_id, fy_id, name, note, created_by) values (t, v_id, e, fy, trim(p->>'name'), coalesce(p->>'note',''), auth.uid());
  else select * into b from acc.budgets where tenant_id = t and acc.budgets.id = v_id for update; if b.id is null then raise exception 'الموازنة غير موجودة'; end if; perform app.entity_ok(t, b.entity_id);
    if b.status = 'approved' then raise exception 'موازنة معتمدة — لا تُعدَّل'; end if; update acc.budgets set name = trim(p->>'name'), note = coalesce(p->>'note','') where tenant_id = t and acc.budgets.id = v_id; delete from acc.budget_lines where tenant_id = t and budget_id = v_id; end if;
  for l in select * from jsonb_array_elements(coalesce(p->'lines','[]'::jsonb)) loop
    a := app.acct_id(t, l->>'account'); if a is null or not exists (select 1 from acc.accounts where tenant_id = t and id = a and type in ('revenue','expense') and not is_group) then raise exception 'حساب موازنة غير صالح: %', l->>'account'; end if;
    for i in 1..12 loop insert into acc.budget_lines (tenant_id, budget_id, account_id, month, amount) values (t, v_id, a, i, coalesce(nullif((l->'months'->>(i - 1)),'')::numeric, 0)) on conflict (tenant_id, budget_id, account_id, month) do update set amount = excluded.amount; end loop;
  end loop;
  perform app.audit('save','budget',v_id::text,'موازنة ' || (p->>'name')); return jsonb_build_object('id', v_id);
end $$;

create or replace function public.budget_approve(p jsonb) returns jsonb language plpgsql security definer set search_path = public, app, acc as $$
declare t uuid := app.need('budgets','approve'); b acc.budgets;
begin
  select * into b from acc.budgets where tenant_id = t and id = (p->>'id')::uuid for update; if b.id is null then raise exception 'الموازنة غير موجودة'; end if; perform app.entity_ok(t, b.entity_id);
  if b.status = 'approved' then raise exception 'معتمدة مسبقًا'; end if; if (app.policy('budgets')->>'sod')::boolean and b.created_by = auth.uid() then raise exception 'فصل المهام: لا يجوز اعتماد موازنة أعددتها بنفسك'; end if;
  update acc.budgets set status = 'approved', approved_by = auth.uid(), approved_at = now() where tenant_id = t and id = b.id; perform app.audit('approve','budget',b.id::text,'اعتماد موازنة ' || b.name); return jsonb_build_object('ok', true);
end $$;

create or replace function public.budget_list(p jsonb default '{}') returns jsonb language plpgsql stable security definer set search_path = public, app, acc as $$
declare t uuid := app.need('budgets','view'); ents uuid[] := app.pick_ents(p);
begin
  return coalesce((select jsonb_agg(jsonb_build_object('id', b.id, 'entity_id', b.entity_id, 'fy_id', b.fy_id, 'fy', f.name, 'name', b.name, 'status', b.status, 'total_revenue', coalesce((select sum(l.amount) from acc.budget_lines l join acc.accounts a on a.tenant_id = l.tenant_id and a.id = l.account_id where l.tenant_id = t and l.budget_id = b.id and a.type = 'revenue'), 0),
      'total_expense', coalesce((select sum(l.amount) from acc.budget_lines l join acc.accounts a on a.tenant_id = l.tenant_id and a.id = l.account_id where l.tenant_id = t and l.budget_id = b.id and a.type = 'expense'), 0)) order by f.start_date desc, b.name)
    from acc.budgets b join acc.fiscal_years f on f.tenant_id = b.tenant_id and f.id = b.fy_id where b.tenant_id = t and b.entity_id = any(ents)), '[]'::jsonb);
end $$;

create or replace function public.budget_get(p jsonb) returns jsonb language plpgsql stable security definer set search_path = public, app, acc as $$
declare t uuid := app.need('budgets','view'); b acc.budgets;
begin
  select * into b from acc.budgets where tenant_id = t and id = (p->>'id')::uuid; if b.id is null then raise exception 'الموازنة غير موجودة'; end if; perform app.entity_ok(t, b.entity_id);
  return to_jsonb(b) || jsonb_build_object('lines', coalesce((select jsonb_agg(jsonb_build_object('account_id', a.id, 'code', a.code, 'name', a.name, 'type', a.type, 'months', (select jsonb_agg(l2.amount order by l2.month) from acc.budget_lines l2 where l2.tenant_id = t and l2.budget_id = b.id and l2.account_id = a.id)) order by a.code)
    from acc.accounts a where a.tenant_id = t and exists (select 1 from acc.budget_lines l where l.tenant_id = t and l.budget_id = b.id and l.account_id = a.id)), '[]'::jsonb));
end $$;

create or replace function public.budget_vs_actual(p jsonb) returns jsonb language plpgsql stable security definer set search_path = public, app, acc as $$
declare t uuid := app.need('reports','view'); b acc.budgets; f acc.fiscal_years; upm int := least(coalesce(nullif(p->>'to_month','')::int, 12), 12);
begin
  if not app.can('budgets','view') then raise exception 'ليست لديك صلاحية الموازنات'; end if;
  select * into b from acc.budgets where tenant_id = t and id = (p->>'id')::uuid; if b.id is null then raise exception 'الموازنة غير موجودة'; end if; perform app.entity_ok(t, b.entity_id);
  select * into f from acc.fiscal_years where tenant_id = t and id = b.fy_id;
  return jsonb_build_object('budget', b.name, 'to_month', upm, 'rows', coalesce((select jsonb_agg(jsonb_build_object('account_id', a.id, 'code', a.code, 'name', a.name, 'type', a.type, 'budget', x.bud, 'actual', coalesce(y.act, 0), 'variance', case when a.type = 'revenue' then coalesce(y.act, 0) - x.bud else x.bud - coalesce(y.act, 0) end,
      'pct', case when x.bud = 0 then null else round(coalesce(y.act, 0) / x.bud * 100, 1) end) order by a.type desc, a.code)
    from (select l.account_id, sum(l.amount) bud from acc.budget_lines l where l.tenant_id = t and l.budget_id = b.id and l.month <= upm group by 1) x join acc.accounts a on a.tenant_id = t and a.id = x.account_id
    left join (select jl.account_id, sum(case when ac.type = 'revenue' then jl.credit - jl.debit else jl.debit - jl.credit end) act from acc.journal_lines jl join acc.journals j on j.tenant_id = jl.tenant_id and j.id = jl.journal_id join acc.accounts ac on ac.tenant_id = jl.tenant_id and ac.id = jl.account_id
      where jl.tenant_id = t and jl.posted and jl.entity_id = b.entity_id and jl.date between f.start_date and (f.start_date + (upm || ' month')::interval - interval '1 day')::date and j.type <> 'CL' group by 1) y on y.account_id = x.account_id), '[]'::jsonb));
end $$;
-- ===== sql/010_connectors.sql =====
-- مُحكَم للحسابات — الموصّلات: مفاتيح API واستقبال القيود من برامج أخرى (قيود تدخل «بانتظار الاعتماد» دائمًا)

create table if not exists acc.api_keys (
  tenant_id uuid not null references acc.tenants(id) on delete cascade, id uuid not null default gen_random_uuid(), name text not null, prefix text not null, key_hash text not null unique,
  entity_id uuid not null, scopes text[] not null default array['ingest_journal'], active boolean not null default true, expires_at timestamptz, last_used_at timestamptz, use_count bigint not null default 0,
  created_by uuid, created_at timestamptz not null default now(), primary key (tenant_id, id), foreign key (tenant_id, entity_id) references acc.entities (tenant_id, id)
);
create table if not exists acc.ingest_log (
  tenant_id uuid not null, id uuid not null default gen_random_uuid(), key_id uuid not null, source text not null, external_id text not null, journal_id uuid, created_at timestamptz not null default now(),
  primary key (tenant_id, id), unique (tenant_id, source, external_id)
);
alter table acc.api_keys enable row level security; alter table acc.ingest_log enable row level security;

create or replace function public.connector_key_create(p jsonb) returns jsonb language plpgsql security definer set search_path = public, app, acc as $$
declare t uuid := app.need('connectors','add'); e uuid := (p->>'entity')::uuid; secret text; pre text; v_id uuid := gen_random_uuid();
begin
  perform app.entity_ok(t, e); if coalesce(trim(p->>'name'),'') = '' then raise exception 'اسم الموصّل مطلوب'; end if;
  pre := substr(replace(gen_random_uuid()::text, '-', ''), 1, 8); secret := 'mk_' || pre || '_' || replace(gen_random_uuid()::text || gen_random_uuid()::text, '-', '');
  insert into acc.api_keys (tenant_id, id, name, prefix, key_hash, entity_id, expires_at, created_by) values (t, v_id, trim(p->>'name'), pre, encode(sha256(convert_to(secret, 'UTF8')), 'hex'), e, nullif(p->>'expires_at','')::timestamptz, auth.uid());
  perform app.audit('create','connector',v_id::text,'مفتاح موصّل ' || trim(p->>'name'));
  return jsonb_build_object('id', v_id, 'key', secret, 'note', 'احفظ المفتاح الآن — لا يظهر مرة أخرى');
end $$;
create or replace function public.connector_key_list(p jsonb default '{}') returns jsonb language plpgsql stable security definer set search_path = public, app, acc as $$
declare t uuid := app.need('connectors','view');
begin return coalesce((select jsonb_agg(jsonb_build_object('id', k.id, 'name', k.name, 'prefix', k.prefix, 'entity_id', k.entity_id, 'active', k.active, 'expires_at', k.expires_at, 'last_used_at', k.last_used_at, 'use_count', k.use_count, 'created_at', k.created_at) order by k.created_at desc) from acc.api_keys k where k.tenant_id = t), '[]'::jsonb); end $$;
create or replace function public.connector_key_revoke(p jsonb) returns jsonb language plpgsql security definer set search_path = public, app, acc as $$
declare t uuid := app.need('connectors','delete');
begin update acc.api_keys set active = false where tenant_id = t and id = (p->>'id')::uuid; if not found then raise exception 'المفتاح غير موجود'; end if; perform app.audit('revoke','connector',p->>'id','إلغاء مفتاح'); return jsonb_build_object('ok', true); end $$;

-- نقطة استقبال عامة (anon) — تُصادَق بالمفتاح فقط
create or replace function public.ingest_journal(p jsonb) returns jsonb language plpgsql security definer set search_path = public, app, acc as $$
declare k acc.api_keys; h text := encode(sha256(convert_to(coalesce(p->>'key',''), 'UTF8')), 'hex'); jid uuid := gen_random_uuid(); d date := (p->>'date')::date; src text := coalesce(nullif(trim(p->>'source'),''), 'external'); ext text := trim(coalesce(p->>'external_id',''));
  per acc.periods; dr numeric; cr numeric; ex uuid; l jsonb; tot numeric;
begin
  select * into k from acc.api_keys where key_hash = h and active and (expires_at is null or expires_at > now());
  if k.id is null or not ('ingest_journal' = any(k.scopes)) then raise exception 'مفتاح غير صالح'; end if;
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
-- ===== sql/011_portal.sql =====
-- مُحكَم للحسابات — بوابة الموظف: طلبات/مطالبات مالية بأنواع قابلة للتعريف، مرفقات، تعاميم وأخبار

create table if not exists acc.request_types (
  tenant_id uuid not null references acc.tenants(id) on delete cascade, id uuid not null default gen_random_uuid(), code text not null, name text not null, name_en text not null default '',
  kind text not null default 'expense' check (kind in ('expense','advance','letter','other')), needs_amount boolean not null default true, needs_attachment boolean not null default false,
  default_account_id uuid, max_amount numeric(18,2), active boolean not null default true, sort int not null default 100, created_at timestamptz not null default now(),
  primary key (tenant_id, id), unique (tenant_id, code), foreign key (tenant_id, default_account_id) references acc.accounts (tenant_id, id)
);
create table if not exists acc.employee_links (tenant_id uuid not null references acc.tenants(id) on delete cascade, user_id uuid not null, party_id uuid not null, primary key (tenant_id, user_id), foreign key (tenant_id, party_id) references acc.parties (tenant_id, id));
create table if not exists acc.requests (
  tenant_id uuid not null references acc.tenants(id) on delete cascade, id uuid not null default gen_random_uuid(), entity_id uuid not null, number text, type_id uuid not null, user_id uuid not null, party_id uuid not null,
  title text not null, description text not null default '', amount numeric(18,2) not null default 0 check (amount >= 0), date date not null default current_date,
  status text not null default 'draft' check (status in ('draft','submitted','approved','rejected','paid','cancelled')),
  decided_by uuid, decided_at timestamptz, decision_note text not null default '', expense_account_id uuid, cost_center_id uuid, journal_id uuid, pay_journal_id uuid, paid_at timestamptz,
  created_at timestamptz not null default now(), submitted_at timestamptz, updated_at timestamptz not null default now(),
  primary key (tenant_id, id), foreign key (tenant_id, entity_id) references acc.entities (tenant_id, id), foreign key (tenant_id, type_id) references acc.request_types (tenant_id, id), foreign key (tenant_id, party_id) references acc.parties (tenant_id, id),
  foreign key (tenant_id, expense_account_id) references acc.accounts (tenant_id, id), foreign key (tenant_id, journal_id) references acc.journals (tenant_id, id), foreign key (tenant_id, pay_journal_id) references acc.journals (tenant_id, id)
);
create unique index if not exists requests_number on acc.requests (tenant_id, number) where number is not null;
create index if not exists requests_user on acc.requests (tenant_id, user_id, created_at desc);
create index if not exists requests_status on acc.requests (tenant_id, status, created_at desc);
create table if not exists acc.notices (
  tenant_id uuid not null references acc.tenants(id) on delete cascade, id uuid not null default gen_random_uuid(), title text not null, body text not null default '', level text not null default 'info' check (level in ('info','important','urgent')),
  pinned boolean not null default false, starts_on date not null default current_date, ends_on date, audience text[], created_by uuid, created_at timestamptz not null default now(), primary key (tenant_id, id)
);
alter table acc.request_types enable row level security; alter table acc.employee_links enable row level security; alter table acc.requests enable row level security; alter table acc.notices enable row level security;

-- أنواع الطلبات (مرنة: يعرّفها المدير)
create or replace function public.reqtype_list(p jsonb default '{}') returns jsonb language plpgsql stable security definer set search_path = public, app, acc as $$
declare t uuid := app.need(null, null); mgr boolean := app.can('requests','manage');
begin
  if not (mgr or app.can('portal','view') or app.can('requests','view')) then raise exception 'ليست لديك صلاحية'; end if;
  return coalesce((select jsonb_agg(jsonb_build_object('id', r.id, 'code', r.code, 'name', r.name, 'name_en', r.name_en, 'kind', r.kind, 'needs_amount', r.needs_amount, 'needs_attachment', r.needs_attachment, 'max_amount', r.max_amount, 'active', r.active, 'default_account_id', case when mgr then r.default_account_id end) order by r.sort, r.name)
    from acc.request_types r where r.tenant_id = t and (mgr or r.active)), '[]'::jsonb);
end $$;
create or replace function public.reqtype_upsert(p jsonb) returns jsonb language plpgsql security definer set search_path = public, app, acc as $$
declare t uuid := app.need('requests','manage'); v_id uuid := nullif(p->>'id','')::uuid; k text := coalesce(nullif(p->>'kind',''), 'expense'); da uuid := app.acct_id(t, nullif(p->>'default_account',''));
begin
  if coalesce(trim(p->>'name'),'') = '' or coalesce(trim(p->>'code'),'') = '' then raise exception 'الرمز والاسم مطلوبان'; end if; if k not in ('expense','advance','letter','other') then raise exception 'نوع غير صالح'; end if;
  if v_id is null then v_id := gen_random_uuid();
    insert into acc.request_types (tenant_id, id, code, name, name_en, kind, needs_amount, needs_attachment, default_account_id, max_amount, sort) values (t, v_id, trim(p->>'code'), trim(p->>'name'), coalesce(p->>'name_en',''), k, coalesce((p->>'needs_amount')::boolean, k <> 'letter'), coalesce((p->>'needs_attachment')::boolean, false), da, nullif(p->>'max_amount','')::numeric, coalesce(nullif(p->>'sort','')::int, 100));
  else update acc.request_types set code = trim(p->>'code'), name = trim(p->>'name'), name_en = coalesce(p->>'name_en',''), kind = k, needs_amount = coalesce((p->>'needs_amount')::boolean, needs_amount), needs_attachment = coalesce((p->>'needs_attachment')::boolean, needs_attachment), default_account_id = da,
      max_amount = nullif(p->>'max_amount','')::numeric, active = coalesce((p->>'active')::boolean, active), sort = coalesce(nullif(p->>'sort','')::int, sort) where tenant_id = t and acc.request_types.id = v_id;
    if not found then raise exception 'النوع غير موجود'; end if; end if;
  perform app.audit('upsert','reqtype',v_id::text,p->>'name'); return jsonb_build_object('id', v_id);
end $$;

create or replace function app.emp_party(t uuid, uid uuid) returns uuid language plpgsql security definer set search_path = public, acc as $$
declare pid uuid; m acc.members;
begin
  select party_id into pid from acc.employee_links where tenant_id = t and user_id = uid; if pid is not null then return pid; end if;
  select * into m from acc.members where tenant_id = t and user_id = uid; pid := gen_random_uuid();
  insert into acc.parties (tenant_id, id, kind, code, name, created_by) values (t, pid, 'employee', 'EMP-' || lpad(app.next_no(t, null, 'party_employee', 0)::text, 5, '0'), coalesce(nullif(m.name,''), m.username, 'موظف'), uid);
  insert into acc.employee_links (tenant_id, user_id, party_id) values (t, uid, pid); return pid;
end $$;

-- ===== جهة الموظف =====
create or replace function public.req_save(p jsonb) returns jsonb language plpgsql security definer set search_path = public, app, acc as $$
declare t uuid := app.need('portal','add'); v_id uuid := nullif(p->>'id','')::uuid; ty acc.request_types; r acc.requests; e uuid; amt numeric := coalesce(nullif(p->>'amount','')::numeric, 0); ents uuid[] := app.ents();
begin
  select * into ty from acc.request_types where tenant_id = t and id = (p->>'type')::uuid and active; if ty.id is null then raise exception 'نوع الطلب غير موجود'; end if;
  if coalesce(trim(p->>'title'),'') = '' then raise exception 'عنوان الطلب مطلوب'; end if;
  if ty.needs_amount and amt <= 0 then raise exception 'المبلغ مطلوب'; end if; if amt < 0 or amt > 1000000000 then raise exception 'مبلغ غير صالح'; end if;
  if ty.max_amount is not null and amt > ty.max_amount then raise exception 'المبلغ يتجاوز الحد الأقصى لهذا النوع (%)', ty.max_amount; end if;
  e := coalesce(nullif(p->>'entity','')::uuid, ents[1]); if e is null or not (e = any(ents)) then raise exception 'الكيان غير مسموح'; end if;
  if v_id is null then v_id := gen_random_uuid();
    insert into acc.requests (tenant_id, id, entity_id, type_id, user_id, party_id, title, description, amount, date) values (t, v_id, e, ty.id, auth.uid(), app.emp_party(t, auth.uid()), trim(p->>'title'), coalesce(p->>'description',''), amt, coalesce(nullif(p->>'date','')::date, current_date));
  else select * into r from acc.requests where tenant_id = t and acc.requests.id = v_id for update; if r.id is null or r.user_id <> auth.uid() then raise exception 'الطلب غير موجود'; end if; if r.status <> 'draft' then raise exception 'يُعدَّل الطلب وهو مسودة فقط'; end if;
    update acc.requests set type_id = ty.id, title = trim(p->>'title'), description = coalesce(p->>'description',''), amount = amt, date = coalesce(nullif(p->>'date','')::date, date), updated_at = now() where tenant_id = t and acc.requests.id = v_id; end if;
  return jsonb_build_object('id', v_id);
end $$;

create or replace function public.req_submit(p jsonb) returns jsonb language plpgsql security definer set search_path = public, app, acc as $$
declare t uuid := app.need('portal','add'); r acc.requests; ty acc.request_types; num bigint;
begin
  select * into r from acc.requests where tenant_id = t and id = (p->>'id')::uuid for update; if r.id is null or r.user_id <> auth.uid() then raise exception 'الطلب غير موجود'; end if;
  if r.status <> 'draft' then raise exception 'الطلب مرفوع مسبقًا'; end if; select * into ty from acc.request_types where tenant_id = t and id = r.type_id;
  if ty.needs_attachment and not exists (select 1 from acc.attachments where tenant_id = t and owner_type = 'request' and owner_id = r.id) then raise exception 'هذا النوع يتطلب إرفاق مستند (فاتورة/إيصال)'; end if;
  num := app.next_no(t, null, 'request', extract(year from current_date)::int);
  update acc.requests set status = 'submitted', submitted_at = now(), updated_at = now(), number = 'REQ-' || extract(year from current_date)::int || '-' || lpad(num::text, 5, '0') where tenant_id = t and id = r.id;
  perform app.audit('submit','request',r.id::text,'رفع طلب ' || r.title || ' — ' || r.amount); return jsonb_build_object('ok', true);
end $$;

create or replace function public.req_cancel(p jsonb) returns jsonb language plpgsql security definer set search_path = public, app, acc as $$
declare t uuid := app.need('portal','add'); r acc.requests;
begin
  select * into r from acc.requests where tenant_id = t and id = (p->>'id')::uuid for update; if r.id is null or r.user_id <> auth.uid() then raise exception 'الطلب غير موجود'; end if;
  if r.status = 'draft' then delete from acc.attachments where tenant_id = t and owner_type = 'request' and owner_id = r.id; delete from acc.requests where tenant_id = t and id = r.id; return jsonb_build_object('deleted', true); end if;
  if r.status <> 'submitted' then raise exception 'لا يمكن إلغاء طلب تم البت فيه'; end if;
  update acc.requests set status = 'cancelled', updated_at = now() where tenant_id = t and id = r.id; perform app.audit('cancel','request',r.id::text,'إلغاء من الموظف'); return jsonb_build_object('ok', true);
end $$;

create or replace function app.req_json(t uuid, r acc.requests, p_full boolean) returns jsonb language sql stable security definer set search_path = public, acc as $$
  select jsonb_build_object('id', r.id, 'number', r.number, 'title', r.title, 'description', case when p_full then r.description end, 'amount', r.amount, 'date', r.date, 'status', r.status, 'submitted_at', r.submitted_at, 'decided_at', r.decided_at, 'decision_note', r.decision_note, 'paid_at', r.paid_at,
    'type', (select name from acc.request_types where tenant_id = t and id = r.type_id), 'type_id', r.type_id, 'kind', (select kind from acc.request_types where tenant_id = t and id = r.type_id),
    'employee', (select name from acc.members where tenant_id = t and user_id = r.user_id), 'user_id', r.user_id, 'entity_id', r.entity_id, 'journal_id', r.journal_id, 'pay_journal_id', r.pay_journal_id, 'party_id', r.party_id,
    'attachments_count', (select count(*) from acc.attachments where tenant_id = t and owner_type = 'request' and owner_id = r.id)) $$;

create or replace function public.req_my(p jsonb default '{}') returns jsonb language plpgsql stable security definer set search_path = public, app, acc as $$
declare t uuid := app.need('portal','view'); pid uuid; st text := nullif(p->>'status','');
begin
  select party_id into pid from acc.employee_links where tenant_id = t and user_id = auth.uid();
  return jsonb_build_object('rows', coalesce((select jsonb_agg(app.req_json(t, r, false) order by r.created_at desc) from (select * from acc.requests where tenant_id = t and user_id = auth.uid() and (st is null or status = st) order by created_at desc limit 300) r), '[]'::jsonb),
    'summary', jsonb_build_object('draft', (select count(*) from acc.requests where tenant_id = t and user_id = auth.uid() and status = 'draft'), 'submitted', (select count(*) from acc.requests where tenant_id = t and user_id = auth.uid() and status = 'submitted'),
      'owed_to_me', (select coalesce(sum(amount), 0) from acc.requests where tenant_id = t and user_id = auth.uid() and status = 'approved' and (select kind from acc.request_types where tenant_id = t and id = type_id) in ('expense','other')),
      'paid_ytd', (select coalesce(sum(amount), 0) from acc.requests where tenant_id = t and user_id = auth.uid() and status = 'paid' and paid_at >= date_trunc('year', now())),
      'rejected', (select count(*) from acc.requests where tenant_id = t and user_id = auth.uid() and status = 'rejected')));
end $$;

create or replace function public.req_get(p jsonb) returns jsonb language plpgsql stable security definer set search_path = public, app, acc as $$
declare t uuid := app.need(null, null); r acc.requests; fin boolean := app.can('requests','view');
begin
  select * into r from acc.requests where tenant_id = t and id = (p->>'id')::uuid; if r.id is null then raise exception 'الطلب غير موجود'; end if;
  if not (r.user_id = auth.uid() or (fin and r.entity_id = any(app.ents()))) then raise exception 'الطلب غير موجود'; end if;
  return app.req_json(t, r, true) || jsonb_build_object('attachments', coalesce((select jsonb_agg(jsonb_build_object('id', x.id, 'filename', x.filename, 'mime', x.mime, 'size', x.size, 'path', x.path, 'uploaded_at', x.uploaded_at) order by x.uploaded_at) from acc.attachments x where x.tenant_id = t and x.owner_type = 'request' and x.owner_id = r.id), '[]'::jsonb),
    'journal_number', case when fin then (select number from acc.journals where tenant_id = t and id = r.journal_id) end, 'pay_journal_number', case when fin then (select number from acc.journals where tenant_id = t and id = r.pay_journal_id) end,
    'history', coalesce((select jsonb_agg(jsonb_build_object('at', h.at, 'by', h.username, 'action', h.action, 'details', h.details) order by h.id) from acc.audit h where h.tenant_id = t and h.entity = 'request' and h.ref = r.id::text), '[]'::jsonb));
end $$;

-- مرفقات الطلبات (مالك الطلب أو المالية)
create or replace function public.req_attach(p jsonb) returns jsonb language plpgsql security definer set search_path = public, app, acc as $$
declare t uuid := app.need(null, null); r acc.requests; path text := p->>'path'; fin boolean := app.can('requests','view'); v_id uuid := gen_random_uuid();
begin
  select * into r from acc.requests where tenant_id = t and id = (p->>'id')::uuid; if r.id is null then raise exception 'الطلب غير موجود'; end if;
  if not ((r.user_id = auth.uid() and r.status in ('draft','submitted') and app.can('portal','add')) or (fin and r.entity_id = any(app.ents()))) then raise exception 'ليست لديك صلاحية إرفاق مستند لهذا الطلب'; end if;
  if split_part(path, '/', 1) <> t::text or path ~ '\.\.' then raise exception 'مسار المرفق غير صالح'; end if; if coalesce((p->>'size')::bigint, 0) > 10485760 then raise exception 'الحد الأقصى للمرفق 10 ميجابايت'; end if;
  if (select count(*) from acc.attachments where tenant_id = t and owner_type = 'request' and owner_id = r.id) >= 10 then raise exception 'الحد الأقصى 10 مرفقات للطلب'; end if;
  insert into acc.attachments (tenant_id, id, entity_id, owner_type, owner_id, path, filename, mime, size, sha256, uploaded_by) values (t, v_id, r.entity_id, 'request', r.id, path, coalesce(nullif(p->>'filename',''), 'file'), coalesce(p->>'mime',''), coalesce((p->>'size')::bigint, 0), coalesce(p->>'sha256',''), auth.uid());
  perform app.audit('attach','request',r.id::text,'إرفاق ' || coalesce(p->>'filename','')); return jsonb_build_object('id', v_id);
end $$;
create or replace function public.req_detach(p jsonb) returns jsonb language plpgsql security definer set search_path = public, app, acc as $$
declare t uuid := app.need(null, null); a acc.attachments; r acc.requests;
begin
  select * into a from acc.attachments where tenant_id = t and id = (p->>'id')::uuid and owner_type = 'request'; if a.id is null then raise exception 'المرفق غير موجود'; end if;
  select * into r from acc.requests where tenant_id = t and id = a.owner_id; if r.user_id <> auth.uid() or r.status <> 'draft' then raise exception 'لا يُحذف المرفق بعد رفع الطلب'; end if;
  delete from acc.attachments where tenant_id = t and id = a.id; return jsonb_build_object('ok', true, 'path', a.path);
end $$;

-- ===== جهة المالية =====
create or replace function public.req_list(p jsonb default '{}') returns jsonb language plpgsql stable security definer set search_path = public, app, acc as $$
declare t uuid := app.need('requests','view'); ents uuid[] := app.pick_ents(p); st text := nullif(p->>'status','');
begin
  return jsonb_build_object('rows', coalesce((select jsonb_agg(app.req_json(t, r, false) order by r.submitted_at desc nulls last, r.created_at desc) from (select * from acc.requests where tenant_id = t and entity_id = any(ents) and status <> 'draft' and (st is null or status = st)
      and (nullif(p->>'user','') is null or user_id = (p->>'user')::uuid) order by submitted_at desc nulls last limit least(coalesce(nullif(p->>'limit','')::int, 200), 1000)) r), '[]'::jsonb),
    'pending', (select count(*) from acc.requests where tenant_id = t and entity_id = any(ents) and status = 'submitted'), 'to_pay', (select coalesce(sum(amount), 0) from acc.requests where tenant_id = t and entity_id = any(ents) and status = 'approved'));
end $$;

create or replace function public.req_decide(p jsonb) returns jsonb language plpgsql security definer set search_path = public, app, acc as $$
declare t uuid := app.need('requests','approve'); r acc.requests; ty acc.request_types; dec text := p->>'decision'; ex uuid; jid uuid; j acc.journals; ap uuid; lines jsonb;
begin
  select * into r from acc.requests where tenant_id = t and id = (p->>'id')::uuid for update; if r.id is null then raise exception 'الطلب غير موجود'; end if; perform app.entity_ok(t, r.entity_id);
  if r.status <> 'submitted' then raise exception 'الطلب ليس بانتظار القرار'; end if; if r.user_id = auth.uid() then raise exception 'فصل المهام: لا يجوز البت في طلبك أنت'; end if;
  select * into ty from acc.request_types where tenant_id = t and id = r.type_id;
  if dec = 'reject' then
    if coalesce(trim(p->>'note'),'') = '' then raise exception 'سبب الرفض مطلوب'; end if;
    update acc.requests set status = 'rejected', decided_by = auth.uid(), decided_at = now(), decision_note = trim(p->>'note'), updated_at = now() where tenant_id = t and id = r.id; perform app.audit('reject','request',r.id::text,trim(p->>'note')); return jsonb_build_object('status','rejected');
  elsif dec <> 'approve' then raise exception 'قرار غير صالح'; end if;
  if ty.kind = 'letter' or r.amount = 0 then   -- طلب بلا أثر مالي
    update acc.requests set status = 'paid', decided_by = auth.uid(), decided_at = now(), paid_at = now(), decision_note = coalesce(p->>'note',''), updated_at = now() where tenant_id = t and id = r.id; perform app.audit('approve','request',r.id::text,'اعتماد (بلا أثر مالي)'); return jsonb_build_object('status','paid');
  end if;
  ex := coalesce(app.acct_id(t, nullif(p->>'account','')), ty.default_account_id); if ex is null then raise exception 'حدّد حساب المصروف/السلفة'; end if;
  ap := app.sysacct(t, 'AP'); jid := gen_random_uuid();
  insert into acc.journals (tenant_id, id, entity_id, type, date, description, reference, status, source, source_id, created_by) values (t, jid, r.entity_id, 'GJ', coalesce(nullif(p->>'date','')::date, r.date), (select name from acc.request_types where tenant_id = t and id = r.type_id) || ' — ' || r.title, r.number, 'draft', 'request', r.id, auth.uid());
  lines := jsonb_build_array(jsonb_build_object('account', ex, 'debit', r.amount, 'cost_center', nullif(p->>'cost_center',''), 'description', r.title), jsonb_build_object('account', ap, 'credit', r.amount, 'party', r.party_id, 'description', 'مستحق للموظف ' || r.number));
  perform app.put_lines(t, jid, r.entity_id, coalesce(nullif(p->>'date','')::date, r.date), lines); j := app.post_journal(jid);
  update acc.requests set status = 'approved', decided_by = auth.uid(), decided_at = now(), decision_note = coalesce(p->>'note',''), expense_account_id = ex, cost_center_id = nullif(p->>'cost_center','')::uuid, journal_id = j.id, updated_at = now() where tenant_id = t and id = r.id;
  update acc.attachments set entity_id = entity_id where false;
  perform app.audit('approve','request',r.id::text,'اعتماد وترحيل ' || j.number || ' — ' || r.amount); return jsonb_build_object('status','approved','journal', j.number, 'journal_id', j.id);
end $$;

create or replace function public.req_pay(p jsonb) returns jsonb language plpgsql security definer set search_path = public, app, acc as $$
declare t uuid := app.need('requests','pay'); r acc.requests; cash uuid; jid uuid := gen_random_uuid(); j acc.journals; d date := coalesce(nullif(p->>'date','')::date, current_date);
begin
  select * into r from acc.requests where tenant_id = t and id = (p->>'id')::uuid for update; if r.id is null then raise exception 'الطلب غير موجود'; end if; perform app.entity_ok(t, r.entity_id);
  if r.status <> 'approved' then raise exception 'الطلب غير معتمد أو مصروف مسبقًا'; end if;
  select a.id into cash from acc.accounts a where a.tenant_id = t and a.id = app.acct_id(t, p->>'cash_account') and a.subtype in ('cash','bank') and not a.is_group; if cash is null then raise exception 'اختر حساب الصندوق/البنك'; end if;
  insert into acc.journals (tenant_id, id, entity_id, type, date, description, reference, status, source, source_id, created_by) values (t, jid, r.entity_id, 'PV', d, 'صرف طلب موظف ' || r.number || ' — ' || r.title, r.number, 'draft', 'request', r.id, auth.uid());
  perform app.put_lines(t, jid, r.entity_id, d, jsonb_build_array(jsonb_build_object('account', app.sysacct(t, 'AP'), 'debit', r.amount, 'party', r.party_id, 'description', 'سداد ' || r.number), jsonb_build_object('account', cash, 'credit', r.amount, 'description', r.title)));
  j := app.post_journal(jid);
  update acc.requests set status = 'paid', pay_journal_id = j.id, paid_at = now(), updated_at = now() where tenant_id = t and id = r.id; perform app.audit('pay','request',r.id::text,'صرف ' || j.number || ' — ' || r.amount); return jsonb_build_object('journal', j.number, 'journal_id', j.id);
end $$;

-- ===== التعاميم والأخبار =====
create or replace function public.notice_list(p jsonb default '{}') returns jsonb language plpgsql stable security definer set search_path = public, app, acc as $$
declare t uuid := app.need(null, null); rid text := (app.me()).role; mgr boolean := app.sys('settings');
begin
  return coalesce((select jsonb_agg(jsonb_build_object('id', n.id, 'title', n.title, 'body', n.body, 'level', n.level, 'pinned', n.pinned, 'starts_on', n.starts_on, 'ends_on', n.ends_on, 'audience', n.audience, 'created_at', n.created_at) order by n.pinned desc, n.created_at desc)
    from acc.notices n where n.tenant_id = t and (mgr or (n.starts_on <= current_date and (n.ends_on is null or n.ends_on >= current_date) and (n.audience is null or rid = any(n.audience))))), '[]'::jsonb);
end $$;
create or replace function public.notice_upsert(p jsonb) returns jsonb language plpgsql security definer set search_path = public, app, acc as $$
declare t uuid := app.need_sys('settings'); v_id uuid := nullif(p->>'id','')::uuid; aud text[] := case when jsonb_typeof(p->'audience') = 'array' and jsonb_array_length(p->'audience') > 0 then array(select jsonb_array_elements_text(p->'audience')) end;
begin
  if coalesce(trim(p->>'title'),'') = '' then raise exception 'عنوان التعميم مطلوب'; end if; if length(coalesce(p->>'body','')) > 5000 then raise exception 'النص طويل'; end if;
  if v_id is null then v_id := gen_random_uuid(); insert into acc.notices (tenant_id, id, title, body, level, pinned, starts_on, ends_on, audience, created_by) values (t, v_id, trim(p->>'title'), coalesce(p->>'body',''), coalesce(nullif(p->>'level',''), 'info'), coalesce((p->>'pinned')::boolean, false), coalesce(nullif(p->>'starts_on','')::date, current_date), nullif(p->>'ends_on','')::date, aud, auth.uid());
  else update acc.notices set title = trim(p->>'title'), body = coalesce(p->>'body',''), level = coalesce(nullif(p->>'level',''), level), pinned = coalesce((p->>'pinned')::boolean, pinned), starts_on = coalesce(nullif(p->>'starts_on','')::date, starts_on), ends_on = nullif(p->>'ends_on','')::date, audience = aud where tenant_id = t and acc.notices.id = v_id; end if;
  perform app.audit('upsert','notice',v_id::text,p->>'title'); return jsonb_build_object('id', v_id);
end $$;
create or replace function public.notice_delete(p jsonb) returns jsonb language plpgsql security definer set search_path = public, app, acc as $$
declare t uuid := app.need_sys('settings'); begin delete from acc.notices where tenant_id = t and id = (p->>'id')::uuid; return jsonb_build_object('ok', true); end $$;
-- ===== sql/012_flex.sql =====
-- مُحكَم للحسابات — المرونة: لا شجرة مفروضة. ابدأ فارغًا أو من قالب أو بالاستيراد، واربط الحسابات الرئيسية بنفسك.

-- دمج قالب في الشجرة الحالية دون المساس بالموجود (يتخطى الرموز المكررة)
create or replace function public.coa_apply_template(p jsonb) returns jsonb language plpgsql security definer set search_path = public, app, acc as $$
declare t uuid := app.need('coa','add'); rows jsonb; r jsonb; pid uuid; ty text; sub text; n int := 0; skipped int := 0; got int;
begin
  select tpl.rows into rows from app.coa_templates tpl where tpl.key = p->>'key'; if rows is null then raise exception 'القالب غير موجود'; end if;
  for r in select * from jsonb_array_elements(rows) loop
    pid := null; if nullif(r->>'parent_code','') is not null then select a.id into pid from acc.accounts a where a.tenant_id = t and a.code = r->>'parent_code'; end if;
    ty := coalesce(r->>'type', (select a.type from acc.accounts a where a.tenant_id = t and a.id = pid)); sub := coalesce(nullif(r->>'subtype',''), 'general');
    insert into acc.accounts (tenant_id, code, name, name_en, parent_id, type, subtype, is_group, cf_class, requires_party, requires_cc, system_key, created_by)
    values (t, r->>'code', r->>'name', coalesce(r->>'name_en',''), pid, ty, sub, coalesce((r->>'is_group')::boolean, false), coalesce(nullif(r->>'cf_class',''), app.default_cf(ty, sub)), sub in ('receivable','payable'), false,
      case when exists (select 1 from acc.accounts a where a.tenant_id = t and a.system_key = nullif(r->>'system_key','')) then null else nullif(r->>'system_key','') end, auth.uid())
    on conflict do nothing;
    get diagnostics got = row_count; if got = 1 then n := n + 1; else skipped := skipped + 1; end if;
  end loop;
  perform app.audit('template','account',p->>'key','دمج قالب ' || (p->>'key') || ': ' || n || ' جديد، ' || skipped || ' موجود'); return jsonb_build_object('added', n, 'skipped', skipped);
end $$;

-- تفريغ الشجرة لمن أراد البدء من الصفر (فقط إن لم توجد أي حركة)
create or replace function public.coa_reset(p jsonb) returns jsonb language plpgsql security definer set search_path = public, app, acc as $$
declare t uuid := app.need_sys('settings'); n int;
begin
  if not app.can('coa','delete') then raise exception 'ليست لديك صلاحية'; end if;
  if exists (select 1 from acc.journal_lines where tenant_id = t limit 1) or exists (select 1 from acc.invoice_lines where tenant_id = t limit 1) then raise exception 'توجد حركات — لا يمكن تفريغ الشجرة'; end if;
  update acc.accounts set parent_id = null where tenant_id = t; delete from acc.tax_codes where tenant_id = t; delete from acc.accounts where tenant_id = t; get diagnostics n = row_count;
  perform app.audit('reset','account','all','تفريغ شجرة الحسابات (' || n || ')'); return jsonb_build_object('deleted', n);
end $$;

-- ربط الحسابات الرئيسية (يختارها المستخدم بنفسه)
create or replace function public.sysmap_list(p jsonb default '{}') returns jsonb language plpgsql stable security definer set search_path = public, app, acc as $$
declare t uuid := app.need('coa','view');
begin
  return (select jsonb_agg(jsonb_build_object('key', k.key, 'label', k.label, 'type', k.ty, 'needed_for', k.nf, 'account_id', a.id, 'code', a.code, 'name', a.name) order by k.ord)
    from (values (1,'AR','حساب العملاء (الذمم المدينة)','asset','فواتير المبيعات وسندات القبض'),(2,'AP','حساب الموردين (الذمم الدائنة)','liability','فواتير المشتريات وسندات الصرف وطلبات الموظفين'),
      (3,'SALES','إيراد المبيعات الافتراضي','revenue','بنود فواتير المبيعات بلا حساب'),(4,'PURCHASES','مشتريات/مصروفات افتراضية','expense','بنود فواتير المشتريات بلا حساب'),
      (5,'VAT_OUT','ضريبة المخرجات','liability','ضريبة المبيعات'),(6,'VAT_IN','ضريبة المدخلات','asset','ضريبة المشتريات'),(7,'RE','الأرباح المبقاة','equity','إقفال السنة'),
      (8,'ASSET_GAIN','أرباح بيع الأصول','revenue','استبعاد الأصول'),(9,'ASSET_LOSS','خسائر بيع الأصول','expense','استبعاد الأصول')) k(ord, key, label, ty, nf)
    left join acc.accounts a on a.tenant_id = t and a.system_key = k.key);
end $$;

-- ربط وظيفة نظامية بحساب (بدون إعادة إرسال بيانات الحساب)
create or replace function public.sysmap_set(p jsonb) returns jsonb language plpgsql security definer set search_path = public, app, acc as $$
declare t uuid := app.need('coa','edit'); k text := p->>'key'; a acc.accounts; want text;
begin
  want := case k when 'AR' then 'asset' when 'AP' then 'liability' when 'SALES' then 'revenue' when 'PURCHASES' then 'expense' when 'VAT_OUT' then 'liability' when 'VAT_IN' then 'asset' when 'RE' then 'equity' when 'ASSET_GAIN' then 'revenue' when 'ASSET_LOSS' then 'expense' end;
  if want is null then raise exception 'وظيفة غير معروفة'; end if;
  select * into a from acc.accounts where tenant_id = t and id = (p->>'account')::uuid; if a.id is null then raise exception 'الحساب غير موجود'; end if;
  if a.is_group then raise exception 'اختر حسابًا فرعيًا (غير تجميعي)'; end if; if not a.active then raise exception 'الحساب موقوف'; end if;
  if a.type <> want then raise exception 'نوع الحساب لا يناسب هذه الوظيفة (المطلوب: %)', want; end if;
  update acc.accounts set system_key = null where tenant_id = t and system_key = k and id <> a.id;
  update acc.accounts set system_key = k where tenant_id = t and id = a.id;
  perform app.audit('update','account',a.id::text,'ربط ' || k || ' بالحساب ' || a.code);
  return jsonb_build_object('ok', true);
end $$;

-- استيراد جماعي للعملاء والموردين
create or replace function public.party_import(p jsonb) returns jsonb language plpgsql security definer set search_path = public, app, acc as $$
declare t uuid := app.need('parties','add'); r jsonb; n int := 0; u int := 0; k text; c text; ex uuid; errs jsonb := '[]'::jsonb; i int := 0; dry boolean := coalesce((p->>'dry')::boolean, false);
begin
  perform app.need('import','add'); if jsonb_array_length(coalesce(p->'rows','[]'::jsonb)) > 5000 then raise exception 'الحد الأقصى 5000 صف'; end if;
  for r in select * from jsonb_array_elements(coalesce(p->'rows','[]'::jsonb)) loop
    i := i + 1; k := coalesce(nullif(r->>'kind',''), 'customer'); c := nullif(trim(coalesce(r->>'code','')), '');
    if coalesce(trim(r->>'name'),'') = '' then errs := errs || jsonb_build_object('row', i, 'error', 'الاسم مطلوب'); continue; end if;
    if k not in ('customer','supplier','both','employee','other') then errs := errs || jsonb_build_object('row', i, 'error', 'نوع غير صالح: ' || k); continue; end if;
    select id into ex from acc.parties where tenant_id = t and code = c;
    if ex is not null then if not dry then update acc.parties set name = trim(r->>'name'), vat_no = coalesce(r->>'vat_no', vat_no), phone = coalesce(r->>'phone', phone), email = coalesce(r->>'email', email), city = coalesce(r->>'city', city), credit_limit = coalesce(nullif(r->>'credit_limit','')::numeric, credit_limit), terms_days = coalesce(nullif(r->>'terms_days','')::int, terms_days) where tenant_id = t and id = ex; end if; u := u + 1;
    else if not dry then
      if c is null then c := case when k = 'supplier' then 'S-' when k = 'employee' then 'EMP-' else 'C-' end || lpad(app.next_no(t, null, 'party_' || k, 0)::text, 5, '0'); end if;
      insert into acc.parties (tenant_id, kind, code, name, name_en, vat_no, phone, email, city, credit_limit, terms_days, created_by) values (t, k, c, trim(r->>'name'), coalesce(r->>'name_en',''), coalesce(r->>'vat_no',''), coalesce(r->>'phone',''), coalesce(r->>'email',''), coalesce(r->>'city',''), coalesce(nullif(r->>'credit_limit','')::numeric, 0), coalesce(nullif(r->>'terms_days','')::int, 30), auth.uid()); end if; n := n + 1; end if;
  end loop;
  if not dry then perform app.audit('import','party','bulk','استيراد أطراف: ' || n || ' جديد، ' || u || ' محدّث'); end if;
  return jsonb_build_object('created', n, 'updated', u, 'errors', errs, 'dry', dry);
end $$;
-- ===== sql/013_files.sql =====
-- مُحكَم للحسابات — مركز المستندات: كل المرفقات في مكان واحد + المستندات الناقصة

-- كل المرفقات مع المستند المالك (رقم/عنوان) للانتقال إليه
create or replace function public.att_all(p jsonb default '{}') returns jsonb language plpgsql stable security definer set search_path = public, app, acc as $$
declare t uuid := app.need('attachments','view'); ents uuid[] := app.ents(); lim int := least(coalesce(nullif(p->>'limit','')::int, 50), 200); off int := coalesce(nullif(p->>'offset','')::int, 0);
  ty text := nullif(p->>'owner_type',''); q text := nullif(trim(coalesce(p->>'q','')), '');
begin
  return (select jsonb_build_object('total', count(*) over (), 'rows', coalesce(jsonb_agg(x.o order by x.at desc), '[]'::jsonb)) from (
    select a.uploaded_at at, jsonb_build_object('id', a.id, 'filename', a.filename, 'mime', a.mime, 'size', a.size, 'path', a.path, 'uploaded_at', a.uploaded_at, 'by', (select name from acc.members where user_id = a.uploaded_by),
      'owner_type', a.owner_type, 'owner_id', a.owner_id, 'note', a.note,
      'owner_label', case a.owner_type
        when 'journal' then (select 'قيد ' || coalesce(j.number, 'مسودة') || ' — ' || left(j.description, 40) from acc.journals j where j.tenant_id = t and j.id = a.owner_id)
        when 'invoice' then (select case i.kind when 'sales' then 'فاتورة مبيعات ' when 'purchase' then 'فاتورة مشتريات ' when 'sales_credit' then 'إشعار دائن ' else 'إشعار مدين ' end || coalesce(i.number, 'مسودة') from acc.invoices i where i.tenant_id = t and i.id = a.owner_id)
        when 'payment' then (select case y.kind when 'receipt' then 'سند قبض ' else 'سند صرف ' end || coalesce(y.number, 'مسودة') from acc.payments y where y.tenant_id = t and y.id = a.owner_id)
        when 'asset' then (select 'أصل ' || s.name from acc.assets s where s.tenant_id = t and s.id = a.owner_id)
        when 'party' then (select 'ملف ' || pa.name from acc.parties pa where pa.tenant_id = t and pa.id = a.owner_id)
        when 'request' then (select 'طلب ' || coalesce(r.number, '') || ' ' || r.title from acc.requests r where r.tenant_id = t and r.id = a.owner_id)
        else a.owner_type end) o
    from acc.attachments a where a.tenant_id = t and (a.entity_id is null or a.entity_id = any(ents)) and (ty is null or a.owner_type = ty)
      and (a.owner_type <> 'request' or app.can('requests','view') or exists (select 1 from acc.requests r where r.tenant_id = t and r.id = a.owner_id and r.user_id = auth.uid()))
      and (q is null or a.filename ilike '%' || q || '%' or a.note ilike '%' || q || '%')
    order by a.uploaded_at desc limit lim offset off) x);
end $$;

-- مستندات تتطلب مرفقًا بحسب السياسة ولا مرفق لها
create or replace function public.att_missing(p jsonb default '{}') returns jsonb language plpgsql stable security definer set search_path = public, app, acc as $$
declare t uuid := app.need('controls','view'); ents uuid[] := app.pick_ents(p); oj numeric := app.attach_over('journal'); op numeric := app.attach_over('purchase'); os numeric := app.attach_over('sales'); opay numeric := app.attach_over('payment'); orc numeric := app.attach_over('receipt');
begin
  return coalesce((select jsonb_agg(z order by (z->>'date') desc) from (
    select jsonb_build_object('type', 'journal', 'id', j.id, 'label', 'قيد ' || j.number, 'date', j.date, 'amount', j.total, 'status', j.status) z from acc.journals j
      where j.tenant_id = t and j.entity_id = any(ents) and j.status in ('posted','pending','approved') and j.type in ('GJ','ADJ') and oj >= 0 and j.total >= oj and app.journal_att_count(t, j.id) = 0
    union all select jsonb_build_object('type', 'invoice', 'id', i.id, 'label', case when i.kind like 'purchase%' then 'فاتورة مشتريات ' else 'فاتورة مبيعات ' end || i.number, 'date', i.date, 'amount', i.total, 'status', i.status) from acc.invoices i
      where i.tenant_id = t and i.entity_id = any(ents) and i.status in ('issued','pending','approved') and ((i.kind like 'purchase%' and op >= 0 and i.total >= op) or (i.kind like 'sales%' and os >= 0 and i.total >= os))
        and not exists (select 1 from acc.attachments a where a.tenant_id = t and a.owner_type = 'invoice' and a.owner_id = i.id)
    union all select jsonb_build_object('type', 'payment', 'id', y.id, 'label', case y.kind when 'receipt' then 'سند قبض ' else 'سند صرف ' end || y.number, 'date', y.date, 'amount', y.amount, 'status', y.status) from acc.payments y
      where y.tenant_id = t and y.entity_id = any(ents) and y.status in ('posted','pending','approved') and ((y.kind = 'payment' and opay >= 0 and y.amount >= opay) or (y.kind = 'receipt' and orc >= 0 and y.amount >= orc))
        and not exists (select 1 from acc.attachments a where a.tenant_id = t and a.owner_type = 'payment' and a.owner_id = y.id)) q), '[]'::jsonb);
end $$;
-- ===== sql/014_audit_tools.sql =====
-- أدوات المراجع والمفتش: فجوات التسلسل، البحث الشامل، مؤشرات سلامة الدفاتر، سجل التصدير
-- فجوات في ترقيم المستندات (كل كيان/نوع/سنة): يجب أن يكون التسلسل متصلًا بلا ثقوب
create or replace function public.seq_gaps(p jsonb default '{}') returns jsonb language plpgsql stable security definer set search_path = public, app, acc as $$
declare t uuid := app.need(null, null); ents uuid[] := app.pick_ents(p); df date := nullif(p->>'from','')::date; dt date := nullif(p->>'to','')::date;
begin
  if not (app.can('controls','view') or app.can('reports','view') or app.can('sales','view')) then raise exception 'ليست لديك صلاحية'; end if;
  return coalesce((select jsonb_agg(jsonb_build_object('entity', e.name, 'prefix', g.pre, 'year', g.yr, 'first', g.mn, 'last', g.mx, 'count', g.cnt, 'missing', g.miss) order by e.name, g.pre, g.yr)
    from (select s.entity_id, s.pre, s.yr, min(s.n) mn, max(s.n) mx, count(*) cnt,
        (select coalesce(jsonb_agg(x), '[]') from (select gs x from generate_series(min(s.n), max(s.n)) gs where not exists (select 1 from acc.journals j2 where j2.tenant_id = t and j2.entity_id = s.entity_id and j2.number = s.pre || '-' || s.yr || '-' || lpad(gs::text, 5, '0')) limit 50) z) miss
      from (select j.entity_id, split_part(j.number, '-', 1) pre, split_part(j.number, '-', 2) yr, split_part(j.number, '-', 3)::int n from acc.journals j
        where j.tenant_id = t and j.entity_id = any(ents) and j.number is not null and (df is null or j.date >= df) and (dt is null or j.date <= dt)) s group by s.entity_id, s.pre, s.yr) g
    join acc.entities e on e.tenant_id = t and e.id = g.entity_id), '[]'::jsonb);
end $$;

-- بحث شامل برقم/اسم/مبلغ/ضريبي/ملف
create or replace function public.global_find(p jsonb) returns jsonb language plpgsql stable security definer set search_path = public, app, acc as $$
declare t uuid := app.need(null, null); ents uuid[] := app.ents(); q text := trim(coalesce(p->>'q','')); n numeric := case when trim(coalesce(p->>'q','')) ~ '^[0-9]+([.,][0-9]+)?$' then replace(trim(p->>'q'), ',', '.')::numeric else null end; res jsonb := '[]'::jsonb;
begin
  if length(q) < 2 then return res; end if;
  if app.can('journals','view') then
    res := res || coalesce((select jsonb_agg(x) from (select jsonb_build_object('type','journal','id',j.id,'label','قيد ' || coalesce(j.number,'مسودة'),'sub',j.description,'date',j.date,'amount',j.total,'status',j.status) x from acc.journals j
      where j.tenant_id = t and j.entity_id = any(ents) and (j.number ilike '%'||q||'%' or j.description ilike '%'||q||'%' or j.reference ilike '%'||q||'%' or (n is not null and j.total = n)) order by j.date desc limit 12) z), '[]'); end if;
  if app.can('sales','view') or app.can('purchases','view') then
    res := res || coalesce((select jsonb_agg(x) from (select jsonb_build_object('type','invoice','id',i.id,'label',case when i.kind like 'sales%' then 'فاتورة مبيعات ' else 'فاتورة مشتريات ' end || coalesce(i.number,'مسودة'),'sub',pa.name || case when i.supplier_ref <> '' then ' — ' || i.supplier_ref else '' end,'date',i.date,'amount',i.total,'status',i.status) x
      from acc.invoices i join acc.parties pa on pa.tenant_id = i.tenant_id and pa.id = i.party_id
      where i.tenant_id = t and i.entity_id = any(ents) and app.can(app.inv_module(i.kind),'view') and (i.number ilike '%'||q||'%' or i.supplier_ref ilike '%'||q||'%' or pa.name ilike '%'||q||'%' or i.notes ilike '%'||q||'%' or i.id::text = q or (n is not null and i.total = n)) order by i.date desc limit 12) z), '[]'); end if;
  if app.can('payments','view') then
    res := res || coalesce((select jsonb_agg(x) from (select jsonb_build_object('type','payment','id',y.id,'label',case y.kind when 'receipt' then 'سند قبض ' else 'سند صرف ' end || coalesce(y.number,'مسودة'),'sub',coalesce(pa.name,'') || ' ' || y.reference || ' ' || y.cheque_no,'date',y.date,'amount',y.amount,'status',y.status) x
      from acc.payments y left join acc.parties pa on pa.tenant_id = y.tenant_id and pa.id = y.party_id
      where y.tenant_id = t and y.entity_id = any(ents) and (y.number ilike '%'||q||'%' or y.reference ilike '%'||q||'%' or y.cheque_no ilike '%'||q||'%' or pa.name ilike '%'||q||'%' or (n is not null and y.amount = n)) order by y.date desc limit 12) z), '[]'); end if;
  if app.can('parties','view') then
    res := res || coalesce((select jsonb_agg(x) from (select jsonb_build_object('type','party','id',pa.id,'label',pa.name,'sub',pa.code || ' ' || pa.vat_no,'kind',pa.kind) x from acc.parties pa
      where pa.tenant_id = t and (pa.name ilike '%'||q||'%' or pa.code ilike '%'||q||'%' or pa.vat_no ilike '%'||q||'%') order by pa.name limit 8) z), '[]'); end if;
  if app.can('coa','view') then
    res := res || coalesce((select jsonb_agg(x) from (select jsonb_build_object('type','account','id',a.id,'label',a.code || ' — ' || a.name,'sub',a.type) x from acc.accounts a
      where a.tenant_id = t and (a.code ilike q||'%' or a.name ilike '%'||q||'%') order by a.code limit 8) z), '[]'); end if;
  return res;
end $$;

-- مؤشرات سلامة الدفاتر: كل مؤشر له رابط للتفاصيل
create or replace function public.health_check(p jsonb default '{}') returns jsonb language plpgsql stable security definer set search_path = public, app, acc as $$
declare t uuid := app.need('reports','view'); ents uuid[] := app.pick_ents(p); res jsonb := '[]'::jsonb; tb jsonb; bs jsonb; d numeric; ar numeric; ap numeric; gl_ar numeric; gl_ap numeric; n bigint; gaps jsonb; cv jsonb := null;
begin
  tb := public.rpt_trial_balance(p); d := abs((tb->'totals'->>'debit')::numeric - (tb->'totals'->>'credit')::numeric);
  res := res || jsonb_build_object('key','tb','label','ميزان المراجعة متزن','ok', d < 0.005,'detail', 'الفرق ' || d,'link','/reports/tb');
  bs := public.rpt_balance_sheet(p); d := abs((bs->>'assets')::numeric - (bs->>'liabilities')::numeric - (bs->>'equity')::numeric);
  res := res || jsonb_build_object('key','bs','label','المركز المالي متزن (أصول = خصوم + حقوق)','ok', d < 0.005,'detail','الفرق ' || d,'link','/reports/bs');
  select coalesce(sum(l.debit - l.credit),0) into gl_ar from acc.journal_lines l join acc.accounts a on a.tenant_id = l.tenant_id and a.id = l.account_id where l.tenant_id = t and l.posted and l.entity_id = any(ents) and a.subtype = 'receivable';
  select coalesce(sum((x->>'total')::numeric),0) into ar from jsonb_array_elements(public.rpt_aging(p || '{"kind":"ar"}')->'rows') x;
  res := res || jsonb_build_object('key','ar','label','أعمار العملاء = حساب العملاء بالأستاذ','ok', abs(ar - gl_ar) < 0.005,'detail','الفرق ' || abs(ar - gl_ar),'link','/reports/aging');
  select coalesce(sum(l.credit - l.debit),0) into gl_ap from acc.journal_lines l join acc.accounts a on a.tenant_id = l.tenant_id and a.id = l.account_id where l.tenant_id = t and l.posted and l.entity_id = any(ents) and a.subtype = 'payable';
  select coalesce(sum((x->>'total')::numeric),0) into ap from jsonb_array_elements(public.rpt_aging(p || '{"kind":"ap"}')->'rows') x;
  res := res || jsonb_build_object('key','ap','label','أعمار الموردين = حساب الموردين بالأستاذ','ok', abs(abs(ap) - abs(gl_ap)) < 0.005,'detail','الفرق ' || abs(abs(ap) - abs(gl_ap)),'link','/reports/aging');
  gaps := public.seq_gaps(p); select count(*) into n from jsonb_array_elements(gaps) g where jsonb_array_length(g->'missing') > 0;
  res := res || jsonb_build_object('key','seq','label','تسلسل ترقيم المستندات بلا فجوات','ok', n = 0,'detail', n || ' تسلسل به فجوات','link','/register');
  select count(*) into n from acc.journals where tenant_id = t and entity_id = any(ents) and status in ('draft','pending') and created_at < now() - interval '14 days';
  res := res || jsonb_build_object('key','stale','label','لا مسودات/معلّقات أقدم من 14 يومًا','ok', n = 0,'detail', n || ' قيد','link','/journals');
  select count(*) into n from acc.invoices where tenant_id = t and entity_id = any(ents) and status in ('draft','pending','approved') and date < current_date - 30;
  res := res || jsonb_build_object('key','inv_open','label','لا فواتير غير مصدرة أقدم من 30 يومًا','ok', n = 0,'detail', n || ' فاتورة','link','/invoices/sales');
  select count(*) into n from acc.journals where tenant_id = t and entity_id = any(ents) and status = 'posted' and approved_by is not null and approved_by = created_by;
  res := res || jsonb_build_object('key','sod','label','لا قيود اعتمدها معدّها','ok', n = 0,'detail', n || ' قيد','link','/controls');
  if app.sys('audit') then cv := public.chain_verify(p); res := res || jsonb_build_object('key','chain','label','سلسلة التدقيق والقيود سليمة (لا عبث)','ok', coalesce((cv->>'ok')::boolean, false),'detail', coalesce(cv->>'audit_rows','0') || ' سجل','link','/audit'); end if;
  return res;
end $$;

-- تسجيل تصدير/طباعة/أرشفة مستند في سجل التدقيق
create or replace function public.doc_export_log(p jsonb) returns jsonb language plpgsql security definer set search_path = public, app, acc as $$
declare t uuid := app.need(null, null); ty text := p->>'type'; id text := p->>'id';
begin
  if ty not in ('invoice','journal','payment','report','pack') then raise exception 'نوع غير صالح'; end if;
  perform app.audit('export', ty, coalesce(id,''), left(coalesce(p->>'note','تصدير/طباعة'), 300)); return jsonb_build_object('ok', true);
end $$;

-- سجل الفواتير الضريبي (مبيعات/مشتريات) للفترة: جاهز للمفتش — الرقم الضريبي للطرف والمبالغ وعدد المرفقات والقيد
create or replace function public.tax_register(p jsonb) returns jsonb language plpgsql stable security definer set search_path = public, app, acc as $$
declare t uuid := app.need(null, null); ents uuid[] := app.pick_ents(p); df date := nullif(p->>'from','')::date; dt date := nullif(p->>'to','')::date; k text := nullif(p->>'side','');
  lim int := least(coalesce(nullif(p->>'limit','')::int, 5000), 20000); off int := coalesce(nullif(p->>'offset','')::int, 0); q text := nullif(trim(coalesce(p->>'q','')), '');
begin
  if not (app.can('reports','view') or app.can('tax','view')) then raise exception 'ليست لديك صلاحية'; end if;
  return (select jsonb_build_object('total', coalesce(max(x.cnt), 0), 'rows', coalesce(jsonb_agg(jsonb_build_object('id', x.id, 'entity', x.ename, 'kind', x.kind, 'number', x.number, 'supplier_ref', x.supplier_ref, 'date', x.date, 'party', x.pname, 'vat_no', x.vat_no, 'subtotal', x.subtotal,
      'discount', x.discount_total, 'tax', x.tax_total, 'total', x.total, 'currency', x.currency, 'status', x.status, 'journal', x.jnum, 'attachments', x.att, 'issued_by', x.iby, 'issued_at', x.issued_at) order by x.rn), '[]'::jsonb))
    from (select i.*, e.name ename, pa.name pname, pa.vat_no, j.number jnum, (select count(*) from acc.attachments a where a.tenant_id = t and a.owner_type = 'invoice' and a.owner_id = i.id) att,
        (select name from acc.members m where m.user_id = i.issued_by) iby, count(*) over() cnt, row_number() over (order by i.date, i.number nulls last, i.id) rn
      from acc.invoices i join acc.parties pa on pa.tenant_id = i.tenant_id and pa.id = i.party_id join acc.entities e on e.tenant_id = i.tenant_id and e.id = i.entity_id left join acc.journals j on j.tenant_id = i.tenant_id and j.id = i.journal_id
      where i.tenant_id = t and i.entity_id = any(ents) and i.status in ('issued','void') and app.can(app.inv_module(i.kind), 'view')
        and (k is null or (k = 'sales' and i.kind in ('sales','sales_credit')) or (k = 'purchase' and i.kind in ('purchase','purchase_debit')))
        and (df is null or i.date >= df) and (dt is null or i.date <= dt)
        and (q is null or i.number ilike '%'||q||'%' or i.supplier_ref ilike '%'||q||'%' or pa.name ilike '%'||q||'%' or pa.vat_no ilike '%'||q||'%')
      order by i.date, i.number nulls last, i.id limit lim offset off) x);
end $$;
-- ===== sql/015_ops.sql =====
-- عمليات متقدمة: قيود دورية/إطفاء، قوائم مجمّعة بحذف التعاملات البينية، أسعار صرف وتقييم عملات، بوابة الذكاء الاصطناعي
create table if not exists acc.recurring (
  tenant_id uuid not null references acc.tenants(id) on delete cascade, id uuid not null default gen_random_uuid(), entity_id uuid not null, name text not null,
  every text not null check (every in ('month','quarter','year')), next_date date not null, end_date date, memo text not null default '', lines jsonb not null,
  active boolean not null default true, last_run date, runs int not null default 0, created_by uuid, created_at timestamptz not null default now(), primary key (tenant_id, id));
create table if not exists acc.fx_rates (
  tenant_id uuid not null references acc.tenants(id) on delete cascade, currency text not null, date date not null, rate numeric(18,6) not null check (rate > 0), created_by uuid, primary key (tenant_id, currency, date));
alter table acc.recurring enable row level security; alter table acc.fx_rates enable row level security;

create or replace function public.rec_list(p jsonb default '{}') returns jsonb language plpgsql stable security definer set search_path = public, app, acc as $$
declare t uuid := app.need('journals','view'); ents uuid[] := app.pick_ents(p);
begin return coalesce((select jsonb_agg(to_jsonb(r) - 'tenant_id' || jsonb_build_object('entity', e.name) order by r.next_date) from acc.recurring r join acc.entities e on e.tenant_id = r.tenant_id and e.id = r.entity_id where r.tenant_id = t and r.entity_id = any(ents)), '[]'::jsonb); end $$;

create or replace function public.rec_save(p jsonb) returns jsonb language plpgsql security definer set search_path = public, app, acc as $$
declare t uuid := app.need('journals','add'); rid uuid := nullif(p->>'id','')::uuid; e uuid := (p->>'entity')::uuid; dr numeric; cr numeric;
begin
  if not (e = any(app.ents())) then raise exception 'ليست لديك صلاحية على هذا الكيان'; end if;
  if jsonb_typeof(p->'lines') <> 'array' or jsonb_array_length(p->'lines') < 2 then raise exception 'القيد الدوري يحتاج سطرين على الأقل'; end if;
  select coalesce(sum((x->>'debit')::numeric),0), coalesce(sum((x->>'credit')::numeric),0) into dr, cr from jsonb_array_elements(p->'lines') x;
  if abs(dr - cr) > 0.005 or dr <= 0 then raise exception 'القيد الدوري غير متزن (مدين % / دائن %)', dr, cr; end if;
  if coalesce(trim(p->>'name'),'') = '' then raise exception 'اسم القيد الدوري مطلوب'; end if;
  if rid is null then insert into acc.recurring (tenant_id, entity_id, name, every, next_date, end_date, memo, lines, active, created_by) values (t, e, trim(p->>'name'), coalesce(p->>'every','month'), (p->>'next_date')::date, nullif(p->>'end_date','')::date, coalesce(p->>'memo',''), p->'lines', coalesce((p->>'active')::boolean, true), auth.uid()) returning id into rid;
  else update acc.recurring set entity_id = e, name = trim(p->>'name'), every = coalesce(p->>'every','month'), next_date = (p->>'next_date')::date, end_date = nullif(p->>'end_date','')::date, memo = coalesce(p->>'memo',''), lines = p->'lines', active = coalesce((p->>'active')::boolean, true) where tenant_id = t and id = rid; end if;
  perform app.audit('upsert','recurring',rid::text,'قيد دوري: ' || (p->>'name')); return jsonb_build_object('id', rid);
end $$;

create or replace function public.rec_delete(p jsonb) returns jsonb language plpgsql security definer set search_path = public, app, acc as $$
declare t uuid := app.need('journals','delete');
begin delete from acc.recurring where tenant_id = t and id = (p->>'id')::uuid and entity_id = any(app.ents()); perform app.audit('delete','recurring',p->>'id','حذف قيد دوري'); return jsonb_build_object('ok', true); end $$;

-- توليد القيود المستحقة كمسودات تمر بدورة الاعتماد المعتادة (لا ترحيل آلي)
create or replace function public.rec_run(p jsonb default '{}') returns jsonb language plpgsql security definer set search_path = public, app, acc as $$
declare t uuid := app.need('journals','add'); asof date := coalesce(nullif(p->>'asof','')::date, current_date); r acc.recurring; n int := 0; k int; step interval; out jsonb := '[]'::jsonb; j jsonb;
begin
  for r in select * from acc.recurring where tenant_id = t and active and next_date <= asof and entity_id = any(app.ents()) order by next_date loop
    step := case r.every when 'month' then interval '1 month' when 'quarter' then interval '3 months' else interval '1 year' end; k := 0;
    while r.next_date <= asof and (r.end_date is null or r.next_date <= r.end_date) and k < 36 loop
      j := public.je_save(jsonb_build_object('entity', r.entity_id, 'date', r.next_date, 'memo', r.name || coalesce(' — ' || nullif(r.memo,''), ''), 'lines', r.lines));
      out := out || jsonb_build_object('recurring', r.name, 'date', r.next_date, 'journal', j->>'id'); n := n + 1; k := k + 1;
      r.next_date := (r.next_date + step)::date; r.runs := r.runs + 1;
    end loop;
    update acc.recurring set next_date = r.next_date, runs = r.runs, last_run = asof, active = active and (end_date is null or r.next_date <= end_date) where tenant_id = t and id = r.id;
  end loop;
  perform app.audit('create','recurring','', 'توليد ' || n || ' قيد دوري حتى ' || asof); return jsonb_build_object('generated', n, 'items', out);
end $$;

-- قوائم مجمّعة: ميزان المجموعة بأعمدة الكيانات وحذف الحسابات البينية (settings.consol.elim = أكواد الحسابات)
create or replace function public.rpt_consolidated(p jsonb default '{}') returns jsonb language plpgsql stable security definer set search_path = public, app, acc as $$
declare t uuid := app.need('reports','view'); ents uuid[] := app.pick_ents(p); el text[]; e uuid; tb jsonb; cols jsonb := '[]'::jsonb; acc_map jsonb := '{}'::jsonb; x jsonb; rows jsonb; diff numeric := 0;
begin
  select coalesce(array(select jsonb_array_elements_text(coalesce(settings->'consol'->'elim','[]'::jsonb))), '{}') into el from acc.tenants where id = t;
  foreach e in array ents loop
    tb := public.rpt_trial_balance(p || jsonb_build_object('entities', jsonb_build_array(e), 'entity', null));
    cols := cols || jsonb_build_object('id', e, 'name', (select name from acc.entities where tenant_id = t and id = e));
    for x in select * from jsonb_array_elements(tb->'rows') loop
      if not (x->>'is_group')::boolean then
        acc_map := jsonb_set(acc_map, array[x->>'code'], coalesce(acc_map->(x->>'code'), jsonb_build_object('code', x->>'code', 'name', x->>'name', 'type', x->>'type', 'by', '{}'::jsonb)) || jsonb_build_object('by', coalesce(acc_map->(x->>'code')->'by','{}'::jsonb) || jsonb_build_object(e::text, (x->>'closing')::numeric)));
      end if;
    end loop;
  end loop;
  select coalesce(jsonb_agg(m order by m->>'code'), '[]') into rows from (select v || jsonb_build_object('total', (select coalesce(sum(value::numeric),0) from jsonb_each_text(v->'by')), 'elim', (v->>'code') = any(el)) m from jsonb_each(acc_map) kv(k, v)) s;
  select coalesce(sum((m->>'total')::numeric),0) into diff from jsonb_array_elements(rows) m where (m->>'elim')::boolean;
  return jsonb_build_object('entities', cols, 'rows', rows, 'elim_codes', to_jsonb(el), 'interco_diff', diff, 'balanced', abs(diff) < 0.005);
end $$;

-- أسعار الصرف وتقييم الأرصدة المفتوحة بالعملة الأجنبية
create or replace function public.fx_rate_set(p jsonb) returns jsonb language plpgsql security definer set search_path = public, app, acc as $$
declare t uuid := app.need_sys('settings');
begin if upper(coalesce(p->>'currency','')) !~ '^[A-Z]{3}$' then raise exception 'رمز العملة 3 أحرف'; end if;
  insert into acc.fx_rates (tenant_id, currency, date, rate, created_by) values (t, upper(p->>'currency'), (p->>'date')::date, (p->>'rate')::numeric, auth.uid()) on conflict (tenant_id, currency, date) do update set rate = excluded.rate;
  perform app.audit('upsert','fx_rate',upper(p->>'currency'),'سعر صرف ' || upper(p->>'currency') || ' = ' || (p->>'rate')); return jsonb_build_object('ok', true); end $$;
create or replace function public.fx_rate_list(p jsonb default '{}') returns jsonb language plpgsql stable security definer set search_path = public, app, acc as $$
declare t uuid := app.need(null, null);
begin return coalesce((select jsonb_agg(jsonb_build_object('currency', currency, 'date', date, 'rate', rate) order by date desc, currency) from (select * from acc.fx_rates where tenant_id = t order by date desc limit 200) x), '[]'::jsonb); end $$;

-- معاينة فروق التقييم (post=true ينشئ قيد تسوية مسودة) — الفواتير غير الدائنة/المدينة فقط
create or replace function public.fx_reval(p jsonb) returns jsonb language plpgsql security definer set search_path = public, app, acc as $$
declare t uuid := app.need('reports','view'); ents uuid[] := app.pick_ents(p); asof date := coalesce(nullif(p->>'asof','')::date, current_date); rows jsonb := '[]'::jsonb; i record; nr numeric; paid numeric; bb numeric; fcb numeric; d numeric; tot_ar numeric := 0; tot_ap numeric := 0; j jsonb; ar uuid; ap uuid; gl uuid := nullif(p->>'gain_loss_account','')::uuid; lines jsonb := '[]'::jsonb; e uuid;
begin
  for i in select * from acc.invoices where tenant_id = t and entity_id = any(ents) and status = 'issued' and rate <> 1 and kind in ('sales','purchase') order by date loop
    select rate into nr from acc.fx_rates where tenant_id = t and currency = i.currency and date <= asof order by date desc limit 1; if nr is null then continue; end if;
    paid := app.inv_paid(t, i.id); bb := i.total_base - paid; if bb <= 0.005 then continue; end if; fcb := bb / i.rate; d := round(fcb * nr - bb, 2);
    if abs(d) < 0.01 then continue; end if;
    rows := rows || jsonb_build_object('invoice', i.number, 'id', i.id, 'kind', i.kind, 'currency', i.currency, 'old_rate', i.rate, 'new_rate', nr, 'balance_fc', round(fcb,2), 'balance_base', round(bb,2), 'diff', d);
    if i.kind = 'sales' then tot_ar := tot_ar + d; else tot_ap := tot_ap + d; end if; e := i.entity_id;
  end loop;
  if coalesce((p->>'post')::boolean, false) and jsonb_array_length(rows) > 0 then
    if gl is null then raise exception 'حدّد حساب أرباح/خسائر فروق العملة (gain_loss_account)'; end if;
    ar := app.sysacct(t, 'AR'); ap := app.sysacct(t, 'AP');
    if tot_ar <> 0 then lines := lines || jsonb_build_object('account', ar, 'debit', greatest(tot_ar,0), 'credit', greatest(-tot_ar,0), 'description', 'تقييم عملات - عملاء'); end if;
    if tot_ap <> 0 then lines := lines || jsonb_build_object('account', ap, 'debit', greatest(-tot_ap,0), 'credit', greatest(tot_ap,0), 'description', 'تقييم عملات - موردون'); end if;
    lines := lines || jsonb_build_object('account', gl, 'debit', greatest(-(tot_ar - tot_ap),0), 'credit', greatest(tot_ar - tot_ap,0), 'description', 'فروق تقييم العملات');
    j := public.je_save(jsonb_build_object('entity', coalesce(nullif(p->>'entity','')::uuid, e), 'type', 'ADJ', 'date', asof, 'memo', 'تقييم أرصدة العملات الأجنبية بتاريخ ' || asof, 'lines', lines));
  end if;
  return jsonb_build_object('rows', rows, 'ar_diff', tot_ar, 'ap_diff', tot_ap, 'journal', j->>'id');
end $$;

-- ===== بوابة الذكاء الاصطناعي =====
create or replace function public.ai_catalog(p jsonb default '{}') returns jsonb language sql stable security definer set search_path = public, app as $$
  select jsonb_build_object('how', 'استدعِ كل دالة عبر REST: POST /rest/v1/rpc/<fn> بجسم {"p": {...}} مع Authorization: Bearer <token> (سجّل الدخول بمستخدم الذكاء). الصلاحيات تُطبَّق من دور المستخدم.', 'login', 'POST /auth/v1/token?grant_type=password {email: <user>@<company>.accounts.mohkam.app, password}', 'functions', jsonb_build_array(
    jsonb_build_object('fn','ai_brief','purpose','لقطة شاملة: مؤشرات السلامة والاستثناءات والنقدية والذمم والضريبة','params','{entity?}'),
    jsonb_build_object('fn','health_check','purpose','مؤشرات سلامة الدفاتر (ميزان، مركز مالي، أعمار، تسلسل، سلسلة التدقيق)','params','{entity?}'),
    jsonb_build_object('fn','global_find','purpose','بحث شامل برقم/اسم/مبلغ','params','{q}'),
    jsonb_build_object('fn','rpt_trial_balance','purpose','ميزان المراجعة','params','{from,to,entity?}'),
    jsonb_build_object('fn','rpt_income','purpose','قائمة الدخل','params','{from,to}'),
    jsonb_build_object('fn','rpt_balance_sheet','purpose','المركز المالي','params','{to}'),
    jsonb_build_object('fn','rpt_cashflow','purpose','التدفقات النقدية','params','{from,to}'),
    jsonb_build_object('fn','rpt_aging','purpose','أعمار الذمم','params','{kind: ar|ap, asof}'),
    jsonb_build_object('fn','rpt_vat','purpose','إقرار ضريبة القيمة المضافة','params','{from,to}'),
    jsonb_build_object('fn','rpt_consolidated','purpose','ميزان مجمّع للمجموعة بحذف البينيات','params','{from,to}'),
    jsonb_build_object('fn','tax_register','purpose','سجل الفواتير الضريبي','params','{side: sales|purchase, from, to, q}'),
    jsonb_build_object('fn','seq_gaps','purpose','فجوات تسلسل الترقيم','params','{from,to}'),
    jsonb_build_object('fn','controls_report','purpose','الاستثناءات الرقابية','params','{}'),
    jsonb_build_object('fn','audit_list','purpose','سجل التدقيق','params','{q,action,limit,offset}'),
    jsonb_build_object('fn','je_list','purpose','قائمة القيود','params','{q,status,limit,offset}'),
    jsonb_build_object('fn','inv_list','purpose','قائمة الفواتير','params','{kind,status,q}'),
    jsonb_build_object('fn','rpt_party_statement','purpose','كشف حساب عميل/مورد','params','{party,from,to}'),
    jsonb_build_object('fn','budget_vs_actual','purpose','الفعلي مقابل الموازنة','params','{id,to_month}'),
    jsonb_build_object('fn','att_missing','purpose','مستندات تنقصها مرفقات','params','{}')),
    'rules', jsonb_build_array('اقرأ فقط ما لم يُطلب غير ذلك صراحةً.', 'لا تُرحِّل ولا تعتمد؛ أنشئ مسودات فقط ودع البشر يعتمدون.', 'اذكر دائمًا رقم المستند ورابط التفاصيل عند الاستشهاد بأي رقم.'));
$$;

create or replace function public.ai_brief(p jsonb default '{}') returns jsonb language plpgsql stable security definer set search_path = public, app, acc as $$
declare res jsonb := jsonb_build_object('generated_at', now()); x jsonb;
begin
  perform app.need(null, null);
  begin x := public.health_check(p); res := res || jsonb_build_object('health', x, 'health_failed', (select coalesce(jsonb_agg(h->>'label'), '[]') from jsonb_array_elements(x) h where not (h->>'ok')::boolean)); exception when others then res := res || jsonb_build_object('health_error', sqlerrm); end;
  begin x := public.controls_report(p); res := res || jsonb_build_object('exceptions', (select coalesce(jsonb_agg(i), '[]') from jsonb_array_elements(x->'items') i where (i->>'count')::numeric > 0)); exception when others then null; end;
  begin res := res || jsonb_build_object('dashboard', public.dashboard(p)); exception when others then null; end;
  begin res := res || jsonb_build_object('vat_ytd', public.rpt_vat(p || jsonb_build_object('from', date_trunc('year', current_date)::date, 'to', current_date))); exception when others then null; end;
  begin res := res || jsonb_build_object('missing_attachments', jsonb_array_length(public.att_missing(p))); exception when others then null; end;
  return res;
end $$;
-- ===== sql/016_analytics.sql =====
-- مُحكَم للحسابات — التحليل المالي والنسب المالية (قراءة فقط من الأستاذ المرحّل)
-- كل الأرقام تُشتق من نفس الأستاذ الذي تُبنى منه القوائم، فتتطابق معها. التصنيف (متداول/غير متداول، تكلفة/مصروف…) يُستنتج
-- من نوع الحساب الفرعي ثم من أسماء المجموعات الأعلى في الشجرة، فيعمل مع أي دليل حسابات (قالب أو مستورد أو يدوي).

create or replace function app.div(a numeric, b numeric) returns numeric language sql immutable as $$
  select case when b is null or b = 0 or a is null then null else a / b end $$;

-- تصنيف الحسابات لأغراض التحليل
create or replace function app.fin_map(t uuid) returns table (account_id uuid, cls text, is_dep boolean) language sql stable security definer set search_path = public, acc as $$
  with recursive anc(id, a, d) as (
    select a.id, a.parent_id, 1 from acc.accounts a where a.tenant_id = t and a.parent_id is not null
    union all select anc.id, p.parent_id, anc.d + 1 from anc join acc.accounts p on p.tenant_id = t and p.id = anc.a where p.parent_id is not null),
  path as (select anc.id, string_agg(g.name || ' ' || g.name_en, ' | ') names from anc join acc.accounts g on g.tenant_id = t and g.id = anc.a group by anc.id),
  x as (select a.id, a.type, a.subtype, a.name || ' ' || a.name_en nm, coalesce(pa.names, '') anc_names from acc.accounts a left join path pa on pa.id = a.id where a.tenant_id = t and not a.is_group),
  y as (select x.*,
      x.anc_names ~* '(غير المتداول|طويل[ةه]? الأجل|non-?current|long-?term)' nc,
      x.anc_names ~* '(المتداول|قصير[ةه]? الأجل|current|short-?term)' and not x.anc_names ~* '(غير المتداول|non-?current)' cur,
      x.nm ~* '(قرض|قروض|loan|تمويل بنكي|مرابحة|تورق)' loanish,
      x.nm ~* '(إهلاك|استهلاك|اهلاك|depreciation|amortiz)' dep_nm
    from x)
  select y.id,
    case y.type
      when 'asset' then case
        when y.subtype in ('cash','bank') then 'cash'
        when y.subtype in ('receivable','allowance') then 'ar'
        when y.subtype = 'inventory' then 'inv'
        when y.subtype in ('fixed','fixed_asset','accum_dep','intangible','investment') or y.nc then 'nca'
        else 'oca' end
      when 'liability' then case
        when y.subtype = 'payable' then 'ap'
        when y.loanish and y.nc then 'ltd'
        when y.loanish and y.subtype = 'loan' and not y.cur then 'ltd'
        when y.loanish then 'std'
        when y.nc or y.subtype = 'provision' and not y.cur then 'ncl'
        else 'cl' end
      when 'equity' then case when y.subtype = 'retained_earnings' then 're' else 'eq' end
      when 'revenue' then case when y.anc_names ~* '(أخرى|other)' and y.subtype <> 'revenue_sales' then 'rev_oth' else 'rev' end
      else case
        when y.subtype = 'interest' or y.nm ~* '(فوائد|أعباء تمويل|اعباء تمويل|interest|finance cost)' then 'int'
        when y.subtype in ('tax','zakat') or y.nm ~* '(زكاة|ضريبة دخل|zakat|income tax)' then 'tax'
        when y.subtype = 'cogs' or y.anc_names ~* '(تكلفة الإيرادات|تكلفة المبيعات|cost of (revenue|sales|goods))' then 'cogs'
        when y.anc_names ~* '(تمويلية|أخرى|other)' and not y.anc_names ~* '(تشغيل|operating)' then 'oth'
        else 'opex' end
    end,
    (y.type = 'expense' and (y.subtype = 'depreciation' or y.dep_nm))
  from y $$;

-- أرصدة الميزانية (مدينة موجبة) مجمّعة بالتصنيف حتى تاريخ معيّن
create or replace function app.fin_bal(t uuid, ents uuid[], asof date) returns jsonb language plpgsql stable security definer set search_path = public, acc, app as $$
declare r jsonb;
begin
  select coalesce(jsonb_object_agg(k, v), '{}'::jsonb) into r from (
    select mp.cls k, sum(l.debit - l.credit) v from acc.journal_lines l join app.fin_map(t) mp on mp.account_id = l.account_id
    where l.tenant_id = t and l.posted and l.entity_id = any(ents) and l.date <= asof and mp.cls in ('cash','ar','inv','oca','nca','ap','std','cl','ltd','ncl','eq','re')
    group by 1) z;
  r := r || jsonb_build_object('pl', (select coalesce(sum(l.debit - l.credit), 0) from acc.journal_lines l join acc.accounts a on a.tenant_id = l.tenant_id and a.id = l.account_id
      where l.tenant_id = t and l.posted and l.entity_id = any(ents) and l.date <= asof and a.type in ('revenue','expense')));
  return r;
end $$;

-- حركة الفترة (بدون قيود الإقفال): إيرادات موجبة، مصروفات موجبة
create or replace function app.fin_flow(t uuid, ents uuid[], df date, dt date) returns jsonb language plpgsql stable security definer set search_path = public, acc, app as $$
declare r jsonb; dep numeric;
begin
  select coalesce(jsonb_object_agg(k, v), '{}'::jsonb) into r from (
    select mp.cls k, sum(case when mp.cls in ('rev','rev_oth') then l.credit - l.debit else l.debit - l.credit end) v
    from acc.journal_lines l join acc.journals j on j.tenant_id = l.tenant_id and j.id = l.journal_id join app.fin_map(t) mp on mp.account_id = l.account_id
    where l.tenant_id = t and l.posted and l.entity_id = any(ents) and l.date between df and dt and mp.cls in ('rev','rev_oth','cogs','opex','int','tax','oth')
      and not (j.type = 'CL' or exists (select 1 from acc.journals o where o.tenant_id = j.tenant_id and o.id = j.reversal_of and o.type = 'CL'))
    group by 1) z;
  select coalesce(sum(l.debit - l.credit), 0) into dep from acc.journal_lines l join acc.journals j on j.tenant_id = l.tenant_id and j.id = l.journal_id join app.fin_map(t) mp on mp.account_id = l.account_id
    where l.tenant_id = t and l.posted and l.entity_id = any(ents) and l.date between df and dt and mp.is_dep
      and not (j.type = 'CL' or exists (select 1 from acc.journals o where o.tenant_id = j.tenant_id and o.id = j.reversal_of and o.type = 'CL'));
  return r || jsonb_build_object('dep', dep);
end $$;

create or replace function app.n(j jsonb, k text) returns numeric language sql immutable as $$ select coalesce((j->>k)::numeric, 0) $$;

-- القيم الأساسية لفترة: الأرصدة الختامية والافتتاحية والحركة + المجاميع المشتقة
create or replace function app.fin_base(t uuid, ents uuid[], df date, dt date) returns jsonb language plpgsql stable security definer set search_path = public, acc, app as $$
declare cl jsonb := app.fin_bal(t, ents, dt); op jsonb := app.fin_bal(t, ents, df - 1); fl jsonb := app.fin_flow(t, ents, df, dt);
  ca numeric; cul numeric; ta numeric; tl numeric; eq numeric; oca numeric; ocul numeric; ota numeric; otl numeric; oeq numeric;
  rev numeric; cogs numeric; opex numeric; ebit numeric; ni numeric; interest numeric; tax numeric; roth numeric; oth numeric;
begin
  ca := app.n(cl,'cash') + app.n(cl,'ar') + app.n(cl,'inv') + app.n(cl,'oca');
  cul := -(app.n(cl,'ap') + app.n(cl,'std') + app.n(cl,'cl'));
  ta := ca + app.n(cl,'nca'); tl := cul - (app.n(cl,'ltd') + app.n(cl,'ncl'));
  eq := ta - tl;                                   -- حقوق الملكية = الأصول − الالتزامات (متطابقة محاسبيًا مع رأس المال + المبقاة + ربح الفترة)
  oca := app.n(op,'cash') + app.n(op,'ar') + app.n(op,'inv') + app.n(op,'oca'); ocul := -(app.n(op,'ap') + app.n(op,'std') + app.n(op,'cl'));
  ota := oca + app.n(op,'nca'); otl := ocul - (app.n(op,'ltd') + app.n(op,'ncl')); oeq := ota - otl;
  rev := app.n(fl,'rev'); cogs := app.n(fl,'cogs'); opex := app.n(fl,'opex'); interest := app.n(fl,'int'); tax := app.n(fl,'tax'); roth := app.n(fl,'rev_oth'); oth := app.n(fl,'oth');
  ebit := rev - cogs - opex; ni := rev + roth - cogs - opex - interest - tax - oth;
  return jsonb_build_object('from', df, 'to', dt, 'days', (dt - df + 1),
    'cash', app.n(cl,'cash'), 'ar', app.n(cl,'ar'), 'inv', app.n(cl,'inv'), 'oca', app.n(cl,'oca'), 'nca', app.n(cl,'nca'),
    'ap', -app.n(cl,'ap'), 'std', -app.n(cl,'std'), 'cl_other', -app.n(cl,'cl'), 'ltd', -app.n(cl,'ltd'), 'ncl', -app.n(cl,'ncl'),
    'ca', ca, 'cl', cul, 'ta', ta, 'tl', tl, 'equity', eq, 're', -(app.n(cl,'re') + app.n(cl,'pl')),
    'o_ar', app.n(op,'ar'), 'o_inv', app.n(op,'inv'), 'o_ap', -app.n(op,'ap'), 'o_ta', ota, 'o_equity', oeq, 'o_cash', app.n(op,'cash'),
    'revenue', rev, 'other_income', roth, 'cogs', cogs, 'opex', opex, 'interest', interest, 'tax', tax, 'other_exp', oth, 'dep', app.n(fl,'dep'),
    'gross', rev - cogs, 'ebit', ebit, 'ebitda', ebit + app.n(fl,'dep'), 'net', ni);
end $$;

-- النسب من القيم الأساسية
create or replace function app.fin_ratios_of(b jsonb) returns jsonb language plpgsql immutable as $$
declare d numeric := greatest(app.n(b,'days'), 1); ann numeric := 365 / greatest(app.n(b,'days'), 1);
  rev numeric := app.n(b,'revenue'); cogs numeric := app.n(b,'cogs'); ni numeric := app.n(b,'net'); ebit numeric := app.n(b,'ebit');
  ca numeric := app.n(b,'ca'); cl numeric := app.n(b,'cl'); ta numeric := app.n(b,'ta'); tl numeric := app.n(b,'tl'); eq numeric := app.n(b,'equity');
  debt numeric := app.n(b,'std') + app.n(b,'ltd'); avg_ta numeric; avg_eq numeric; avg_ar numeric; avg_inv numeric; avg_ap numeric;
  dso numeric; dio numeric; dpo numeric; z numeric;
begin
  avg_ta := case when app.n(b,'o_ta') <> 0 then (ta + app.n(b,'o_ta')) / 2 else ta end;
  avg_eq := case when app.n(b,'o_equity') <> 0 then (eq + app.n(b,'o_equity')) / 2 else eq end;
  avg_ar := case when app.n(b,'o_ar') <> 0 then (app.n(b,'ar') + app.n(b,'o_ar')) / 2 else app.n(b,'ar') end;
  avg_inv := case when app.n(b,'o_inv') <> 0 then (app.n(b,'inv') + app.n(b,'o_inv')) / 2 else app.n(b,'inv') end;
  avg_ap := case when app.n(b,'o_ap') <> 0 then (app.n(b,'ap') + app.n(b,'o_ap')) / 2 else app.n(b,'ap') end;
  dso := app.div(avg_ar, rev) * d; dio := app.div(avg_inv, cogs) * d; dpo := app.div(avg_ap, cogs) * d;
  z := case when ta <> 0 and tl <> 0 then 6.56 * ((ca - cl) / ta) + 3.26 * (app.n(b,'re') / ta) + 6.72 * ((ebit * ann) / ta) + 1.05 * (eq / tl) end;
  return jsonb_build_object(
    'current_ratio', app.div(ca, cl), 'quick_ratio', app.div(app.n(b,'cash') + app.n(b,'ar'), cl), 'cash_ratio', app.div(app.n(b,'cash'), cl),
    'working_capital', ca - cl, 'wc_to_assets', app.div(ca - cl, ta),
    'gross_margin', app.div(rev - cogs, rev), 'operating_margin', app.div(ebit, rev), 'ebitda_margin', app.div(app.n(b,'ebitda'), rev), 'net_margin', app.div(ni, rev),
    'cogs_ratio', app.div(cogs, rev), 'opex_ratio', app.div(app.n(b,'opex'), rev),
    'roa', app.div(ni, avg_ta), 'roe', app.div(ni, avg_eq), 'roa_ann', app.div(ni, avg_ta) * ann, 'roe_ann', app.div(ni, avg_eq) * ann, 'roce', app.div(ebit, ta - cl),
    'dso', dso, 'dio', dio, 'dpo', dpo, 'ccc', case when dso is not null then dso + coalesce(dio, 0) - coalesce(dpo, 0) end,
    'asset_turnover', app.div(rev, avg_ta), 'ar_turnover', app.div(rev, avg_ar), 'inventory_turnover', app.div(cogs, avg_inv), 'fixed_turnover', app.div(rev, app.n(b,'nca')),
    'debt_to_equity', app.div(debt, eq), 'liab_to_equity', app.div(tl, eq), 'debt_to_assets', app.div(tl, ta), 'equity_ratio', app.div(eq, ta), 'equity_multiplier', app.div(avg_ta, avg_eq),
    'interest_cover', app.div(ebit, app.n(b,'interest')), 'net_debt', debt - app.n(b,'cash'), 'net_debt_to_ebitda', app.div(debt - app.n(b,'cash'), app.n(b,'ebitda') * ann),
    'altman_z', z,
    'dupont', jsonb_build_object('net_margin', app.div(ni, rev), 'asset_turnover', app.div(rev, avg_ta), 'equity_multiplier', app.div(avg_ta, avg_eq), 'roe', app.div(ni, avg_eq)));
end $$;

-- سلسلة شهرية (آخر n شهرًا) لأهم الأرقام والنسب
create or replace function app.fin_series(t uuid, ents uuid[], dt date, n int) returns jsonb language plpgsql stable security definer set search_path = public, acc, app as $$
declare res jsonb;
begin
  with mp as (select * from app.fin_map(t)),
  mm as (select date_trunc('month', l.date)::date mo, mp.cls,
      sum(l.debit - l.credit) net_all,
      sum(case when not (j.type = 'CL' or exists (select 1 from acc.journals o where o.tenant_id = j.tenant_id and o.id = j.reversal_of and o.type = 'CL')) then l.debit - l.credit else 0 end) net_x
    from acc.journal_lines l join acc.journals j on j.tenant_id = l.tenant_id and j.id = l.journal_id join mp on mp.account_id = l.account_id
    where l.tenant_id = t and l.posted and l.entity_id = any(ents) and l.date <= dt group by 1, 2),
  ms as (select (date_trunc('month', dt) - (g || ' month')::interval)::date m from generate_series(0, greatest(n, 1) - 1) g),
  s as (select ms.m,
      coalesce(sum(mm.net_all) filter (where mm.mo <= ms.m and mm.cls = 'cash'), 0) cash, coalesce(sum(mm.net_all) filter (where mm.mo <= ms.m and mm.cls = 'ar'), 0) ar,
      coalesce(sum(mm.net_all) filter (where mm.mo <= ms.m and mm.cls = 'inv'), 0) inv, coalesce(sum(mm.net_all) filter (where mm.mo <= ms.m and mm.cls = 'oca'), 0) oca,
      coalesce(sum(mm.net_all) filter (where mm.mo <= ms.m and mm.cls = 'nca'), 0) nca,
      -coalesce(sum(mm.net_all) filter (where mm.mo <= ms.m and mm.cls in ('ap','std','cl')), 0) cl,
      -coalesce(sum(mm.net_all) filter (where mm.mo <= ms.m and mm.cls in ('ltd','ncl')), 0) ncl,
      coalesce(sum(-mm.net_x) filter (where mm.mo = ms.m and mm.cls = 'rev'), 0) rev, coalesce(sum(-mm.net_x) filter (where mm.mo = ms.m and mm.cls = 'rev_oth'), 0) roth,
      coalesce(sum(mm.net_x) filter (where mm.mo = ms.m and mm.cls = 'cogs'), 0) cogs, coalesce(sum(mm.net_x) filter (where mm.mo = ms.m and mm.cls = 'opex'), 0) opex,
      coalesce(sum(mm.net_x) filter (where mm.mo = ms.m and mm.cls in ('int','tax','oth')), 0) below
    from ms cross join mm group by ms.m),
  s2 as (select s.*, (cash + ar + inv + oca) ca, (cash + ar + inv + oca + nca) ta, (cl + ncl) tl, (rev + roth - cogs - opex - below) net from s)
  select coalesce(jsonb_agg(jsonb_build_object('month', to_char(m, 'YYYY-MM'), 'revenue', rev, 'cogs', cogs, 'opex', opex, 'net', net, 'cash', cash, 'ar', ar, 'inv', inv,
      'ca', ca, 'cl', cl, 'ta', ta, 'tl', tl, 'equity', ta - tl, 'current_ratio', app.div(ca, cl), 'gross_margin', app.div(rev - cogs, rev), 'net_margin', app.div(net, rev),
      'debt_ratio', app.div(tl, ta)) order by m), '[]'::jsonb) into res from s2;
  return res;
end $$;

-- الواجهة: التحليل المالي لفترة مع مقارنة (افتراضيًا: نفس الفترة من السنة السابقة)
create or replace function public.fin_ratios(p jsonb default '{}') returns jsonb language plpgsql stable security definer set search_path = public, app, acc as $$
declare t uuid := app.need('reports','view'); ents uuid[] := app.pick_ents(p);
  dt date := coalesce(nullif(p->>'to','')::date, current_date); df date := coalesce(nullif(p->>'from','')::date, date_trunc('year', dt)::date);
  cf date := coalesce(nullif(p->>'cmp_from','')::date, (df - interval '1 year')::date); ct date := coalesce(nullif(p->>'cmp_to','')::date, (dt - interval '1 year')::date);
  cur jsonb; pri jsonb; rc jsonb; rp jsonb; cfl jsonb; cfp jsonb; sub jsonb := p - 'from' - 'to' - 'cmp_from' - 'cmp_to';
begin
  if df > dt or cf > ct then raise exception 'الفترة غير صحيحة'; end if;
  cur := app.fin_base(t, ents, df, dt); pri := app.fin_base(t, ents, cf, ct); rc := app.fin_ratios_of(cur); rp := app.fin_ratios_of(pri);
  begin cfl := public.rpt_cashflow(sub || jsonb_build_object('from', df, 'to', dt)); cfp := public.rpt_cashflow(sub || jsonb_build_object('from', cf, 'to', ct));
  exception when others then cfl := null; cfp := null; end;
  return jsonb_build_object('from', df, 'to', dt, 'cmp_from', cf, 'cmp_to', ct,
    'cur', cur, 'prior', pri, 'ratios', rc || jsonb_build_object('ocf', app.n(cfl,'operating'), 'icf', app.n(cfl,'investing'), 'fcf', app.n(cfl,'operating') + app.n(cfl,'investing'),
        'ocf_to_ni', app.div(app.n(cfl,'operating'), app.n(cur,'net')), 'ocf_to_cl', app.div(app.n(cfl,'operating'), app.n(cur,'cl'))),
    'prior_ratios', rp || jsonb_build_object('ocf', app.n(cfp,'operating'), 'icf', app.n(cfp,'investing'), 'fcf', app.n(cfp,'operating') + app.n(cfp,'investing'),
        'ocf_to_ni', app.div(app.n(cfp,'operating'), app.n(pri,'net')), 'ocf_to_cl', app.div(app.n(cfp,'operating'), app.n(pri,'cl'))),
    'growth', jsonb_build_object('revenue', app.div(app.n(cur,'revenue') - app.n(pri,'revenue'), abs(app.n(pri,'revenue'))), 'net', app.div(app.n(cur,'net') - app.n(pri,'net'), abs(app.n(pri,'net'))),
        'assets', app.div(app.n(cur,'ta') - app.n(pri,'ta'), abs(app.n(pri,'ta'))), 'equity', app.div(app.n(cur,'equity') - app.n(pri,'equity'), abs(app.n(pri,'equity')))),
    'cash_flow', jsonb_build_object('opening', app.n(cfl,'opening_cash'), 'closing', app.n(cfl,'closing_cash'), 'operating', app.n(cfl,'operating'), 'investing', app.n(cfl,'investing'), 'financing', app.n(cfl,'financing')),
    'series', case when coalesce((p->>'trend')::boolean, true) then app.fin_series(t, ents, dt, least(greatest(coalesce(nullif(p->>'months','')::int, 12), 3), 36)) else '[]'::jsonb end);
end $$;

-- مقارنة الشركات (الكيانات) داخل المجموعة: لكل شركة أهم الأرقام والنسب + إجمالي المجموعة
create or replace function public.fin_by_entity(p jsonb default '{}') returns jsonb language plpgsql stable security definer set search_path = public, app, acc as $$
declare t uuid := app.need('reports','view'); ents uuid[] := app.pick_ents(p);
  dt date := coalesce(nullif(p->>'to','')::date, current_date); df date := coalesce(nullif(p->>'from','')::date, date_trunc('year', dt)::date); e record; rows jsonb := '[]'::jsonb; b jsonb;
begin
  for e in select id, code, name from acc.entities where tenant_id = t and id = any(ents) and active order by code loop
    b := app.fin_base(t, array[e.id], df, dt);
    rows := rows || jsonb_build_array(jsonb_build_object('id', e.id, 'code', e.code, 'name', e.name, 'base', b, 'ratios', app.fin_ratios_of(b)));
  end loop;
  b := app.fin_base(t, ents, df, dt);
  return jsonb_build_object('from', df, 'to', dt, 'rows', rows, 'group', jsonb_build_object('base', b, 'ratios', app.fin_ratios_of(b)));
end $$;

-- بنود القوائم بتصنيف التحليل (للتحليل الرأسي والأفقي): الدخل للفترة، والمركز المالي في نهاية الفترة، مع المقارنة
create or replace function public.fin_lines(p jsonb default '{}') returns jsonb language plpgsql stable security definer set search_path = public, app, acc as $$
declare t uuid := app.need('reports','view'); ents uuid[] := app.pick_ents(p);
  dt date := coalesce(nullif(p->>'to','')::date, current_date); df date := coalesce(nullif(p->>'from','')::date, date_trunc('year', dt)::date);
  cf date := coalesce(nullif(p->>'cmp_from','')::date, (df - interval '1 year')::date); ct date := coalesce(nullif(p->>'cmp_to','')::date, (dt - interval '1 year')::date);
  pl jsonb; bs jsonb; un numeric; unc numeric;
begin
  select coalesce(jsonb_agg(jsonb_build_object('code', a.code, 'name', a.name, 'cls', mp.cls, 'amount', x.cur, 'cmp', x.prv) order by a.code), '[]'::jsonb) into pl
  from (select l.account_id,
      coalesce(sum(case when l.date between df and dt then case when a.type = 'revenue' then l.credit - l.debit else l.debit - l.credit end end), 0) cur,
      coalesce(sum(case when l.date between cf and ct then case when a.type = 'revenue' then l.credit - l.debit else l.debit - l.credit end end), 0) prv
    from acc.journal_lines l join acc.journals j on j.tenant_id = l.tenant_id and j.id = l.journal_id join acc.accounts a on a.tenant_id = l.tenant_id and a.id = l.account_id
    where l.tenant_id = t and l.posted and l.entity_id = any(ents) and a.type in ('revenue','expense') and (l.date between df and dt or l.date between cf and ct)
      and not (j.type = 'CL' or exists (select 1 from acc.journals o where o.tenant_id = j.tenant_id and o.id = j.reversal_of and o.type = 'CL'))
    group by 1) x join acc.accounts a on a.tenant_id = t and a.id = x.account_id join app.fin_map(t) mp on mp.account_id = a.id where x.cur <> 0 or x.prv <> 0;
  select coalesce(jsonb_agg(jsonb_build_object('code', a.code, 'name', a.name, 'cls', mp.cls, 'amount', x.cur, 'cmp', x.prv) order by a.code), '[]'::jsonb) into bs
  from (select l.account_id,
      coalesce(sum(case when l.date <= dt then case when a.type = 'asset' then l.debit - l.credit else l.credit - l.debit end end), 0) cur,
      coalesce(sum(case when l.date <= ct then case when a.type = 'asset' then l.debit - l.credit else l.credit - l.debit end end), 0) prv
    from acc.journal_lines l join acc.accounts a on a.tenant_id = l.tenant_id and a.id = l.account_id
    where l.tenant_id = t and l.posted and l.entity_id = any(ents) and a.type in ('asset','liability','equity') and l.date <= greatest(dt, ct) group by 1) x
    join acc.accounts a on a.tenant_id = t and a.id = x.account_id join app.fin_map(t) mp on mp.account_id = a.id where x.cur <> 0 or x.prv <> 0;
  select coalesce(sum(case when l.date <= dt then l.credit - l.debit end), 0), coalesce(sum(case when l.date <= ct then l.credit - l.debit end), 0) into un, unc
    from acc.journal_lines l join acc.accounts a on a.tenant_id = l.tenant_id and a.id = l.account_id where l.tenant_id = t and l.posted and l.entity_id = any(ents) and a.type in ('revenue','expense');
  return jsonb_build_object('from', df, 'to', dt, 'cmp_from', cf, 'cmp_to', ct, 'pl', pl, 'bs', bs, 'unclosed', un, 'cmp_unclosed', unc);
end $$;
-- ===== sql/090_templates.sql =====
-- مُولَّد آليًا من db/templates/build_templates.py — لا تُعدَّل يدويًا
create table if not exists app.coa_templates (key text primary key, name text not null, description text not null default '', rows jsonb not null);
insert into app.coa_templates (key,name,description,rows) values ('general','عام — خدمات وتجارة','شجرة حسابات عربية قياسية (متوافقة مع المعايير الدولية) للخدمات والتجارة','[{"code": "1", "name": "الأصول", "name_en": "Assets", "type": "asset", "subtype": "general", "is_group": true, "system_key": null}, {"code": "11", "name": "الأصول المتداولة", "name_en": "Current assets", "type": "asset", "subtype": "general", "is_group": true, "system_key": null, "parent_code": "1"}, {"code": "1101", "name": "النقد وما في حكمه", "name_en": "Cash and cash equivalents", "type": "asset", "subtype": "general", "is_group": true, "system_key": null, "parent_code": "11"}, {"code": "110101", "name": "الصندوق الرئيسي", "name_en": "Main cash on hand", "type": "asset", "subtype": "cash", "is_group": false, "system_key": "CASH", "parent_code": "1101"}, {"code": "110102", "name": "عهد وسلف نقدية", "name_en": "Petty cash and imprest", "type": "asset", "subtype": "cash", "is_group": false, "system_key": null, "parent_code": "1101"}, {"code": "110103", "name": "البنك — الحساب الجاري الرئيسي", "name_en": "Bank — main current account", "type": "asset", "subtype": "bank", "is_group": false, "system_key": "BANK", "parent_code": "1101"}, {"code": "110104", "name": "البنك — حساب ثانٍ", "name_en": "Bank — secondary account", "type": "asset", "subtype": "bank", "is_group": false, "system_key": null, "parent_code": "1101"}, {"code": "110105", "name": "شيكات تحت التحصيل", "name_en": "Cheques under collection", "type": "asset", "subtype": "general", "is_group": false, "system_key": "CHEQUES_IN", "parent_code": "1101"}, {"code": "1102", "name": "العملاء والذمم المدينة", "name_en": "Trade and other receivables", "type": "asset", "subtype": "general", "is_group": true, "system_key": null, "parent_code": "11"}, {"code": "110201", "name": "العملاء (ذمم مدينة تجارية)", "name_en": "Trade receivables", "type": "asset", "subtype": "receivable", "is_group": false, "system_key": "AR", "parent_code": "1102"}, {"code": "110202", "name": "أوراق القبض", "name_en": "Notes receivable", "type": "asset", "subtype": "receivable", "is_group": false, "system_key": null, "parent_code": "1102"}, {"code": "110203", "name": "مخصص الديون المشكوك في تحصيلها", "name_en": "Allowance for doubtful debts", "type": "asset", "subtype": "allowance", "is_group": false, "system_key": null, "parent_code": "1102"}, {"code": "110204", "name": "سلف وذمم الموظفين", "name_en": "Employee advances and receivables", "type": "asset", "subtype": "receivable", "is_group": false, "system_key": null, "parent_code": "1102"}, {"code": "1103", "name": "المخزون", "name_en": "Inventory", "type": "asset", "subtype": "general", "is_group": true, "system_key": null, "parent_code": "11"}, {"code": "110301", "name": "مخزون البضاعة", "name_en": "Merchandise inventory", "type": "asset", "subtype": "inventory", "is_group": false, "system_key": "INVENTORY", "parent_code": "1103"}, {"code": "1104", "name": "مصروفات مقدمة وأرصدة مدينة أخرى", "name_en": "Prepayments and other current assets", "type": "asset", "subtype": "general", "is_group": true, "system_key": null, "parent_code": "11"}, {"code": "110401", "name": "مصروفات مدفوعة مقدمًا", "name_en": "Prepaid expenses", "type": "asset", "subtype": "prepaid", "is_group": false, "system_key": null, "parent_code": "1104"}, {"code": "110402", "name": "دفعات مقدمة للموردين", "name_en": "Advances to suppliers", "type": "asset", "subtype": "general", "is_group": false, "system_key": "SUPPLIER_ADV", "parent_code": "1104"}, {"code": "110403", "name": "تأمينات مستردة وودائع", "name_en": "Refundable deposits", "type": "asset", "subtype": "general", "is_group": false, "system_key": null, "parent_code": "1104"}, {"code": "110404", "name": "ضريبة القيمة المضافة — مدخلات", "name_en": "VAT — input", "type": "asset", "subtype": "vat_input", "is_group": false, "system_key": "VAT_IN", "parent_code": "1104"}, {"code": "110405", "name": "ضريبة القيمة المضافة — مستردة", "name_en": "VAT — refundable", "type": "asset", "subtype": "vat_receivable", "is_group": false, "system_key": null, "parent_code": "1104"}, {"code": "110406", "name": "عهد الموظفين", "name_en": "Employee custodies", "type": "asset", "subtype": "general", "is_group": false, "system_key": null, "parent_code": "1104"}, {"code": "110407", "name": "حسابات الشركات الشقيقة (مدينة)", "name_en": "Intercompany receivables", "type": "asset", "subtype": "intercompany", "is_group": false, "system_key": null, "parent_code": "1104"}, {"code": "12", "name": "الأصول غير المتداولة", "name_en": "Non-current assets", "type": "asset", "subtype": "general", "is_group": true, "system_key": null, "parent_code": "1"}, {"code": "1201", "name": "الممتلكات والآلات والمعدات", "name_en": "Property, plant and equipment", "type": "asset", "subtype": "general", "is_group": true, "system_key": null, "parent_code": "12"}, {"code": "120101", "name": "أراضي", "name_en": "Land", "type": "asset", "subtype": "fixed_asset", "is_group": false, "system_key": null, "parent_code": "1201"}, {"code": "120102", "name": "مبانٍ وإنشاءات", "name_en": "Buildings", "type": "asset", "subtype": "fixed_asset", "is_group": false, "system_key": null, "parent_code": "1201"}, {"code": "120103", "name": "آلات ومعدات", "name_en": "Machinery and equipment", "type": "asset", "subtype": "fixed_asset", "is_group": false, "system_key": null, "parent_code": "1201"}, {"code": "120104", "name": "أثاث ومفروشات", "name_en": "Furniture and fixtures", "type": "asset", "subtype": "fixed_asset", "is_group": false, "system_key": null, "parent_code": "1201"}, {"code": "120105", "name": "سيارات ومركبات", "name_en": "Vehicles", "type": "asset", "subtype": "fixed_asset", "is_group": false, "system_key": null, "parent_code": "1201"}, {"code": "120106", "name": "أجهزة حاسب وبرامج", "name_en": "Computers and software", "type": "asset", "subtype": "fixed_asset", "is_group": false, "system_key": null, "parent_code": "1201"}, {"code": "120107", "name": "أعمال رأسمالية تحت التنفيذ", "name_en": "Capital work in progress", "type": "asset", "subtype": "fixed_asset", "is_group": false, "system_key": null, "parent_code": "1201"}, {"code": "1202", "name": "مجمع الإهلاك", "name_en": "Accumulated depreciation", "type": "asset", "subtype": "general", "is_group": true, "system_key": null, "parent_code": "12"}, {"code": "120201", "name": "مجمع إهلاك المباني", "name_en": "Acc. dep. — buildings", "type": "asset", "subtype": "accum_dep", "is_group": false, "system_key": null, "parent_code": "1202"}, {"code": "120202", "name": "مجمع إهلاك الآلات والمعدات", "name_en": "Acc. dep. — machinery", "type": "asset", "subtype": "accum_dep", "is_group": false, "system_key": null, "parent_code": "1202"}, {"code": "120203", "name": "مجمع إهلاك الأثاث", "name_en": "Acc. dep. — furniture", "type": "asset", "subtype": "accum_dep", "is_group": false, "system_key": null, "parent_code": "1202"}, {"code": "120204", "name": "مجمع إهلاك السيارات", "name_en": "Acc. dep. — vehicles", "type": "asset", "subtype": "accum_dep", "is_group": false, "system_key": null, "parent_code": "1202"}, {"code": "120205", "name": "مجمع إهلاك الأجهزة والبرامج", "name_en": "Acc. dep. — computers", "type": "asset", "subtype": "accum_dep", "is_group": false, "system_key": null, "parent_code": "1202"}, {"code": "1203", "name": "أصول غير ملموسة واستثمارات", "name_en": "Intangibles and investments", "type": "asset", "subtype": "general", "is_group": true, "system_key": null, "parent_code": "12"}, {"code": "120301", "name": "أصول غير ملموسة", "name_en": "Intangible assets", "type": "asset", "subtype": "intangible", "is_group": false, "system_key": null, "parent_code": "1203"}, {"code": "120302", "name": "استثمارات طويلة الأجل", "name_en": "Long-term investments", "type": "asset", "subtype": "investment", "is_group": false, "system_key": null, "parent_code": "1203"}, {"code": "2", "name": "الخصوم", "name_en": "Liabilities", "type": "liability", "subtype": "general", "is_group": true, "system_key": null}, {"code": "21", "name": "الخصوم المتداولة", "name_en": "Current liabilities", "type": "liability", "subtype": "general", "is_group": true, "system_key": null, "parent_code": "2"}, {"code": "2101", "name": "الموردون والذمم الدائنة", "name_en": "Trade and other payables", "type": "liability", "subtype": "general", "is_group": true, "system_key": null, "parent_code": "21"}, {"code": "210101", "name": "الموردون", "name_en": "Trade payables", "type": "liability", "subtype": "payable", "is_group": false, "system_key": "AP", "parent_code": "2101"}, {"code": "210102", "name": "أوراق الدفع", "name_en": "Notes payable", "type": "liability", "subtype": "payable", "is_group": false, "system_key": null, "parent_code": "2101"}, {"code": "210103", "name": "مقاولو الباطن", "name_en": "Subcontractors", "type": "liability", "subtype": "payable", "is_group": false, "system_key": null, "parent_code": "2101"}, {"code": "2102", "name": "مستحقات وخصوم أخرى", "name_en": "Accruals and other liabilities", "type": "liability", "subtype": "general", "is_group": true, "system_key": null, "parent_code": "21"}, {"code": "210201", "name": "مصروفات مستحقة", "name_en": "Accrued expenses", "type": "liability", "subtype": "accrued", "is_group": false, "system_key": null, "parent_code": "2102"}, {"code": "210202", "name": "رواتب وأجور مستحقة", "name_en": "Accrued salaries", "type": "liability", "subtype": "accrued", "is_group": false, "system_key": "PAYROLL_PAYABLE", "parent_code": "2102"}, {"code": "210203", "name": "دفعات مقدمة من العملاء", "name_en": "Customer advances", "type": "liability", "subtype": "general", "is_group": false, "system_key": "CUSTOMER_ADV", "parent_code": "2102"}, {"code": "210204", "name": "إيرادات مقدمة", "name_en": "Unearned revenue", "type": "liability", "subtype": "general", "is_group": false, "system_key": null, "parent_code": "2102"}, {"code": "2103", "name": "الضرائب والرسوم المستحقة", "name_en": "Taxes and levies payable", "type": "liability", "subtype": "general", "is_group": true, "system_key": null, "parent_code": "21"}, {"code": "210301", "name": "ضريبة القيمة المضافة — مخرجات", "name_en": "VAT — output", "type": "liability", "subtype": "vat_output", "is_group": false, "system_key": "VAT_OUT", "parent_code": "2103"}, {"code": "210302", "name": "ضريبة القيمة المضافة — مستحقة السداد", "name_en": "VAT — payable", "type": "liability", "subtype": "vat_payable", "is_group": false, "system_key": "VAT_PAY", "parent_code": "2103"}, {"code": "210303", "name": "ضريبة الاستقطاع المستحقة", "name_en": "Withholding tax payable", "type": "liability", "subtype": "general", "is_group": false, "system_key": null, "parent_code": "2103"}, {"code": "210304", "name": "زكاة وضريبة دخل مستحقة", "name_en": "Zakat and income tax payable", "type": "liability", "subtype": "general", "is_group": false, "system_key": null, "parent_code": "2103"}, {"code": "210305", "name": "مستحقات التأمينات الاجتماعية", "name_en": "GOSI payable", "type": "liability", "subtype": "general", "is_group": false, "system_key": null, "parent_code": "2103"}, {"code": "2104", "name": "قروض قصيرة الأجل", "name_en": "Short-term borrowings", "type": "liability", "subtype": "general", "is_group": true, "system_key": null, "parent_code": "21"}, {"code": "210401", "name": "قروض وتسهيلات بنكية قصيرة الأجل", "name_en": "Short-term loans and facilities", "type": "liability", "subtype": "loan", "is_group": false, "system_key": null, "parent_code": "2104"}, {"code": "210402", "name": "الجزء المتداول من القروض طويلة الأجل", "name_en": "Current portion of long-term loans", "type": "liability", "subtype": "loan", "is_group": false, "system_key": null, "parent_code": "2104"}, {"code": "2105", "name": "حسابات وسيطة", "name_en": "Clearing and intercompany", "type": "liability", "subtype": "general", "is_group": true, "system_key": null, "parent_code": "21"}, {"code": "210501", "name": "جاري الشركاء", "name_en": "Partners current accounts", "type": "liability", "subtype": "general", "is_group": false, "system_key": null, "parent_code": "2105"}, {"code": "210601", "name": "حسابات الشركات الشقيقة (دائنة)", "name_en": "Intercompany payables", "type": "liability", "subtype": "intercompany", "is_group": false, "system_key": null, "parent_code": "21"}, {"code": "210701", "name": "حساب تسويات معلّق", "name_en": "Suspense account", "type": "liability", "subtype": "general", "is_group": false, "system_key": "SUSPENSE", "parent_code": "21"}, {"code": "22", "name": "الخصوم غير المتداولة", "name_en": "Non-current liabilities", "type": "liability", "subtype": "general", "is_group": true, "system_key": null, "parent_code": "2"}, {"code": "2201", "name": "مخصص مكافأة نهاية الخدمة", "name_en": "End-of-service provision", "type": "liability", "subtype": "provision", "is_group": false, "system_key": null, "parent_code": "22"}, {"code": "2202", "name": "قروض طويلة الأجل", "name_en": "Long-term loans", "type": "liability", "subtype": "loan", "is_group": false, "system_key": null, "parent_code": "22"}, {"code": "3", "name": "حقوق الملكية", "name_en": "Equity", "type": "equity", "subtype": "general", "is_group": true, "system_key": null}, {"code": "31", "name": "رأس المال", "name_en": "Capital", "type": "equity", "subtype": "general", "is_group": true, "system_key": null, "parent_code": "3"}, {"code": "3101", "name": "رأس المال المدفوع", "name_en": "Paid-in capital", "type": "equity", "subtype": "capital", "is_group": false, "system_key": "CAPITAL", "parent_code": "31"}, {"code": "32", "name": "الاحتياطيات", "name_en": "Reserves", "type": "equity", "subtype": "general", "is_group": true, "system_key": null, "parent_code": "3"}, {"code": "3201", "name": "احتياطي نظامي", "name_en": "Statutory reserve", "type": "equity", "subtype": "equity", "is_group": false, "system_key": null, "parent_code": "32"}, {"code": "33", "name": "الأرباح المبقاة", "name_en": "Retained earnings", "type": "equity", "subtype": "general", "is_group": true, "system_key": null, "parent_code": "3"}, {"code": "3301", "name": "أرباح (خسائر) مبقاة", "name_en": "Retained earnings (accumulated losses)", "type": "equity", "subtype": "retained_earnings", "is_group": false, "system_key": "RE", "parent_code": "33"}, {"code": "3302", "name": "مسحوبات الشركاء", "name_en": "Partners drawings", "type": "equity", "subtype": "drawings", "is_group": false, "system_key": null, "parent_code": "33"}, {"code": "3303", "name": "توزيعات أرباح", "name_en": "Dividends", "type": "equity", "subtype": "dividends", "is_group": false, "system_key": null, "parent_code": "33"}, {"code": "4", "name": "الإيرادات", "name_en": "Revenue", "type": "revenue", "subtype": "general", "is_group": true, "system_key": null}, {"code": "41", "name": "إيرادات النشاط", "name_en": "Operating revenue", "type": "revenue", "subtype": "general", "is_group": true, "system_key": null, "parent_code": "4"}, {"code": "4101", "name": "إيرادات المبيعات", "name_en": "Sales revenue", "type": "revenue", "subtype": "revenue_sales", "is_group": false, "system_key": "SALES", "parent_code": "41"}, {"code": "4102", "name": "إيرادات الخدمات", "name_en": "Service revenue", "type": "revenue", "subtype": "revenue_sales", "is_group": false, "system_key": "SERVICES", "parent_code": "41"}, {"code": "4103", "name": "إيرادات العقود والمشاريع", "name_en": "Contract revenue", "type": "revenue", "subtype": "revenue_sales", "is_group": false, "system_key": null, "parent_code": "41"}, {"code": "4104", "name": "مردودات ومسموحات المبيعات", "name_en": "Sales returns and allowances", "type": "revenue", "subtype": "contra_revenue", "is_group": false, "system_key": null, "parent_code": "41"}, {"code": "4105", "name": "خصم مسموح به", "name_en": "Sales discounts", "type": "revenue", "subtype": "contra_revenue", "is_group": false, "system_key": null, "parent_code": "41"}, {"code": "42", "name": "إيرادات أخرى", "name_en": "Other income", "type": "revenue", "subtype": "general", "is_group": true, "system_key": null, "parent_code": "4"}, {"code": "4201", "name": "إيرادات متنوعة", "name_en": "Miscellaneous income", "type": "revenue", "subtype": "general", "is_group": false, "system_key": null, "parent_code": "42"}, {"code": "4202", "name": "أرباح بيع أصول ثابتة", "name_en": "Gain on disposal of assets", "type": "revenue", "subtype": "general", "is_group": false, "system_key": "ASSET_GAIN", "parent_code": "42"}, {"code": "4203", "name": "أرباح فروق عملة", "name_en": "Foreign exchange gains", "type": "revenue", "subtype": "general", "is_group": false, "system_key": "FX_GAIN", "parent_code": "42"}, {"code": "4204", "name": "إيرادات فوائد وعمولات", "name_en": "Interest and commission income", "type": "revenue", "subtype": "general", "is_group": false, "system_key": null, "parent_code": "42"}, {"code": "5", "name": "تكلفة الإيرادات", "name_en": "Cost of revenue", "type": "expense", "subtype": "general", "is_group": true, "system_key": null}, {"code": "51", "name": "تكلفة المبيعات والخدمات", "name_en": "Cost of sales and services", "type": "expense", "subtype": "general", "is_group": true, "system_key": null, "parent_code": "5"}, {"code": "5101", "name": "تكلفة البضاعة المباعة", "name_en": "Cost of goods sold", "type": "expense", "subtype": "cogs", "is_group": false, "system_key": "COGS", "parent_code": "51"}, {"code": "5102", "name": "تكلفة الخدمات", "name_en": "Cost of services", "type": "expense", "subtype": "cogs", "is_group": false, "system_key": null, "parent_code": "51"}, {"code": "5103", "name": "أجور مباشرة", "name_en": "Direct labour", "type": "expense", "subtype": "cogs", "is_group": false, "system_key": null, "parent_code": "51"}, {"code": "5104", "name": "مشتريات ومواد مباشرة", "name_en": "Direct purchases and materials", "type": "expense", "subtype": "cogs", "is_group": false, "system_key": "PURCHASES", "parent_code": "51"}, {"code": "5105", "name": "مقاولو الباطن (تكلفة)", "name_en": "Subcontractor costs", "type": "expense", "subtype": "cogs", "is_group": false, "system_key": null, "parent_code": "51"}, {"code": "5106", "name": "فروقات جرد المخزون", "name_en": "Inventory count differences", "type": "expense", "subtype": "cogs", "is_group": false, "system_key": null, "parent_code": "51"}, {"code": "6", "name": "مصروفات التشغيل", "name_en": "Operating expenses", "type": "expense", "subtype": "general", "is_group": true, "system_key": null}, {"code": "61", "name": "مصروفات إدارية وعمومية", "name_en": "General and administrative", "type": "expense", "subtype": "general", "is_group": true, "system_key": null, "parent_code": "6"}, {"code": "6101", "name": "رواتب وأجور", "name_en": "Salaries and wages", "type": "expense", "subtype": "general", "is_group": false, "system_key": "SALARIES", "parent_code": "61"}, {"code": "6102", "name": "بدلات ومزايا", "name_en": "Allowances and benefits", "type": "expense", "subtype": "general", "is_group": false, "system_key": null, "parent_code": "61"}, {"code": "6103", "name": "تأمينات اجتماعية (حصة صاحب العمل)", "name_en": "GOSI — employer share", "type": "expense", "subtype": "general", "is_group": false, "system_key": null, "parent_code": "61"}, {"code": "6104", "name": "مكافأة نهاية الخدمة", "name_en": "End-of-service benefit expense", "type": "expense", "subtype": "general", "is_group": false, "system_key": null, "parent_code": "61"}, {"code": "6105", "name": "إيجارات", "name_en": "Rent", "type": "expense", "subtype": "general", "is_group": false, "system_key": null, "parent_code": "61"}, {"code": "6106", "name": "كهرباء وماء واتصالات", "name_en": "Utilities and communications", "type": "expense", "subtype": "general", "is_group": false, "system_key": null, "parent_code": "61"}, {"code": "6107", "name": "صيانة وإصلاح", "name_en": "Repairs and maintenance", "type": "expense", "subtype": "general", "is_group": false, "system_key": null, "parent_code": "61"}, {"code": "6108", "name": "رسوم حكومية وتراخيص واشتراكات", "name_en": "Government fees, licences and subscriptions", "type": "expense", "subtype": "general", "is_group": false, "system_key": null, "parent_code": "61"}, {"code": "6109", "name": "أتعاب مهنية واستشارات", "name_en": "Professional fees", "type": "expense", "subtype": "general", "is_group": false, "system_key": null, "parent_code": "61"}, {"code": "6110", "name": "قرطاسية ومطبوعات", "name_en": "Stationery and printing", "type": "expense", "subtype": "general", "is_group": false, "system_key": null, "parent_code": "61"}, {"code": "6111", "name": "ضيافة ونظافة", "name_en": "Hospitality and cleaning", "type": "expense", "subtype": "general", "is_group": false, "system_key": null, "parent_code": "61"}, {"code": "6112", "name": "سفر وانتقالات", "name_en": "Travel and transport", "type": "expense", "subtype": "general", "is_group": false, "system_key": null, "parent_code": "61"}, {"code": "6113", "name": "تأمين", "name_en": "Insurance", "type": "expense", "subtype": "general", "is_group": false, "system_key": null, "parent_code": "61"}, {"code": "6114", "name": "مصروف الإهلاك", "name_en": "Depreciation expense", "type": "expense", "subtype": "depreciation", "is_group": false, "system_key": "DEP_EXP", "parent_code": "61"}, {"code": "6115", "name": "ديون معدومة ومخصص ديون مشكوك فيها", "name_en": "Bad debts and allowance expense", "type": "expense", "subtype": "general", "is_group": false, "system_key": "BAD_DEBT", "parent_code": "61"}, {"code": "6116", "name": "مصروفات بنكية وعمولات", "name_en": "Bank charges", "type": "expense", "subtype": "general", "is_group": false, "system_key": null, "parent_code": "61"}, {"code": "6117", "name": "غرامات وجزاءات", "name_en": "Fines and penalties", "type": "expense", "subtype": "general", "is_group": false, "system_key": null, "parent_code": "61"}, {"code": "6118", "name": "مصروفات متنوعة", "name_en": "Miscellaneous expenses", "type": "expense", "subtype": "general", "is_group": false, "system_key": null, "parent_code": "61"}, {"code": "62", "name": "مصروفات البيع والتسويق", "name_en": "Selling and marketing", "type": "expense", "subtype": "general", "is_group": true, "system_key": null, "parent_code": "6"}, {"code": "6201", "name": "دعاية وإعلان", "name_en": "Advertising", "type": "expense", "subtype": "general", "is_group": false, "system_key": null, "parent_code": "62"}, {"code": "6202", "name": "عمولات مبيعات", "name_en": "Sales commissions", "type": "expense", "subtype": "general", "is_group": false, "system_key": null, "parent_code": "62"}, {"code": "6203", "name": "نقل وشحن", "name_en": "Freight and delivery", "type": "expense", "subtype": "general", "is_group": false, "system_key": null, "parent_code": "62"}, {"code": "7", "name": "مصروفات تمويلية وأخرى", "name_en": "Finance and other expenses", "type": "expense", "subtype": "general", "is_group": true, "system_key": null}, {"code": "7101", "name": "فوائد وأعباء تمويل", "name_en": "Finance costs", "type": "expense", "subtype": "general", "is_group": false, "system_key": null, "parent_code": "7"}, {"code": "7102", "name": "خسائر بيع أصول ثابتة", "name_en": "Loss on disposal of assets", "type": "expense", "subtype": "general", "is_group": false, "system_key": "ASSET_LOSS", "parent_code": "7"}, {"code": "7103", "name": "خسائر فروق عملة", "name_en": "Foreign exchange losses", "type": "expense", "subtype": "general", "is_group": false, "system_key": "FX_LOSS", "parent_code": "7"}, {"code": "7104", "name": "زكاة وضريبة دخل", "name_en": "Zakat and income tax expense", "type": "expense", "subtype": "general", "is_group": false, "system_key": "ZAKAT_EXP", "parent_code": "7"}, {"code": "7105", "name": "فروق التقريب", "name_en": "Rounding differences", "type": "expense", "subtype": "general", "is_group": false, "system_key": "ROUNDING", "parent_code": "7"}]'::jsonb) on conflict (key) do update set name=excluded.name, description=excluded.description, rows=excluded.rows;
insert into app.coa_templates (key,name,description,rows) values ('manufacturing','تصنيع — مصانع وورش','تضيف المواد الخام والإنتاج تحت التشغيل وتكاليف التصنيع','[{"code": "1", "name": "الأصول", "name_en": "Assets", "type": "asset", "subtype": "general", "is_group": true, "system_key": null}, {"code": "11", "name": "الأصول المتداولة", "name_en": "Current assets", "type": "asset", "subtype": "general", "is_group": true, "system_key": null, "parent_code": "1"}, {"code": "1101", "name": "النقد وما في حكمه", "name_en": "Cash and cash equivalents", "type": "asset", "subtype": "general", "is_group": true, "system_key": null, "parent_code": "11"}, {"code": "110101", "name": "الصندوق الرئيسي", "name_en": "Main cash on hand", "type": "asset", "subtype": "cash", "is_group": false, "system_key": "CASH", "parent_code": "1101"}, {"code": "110102", "name": "عهد وسلف نقدية", "name_en": "Petty cash and imprest", "type": "asset", "subtype": "cash", "is_group": false, "system_key": null, "parent_code": "1101"}, {"code": "110103", "name": "البنك — الحساب الجاري الرئيسي", "name_en": "Bank — main current account", "type": "asset", "subtype": "bank", "is_group": false, "system_key": "BANK", "parent_code": "1101"}, {"code": "110104", "name": "البنك — حساب ثانٍ", "name_en": "Bank — secondary account", "type": "asset", "subtype": "bank", "is_group": false, "system_key": null, "parent_code": "1101"}, {"code": "110105", "name": "شيكات تحت التحصيل", "name_en": "Cheques under collection", "type": "asset", "subtype": "general", "is_group": false, "system_key": "CHEQUES_IN", "parent_code": "1101"}, {"code": "1102", "name": "العملاء والذمم المدينة", "name_en": "Trade and other receivables", "type": "asset", "subtype": "general", "is_group": true, "system_key": null, "parent_code": "11"}, {"code": "110201", "name": "العملاء (ذمم مدينة تجارية)", "name_en": "Trade receivables", "type": "asset", "subtype": "receivable", "is_group": false, "system_key": "AR", "parent_code": "1102"}, {"code": "110202", "name": "أوراق القبض", "name_en": "Notes receivable", "type": "asset", "subtype": "receivable", "is_group": false, "system_key": null, "parent_code": "1102"}, {"code": "110203", "name": "مخصص الديون المشكوك في تحصيلها", "name_en": "Allowance for doubtful debts", "type": "asset", "subtype": "allowance", "is_group": false, "system_key": null, "parent_code": "1102"}, {"code": "110204", "name": "سلف وذمم الموظفين", "name_en": "Employee advances and receivables", "type": "asset", "subtype": "receivable", "is_group": false, "system_key": null, "parent_code": "1102"}, {"code": "1103", "name": "المخزون", "name_en": "Inventory", "type": "asset", "subtype": "general", "is_group": true, "system_key": null, "parent_code": "11"}, {"code": "110301", "name": "مخزون البضاعة", "name_en": "Merchandise inventory", "type": "asset", "subtype": "inventory", "is_group": false, "system_key": "INVENTORY", "parent_code": "1103"}, {"code": "110302", "name": "مخزون المواد الخام", "name_en": "Raw materials inventory", "type": "asset", "subtype": "inventory", "is_group": false, "system_key": null, "parent_code": "1103"}, {"code": "110303", "name": "إنتاج تحت التشغيل", "name_en": "Work in progress", "type": "asset", "subtype": "inventory", "is_group": false, "system_key": null, "parent_code": "1103"}, {"code": "110304", "name": "بضاعة تامة الصنع", "name_en": "Finished goods", "type": "asset", "subtype": "inventory", "is_group": false, "system_key": null, "parent_code": "1103"}, {"code": "110305", "name": "قطع غيار ومهمات", "name_en": "Spare parts and supplies", "type": "asset", "subtype": "inventory", "is_group": false, "system_key": null, "parent_code": "1103"}, {"code": "1104", "name": "مصروفات مقدمة وأرصدة مدينة أخرى", "name_en": "Prepayments and other current assets", "type": "asset", "subtype": "general", "is_group": true, "system_key": null, "parent_code": "11"}, {"code": "110401", "name": "مصروفات مدفوعة مقدمًا", "name_en": "Prepaid expenses", "type": "asset", "subtype": "prepaid", "is_group": false, "system_key": null, "parent_code": "1104"}, {"code": "110402", "name": "دفعات مقدمة للموردين", "name_en": "Advances to suppliers", "type": "asset", "subtype": "general", "is_group": false, "system_key": "SUPPLIER_ADV", "parent_code": "1104"}, {"code": "110403", "name": "تأمينات مستردة وودائع", "name_en": "Refundable deposits", "type": "asset", "subtype": "general", "is_group": false, "system_key": null, "parent_code": "1104"}, {"code": "110404", "name": "ضريبة القيمة المضافة — مدخلات", "name_en": "VAT — input", "type": "asset", "subtype": "vat_input", "is_group": false, "system_key": "VAT_IN", "parent_code": "1104"}, {"code": "110405", "name": "ضريبة القيمة المضافة — مستردة", "name_en": "VAT — refundable", "type": "asset", "subtype": "vat_receivable", "is_group": false, "system_key": null, "parent_code": "1104"}, {"code": "110406", "name": "عهد الموظفين", "name_en": "Employee custodies", "type": "asset", "subtype": "general", "is_group": false, "system_key": null, "parent_code": "1104"}, {"code": "110407", "name": "حسابات الشركات الشقيقة (مدينة)", "name_en": "Intercompany receivables", "type": "asset", "subtype": "intercompany", "is_group": false, "system_key": null, "parent_code": "1104"}, {"code": "12", "name": "الأصول غير المتداولة", "name_en": "Non-current assets", "type": "asset", "subtype": "general", "is_group": true, "system_key": null, "parent_code": "1"}, {"code": "1201", "name": "الممتلكات والآلات والمعدات", "name_en": "Property, plant and equipment", "type": "asset", "subtype": "general", "is_group": true, "system_key": null, "parent_code": "12"}, {"code": "120101", "name": "أراضي", "name_en": "Land", "type": "asset", "subtype": "fixed_asset", "is_group": false, "system_key": null, "parent_code": "1201"}, {"code": "120102", "name": "مبانٍ وإنشاءات", "name_en": "Buildings", "type": "asset", "subtype": "fixed_asset", "is_group": false, "system_key": null, "parent_code": "1201"}, {"code": "120103", "name": "آلات ومعدات", "name_en": "Machinery and equipment", "type": "asset", "subtype": "fixed_asset", "is_group": false, "system_key": null, "parent_code": "1201"}, {"code": "120104", "name": "أثاث ومفروشات", "name_en": "Furniture and fixtures", "type": "asset", "subtype": "fixed_asset", "is_group": false, "system_key": null, "parent_code": "1201"}, {"code": "120105", "name": "سيارات ومركبات", "name_en": "Vehicles", "type": "asset", "subtype": "fixed_asset", "is_group": false, "system_key": null, "parent_code": "1201"}, {"code": "120106", "name": "أجهزة حاسب وبرامج", "name_en": "Computers and software", "type": "asset", "subtype": "fixed_asset", "is_group": false, "system_key": null, "parent_code": "1201"}, {"code": "120107", "name": "أعمال رأسمالية تحت التنفيذ", "name_en": "Capital work in progress", "type": "asset", "subtype": "fixed_asset", "is_group": false, "system_key": null, "parent_code": "1201"}, {"code": "1202", "name": "مجمع الإهلاك", "name_en": "Accumulated depreciation", "type": "asset", "subtype": "general", "is_group": true, "system_key": null, "parent_code": "12"}, {"code": "120201", "name": "مجمع إهلاك المباني", "name_en": "Acc. dep. — buildings", "type": "asset", "subtype": "accum_dep", "is_group": false, "system_key": null, "parent_code": "1202"}, {"code": "120202", "name": "مجمع إهلاك الآلات والمعدات", "name_en": "Acc. dep. — machinery", "type": "asset", "subtype": "accum_dep", "is_group": false, "system_key": null, "parent_code": "1202"}, {"code": "120203", "name": "مجمع إهلاك الأثاث", "name_en": "Acc. dep. — furniture", "type": "asset", "subtype": "accum_dep", "is_group": false, "system_key": null, "parent_code": "1202"}, {"code": "120204", "name": "مجمع إهلاك السيارات", "name_en": "Acc. dep. — vehicles", "type": "asset", "subtype": "accum_dep", "is_group": false, "system_key": null, "parent_code": "1202"}, {"code": "120205", "name": "مجمع إهلاك الأجهزة والبرامج", "name_en": "Acc. dep. — computers", "type": "asset", "subtype": "accum_dep", "is_group": false, "system_key": null, "parent_code": "1202"}, {"code": "1203", "name": "أصول غير ملموسة واستثمارات", "name_en": "Intangibles and investments", "type": "asset", "subtype": "general", "is_group": true, "system_key": null, "parent_code": "12"}, {"code": "120301", "name": "أصول غير ملموسة", "name_en": "Intangible assets", "type": "asset", "subtype": "intangible", "is_group": false, "system_key": null, "parent_code": "1203"}, {"code": "120302", "name": "استثمارات طويلة الأجل", "name_en": "Long-term investments", "type": "asset", "subtype": "investment", "is_group": false, "system_key": null, "parent_code": "1203"}, {"code": "2", "name": "الخصوم", "name_en": "Liabilities", "type": "liability", "subtype": "general", "is_group": true, "system_key": null}, {"code": "21", "name": "الخصوم المتداولة", "name_en": "Current liabilities", "type": "liability", "subtype": "general", "is_group": true, "system_key": null, "parent_code": "2"}, {"code": "2101", "name": "الموردون والذمم الدائنة", "name_en": "Trade and other payables", "type": "liability", "subtype": "general", "is_group": true, "system_key": null, "parent_code": "21"}, {"code": "210101", "name": "الموردون", "name_en": "Trade payables", "type": "liability", "subtype": "payable", "is_group": false, "system_key": "AP", "parent_code": "2101"}, {"code": "210102", "name": "أوراق الدفع", "name_en": "Notes payable", "type": "liability", "subtype": "payable", "is_group": false, "system_key": null, "parent_code": "2101"}, {"code": "210103", "name": "مقاولو الباطن", "name_en": "Subcontractors", "type": "liability", "subtype": "payable", "is_group": false, "system_key": null, "parent_code": "2101"}, {"code": "2102", "name": "مستحقات وخصوم أخرى", "name_en": "Accruals and other liabilities", "type": "liability", "subtype": "general", "is_group": true, "system_key": null, "parent_code": "21"}, {"code": "210201", "name": "مصروفات مستحقة", "name_en": "Accrued expenses", "type": "liability", "subtype": "accrued", "is_group": false, "system_key": null, "parent_code": "2102"}, {"code": "210202", "name": "رواتب وأجور مستحقة", "name_en": "Accrued salaries", "type": "liability", "subtype": "accrued", "is_group": false, "system_key": "PAYROLL_PAYABLE", "parent_code": "2102"}, {"code": "210203", "name": "دفعات مقدمة من العملاء", "name_en": "Customer advances", "type": "liability", "subtype": "general", "is_group": false, "system_key": "CUSTOMER_ADV", "parent_code": "2102"}, {"code": "210204", "name": "إيرادات مقدمة", "name_en": "Unearned revenue", "type": "liability", "subtype": "general", "is_group": false, "system_key": null, "parent_code": "2102"}, {"code": "2103", "name": "الضرائب والرسوم المستحقة", "name_en": "Taxes and levies payable", "type": "liability", "subtype": "general", "is_group": true, "system_key": null, "parent_code": "21"}, {"code": "210301", "name": "ضريبة القيمة المضافة — مخرجات", "name_en": "VAT — output", "type": "liability", "subtype": "vat_output", "is_group": false, "system_key": "VAT_OUT", "parent_code": "2103"}, {"code": "210302", "name": "ضريبة القيمة المضافة — مستحقة السداد", "name_en": "VAT — payable", "type": "liability", "subtype": "vat_payable", "is_group": false, "system_key": "VAT_PAY", "parent_code": "2103"}, {"code": "210303", "name": "ضريبة الاستقطاع المستحقة", "name_en": "Withholding tax payable", "type": "liability", "subtype": "general", "is_group": false, "system_key": null, "parent_code": "2103"}, {"code": "210304", "name": "زكاة وضريبة دخل مستحقة", "name_en": "Zakat and income tax payable", "type": "liability", "subtype": "general", "is_group": false, "system_key": null, "parent_code": "2103"}, {"code": "210305", "name": "مستحقات التأمينات الاجتماعية", "name_en": "GOSI payable", "type": "liability", "subtype": "general", "is_group": false, "system_key": null, "parent_code": "2103"}, {"code": "2104", "name": "قروض قصيرة الأجل", "name_en": "Short-term borrowings", "type": "liability", "subtype": "general", "is_group": true, "system_key": null, "parent_code": "21"}, {"code": "210401", "name": "قروض وتسهيلات بنكية قصيرة الأجل", "name_en": "Short-term loans and facilities", "type": "liability", "subtype": "loan", "is_group": false, "system_key": null, "parent_code": "2104"}, {"code": "210402", "name": "الجزء المتداول من القروض طويلة الأجل", "name_en": "Current portion of long-term loans", "type": "liability", "subtype": "loan", "is_group": false, "system_key": null, "parent_code": "2104"}, {"code": "2105", "name": "حسابات وسيطة", "name_en": "Clearing and intercompany", "type": "liability", "subtype": "general", "is_group": true, "system_key": null, "parent_code": "21"}, {"code": "210501", "name": "جاري الشركاء", "name_en": "Partners current accounts", "type": "liability", "subtype": "general", "is_group": false, "system_key": null, "parent_code": "2105"}, {"code": "210601", "name": "حسابات الشركات الشقيقة (دائنة)", "name_en": "Intercompany payables", "type": "liability", "subtype": "intercompany", "is_group": false, "system_key": null, "parent_code": "21"}, {"code": "210701", "name": "حساب تسويات معلّق", "name_en": "Suspense account", "type": "liability", "subtype": "general", "is_group": false, "system_key": "SUSPENSE", "parent_code": "21"}, {"code": "22", "name": "الخصوم غير المتداولة", "name_en": "Non-current liabilities", "type": "liability", "subtype": "general", "is_group": true, "system_key": null, "parent_code": "2"}, {"code": "2201", "name": "مخصص مكافأة نهاية الخدمة", "name_en": "End-of-service provision", "type": "liability", "subtype": "provision", "is_group": false, "system_key": null, "parent_code": "22"}, {"code": "2202", "name": "قروض طويلة الأجل", "name_en": "Long-term loans", "type": "liability", "subtype": "loan", "is_group": false, "system_key": null, "parent_code": "22"}, {"code": "3", "name": "حقوق الملكية", "name_en": "Equity", "type": "equity", "subtype": "general", "is_group": true, "system_key": null}, {"code": "31", "name": "رأس المال", "name_en": "Capital", "type": "equity", "subtype": "general", "is_group": true, "system_key": null, "parent_code": "3"}, {"code": "3101", "name": "رأس المال المدفوع", "name_en": "Paid-in capital", "type": "equity", "subtype": "capital", "is_group": false, "system_key": "CAPITAL", "parent_code": "31"}, {"code": "32", "name": "الاحتياطيات", "name_en": "Reserves", "type": "equity", "subtype": "general", "is_group": true, "system_key": null, "parent_code": "3"}, {"code": "3201", "name": "احتياطي نظامي", "name_en": "Statutory reserve", "type": "equity", "subtype": "equity", "is_group": false, "system_key": null, "parent_code": "32"}, {"code": "33", "name": "الأرباح المبقاة", "name_en": "Retained earnings", "type": "equity", "subtype": "general", "is_group": true, "system_key": null, "parent_code": "3"}, {"code": "3301", "name": "أرباح (خسائر) مبقاة", "name_en": "Retained earnings (accumulated losses)", "type": "equity", "subtype": "retained_earnings", "is_group": false, "system_key": "RE", "parent_code": "33"}, {"code": "3302", "name": "مسحوبات الشركاء", "name_en": "Partners drawings", "type": "equity", "subtype": "drawings", "is_group": false, "system_key": null, "parent_code": "33"}, {"code": "3303", "name": "توزيعات أرباح", "name_en": "Dividends", "type": "equity", "subtype": "dividends", "is_group": false, "system_key": null, "parent_code": "33"}, {"code": "4", "name": "الإيرادات", "name_en": "Revenue", "type": "revenue", "subtype": "general", "is_group": true, "system_key": null}, {"code": "41", "name": "إيرادات النشاط", "name_en": "Operating revenue", "type": "revenue", "subtype": "general", "is_group": true, "system_key": null, "parent_code": "4"}, {"code": "4101", "name": "إيرادات المبيعات", "name_en": "Sales revenue", "type": "revenue", "subtype": "revenue_sales", "is_group": false, "system_key": "SALES", "parent_code": "41"}, {"code": "4102", "name": "إيرادات الخدمات", "name_en": "Service revenue", "type": "revenue", "subtype": "revenue_sales", "is_group": false, "system_key": "SERVICES", "parent_code": "41"}, {"code": "4103", "name": "إيرادات العقود والمشاريع", "name_en": "Contract revenue", "type": "revenue", "subtype": "revenue_sales", "is_group": false, "system_key": null, "parent_code": "41"}, {"code": "4104", "name": "مردودات ومسموحات المبيعات", "name_en": "Sales returns and allowances", "type": "revenue", "subtype": "contra_revenue", "is_group": false, "system_key": null, "parent_code": "41"}, {"code": "4105", "name": "خصم مسموح به", "name_en": "Sales discounts", "type": "revenue", "subtype": "contra_revenue", "is_group": false, "system_key": null, "parent_code": "41"}, {"code": "42", "name": "إيرادات أخرى", "name_en": "Other income", "type": "revenue", "subtype": "general", "is_group": true, "system_key": null, "parent_code": "4"}, {"code": "4201", "name": "إيرادات متنوعة", "name_en": "Miscellaneous income", "type": "revenue", "subtype": "general", "is_group": false, "system_key": null, "parent_code": "42"}, {"code": "4202", "name": "أرباح بيع أصول ثابتة", "name_en": "Gain on disposal of assets", "type": "revenue", "subtype": "general", "is_group": false, "system_key": "ASSET_GAIN", "parent_code": "42"}, {"code": "4203", "name": "أرباح فروق عملة", "name_en": "Foreign exchange gains", "type": "revenue", "subtype": "general", "is_group": false, "system_key": "FX_GAIN", "parent_code": "42"}, {"code": "4204", "name": "إيرادات فوائد وعمولات", "name_en": "Interest and commission income", "type": "revenue", "subtype": "general", "is_group": false, "system_key": null, "parent_code": "42"}, {"code": "5", "name": "تكلفة الإيرادات", "name_en": "Cost of revenue", "type": "expense", "subtype": "general", "is_group": true, "system_key": null}, {"code": "51", "name": "تكلفة المبيعات والخدمات", "name_en": "Cost of sales and services", "type": "expense", "subtype": "general", "is_group": true, "system_key": null, "parent_code": "5"}, {"code": "5101", "name": "تكلفة البضاعة المباعة", "name_en": "Cost of goods sold", "type": "expense", "subtype": "cogs", "is_group": false, "system_key": "COGS", "parent_code": "51"}, {"code": "5102", "name": "تكلفة الخدمات", "name_en": "Cost of services", "type": "expense", "subtype": "cogs", "is_group": false, "system_key": null, "parent_code": "51"}, {"code": "5103", "name": "أجور مباشرة", "name_en": "Direct labour", "type": "expense", "subtype": "cogs", "is_group": false, "system_key": null, "parent_code": "51"}, {"code": "5104", "name": "مشتريات ومواد مباشرة", "name_en": "Direct purchases and materials", "type": "expense", "subtype": "cogs", "is_group": false, "system_key": "PURCHASES", "parent_code": "51"}, {"code": "5105", "name": "مقاولو الباطن (تكلفة)", "name_en": "Subcontractor costs", "type": "expense", "subtype": "cogs", "is_group": false, "system_key": null, "parent_code": "51"}, {"code": "5106", "name": "فروقات جرد المخزون", "name_en": "Inventory count differences", "type": "expense", "subtype": "cogs", "is_group": false, "system_key": null, "parent_code": "51"}, {"code": "52", "name": "تكاليف التصنيع", "name_en": "Manufacturing costs", "type": "expense", "subtype": "general", "is_group": true, "system_key": null, "parent_code": "5"}, {"code": "5201", "name": "مواد خام مستهلكة", "name_en": "Raw materials consumed", "type": "expense", "subtype": "cogs", "is_group": false, "system_key": null, "parent_code": "52"}, {"code": "5202", "name": "أجور عمالة مباشرة", "name_en": "Direct production labour", "type": "expense", "subtype": "cogs", "is_group": false, "system_key": null, "parent_code": "52"}, {"code": "5203", "name": "تكاليف صناعية غير مباشرة", "name_en": "Manufacturing overhead", "type": "expense", "subtype": "cogs", "is_group": false, "system_key": null, "parent_code": "52"}, {"code": "5204", "name": "صيانة معدات الإنتاج", "name_en": "Production equipment maintenance", "type": "expense", "subtype": "cogs", "is_group": false, "system_key": null, "parent_code": "52"}, {"code": "5205", "name": "إهلاك معدات الإنتاج", "name_en": "Production equipment depreciation", "type": "expense", "subtype": "depreciation", "is_group": false, "system_key": null, "parent_code": "52"}, {"code": "5206", "name": "فاقد وهالك إنتاج", "name_en": "Production scrap and waste", "type": "expense", "subtype": "cogs", "is_group": false, "system_key": null, "parent_code": "52"}, {"code": "5207", "name": "طلاء وتشطيب وتركيب", "name_en": "Painting, finishing and installation", "type": "expense", "subtype": "cogs", "is_group": false, "system_key": null, "parent_code": "52"}, {"code": "6", "name": "مصروفات التشغيل", "name_en": "Operating expenses", "type": "expense", "subtype": "general", "is_group": true, "system_key": null}, {"code": "61", "name": "مصروفات إدارية وعمومية", "name_en": "General and administrative", "type": "expense", "subtype": "general", "is_group": true, "system_key": null, "parent_code": "6"}, {"code": "6101", "name": "رواتب وأجور", "name_en": "Salaries and wages", "type": "expense", "subtype": "general", "is_group": false, "system_key": "SALARIES", "parent_code": "61"}, {"code": "6102", "name": "بدلات ومزايا", "name_en": "Allowances and benefits", "type": "expense", "subtype": "general", "is_group": false, "system_key": null, "parent_code": "61"}, {"code": "6103", "name": "تأمينات اجتماعية (حصة صاحب العمل)", "name_en": "GOSI — employer share", "type": "expense", "subtype": "general", "is_group": false, "system_key": null, "parent_code": "61"}, {"code": "6104", "name": "مكافأة نهاية الخدمة", "name_en": "End-of-service benefit expense", "type": "expense", "subtype": "general", "is_group": false, "system_key": null, "parent_code": "61"}, {"code": "6105", "name": "إيجارات", "name_en": "Rent", "type": "expense", "subtype": "general", "is_group": false, "system_key": null, "parent_code": "61"}, {"code": "6106", "name": "كهرباء وماء واتصالات", "name_en": "Utilities and communications", "type": "expense", "subtype": "general", "is_group": false, "system_key": null, "parent_code": "61"}, {"code": "6107", "name": "صيانة وإصلاح", "name_en": "Repairs and maintenance", "type": "expense", "subtype": "general", "is_group": false, "system_key": null, "parent_code": "61"}, {"code": "6108", "name": "رسوم حكومية وتراخيص واشتراكات", "name_en": "Government fees, licences and subscriptions", "type": "expense", "subtype": "general", "is_group": false, "system_key": null, "parent_code": "61"}, {"code": "6109", "name": "أتعاب مهنية واستشارات", "name_en": "Professional fees", "type": "expense", "subtype": "general", "is_group": false, "system_key": null, "parent_code": "61"}, {"code": "6110", "name": "قرطاسية ومطبوعات", "name_en": "Stationery and printing", "type": "expense", "subtype": "general", "is_group": false, "system_key": null, "parent_code": "61"}, {"code": "6111", "name": "ضيافة ونظافة", "name_en": "Hospitality and cleaning", "type": "expense", "subtype": "general", "is_group": false, "system_key": null, "parent_code": "61"}, {"code": "6112", "name": "سفر وانتقالات", "name_en": "Travel and transport", "type": "expense", "subtype": "general", "is_group": false, "system_key": null, "parent_code": "61"}, {"code": "6113", "name": "تأمين", "name_en": "Insurance", "type": "expense", "subtype": "general", "is_group": false, "system_key": null, "parent_code": "61"}, {"code": "6114", "name": "مصروف الإهلاك", "name_en": "Depreciation expense", "type": "expense", "subtype": "depreciation", "is_group": false, "system_key": "DEP_EXP", "parent_code": "61"}, {"code": "6115", "name": "ديون معدومة ومخصص ديون مشكوك فيها", "name_en": "Bad debts and allowance expense", "type": "expense", "subtype": "general", "is_group": false, "system_key": "BAD_DEBT", "parent_code": "61"}, {"code": "6116", "name": "مصروفات بنكية وعمولات", "name_en": "Bank charges", "type": "expense", "subtype": "general", "is_group": false, "system_key": null, "parent_code": "61"}, {"code": "6117", "name": "غرامات وجزاءات", "name_en": "Fines and penalties", "type": "expense", "subtype": "general", "is_group": false, "system_key": null, "parent_code": "61"}, {"code": "6118", "name": "مصروفات متنوعة", "name_en": "Miscellaneous expenses", "type": "expense", "subtype": "general", "is_group": false, "system_key": null, "parent_code": "61"}, {"code": "62", "name": "مصروفات البيع والتسويق", "name_en": "Selling and marketing", "type": "expense", "subtype": "general", "is_group": true, "system_key": null, "parent_code": "6"}, {"code": "6201", "name": "دعاية وإعلان", "name_en": "Advertising", "type": "expense", "subtype": "general", "is_group": false, "system_key": null, "parent_code": "62"}, {"code": "6202", "name": "عمولات مبيعات", "name_en": "Sales commissions", "type": "expense", "subtype": "general", "is_group": false, "system_key": null, "parent_code": "62"}, {"code": "6203", "name": "نقل وشحن", "name_en": "Freight and delivery", "type": "expense", "subtype": "general", "is_group": false, "system_key": null, "parent_code": "62"}, {"code": "7", "name": "مصروفات تمويلية وأخرى", "name_en": "Finance and other expenses", "type": "expense", "subtype": "general", "is_group": true, "system_key": null}, {"code": "7101", "name": "فوائد وأعباء تمويل", "name_en": "Finance costs", "type": "expense", "subtype": "general", "is_group": false, "system_key": null, "parent_code": "7"}, {"code": "7102", "name": "خسائر بيع أصول ثابتة", "name_en": "Loss on disposal of assets", "type": "expense", "subtype": "general", "is_group": false, "system_key": "ASSET_LOSS", "parent_code": "7"}, {"code": "7103", "name": "خسائر فروق عملة", "name_en": "Foreign exchange losses", "type": "expense", "subtype": "general", "is_group": false, "system_key": "FX_LOSS", "parent_code": "7"}, {"code": "7104", "name": "زكاة وضريبة دخل", "name_en": "Zakat and income tax expense", "type": "expense", "subtype": "general", "is_group": false, "system_key": "ZAKAT_EXP", "parent_code": "7"}, {"code": "7105", "name": "فروق التقريب", "name_en": "Rounding differences", "type": "expense", "subtype": "general", "is_group": false, "system_key": "ROUNDING", "parent_code": "7"}]'::jsonb) on conflict (key) do update set name=excluded.name, description=excluded.description, rows=excluded.rows;
insert into app.coa_templates (key,name,description,rows) values ('contracting','مقاولات ومشاريع','تضيف أعمال تحت التنفيذ والمحتجزات وتكاليف المشاريع','[{"code": "1", "name": "الأصول", "name_en": "Assets", "type": "asset", "subtype": "general", "is_group": true, "system_key": null}, {"code": "11", "name": "الأصول المتداولة", "name_en": "Current assets", "type": "asset", "subtype": "general", "is_group": true, "system_key": null, "parent_code": "1"}, {"code": "1101", "name": "النقد وما في حكمه", "name_en": "Cash and cash equivalents", "type": "asset", "subtype": "general", "is_group": true, "system_key": null, "parent_code": "11"}, {"code": "110101", "name": "الصندوق الرئيسي", "name_en": "Main cash on hand", "type": "asset", "subtype": "cash", "is_group": false, "system_key": "CASH", "parent_code": "1101"}, {"code": "110102", "name": "عهد وسلف نقدية", "name_en": "Petty cash and imprest", "type": "asset", "subtype": "cash", "is_group": false, "system_key": null, "parent_code": "1101"}, {"code": "110103", "name": "البنك — الحساب الجاري الرئيسي", "name_en": "Bank — main current account", "type": "asset", "subtype": "bank", "is_group": false, "system_key": "BANK", "parent_code": "1101"}, {"code": "110104", "name": "البنك — حساب ثانٍ", "name_en": "Bank — secondary account", "type": "asset", "subtype": "bank", "is_group": false, "system_key": null, "parent_code": "1101"}, {"code": "110105", "name": "شيكات تحت التحصيل", "name_en": "Cheques under collection", "type": "asset", "subtype": "general", "is_group": false, "system_key": "CHEQUES_IN", "parent_code": "1101"}, {"code": "1102", "name": "العملاء والذمم المدينة", "name_en": "Trade and other receivables", "type": "asset", "subtype": "general", "is_group": true, "system_key": null, "parent_code": "11"}, {"code": "110201", "name": "العملاء (ذمم مدينة تجارية)", "name_en": "Trade receivables", "type": "asset", "subtype": "receivable", "is_group": false, "system_key": "AR", "parent_code": "1102"}, {"code": "110202", "name": "أوراق القبض", "name_en": "Notes receivable", "type": "asset", "subtype": "receivable", "is_group": false, "system_key": null, "parent_code": "1102"}, {"code": "110203", "name": "مخصص الديون المشكوك في تحصيلها", "name_en": "Allowance for doubtful debts", "type": "asset", "subtype": "allowance", "is_group": false, "system_key": null, "parent_code": "1102"}, {"code": "110204", "name": "سلف وذمم الموظفين", "name_en": "Employee advances and receivables", "type": "asset", "subtype": "receivable", "is_group": false, "system_key": null, "parent_code": "1102"}, {"code": "1103", "name": "المخزون", "name_en": "Inventory", "type": "asset", "subtype": "general", "is_group": true, "system_key": null, "parent_code": "11"}, {"code": "110301", "name": "مخزون البضاعة", "name_en": "Merchandise inventory", "type": "asset", "subtype": "inventory", "is_group": false, "system_key": "INVENTORY", "parent_code": "1103"}, {"code": "1104", "name": "مصروفات مقدمة وأرصدة مدينة أخرى", "name_en": "Prepayments and other current assets", "type": "asset", "subtype": "general", "is_group": true, "system_key": null, "parent_code": "11"}, {"code": "110401", "name": "مصروفات مدفوعة مقدمًا", "name_en": "Prepaid expenses", "type": "asset", "subtype": "prepaid", "is_group": false, "system_key": null, "parent_code": "1104"}, {"code": "110402", "name": "دفعات مقدمة للموردين", "name_en": "Advances to suppliers", "type": "asset", "subtype": "general", "is_group": false, "system_key": "SUPPLIER_ADV", "parent_code": "1104"}, {"code": "110403", "name": "تأمينات مستردة وودائع", "name_en": "Refundable deposits", "type": "asset", "subtype": "general", "is_group": false, "system_key": null, "parent_code": "1104"}, {"code": "110404", "name": "ضريبة القيمة المضافة — مدخلات", "name_en": "VAT — input", "type": "asset", "subtype": "vat_input", "is_group": false, "system_key": "VAT_IN", "parent_code": "1104"}, {"code": "110405", "name": "ضريبة القيمة المضافة — مستردة", "name_en": "VAT — refundable", "type": "asset", "subtype": "vat_receivable", "is_group": false, "system_key": null, "parent_code": "1104"}, {"code": "110406", "name": "عهد الموظفين", "name_en": "Employee custodies", "type": "asset", "subtype": "general", "is_group": false, "system_key": null, "parent_code": "1104"}, {"code": "110407", "name": "حسابات الشركات الشقيقة (مدينة)", "name_en": "Intercompany receivables", "type": "asset", "subtype": "intercompany", "is_group": false, "system_key": null, "parent_code": "1104"}, {"code": "1105", "name": "أعمال المشاريع", "name_en": "Contract assets", "type": "asset", "subtype": "general", "is_group": true, "system_key": null, "parent_code": "11"}, {"code": "110501", "name": "أعمال تحت التنفيذ", "name_en": "Contract work in progress", "type": "asset", "subtype": "general", "is_group": false, "system_key": null, "parent_code": "1105"}, {"code": "110502", "name": "مستخلصات مستحقة غير مفوترة", "name_en": "Unbilled certified work", "type": "asset", "subtype": "general", "is_group": false, "system_key": null, "parent_code": "1105"}, {"code": "110503", "name": "محتجزات لدى العملاء", "name_en": "Retention receivable", "type": "asset", "subtype": "receivable", "is_group": false, "system_key": null, "parent_code": "1105"}, {"code": "12", "name": "الأصول غير المتداولة", "name_en": "Non-current assets", "type": "asset", "subtype": "general", "is_group": true, "system_key": null, "parent_code": "1"}, {"code": "1201", "name": "الممتلكات والآلات والمعدات", "name_en": "Property, plant and equipment", "type": "asset", "subtype": "general", "is_group": true, "system_key": null, "parent_code": "12"}, {"code": "120101", "name": "أراضي", "name_en": "Land", "type": "asset", "subtype": "fixed_asset", "is_group": false, "system_key": null, "parent_code": "1201"}, {"code": "120102", "name": "مبانٍ وإنشاءات", "name_en": "Buildings", "type": "asset", "subtype": "fixed_asset", "is_group": false, "system_key": null, "parent_code": "1201"}, {"code": "120103", "name": "آلات ومعدات", "name_en": "Machinery and equipment", "type": "asset", "subtype": "fixed_asset", "is_group": false, "system_key": null, "parent_code": "1201"}, {"code": "120104", "name": "أثاث ومفروشات", "name_en": "Furniture and fixtures", "type": "asset", "subtype": "fixed_asset", "is_group": false, "system_key": null, "parent_code": "1201"}, {"code": "120105", "name": "سيارات ومركبات", "name_en": "Vehicles", "type": "asset", "subtype": "fixed_asset", "is_group": false, "system_key": null, "parent_code": "1201"}, {"code": "120106", "name": "أجهزة حاسب وبرامج", "name_en": "Computers and software", "type": "asset", "subtype": "fixed_asset", "is_group": false, "system_key": null, "parent_code": "1201"}, {"code": "120107", "name": "أعمال رأسمالية تحت التنفيذ", "name_en": "Capital work in progress", "type": "asset", "subtype": "fixed_asset", "is_group": false, "system_key": null, "parent_code": "1201"}, {"code": "1202", "name": "مجمع الإهلاك", "name_en": "Accumulated depreciation", "type": "asset", "subtype": "general", "is_group": true, "system_key": null, "parent_code": "12"}, {"code": "120201", "name": "مجمع إهلاك المباني", "name_en": "Acc. dep. — buildings", "type": "asset", "subtype": "accum_dep", "is_group": false, "system_key": null, "parent_code": "1202"}, {"code": "120202", "name": "مجمع إهلاك الآلات والمعدات", "name_en": "Acc. dep. — machinery", "type": "asset", "subtype": "accum_dep", "is_group": false, "system_key": null, "parent_code": "1202"}, {"code": "120203", "name": "مجمع إهلاك الأثاث", "name_en": "Acc. dep. — furniture", "type": "asset", "subtype": "accum_dep", "is_group": false, "system_key": null, "parent_code": "1202"}, {"code": "120204", "name": "مجمع إهلاك السيارات", "name_en": "Acc. dep. — vehicles", "type": "asset", "subtype": "accum_dep", "is_group": false, "system_key": null, "parent_code": "1202"}, {"code": "120205", "name": "مجمع إهلاك الأجهزة والبرامج", "name_en": "Acc. dep. — computers", "type": "asset", "subtype": "accum_dep", "is_group": false, "system_key": null, "parent_code": "1202"}, {"code": "1203", "name": "أصول غير ملموسة واستثمارات", "name_en": "Intangibles and investments", "type": "asset", "subtype": "general", "is_group": true, "system_key": null, "parent_code": "12"}, {"code": "120301", "name": "أصول غير ملموسة", "name_en": "Intangible assets", "type": "asset", "subtype": "intangible", "is_group": false, "system_key": null, "parent_code": "1203"}, {"code": "120302", "name": "استثمارات طويلة الأجل", "name_en": "Long-term investments", "type": "asset", "subtype": "investment", "is_group": false, "system_key": null, "parent_code": "1203"}, {"code": "2", "name": "الخصوم", "name_en": "Liabilities", "type": "liability", "subtype": "general", "is_group": true, "system_key": null}, {"code": "21", "name": "الخصوم المتداولة", "name_en": "Current liabilities", "type": "liability", "subtype": "general", "is_group": true, "system_key": null, "parent_code": "2"}, {"code": "2101", "name": "الموردون والذمم الدائنة", "name_en": "Trade and other payables", "type": "liability", "subtype": "general", "is_group": true, "system_key": null, "parent_code": "21"}, {"code": "210101", "name": "الموردون", "name_en": "Trade payables", "type": "liability", "subtype": "payable", "is_group": false, "system_key": "AP", "parent_code": "2101"}, {"code": "210102", "name": "أوراق الدفع", "name_en": "Notes payable", "type": "liability", "subtype": "payable", "is_group": false, "system_key": null, "parent_code": "2101"}, {"code": "210103", "name": "مقاولو الباطن", "name_en": "Subcontractors", "type": "liability", "subtype": "payable", "is_group": false, "system_key": null, "parent_code": "2101"}, {"code": "210106", "name": "محتجزات للمقاولين", "name_en": "Retention payable", "type": "liability", "subtype": "payable", "is_group": false, "system_key": null, "parent_code": "2101"}, {"code": "2102", "name": "مستحقات وخصوم أخرى", "name_en": "Accruals and other liabilities", "type": "liability", "subtype": "general", "is_group": true, "system_key": null, "parent_code": "21"}, {"code": "210201", "name": "مصروفات مستحقة", "name_en": "Accrued expenses", "type": "liability", "subtype": "accrued", "is_group": false, "system_key": null, "parent_code": "2102"}, {"code": "210202", "name": "رواتب وأجور مستحقة", "name_en": "Accrued salaries", "type": "liability", "subtype": "accrued", "is_group": false, "system_key": "PAYROLL_PAYABLE", "parent_code": "2102"}, {"code": "210203", "name": "دفعات مقدمة من العملاء", "name_en": "Customer advances", "type": "liability", "subtype": "general", "is_group": false, "system_key": "CUSTOMER_ADV", "parent_code": "2102"}, {"code": "210204", "name": "إيرادات مقدمة", "name_en": "Unearned revenue", "type": "liability", "subtype": "general", "is_group": false, "system_key": null, "parent_code": "2102"}, {"code": "2103", "name": "الضرائب والرسوم المستحقة", "name_en": "Taxes and levies payable", "type": "liability", "subtype": "general", "is_group": true, "system_key": null, "parent_code": "21"}, {"code": "210301", "name": "ضريبة القيمة المضافة — مخرجات", "name_en": "VAT — output", "type": "liability", "subtype": "vat_output", "is_group": false, "system_key": "VAT_OUT", "parent_code": "2103"}, {"code": "210302", "name": "ضريبة القيمة المضافة — مستحقة السداد", "name_en": "VAT — payable", "type": "liability", "subtype": "vat_payable", "is_group": false, "system_key": "VAT_PAY", "parent_code": "2103"}, {"code": "210303", "name": "ضريبة الاستقطاع المستحقة", "name_en": "Withholding tax payable", "type": "liability", "subtype": "general", "is_group": false, "system_key": null, "parent_code": "2103"}, {"code": "210304", "name": "زكاة وضريبة دخل مستحقة", "name_en": "Zakat and income tax payable", "type": "liability", "subtype": "general", "is_group": false, "system_key": null, "parent_code": "2103"}, {"code": "210305", "name": "مستحقات التأمينات الاجتماعية", "name_en": "GOSI payable", "type": "liability", "subtype": "general", "is_group": false, "system_key": null, "parent_code": "2103"}, {"code": "2104", "name": "قروض قصيرة الأجل", "name_en": "Short-term borrowings", "type": "liability", "subtype": "general", "is_group": true, "system_key": null, "parent_code": "21"}, {"code": "210401", "name": "قروض وتسهيلات بنكية قصيرة الأجل", "name_en": "Short-term loans and facilities", "type": "liability", "subtype": "loan", "is_group": false, "system_key": null, "parent_code": "2104"}, {"code": "210402", "name": "الجزء المتداول من القروض طويلة الأجل", "name_en": "Current portion of long-term loans", "type": "liability", "subtype": "loan", "is_group": false, "system_key": null, "parent_code": "2104"}, {"code": "2105", "name": "حسابات وسيطة", "name_en": "Clearing and intercompany", "type": "liability", "subtype": "general", "is_group": true, "system_key": null, "parent_code": "21"}, {"code": "210501", "name": "جاري الشركاء", "name_en": "Partners current accounts", "type": "liability", "subtype": "general", "is_group": false, "system_key": null, "parent_code": "2105"}, {"code": "210601", "name": "حسابات الشركات الشقيقة (دائنة)", "name_en": "Intercompany payables", "type": "liability", "subtype": "intercompany", "is_group": false, "system_key": null, "parent_code": "21"}, {"code": "210701", "name": "حساب تسويات معلّق", "name_en": "Suspense account", "type": "liability", "subtype": "general", "is_group": false, "system_key": "SUSPENSE", "parent_code": "21"}, {"code": "22", "name": "الخصوم غير المتداولة", "name_en": "Non-current liabilities", "type": "liability", "subtype": "general", "is_group": true, "system_key": null, "parent_code": "2"}, {"code": "2201", "name": "مخصص مكافأة نهاية الخدمة", "name_en": "End-of-service provision", "type": "liability", "subtype": "provision", "is_group": false, "system_key": null, "parent_code": "22"}, {"code": "2202", "name": "قروض طويلة الأجل", "name_en": "Long-term loans", "type": "liability", "subtype": "loan", "is_group": false, "system_key": null, "parent_code": "22"}, {"code": "3", "name": "حقوق الملكية", "name_en": "Equity", "type": "equity", "subtype": "general", "is_group": true, "system_key": null}, {"code": "31", "name": "رأس المال", "name_en": "Capital", "type": "equity", "subtype": "general", "is_group": true, "system_key": null, "parent_code": "3"}, {"code": "3101", "name": "رأس المال المدفوع", "name_en": "Paid-in capital", "type": "equity", "subtype": "capital", "is_group": false, "system_key": "CAPITAL", "parent_code": "31"}, {"code": "32", "name": "الاحتياطيات", "name_en": "Reserves", "type": "equity", "subtype": "general", "is_group": true, "system_key": null, "parent_code": "3"}, {"code": "3201", "name": "احتياطي نظامي", "name_en": "Statutory reserve", "type": "equity", "subtype": "equity", "is_group": false, "system_key": null, "parent_code": "32"}, {"code": "33", "name": "الأرباح المبقاة", "name_en": "Retained earnings", "type": "equity", "subtype": "general", "is_group": true, "system_key": null, "parent_code": "3"}, {"code": "3301", "name": "أرباح (خسائر) مبقاة", "name_en": "Retained earnings (accumulated losses)", "type": "equity", "subtype": "retained_earnings", "is_group": false, "system_key": "RE", "parent_code": "33"}, {"code": "3302", "name": "مسحوبات الشركاء", "name_en": "Partners drawings", "type": "equity", "subtype": "drawings", "is_group": false, "system_key": null, "parent_code": "33"}, {"code": "3303", "name": "توزيعات أرباح", "name_en": "Dividends", "type": "equity", "subtype": "dividends", "is_group": false, "system_key": null, "parent_code": "33"}, {"code": "4", "name": "الإيرادات", "name_en": "Revenue", "type": "revenue", "subtype": "general", "is_group": true, "system_key": null}, {"code": "41", "name": "إيرادات النشاط", "name_en": "Operating revenue", "type": "revenue", "subtype": "general", "is_group": true, "system_key": null, "parent_code": "4"}, {"code": "4101", "name": "إيرادات المبيعات", "name_en": "Sales revenue", "type": "revenue", "subtype": "revenue_sales", "is_group": false, "system_key": "SALES", "parent_code": "41"}, {"code": "4102", "name": "إيرادات الخدمات", "name_en": "Service revenue", "type": "revenue", "subtype": "revenue_sales", "is_group": false, "system_key": "SERVICES", "parent_code": "41"}, {"code": "4103", "name": "إيرادات العقود والمشاريع", "name_en": "Contract revenue", "type": "revenue", "subtype": "revenue_sales", "is_group": false, "system_key": null, "parent_code": "41"}, {"code": "4104", "name": "مردودات ومسموحات المبيعات", "name_en": "Sales returns and allowances", "type": "revenue", "subtype": "contra_revenue", "is_group": false, "system_key": null, "parent_code": "41"}, {"code": "4105", "name": "خصم مسموح به", "name_en": "Sales discounts", "type": "revenue", "subtype": "contra_revenue", "is_group": false, "system_key": null, "parent_code": "41"}, {"code": "42", "name": "إيرادات أخرى", "name_en": "Other income", "type": "revenue", "subtype": "general", "is_group": true, "system_key": null, "parent_code": "4"}, {"code": "4201", "name": "إيرادات متنوعة", "name_en": "Miscellaneous income", "type": "revenue", "subtype": "general", "is_group": false, "system_key": null, "parent_code": "42"}, {"code": "4202", "name": "أرباح بيع أصول ثابتة", "name_en": "Gain on disposal of assets", "type": "revenue", "subtype": "general", "is_group": false, "system_key": "ASSET_GAIN", "parent_code": "42"}, {"code": "4203", "name": "أرباح فروق عملة", "name_en": "Foreign exchange gains", "type": "revenue", "subtype": "general", "is_group": false, "system_key": "FX_GAIN", "parent_code": "42"}, {"code": "4204", "name": "إيرادات فوائد وعمولات", "name_en": "Interest and commission income", "type": "revenue", "subtype": "general", "is_group": false, "system_key": null, "parent_code": "42"}, {"code": "5", "name": "تكلفة الإيرادات", "name_en": "Cost of revenue", "type": "expense", "subtype": "general", "is_group": true, "system_key": null}, {"code": "51", "name": "تكلفة المبيعات والخدمات", "name_en": "Cost of sales and services", "type": "expense", "subtype": "general", "is_group": true, "system_key": null, "parent_code": "5"}, {"code": "5101", "name": "تكلفة البضاعة المباعة", "name_en": "Cost of goods sold", "type": "expense", "subtype": "cogs", "is_group": false, "system_key": "COGS", "parent_code": "51"}, {"code": "5102", "name": "تكلفة الخدمات", "name_en": "Cost of services", "type": "expense", "subtype": "cogs", "is_group": false, "system_key": null, "parent_code": "51"}, {"code": "5103", "name": "أجور مباشرة", "name_en": "Direct labour", "type": "expense", "subtype": "cogs", "is_group": false, "system_key": null, "parent_code": "51"}, {"code": "5104", "name": "مشتريات ومواد مباشرة", "name_en": "Direct purchases and materials", "type": "expense", "subtype": "cogs", "is_group": false, "system_key": "PURCHASES", "parent_code": "51"}, {"code": "5105", "name": "مقاولو الباطن (تكلفة)", "name_en": "Subcontractor costs", "type": "expense", "subtype": "cogs", "is_group": false, "system_key": null, "parent_code": "51"}, {"code": "5106", "name": "فروقات جرد المخزون", "name_en": "Inventory count differences", "type": "expense", "subtype": "cogs", "is_group": false, "system_key": null, "parent_code": "51"}, {"code": "52", "name": "تكاليف المشاريع", "name_en": "Project costs", "type": "expense", "subtype": "general", "is_group": true, "system_key": null, "parent_code": "5"}, {"code": "5201", "name": "مواد المشاريع", "name_en": "Project materials", "type": "expense", "subtype": "cogs", "is_group": false, "system_key": null, "parent_code": "52"}, {"code": "5202", "name": "عمالة المشاريع", "name_en": "Project labour", "type": "expense", "subtype": "cogs", "is_group": false, "system_key": null, "parent_code": "52"}, {"code": "5203", "name": "مقاولو باطن المشاريع", "name_en": "Project subcontractors", "type": "expense", "subtype": "cogs", "is_group": false, "system_key": null, "parent_code": "52"}, {"code": "5204", "name": "معدات ونقل المشاريع", "name_en": "Project equipment and transport", "type": "expense", "subtype": "cogs", "is_group": false, "system_key": null, "parent_code": "52"}, {"code": "5205", "name": "تأمين وضمانات المشاريع", "name_en": "Project insurance and bonds", "type": "expense", "subtype": "cogs", "is_group": false, "system_key": null, "parent_code": "52"}, {"code": "6", "name": "مصروفات التشغيل", "name_en": "Operating expenses", "type": "expense", "subtype": "general", "is_group": true, "system_key": null}, {"code": "61", "name": "مصروفات إدارية وعمومية", "name_en": "General and administrative", "type": "expense", "subtype": "general", "is_group": true, "system_key": null, "parent_code": "6"}, {"code": "6101", "name": "رواتب وأجور", "name_en": "Salaries and wages", "type": "expense", "subtype": "general", "is_group": false, "system_key": "SALARIES", "parent_code": "61"}, {"code": "6102", "name": "بدلات ومزايا", "name_en": "Allowances and benefits", "type": "expense", "subtype": "general", "is_group": false, "system_key": null, "parent_code": "61"}, {"code": "6103", "name": "تأمينات اجتماعية (حصة صاحب العمل)", "name_en": "GOSI — employer share", "type": "expense", "subtype": "general", "is_group": false, "system_key": null, "parent_code": "61"}, {"code": "6104", "name": "مكافأة نهاية الخدمة", "name_en": "End-of-service benefit expense", "type": "expense", "subtype": "general", "is_group": false, "system_key": null, "parent_code": "61"}, {"code": "6105", "name": "إيجارات", "name_en": "Rent", "type": "expense", "subtype": "general", "is_group": false, "system_key": null, "parent_code": "61"}, {"code": "6106", "name": "كهرباء وماء واتصالات", "name_en": "Utilities and communications", "type": "expense", "subtype": "general", "is_group": false, "system_key": null, "parent_code": "61"}, {"code": "6107", "name": "صيانة وإصلاح", "name_en": "Repairs and maintenance", "type": "expense", "subtype": "general", "is_group": false, "system_key": null, "parent_code": "61"}, {"code": "6108", "name": "رسوم حكومية وتراخيص واشتراكات", "name_en": "Government fees, licences and subscriptions", "type": "expense", "subtype": "general", "is_group": false, "system_key": null, "parent_code": "61"}, {"code": "6109", "name": "أتعاب مهنية واستشارات", "name_en": "Professional fees", "type": "expense", "subtype": "general", "is_group": false, "system_key": null, "parent_code": "61"}, {"code": "6110", "name": "قرطاسية ومطبوعات", "name_en": "Stationery and printing", "type": "expense", "subtype": "general", "is_group": false, "system_key": null, "parent_code": "61"}, {"code": "6111", "name": "ضيافة ونظافة", "name_en": "Hospitality and cleaning", "type": "expense", "subtype": "general", "is_group": false, "system_key": null, "parent_code": "61"}, {"code": "6112", "name": "سفر وانتقالات", "name_en": "Travel and transport", "type": "expense", "subtype": "general", "is_group": false, "system_key": null, "parent_code": "61"}, {"code": "6113", "name": "تأمين", "name_en": "Insurance", "type": "expense", "subtype": "general", "is_group": false, "system_key": null, "parent_code": "61"}, {"code": "6114", "name": "مصروف الإهلاك", "name_en": "Depreciation expense", "type": "expense", "subtype": "depreciation", "is_group": false, "system_key": "DEP_EXP", "parent_code": "61"}, {"code": "6115", "name": "ديون معدومة ومخصص ديون مشكوك فيها", "name_en": "Bad debts and allowance expense", "type": "expense", "subtype": "general", "is_group": false, "system_key": "BAD_DEBT", "parent_code": "61"}, {"code": "6116", "name": "مصروفات بنكية وعمولات", "name_en": "Bank charges", "type": "expense", "subtype": "general", "is_group": false, "system_key": null, "parent_code": "61"}, {"code": "6117", "name": "غرامات وجزاءات", "name_en": "Fines and penalties", "type": "expense", "subtype": "general", "is_group": false, "system_key": null, "parent_code": "61"}, {"code": "6118", "name": "مصروفات متنوعة", "name_en": "Miscellaneous expenses", "type": "expense", "subtype": "general", "is_group": false, "system_key": null, "parent_code": "61"}, {"code": "62", "name": "مصروفات البيع والتسويق", "name_en": "Selling and marketing", "type": "expense", "subtype": "general", "is_group": true, "system_key": null, "parent_code": "6"}, {"code": "6201", "name": "دعاية وإعلان", "name_en": "Advertising", "type": "expense", "subtype": "general", "is_group": false, "system_key": null, "parent_code": "62"}, {"code": "6202", "name": "عمولات مبيعات", "name_en": "Sales commissions", "type": "expense", "subtype": "general", "is_group": false, "system_key": null, "parent_code": "62"}, {"code": "6203", "name": "نقل وشحن", "name_en": "Freight and delivery", "type": "expense", "subtype": "general", "is_group": false, "system_key": null, "parent_code": "62"}, {"code": "7", "name": "مصروفات تمويلية وأخرى", "name_en": "Finance and other expenses", "type": "expense", "subtype": "general", "is_group": true, "system_key": null}, {"code": "7101", "name": "فوائد وأعباء تمويل", "name_en": "Finance costs", "type": "expense", "subtype": "general", "is_group": false, "system_key": null, "parent_code": "7"}, {"code": "7102", "name": "خسائر بيع أصول ثابتة", "name_en": "Loss on disposal of assets", "type": "expense", "subtype": "general", "is_group": false, "system_key": "ASSET_LOSS", "parent_code": "7"}, {"code": "7103", "name": "خسائر فروق عملة", "name_en": "Foreign exchange losses", "type": "expense", "subtype": "general", "is_group": false, "system_key": "FX_LOSS", "parent_code": "7"}, {"code": "7104", "name": "زكاة وضريبة دخل", "name_en": "Zakat and income tax expense", "type": "expense", "subtype": "general", "is_group": false, "system_key": "ZAKAT_EXP", "parent_code": "7"}, {"code": "7105", "name": "فروق التقريب", "name_en": "Rounding differences", "type": "expense", "subtype": "general", "is_group": false, "system_key": "ROUNDING", "parent_code": "7"}]'::jsonb) on conflict (key) do update set name=excluded.name, description=excluded.description, rows=excluded.rows;
insert into app.coa_templates (key,name,description,rows) values ('minimal','مبسّطة','شجرة مصغّرة للبدء السريع','[{"code": "1", "name": "الأصول", "name_en": "Assets", "type": "asset", "subtype": "general", "is_group": true, "system_key": null}, {"code": "1101", "name": "النقدية", "name_en": "Cash", "type": "asset", "subtype": "cash", "is_group": false, "system_key": "CASH", "parent_code": "1"}, {"code": "1102", "name": "البنك", "name_en": "Bank", "type": "asset", "subtype": "bank", "is_group": false, "system_key": "BANK", "parent_code": "1"}, {"code": "1201", "name": "العملاء", "name_en": "Receivables", "type": "asset", "subtype": "receivable", "is_group": false, "system_key": "AR", "parent_code": "1"}, {"code": "1301", "name": "مدفوعات مقدمة ومدينون", "name_en": "Other assets", "type": "asset", "subtype": "general", "is_group": false, "system_key": null, "parent_code": "1"}, {"code": "1404", "name": "ضريبة مدخلات", "name_en": "VAT input", "type": "asset", "subtype": "vat_input", "is_group": false, "system_key": "VAT_IN", "parent_code": "1"}, {"code": "1501", "name": "أصول ثابتة", "name_en": "Fixed assets", "type": "asset", "subtype": "fixed_asset", "is_group": false, "system_key": null, "parent_code": "1"}, {"code": "1502", "name": "مجمع الإهلاك", "name_en": "Accumulated depreciation", "type": "asset", "subtype": "accum_dep", "is_group": false, "system_key": null, "parent_code": "1"}, {"code": "2", "name": "الخصوم", "name_en": "Liabilities", "type": "liability", "subtype": "general", "is_group": true, "system_key": null}, {"code": "2101", "name": "الموردون", "name_en": "Payables", "type": "liability", "subtype": "payable", "is_group": false, "system_key": "AP", "parent_code": "2"}, {"code": "2201", "name": "مصروفات مستحقة", "name_en": "Accruals", "type": "liability", "subtype": "accrued", "is_group": false, "system_key": null, "parent_code": "2"}, {"code": "2301", "name": "ضريبة مخرجات", "name_en": "VAT output", "type": "liability", "subtype": "vat_output", "is_group": false, "system_key": "VAT_OUT", "parent_code": "2"}, {"code": "2302", "name": "ضريبة مستحقة السداد", "name_en": "VAT payable", "type": "liability", "subtype": "vat_payable", "is_group": false, "system_key": "VAT_PAY", "parent_code": "2"}, {"code": "2401", "name": "قروض", "name_en": "Loans", "type": "liability", "subtype": "loan", "is_group": false, "system_key": null, "parent_code": "2"}, {"code": "2701", "name": "تسويات معلّقة", "name_en": "Suspense", "type": "liability", "subtype": "general", "is_group": false, "system_key": "SUSPENSE", "parent_code": "2"}, {"code": "3", "name": "حقوق الملكية", "name_en": "Equity", "type": "equity", "subtype": "general", "is_group": true, "system_key": null}, {"code": "3101", "name": "رأس المال", "name_en": "Capital", "type": "equity", "subtype": "capital", "is_group": false, "system_key": "CAPITAL", "parent_code": "3"}, {"code": "3301", "name": "أرباح مبقاة", "name_en": "Retained earnings", "type": "equity", "subtype": "retained_earnings", "is_group": false, "system_key": "RE", "parent_code": "3"}, {"code": "3302", "name": "مسحوبات", "name_en": "Drawings", "type": "equity", "subtype": "drawings", "is_group": false, "system_key": null, "parent_code": "3"}, {"code": "4", "name": "الإيرادات", "name_en": "Revenue", "type": "revenue", "subtype": "general", "is_group": true, "system_key": null}, {"code": "4101", "name": "المبيعات", "name_en": "Sales", "type": "revenue", "subtype": "revenue_sales", "is_group": false, "system_key": "SALES", "parent_code": "4"}, {"code": "4201", "name": "إيرادات أخرى", "name_en": "Other income", "type": "revenue", "subtype": "general", "is_group": false, "system_key": null, "parent_code": "4"}, {"code": "4202", "name": "أرباح بيع أصول", "name_en": "Gain on disposal", "type": "revenue", "subtype": "general", "is_group": false, "system_key": "ASSET_GAIN", "parent_code": "4"}, {"code": "4203", "name": "أرباح فروق عملة", "name_en": "FX gain", "type": "revenue", "subtype": "general", "is_group": false, "system_key": "FX_GAIN", "parent_code": "4"}, {"code": "5", "name": "المصروفات", "name_en": "Expenses", "type": "expense", "subtype": "general", "is_group": true, "system_key": null}, {"code": "5101", "name": "تكلفة المبيعات", "name_en": "Cost of sales", "type": "expense", "subtype": "cogs", "is_group": false, "system_key": "COGS", "parent_code": "5"}, {"code": "5104", "name": "مشتريات", "name_en": "Purchases", "type": "expense", "subtype": "cogs", "is_group": false, "system_key": "PURCHASES", "parent_code": "5"}, {"code": "6101", "name": "رواتب", "name_en": "Salaries", "type": "expense", "subtype": "general", "is_group": false, "system_key": "SALARIES"}, {"code": "6105", "name": "إيجارات", "name_en": "Rent", "type": "expense", "subtype": "general", "is_group": false, "system_key": null}, {"code": "6106", "name": "مرافق واتصالات", "name_en": "Utilities", "type": "expense", "subtype": "general", "is_group": false, "system_key": null}, {"code": "6114", "name": "مصروف الإهلاك", "name_en": "Depreciation", "type": "expense", "subtype": "depreciation", "is_group": false, "system_key": "DEP_EXP"}, {"code": "6115", "name": "ديون معدومة", "name_en": "Bad debts", "type": "expense", "subtype": "general", "is_group": false, "system_key": "BAD_DEBT"}, {"code": "6118", "name": "مصروفات متنوعة", "name_en": "Miscellaneous", "type": "expense", "subtype": "general", "is_group": false, "system_key": null}, {"code": "7102", "name": "خسائر بيع أصول", "name_en": "Loss on disposal", "type": "expense", "subtype": "general", "is_group": false, "system_key": "ASSET_LOSS"}, {"code": "7103", "name": "خسائر فروق عملة", "name_en": "FX loss", "type": "expense", "subtype": "general", "is_group": false, "system_key": "FX_LOSS"}, {"code": "7104", "name": "زكاة وضريبة دخل", "name_en": "Zakat and tax", "type": "expense", "subtype": "general", "is_group": false, "system_key": "ZAKAT_EXP"}, {"code": "7105", "name": "فروق تقريب", "name_en": "Rounding", "type": "expense", "subtype": "general", "is_group": false, "system_key": "ROUNDING"}]'::jsonb) on conflict (key) do update set name=excluded.name, description=excluded.description, rows=excluded.rows;
-- ===== sql/998_storage.sql =====
-- مُحكَم للحسابات — تخزين المرفقات (Supabase Storage): دلو خاص، كل شركة في مجلد باسم رقمها، حد 10MB
create or replace function public.tenant_folder(p jsonb default '{}') returns text language sql stable security definer set search_path = public, acc as $$ select (select tenant_id::text from acc.members where user_id = auth.uid() and active) $$;
do $$ begin
  if exists (select 1 from information_schema.schemata where schema_name = 'storage') then
    insert into storage.buckets (id, name, public, file_size_limit) values ('acc-files', 'acc-files', false, 10485760) on conflict (id) do update set public = false, file_size_limit = 10485760;
    drop policy if exists acc_files_select on storage.objects; drop policy if exists acc_files_insert on storage.objects; drop policy if exists acc_files_delete on storage.objects;
    create policy acc_files_select on storage.objects for select to authenticated using (bucket_id = 'acc-files' and (storage.foldername(name))[1] = public.tenant_folder());
    create policy acc_files_insert on storage.objects for insert to authenticated with check (bucket_id = 'acc-files' and (storage.foldername(name))[1] = public.tenant_folder());
    create policy acc_files_delete on storage.objects for delete to authenticated using (bucket_id = 'acc-files' and (storage.foldername(name))[1] = public.tenant_folder());
  end if;
end $$;
-- ===== sql/999_grants.sql =====
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
      and (p.proname in ('login_email','register_company','ingest_journal') or p.pronargs = 0 or p.proargtypes::text = (select oid::text from pg_type where typname = 'jsonb')) loop
    if f.proname in ('register_company','ingest_journal','login_email') then execute format('grant execute on function %s to anon, authenticated', f.sig);
    else execute format('grant execute on function %s to authenticated', f.sig); end if;
  end loop;
end $$;
alter default privileges in schema public revoke execute on functions from public, anon;
