-- مُحكَم 1.6.0.1 — تدقيق قبل/بعد + تعارض المهام + قوالب أدوار + إطفاء + مستودعات وجرد + شيكات + عُهد (آمن للتكرار؛ كله إضافي)
-- ===== 037_audit_diff_sod =====
-- مُحكَم للحسابات 1.6 (دفعة 1) — سجل القيمة السابقة/الجديدة + تقرير تعارض المهام
-- إضافي ومتكرر التشغيل: لا يغيّر بيانات ولا دوالًا قائمة. التفاصيل داخل حقل details المشمول بسلسلة التجزئة.

create or replace function app.audit_diff_trg() returns trigger language plpgsql security definer set search_path = public, acc, app as $$
declare o jsonb; n jsonb; k text; d jsonb := '{}'::jsonb; t uuid; m acc.members; ref text;
  skip text[] := array['updated_at','created_at','last_login','changed_at','posted_at','submitted_at'] || coalesce(string_to_array(nullif(tg_argv[1],''), ','), '{}'::text[]);
begin
  select * into m from app.me(); if m.tenant_id is null then return coalesce(new, old); end if;
  if current_setting('app.demo_wipe', true) = '1' then return coalesce(new, old); end if;
  if tg_op = 'DELETE' then
    o := to_jsonb(old); t := (o->>'tenant_id')::uuid;
    if t is distinct from m.tenant_id then return old; end if;       -- لا نكتب في سجل شركة أخرى (مثلًا عند حذف شركة بالكامل)
    ref := left(coalesce(o->>'code', o->>'id', o->>'user_id', ''), 100);
    perform app.audit_for(t, m.user_id, m.username, 'delete', tg_argv[0], ref, left(jsonb_build_object('name', o->>'name', 'code', o->>'code')::text, 500));
    return old;
  end if;
  o := to_jsonb(old); n := to_jsonb(new); t := (n->>'tenant_id')::uuid;
  if t is distinct from m.tenant_id then return new; end if;
  for k in select jsonb_object_keys(n) loop
    if k = any(skip) then continue; end if;
    if (o->k) is distinct from (n->k) then d := d || jsonb_build_object(k, jsonb_build_array(o->k, n->k)); end if;
  end loop;
  if d = '{}'::jsonb then return new; end if;
  ref := left(coalesce(n->>'code', n->>'id', n->>'user_id', ''), 100);
  perform app.audit_for(t, m.user_id, m.username, 'change', tg_argv[0], ref, left(d::text, 3000));
  return new;
end $$;

do $$ declare r record; begin
  for r in select * from (values
    ('parties','party',''), ('accounts','account',''), ('items','item',''), ('tax_codes','tax_code',''), ('entities','entity',''),
    ('roles','role',''), ('members','member',''), ('budgets','budget',''), ('assets','asset','accumulated,dep_through'),
    ('dims','dim',''), ('recurring','recurring','next_date,last_run,runs')) as v(tbl, lbl, skp) loop
    execute format('drop trigger if exists audit_diff on acc.%I', r.tbl);
    execute format('create trigger audit_diff after update or delete on acc.%I for each row execute function app.audit_diff_trg(%L, %L)', r.tbl, r.lbl, r.skp);
  end loop;
end $$;

-- تقرير تعارض المهام (كشف بعدي، لكل المنشأة أو كيانات محددة)
create or replace function public.sod_report(p jsonb default '{}') returns jsonb language plpgsql stable security definer set search_path = public, app, acc as $$
declare t uuid := app.need('controls', 'view'); ents uuid[] := app.pick_ents(p); res jsonb := '[]'::jsonb; n bigint; smp jsonb;
begin
  -- 1) دفعات اعتمدها من أنشأ الطرف نفسه (مورّد/عميل) قبل أقل من 30 يومًا من إنشائه
  select count(*), coalesce(jsonb_agg(x.number) filter (where x.rn <= 5), '[]'::jsonb) into n, smp from (
    select py.number, row_number() over (order by py.date desc) rn from acc.payments py join acc.parties pa on pa.tenant_id = py.tenant_id and pa.id = py.party_id
    where py.tenant_id = t and py.entity_id = any(ents) and py.status in ('approved','posted') and py.approved_by is not null and pa.created_by = py.approved_by and py.date - pa.created_at::date <= 30) x;
  res := res || jsonb_build_object('code','payee_creator_approves','severity','high','count',n,'sample',smp,'title','دفعات اعتمدها من أنشأ الطرف المستفيد قبل أقل من 30 يومًا');
  -- 2) دفعات اعتمدها من أدخل الفاتورة المسدَّدة
  select count(distinct py.id), coalesce(jsonb_agg(distinct py.number) filter (where py.number is not null), '[]'::jsonb) into n, smp from acc.payments py
    join acc.allocations al on al.tenant_id = py.tenant_id and al.source_kind = 'payment' and al.source_id = py.id
    join acc.invoices iv on iv.tenant_id = al.tenant_id and iv.id = al.invoice_id
    where py.tenant_id = t and py.entity_id = any(ents) and py.kind = 'payment' and py.approved_by is not null and iv.created_by = py.approved_by;
  res := res || jsonb_build_object('code','invoice_enterer_authorizes_payment','severity','high','count',n,'sample',(select coalesce(jsonb_agg(v), '[]'::jsonb) from (select v from jsonb_array_elements(smp) v limit 5) q),'title','دفعات اعتمدها من أدخل الفاتورة المسدَّدة');
  -- 3) دفعات أنشأها ومرّرها المستخدم نفسه
  select count(*) into n from acc.payments where tenant_id = t and entity_id = any(ents) and status in ('approved','posted') and approved_by is not null and approved_by = created_by;
  res := res || jsonb_build_object('code','payment_self_approved','severity','high','count',n,'sample','[]'::jsonb,'title','دفعات أنشأها واعتمدها المستخدم نفسه');
  -- 4) فواتير أنشأها واعتمدها المستخدم نفسه
  select count(*) into n from acc.invoices where tenant_id = t and entity_id = any(ents) and status in ('approved','posted') and approved_by is not null and approved_by = created_by;
  res := res || jsonb_build_object('code','invoice_self_approved','severity','medium','count',n,'sample','[]'::jsonb,'title','فواتير أنشأها واعتمدها المستخدم نفسه');
  -- 5) فترات أعاد فتحها من رحّل قيودًا فيها
  select count(*) into n from acc.periods pr where pr.tenant_id = t and pr.entity_id = any(ents) and pr.status = 'open' and pr.changed_by is not null
    and exists (select 1 from acc.journals j where j.tenant_id = pr.tenant_id and j.entity_id = pr.entity_id and j.date between pr.start_date and pr.end_date and j.posted_by = pr.changed_by);
  res := res || jsonb_build_object('code','reopen_by_poster','severity','medium','count',n,'sample','[]'::jsonb,'title','فترات أعاد فتحها مستخدم رحّل قيودًا فيها');
  return jsonb_build_object('items', res, 'total', (select coalesce(sum((x->>'count')::bigint), 0) from jsonb_array_elements(res) x));
end $$;

insert into app.api_ops (op, fn, writes, descr) values ('controls.sod', 'sod_report', false, 'تقرير تعارض المهام') on conflict (op) do update set fn = excluded.fn, writes = excluded.writes, descr = excluded.descr;

-- ===== 038_role_templates =====
-- مُحكَم للحسابات 1.6 (دفعة 2) — قوالب أدوار جاهزة إضافية (اختيارية؛ لا تُنشأ تلقائيًا ولا تغيّر أدوارًا قائمة)
create or replace function app.role_template_defs() returns jsonb language sql immutable as $$
select jsonb_build_array(
 jsonb_build_object('id','senior','name','محاسب أول','description','إعداد القيود والفواتير والسندات والترحيل بعد الاعتماد وتسوية البنوك، بدون إقفال أو إعادة فتح','sys','[]'::jsonb,'perms','{"dashboard":["view"],"coa":["view","export"],"journals":["view","add","edit","delete","post","reverse","export"],"sales":["view","add","edit","post","export"],"purchases":["view","add","edit","post","export"],"payments":["view","add","edit","post","export"],"parties":["view","add","edit","export"],"bank":["view","add","edit","reconcile","export"],"assets":["view","add","edit","export"],"budgets":["view","export"],"tax":["view","export"],"reports":["view","export"],"attachments":["view","add"],"costcenters":["view"],"import":["add"]}'::jsonb),
 jsonb_build_object('id','invacc','name','محاسب مخزون','description','الأصناف وحركات المخزون وتقارير التقييم وتسوية المخزون مع الأستاذ','sys','[]'::jsonb,'perms','{"dashboard":["view"],"coa":["view"],"journals":["view"],"sales":["view","export"],"purchases":["view","export"],"parties":["view"],"reports":["view","export"],"attachments":["view","add"],"costcenters":["view"],"import":["add"]}'::jsonb),
 jsonb_build_object('id','costacc','name','محاسب تكاليف','description','مراكز التكلفة والمشاريع وتقارير الربحية والموازنات بدون اعتماد','sys','[]'::jsonb,'perms','{"dashboard":["view"],"coa":["view","export"],"journals":["view","export"],"sales":["view","export"],"purchases":["view","export"],"payments":["view","export"],"parties":["view"],"budgets":["view","add","edit","export"],"reports":["view","export"],"costcenters":["view","add","edit","delete"],"attachments":["view"]}'::jsonb),
 jsonb_build_object('id','controller','name','مراقب مالي','description','اعتماد القيود والفواتير والسندات والإقفال الشهري والرقابة، بدون إدارة المستخدمين','sys','["audit"]'::jsonb,'perms','{"dashboard":["view"],"coa":["view","export"],"journals":["view","approve","post","reverse","export"],"sales":["view","approve","post","export"],"purchases":["view","approve","post","export"],"payments":["view","approve","post","export"],"parties":["view","export"],"bank":["view","reconcile","export"],"assets":["view","post","export"],"budgets":["view","approve","export"],"tax":["view","export"],"reports":["view","export"],"periods":["view","close"],"attachments":["view","add"],"controls":["view"],"costcenters":["view"],"requests":["view","approve"]}'::jsonb),
 jsonb_build_object('id','extauditor','name','مراجع خارجي (قراءة فقط)','description','اطلاع مقيّد على الدفاتر والتقارير والمرفقات بلا أي تعديل ولا إدارة','sys','["audit"]'::jsonb,'perms','{"dashboard":["view"],"coa":["view","export"],"journals":["view","export"],"sales":["view","export"],"purchases":["view","export"],"payments":["view","export"],"parties":["view"],"bank":["view","export"],"assets":["view","export"],"budgets":["view"],"tax":["view","export"],"reports":["view","export"],"periods":["view"],"attachments":["view"],"controls":["view"]}'::jsonb),
 jsonb_build_object('id','coadmin','name','مدير الشركة (إداري)','description','إدارة المستخدمين والإعدادات بدون صلاحيات مالية على القيود','sys','["settings","users"]'::jsonb,'perms','{"dashboard":["view"],"coa":["view"],"reports":["view"],"attachments":["view"]}'::jsonb)
) $$;

create or replace function public.role_template_list(p jsonb default '{}') returns jsonb language plpgsql stable security definer set search_path = public, app, acc as $$
declare t uuid := app.need_sys('users');
begin
  return coalesce((select jsonb_agg(d || jsonb_build_object('installed', exists (select 1 from acc.roles r where r.tenant_id = t and r.id = d->>'id')) order by ord) from jsonb_array_elements(app.role_template_defs()) with ordinality as x(d, ord)), '[]'::jsonb);
end $$;

create or replace function public.role_template_apply(p jsonb) returns jsonb language plpgsql security definer set search_path = public, app, acc as $$
declare t uuid := app.need_sys('users'); d jsonb; n int := 0; ids text[] := array(select jsonb_array_elements_text(coalesce(p->'ids', '[]'::jsonb)));
begin
  if cardinality(ids) = 0 then raise exception 'اختر قالبًا واحدًا على الأقل'; end if;
  for d in select * from jsonb_array_elements(app.role_template_defs()) loop
    continue when not (d->>'id' = any(ids));
    if (select role from app.me()) <> 'owner' and exists (select 1 from jsonb_array_elements_text(d->'sys') s where not app.sys(s)) then raise exception 'لا تمنح صلاحيات نظام لا تملكها'; end if;
    insert into acc.roles (tenant_id, id, name, description, perms, sys) values (t, d->>'id', d->>'name', d->>'description', d->'perms', d->'sys') on conflict (tenant_id, id) do nothing;
    if found then n := n + 1; perform app.audit('role', 'role', d->>'id', 'إضافة قالب دور جاهز: ' || (d->>'name')); end if;
  end loop;
  return jsonb_build_object('added', n);
end $$;

-- ===== 039_deferrals =====
-- مُحكَم للحسابات 1.6 (دفعة 3أ) — المصروفات المقدّمة والإيرادات المؤجلة: جداول إطفاء شهرية تولّد قيودًا مسودة (تمر بدورة الاعتماد المعتادة)
create table if not exists acc.deferrals (
  tenant_id uuid not null references acc.tenants(id) on delete cascade, id uuid not null default gen_random_uuid(), entity_id uuid not null,
  kind text not null check (kind in ('prepaid_expense','deferred_revenue')), name text not null, total numeric(18,2) not null check (total > 0),
  start_date date not null, months int not null check (months between 1 and 120), bs_account_id uuid not null, pl_account_id uuid not null,
  cost_center_id uuid, project_id uuid, status text not null default 'active' check (status in ('active','done','stopped')), note text not null default '',
  created_by uuid, created_at timestamptz not null default now(),
  primary key (tenant_id, id), foreign key (tenant_id, entity_id) references acc.entities (tenant_id, id),
  foreign key (tenant_id, bs_account_id) references acc.accounts (tenant_id, id), foreign key (tenant_id, pl_account_id) references acc.accounts (tenant_id, id));
create table if not exists acc.deferral_runs (
  tenant_id uuid not null, deferral_id uuid not null, month_no int not null, date date not null, amount numeric(18,2) not null, journal_id uuid,
  primary key (tenant_id, deferral_id, month_no), foreign key (tenant_id, deferral_id) references acc.deferrals (tenant_id, id) on delete cascade);
alter table acc.deferrals enable row level security; alter table acc.deferral_runs enable row level security;

insert into app.feature_cat (key, name, grp, core, since, sort) values ('deferrals', 'المقدّمات والإيرادات المؤجلة (جداول الإطفاء)', 'المالية', false, 1, 25)
on conflict (key) do update set name = excluded.name, grp = excluded.grp, core = excluded.core, sort = excluded.sort;

create or replace function public.deferral_list(p jsonb default '{}') returns jsonb language plpgsql stable security definer set search_path = public, app, acc as $$
declare t uuid := app.need('journals', 'view');
begin
  if not app.feat_on('deferrals') then raise exception 'الميزة غير مفعّلة لشركتك'; end if;
  return coalesce((select jsonb_agg(to_jsonb(d) || jsonb_build_object('posted', coalesce(r.n, 0), 'recognized', coalesce(r.s, 0),
      'bs_code', (select code from acc.accounts a where a.tenant_id = t and a.id = d.bs_account_id), 'pl_code', (select code from acc.accounts a where a.tenant_id = t and a.id = d.pl_account_id),
      'monthly', round(d.total / d.months, 2)) order by d.created_at desc)
    from acc.deferrals d left join (select deferral_id, count(*) n, sum(amount) s from acc.deferral_runs where tenant_id = t group by 1) r on r.deferral_id = d.id
    where d.tenant_id = t and d.entity_id = any(app.ents())), '[]'::jsonb);
end $$;

create or replace function public.deferral_save(p jsonb) returns jsonb language plpgsql security definer set search_path = public, app, acc as $$
declare t uuid := app.need('journals', 'add'); e uuid := (p->>'entity')::uuid; bs acc.accounts; pl acc.accounts; k text := p->>'kind'; nid uuid;
begin
  if not app.feat_on('deferrals') then raise exception 'الميزة غير مفعّلة لشركتك'; end if;
  if e is null or not (e = any(app.ents())) then raise exception 'كيان غير مسموح'; end if;
  if k not in ('prepaid_expense','deferred_revenue') then raise exception 'نوع غير صحيح'; end if;
  select * into bs from acc.accounts where tenant_id = t and id = (p->>'bs_account')::uuid; select * into pl from acc.accounts where tenant_id = t and id = (p->>'pl_account')::uuid;
  if bs.id is null or pl.id is null or bs.is_group or pl.is_group then raise exception 'اختر حسابين فرعيين صالحين'; end if;
  if k = 'prepaid_expense' and (bs.type <> 'asset' or pl.type <> 'expense') then raise exception 'المصروف المقدّم: حساب الميزانية أصل وحساب الإطفاء مصروف'; end if;
  if k = 'deferred_revenue' and (bs.type <> 'liability' or pl.type <> 'revenue') then raise exception 'الإيراد المؤجل: حساب الميزانية التزام وحساب الإطفاء إيراد'; end if;
  if nullif(trim(p->>'name'), '') is null then raise exception 'الاسم مطلوب'; end if;
  insert into acc.deferrals (tenant_id, entity_id, kind, name, total, start_date, months, bs_account_id, pl_account_id, cost_center_id, project_id, note, created_by)
  values (t, e, k, trim(p->>'name'), (p->>'total')::numeric, (p->>'start_date')::date, (p->>'months')::int, bs.id, pl.id, nullif(p->>'cost_center','')::uuid, nullif(p->>'project','')::uuid, coalesce(p->>'note',''), auth.uid())
  returning acc.deferrals.id into nid;
  perform app.audit('create', 'deferral', nid::text, trim(p->>'name') || ' — ' || (p->>'total') || ' على ' || (p->>'months') || ' شهر');
  return jsonb_build_object('id', nid);
end $$;

-- توليد قيود الإطفاء المستحقة حتى تاريخ معيّن. متكرر بلا ضرر: كل شهر يُولَّد مرة واحدة فقط (مفتاح فريد)
create or replace function public.deferral_run(p jsonb default '{}') returns jsonb language plpgsql security definer set search_path = public, app, acc as $$
declare t uuid := app.need('journals', 'add'); asof date := coalesce(nullif(p->>'asof','')::date, current_date); d acc.deferrals; i int; dt date; amt numeric; paid numeric; j jsonb; n int := 0; out jsonb := '[]'::jsonb; lines jsonb;
begin
  if not app.feat_on('deferrals') then raise exception 'الميزة غير مفعّلة لشركتك'; end if;
  for d in select * from acc.deferrals where tenant_id = t and status = 'active' and entity_id = any(app.ents()) and (nullif(p->>'id','') is null or id = (p->>'id')::uuid) order by start_date loop
    for i in 1..d.months loop
      dt := (date_trunc('month', d.start_date) + make_interval(months => i) - interval '1 day')::date;       -- آخر يوم من الشهر
      exit when dt > asof;
      continue when exists (select 1 from acc.deferral_runs r where r.tenant_id = t and r.deferral_id = d.id and r.month_no = i);
      select coalesce(sum(amount), 0) into paid from acc.deferral_runs r where r.tenant_id = t and r.deferral_id = d.id;
      amt := case when i = d.months then d.total - paid else round(d.total / d.months, 2) end;
      continue when amt <= 0;
      lines := case d.kind
        when 'prepaid_expense' then jsonb_build_array(jsonb_build_object('account', d.pl_account_id, 'debit', amt, 'credit', 0, 'cost_center', d.cost_center_id, 'project', d.project_id), jsonb_build_object('account', d.bs_account_id, 'debit', 0, 'credit', amt))
        else jsonb_build_array(jsonb_build_object('account', d.bs_account_id, 'debit', amt, 'credit', 0), jsonb_build_object('account', d.pl_account_id, 'debit', 0, 'credit', amt, 'cost_center', d.cost_center_id, 'project', d.project_id)) end;
      j := public.je_save(jsonb_build_object('entity', d.entity_id, 'date', dt, 'memo', 'إطفاء ' || d.name || ' — شهر ' || i || ' من ' || d.months, 'lines', lines, 'type', 'ADJ'));
      insert into acc.deferral_runs (tenant_id, deferral_id, month_no, date, amount, journal_id) values (t, d.id, i, dt, amt, (j->>'id')::uuid);
      out := out || jsonb_build_object('deferral', d.name, 'month', i, 'date', dt, 'amount', amt, 'journal', j->>'id'); n := n + 1;
    end loop;
    if (select count(*) from acc.deferral_runs r where r.tenant_id = t and r.deferral_id = d.id) >= d.months then update acc.deferrals set status = 'done' where tenant_id = t and id = d.id; end if;
  end loop;
  perform app.audit('create', 'deferral', '', 'توليد ' || n || ' قيد إطفاء حتى ' || asof);
  return jsonb_build_object('generated', n, 'items', out);
end $$;

create or replace function public.deferral_stop(p jsonb) returns jsonb language plpgsql security definer set search_path = public, app, acc as $$
declare t uuid := app.need('journals', 'edit');
begin
  update acc.deferrals set status = 'stopped' where tenant_id = t and id = (p->>'id')::uuid and status = 'active' and entity_id = any(app.ents());
  if not found then raise exception 'الجدول غير موجود أو ليس فعّالًا'; end if;
  perform app.audit('update', 'deferral', p->>'id', 'إيقاف جدول الإطفاء'); return jsonb_build_object('ok', true);
end $$;

-- ===== 040_warehouses_counts =====
-- مُحكَم للحسابات 1.6 (دفعة 3ب) — المستودعات والتحويلات والجرد الفعلي مع تسوية فروق المخزون
-- مبدأ التوافق: الكميات الكلية وتقييم المتوسط المرجّح في acc.stock_bal كما هي. المستودعات طبقة مواقع فوقها:
-- كمية «المستودع الرئيسي» = الإجمالي − ما وُزّع على المستودعات. التحويل بين المواقع لا يغيّر القيمة ولا الأستاذ؛ فروق الجرد تغيّرهما بقيد مسجَّل.
create table if not exists acc.warehouses (
  tenant_id uuid not null references acc.tenants(id) on delete cascade, id uuid not null default gen_random_uuid(), entity_id uuid not null, code text not null, name text not null,
  active boolean not null default true, created_at timestamptz not null default now(), primary key (tenant_id, id), unique (tenant_id, entity_id, code), foreign key (tenant_id, entity_id) references acc.entities (tenant_id, id));
create table if not exists acc.stock_wh (
  tenant_id uuid not null, entity_id uuid not null, item_id uuid not null, warehouse_id uuid not null, qty numeric(18,4) not null default 0 check (qty >= 0),
  primary key (tenant_id, entity_id, item_id, warehouse_id), foreign key (tenant_id, item_id) references acc.items (tenant_id, id), foreign key (tenant_id, warehouse_id) references acc.warehouses (tenant_id, id));
create table if not exists acc.stock_transfers (
  tenant_id uuid not null references acc.tenants(id) on delete cascade, id uuid not null default gen_random_uuid(), entity_id uuid not null, number bigint, date date not null,
  from_wh uuid, to_wh uuid, note text not null default '', lines jsonb not null, created_by uuid, created_at timestamptz not null default now(), primary key (tenant_id, id));
create table if not exists acc.stock_counts (
  tenant_id uuid not null references acc.tenants(id) on delete cascade, id uuid not null default gen_random_uuid(), entity_id uuid not null, wh_id uuid, date date not null,
  adjust_account_id uuid not null, status text not null default 'draft' check (status in ('draft','posted','cancelled')), note text not null default '', journal_id uuid,
  created_by uuid, created_at timestamptz not null default now(), posted_by uuid, posted_at timestamptz, primary key (tenant_id, id));
create table if not exists acc.stock_count_lines (
  tenant_id uuid not null, count_id uuid not null, item_id uuid not null, system_qty numeric(18,4) not null, counted_qty numeric(18,4) check (counted_qty is null or counted_qty >= 0),
  unit_cost numeric(18,6) not null default 0, primary key (tenant_id, count_id, item_id), foreign key (tenant_id, count_id) references acc.stock_counts (tenant_id, id) on delete cascade);
alter table acc.warehouses enable row level security; alter table acc.stock_wh enable row level security; alter table acc.stock_transfers enable row level security;
alter table acc.stock_counts enable row level security; alter table acc.stock_count_lines enable row level security;

insert into app.feature_cat (key, name, grp, core, since, sort) values ('warehouses', 'المستودعات والتحويلات والجرد الفعلي', 'المالية', false, 1, 26)
on conflict (key) do update set name = excluded.name, grp = excluded.grp, core = excluded.core, sort = excluded.sort;

-- الكمية المتاحة في موقع: مستودع محدد، أو الرئيسي (null)
create or replace function app.loc_qty(t uuid, e uuid, it uuid, wh uuid) returns numeric language sql stable security definer set search_path = public, acc as $$
  select case when wh is null then coalesce((select qty from acc.stock_bal where tenant_id = t and entity_id = e and item_id = it), 0) - coalesce((select sum(qty) from acc.stock_wh where tenant_id = t and entity_id = e and item_id = it), 0)
              else coalesce((select qty from acc.stock_wh where tenant_id = t and entity_id = e and item_id = it and warehouse_id = wh), 0) end $$;

create or replace function public.wh_list(p jsonb default '{}') returns jsonb language plpgsql stable security definer set search_path = public, app, acc as $$
declare t uuid := app.need_inv('view');
begin
  if not app.feat_on('warehouses') then raise exception 'الميزة غير مفعّلة لشركتك'; end if;
  return coalesce((select jsonb_agg(to_jsonb(w) - 'tenant_id' order by w.entity_id, w.code) from acc.warehouses w where w.tenant_id = t and w.entity_id = any(app.ents())), '[]'::jsonb);
end $$;

create or replace function public.wh_upsert(p jsonb) returns jsonb language plpgsql security definer set search_path = public, app, acc as $$
declare t uuid := app.need_inv('add'); e uuid := (p->>'entity')::uuid; nid uuid := nullif(p->>'id','')::uuid;
begin
  if not app.feat_on('warehouses') then raise exception 'الميزة غير مفعّلة لشركتك'; end if;
  if e is null or not (e = any(app.ents())) then raise exception 'كيان غير مسموح'; end if;
  if nullif(trim(p->>'code'),'') is null or nullif(trim(p->>'name'),'') is null then raise exception 'الرمز والاسم مطلوبان'; end if;
  if nid is null then insert into acc.warehouses (tenant_id, entity_id, code, name) values (t, e, trim(p->>'code'), trim(p->>'name')) returning id into nid;
  else update acc.warehouses set code = trim(p->>'code'), name = trim(p->>'name'), active = coalesce((p->>'active')::boolean, active) where tenant_id = t and id = nid and entity_id = any(app.ents()); end if;
  perform app.audit('upsert', 'warehouse', nid::text, trim(p->>'code') || ' — ' || trim(p->>'name')); return jsonb_build_object('id', nid);
end $$;

-- أرصدة الأصناف لكل موقع (الرئيسي + المستودعات)
create or replace function public.wh_stock(p jsonb default '{}') returns jsonb language plpgsql stable security definer set search_path = public, app, acc as $$
declare t uuid := app.need_inv('view'); ents uuid[] := app.pick_ents(p);
begin
  if not app.feat_on('warehouses') then raise exception 'الميزة غير مفعّلة لشركتك'; end if;
  return coalesce((select jsonb_agg(x order by x->>'item_code', x->>'location') from (
    select jsonb_build_object('entity', b.entity_id, 'item', i.id, 'item_code', i.code, 'item_name', i.name, 'location', 'المستودع الرئيسي', 'wh', null, 'qty', app.loc_qty(t, b.entity_id, i.id, null), 'avg_cost', b.avg_cost,
        'value', round(app.loc_qty(t, b.entity_id, i.id, null) * b.avg_cost, 2)) x
      from acc.stock_bal b join acc.items i on i.tenant_id = b.tenant_id and i.id = b.item_id where b.tenant_id = t and b.entity_id = any(ents) and app.loc_qty(t, b.entity_id, i.id, null) <> 0
    union all
    select jsonb_build_object('entity', s.entity_id, 'item', i.id, 'item_code', i.code, 'item_name', i.name, 'location', w.name, 'wh', w.id, 'qty', s.qty, 'avg_cost', coalesce(b.avg_cost, 0), 'value', round(s.qty * coalesce(b.avg_cost, 0), 2))
      from acc.stock_wh s join acc.items i on i.tenant_id = s.tenant_id and i.id = s.item_id join acc.warehouses w on w.tenant_id = s.tenant_id and w.id = s.warehouse_id
      left join acc.stock_bal b on b.tenant_id = s.tenant_id and b.entity_id = s.entity_id and b.item_id = s.item_id where s.tenant_id = t and s.entity_id = any(ents) and s.qty <> 0) q), '[]'::jsonb);
end $$;

-- تحويل بين مواقع (null = الرئيسي): يُنفَّذ فورًا، لا يمس القيمة ولا الأستاذ
create or replace function public.stock_transfer(p jsonb) returns jsonb language plpgsql security definer set search_path = public, app, acc as $$
declare t uuid := app.need_inv('edit'); e uuid := (p->>'entity')::uuid; f uuid := nullif(p->>'from','')::uuid; g uuid := nullif(p->>'to','')::uuid; d date := coalesce(nullif(p->>'date','')::date, current_date); l jsonb; it uuid; q numeric; nid uuid := gen_random_uuid(); no bigint; nm text;
begin
  if not app.feat_on('warehouses') then raise exception 'الميزة غير مفعّلة لشركتك'; end if;
  if e is null or not (e = any(app.ents())) then raise exception 'كيان غير مسموح'; end if;
  if f is not distinct from g then raise exception 'موقع المصدر والوجهة متطابقان'; end if;
  if (f is not null and not exists (select 1 from acc.warehouses where tenant_id = t and id = f and entity_id = e)) or (g is not null and not exists (select 1 from acc.warehouses where tenant_id = t and id = g and entity_id = e and active)) then raise exception 'مستودع غير صالح لهذا الكيان'; end if;
  if jsonb_typeof(p->'lines') <> 'array' or jsonb_array_length(p->'lines') = 0 then raise exception 'أضف صنفًا واحدًا على الأقل'; end if;
  for l in select * from jsonb_array_elements(p->'lines') loop
    it := (l->>'item')::uuid; q := (l->>'qty')::numeric;
    if q is null or q <= 0 then raise exception 'الكمية يجب أن تكون موجبة'; end if;
    if not exists (select 1 from acc.items where tenant_id = t and id = it) then raise exception 'صنف غير موجود'; end if;
    if app.loc_qty(t, e, it, f) < q then select name into nm from acc.items where tenant_id = t and id = it; raise exception 'الكمية المتاحة في موقع المصدر لا تكفي للصنف «%»', nm; end if;
    if f is not null then update acc.stock_wh set qty = qty - q where tenant_id = t and entity_id = e and item_id = it and warehouse_id = f; end if;
    if g is not null then insert into acc.stock_wh (tenant_id, entity_id, item_id, warehouse_id, qty) values (t, e, it, g, q) on conflict (tenant_id, entity_id, item_id, warehouse_id) do update set qty = acc.stock_wh.qty + q; end if;
  end loop;
  no := app.next_no(t, e, 'ST', extract(year from d)::int);
  insert into acc.stock_transfers (tenant_id, id, entity_id, number, date, from_wh, to_wh, note, lines, created_by) values (t, nid, e, no, d, f, g, coalesce(p->>'note',''), p->'lines', auth.uid());
  perform app.audit('create', 'stock_transfer', nid::text, 'تحويل مخزون رقم ' || no); return jsonb_build_object('id', nid, 'number', no);
end $$;

create or replace function public.stock_transfer_list(p jsonb default '{}') returns jsonb language plpgsql stable security definer set search_path = public, app, acc as $$
declare t uuid := app.need_inv('view');
begin
  if not app.feat_on('warehouses') then raise exception 'الميزة غير مفعّلة لشركتك'; end if;
  return coalesce((select jsonb_agg(to_jsonb(x) - 'tenant_id' || jsonb_build_object('from_name', coalesce((select name from acc.warehouses w where w.tenant_id = t and w.id = x.from_wh), 'المستودع الرئيسي'), 'to_name', coalesce((select name from acc.warehouses w where w.tenant_id = t and w.id = x.to_wh), 'المستودع الرئيسي')) order by x.date desc, x.number desc)
    from acc.stock_transfers x where x.tenant_id = t and x.entity_id = any(app.ents())), '[]'::jsonb);
end $$;

-- الجرد الفعلي: لقطة بالكميات الدفترية في موقع معيّن ثم إدخال الكميات المعدودة ثم الترحيل
create or replace function public.count_create(p jsonb) returns jsonb language plpgsql security definer set search_path = public, app, acc as $$
declare t uuid := app.need_inv('edit'); e uuid := (p->>'entity')::uuid; w uuid := nullif(p->>'wh','')::uuid; d date := coalesce(nullif(p->>'date','')::date, current_date); adj uuid := (p->>'adjust_account')::uuid; nid uuid := gen_random_uuid(); n int;
begin
  if not app.feat_on('warehouses') then raise exception 'الميزة غير مفعّلة لشركتك'; end if;
  if e is null or not (e = any(app.ents())) then raise exception 'كيان غير مسموح'; end if;
  if w is not null and not exists (select 1 from acc.warehouses where tenant_id = t and id = w and entity_id = e) then raise exception 'مستودع غير صالح'; end if;
  if not exists (select 1 from acc.accounts where tenant_id = t and id = adj and not is_group and type in ('expense','revenue')) then raise exception 'حساب فروق الجرد: اختر حساب مصروف أو إيراد'; end if;
  insert into acc.stock_counts (tenant_id, id, entity_id, wh_id, date, adjust_account_id, note, created_by) values (t, nid, e, w, d, adj, coalesce(p->>'note',''), auth.uid());
  insert into acc.stock_count_lines (tenant_id, count_id, item_id, system_qty, unit_cost)
    select t, nid, i.id, app.loc_qty(t, e, i.id, w), coalesce((select avg_cost from acc.stock_bal b where b.tenant_id = t and b.entity_id = e and b.item_id = i.id), 0)
    from acc.items i where i.tenant_id = t and i.active and (app.loc_qty(t, e, i.id, w) <> 0 or (nullif(p->>'all','') is not null and (p->>'all')::boolean));
  get diagnostics n = row_count;
  perform app.audit('create', 'stock_count', nid::text, 'جرد جديد — ' || n || ' صنف'); return jsonb_build_object('id', nid, 'lines', n);
end $$;

create or replace function public.count_get(p jsonb) returns jsonb language plpgsql stable security definer set search_path = public, app, acc as $$
declare t uuid := app.need_inv('view'); c acc.stock_counts;
begin
  select * into c from acc.stock_counts where tenant_id = t and id = (p->>'id')::uuid and entity_id = any(app.ents()); if c.id is null then raise exception 'الجرد غير موجود'; end if;
  return to_jsonb(c) || jsonb_build_object('wh_name', coalesce((select name from acc.warehouses w where w.tenant_id = t and w.id = c.wh_id), 'المستودع الرئيسي'),
    'lines', coalesce((select jsonb_agg(jsonb_build_object('item', l.item_id, 'code', i.code, 'name', i.name, 'system_qty', l.system_qty, 'counted_qty', l.counted_qty, 'unit_cost', l.unit_cost, 'diff', case when l.counted_qty is null then null else l.counted_qty - l.system_qty end,
      'diff_value', case when l.counted_qty is null then null else round((l.counted_qty - l.system_qty) * l.unit_cost, 2) end) order by i.code)
      from acc.stock_count_lines l join acc.items i on i.tenant_id = l.tenant_id and i.id = l.item_id where l.tenant_id = t and l.count_id = c.id), '[]'::jsonb));
end $$;

create or replace function public.count_list(p jsonb default '{}') returns jsonb language plpgsql stable security definer set search_path = public, app, acc as $$
declare t uuid := app.need_inv('view');
begin
  if not app.feat_on('warehouses') then raise exception 'الميزة غير مفعّلة لشركتك'; end if;
  return coalesce((select jsonb_agg(to_jsonb(c) - 'tenant_id' || jsonb_build_object('wh_name', coalesce((select name from acc.warehouses w where w.tenant_id = t and w.id = c.wh_id), 'المستودع الرئيسي'),
    'lines', (select count(*) from acc.stock_count_lines l where l.tenant_id = t and l.count_id = c.id)) order by c.date desc, c.created_at desc) from acc.stock_counts c where c.tenant_id = t and c.entity_id = any(app.ents())), '[]'::jsonb);
end $$;

create or replace function public.count_save_lines(p jsonb) returns jsonb language plpgsql security definer set search_path = public, app, acc as $$
declare t uuid := app.need_inv('edit'); c acc.stock_counts; l jsonb;
begin
  select * into c from acc.stock_counts where tenant_id = t and id = (p->>'id')::uuid and entity_id = any(app.ents()) for update;
  if c.id is null then raise exception 'الجرد غير موجود'; end if; if c.status <> 'draft' then raise exception 'الجرد مرحّل أو ملغى ولا يُعدَّل'; end if;
  for l in select * from jsonb_array_elements(coalesce(p->'lines', '[]'::jsonb)) loop
    if nullif(l->>'counted', '') is not null and (l->>'counted')::numeric < 0 then raise exception 'الكمية المعدودة لا تكون سالبة'; end if;
    update acc.stock_count_lines set counted_qty = nullif(l->>'counted', '')::numeric where tenant_id = t and count_id = c.id and item_id = (l->>'item')::uuid;
  end loop;
  return jsonb_build_object('ok', true);
end $$;

create or replace function public.count_post(p jsonb) returns jsonb language plpgsql security definer set search_path = public, app, acc as $$
declare t uuid := app.need('journals', 'post'); c acc.stock_counts; r record; diff numeric; cost numeric; val numeric; jl jsonb := '[]'::jsonb; jid uuid; j acc.journals; ninfo int := 0; total_gain numeric := 0; total_loss numeric := 0;
begin
  if not app.feat_on('warehouses') then raise exception 'الميزة غير مفعّلة لشركتك'; end if;
  select * into c from acc.stock_counts where tenant_id = t and id = (p->>'id')::uuid and entity_id = any(app.ents()) for update;
  if c.id is null then raise exception 'الجرد غير موجود'; end if; if c.status <> 'draft' then raise exception 'الجرد مرحّل أو ملغى سابقًا'; end if;
  if exists (select 1 from acc.stock_count_lines where tenant_id = t and count_id = c.id and counted_qty is null) and not coalesce((p->>'skip_uncounted')::boolean, false) then raise exception 'توجد أصناف لم تُعدّ — أكملها أو اختر «تجاهل غير المعدود»'; end if;
  for r in select l.*, i.inv_account_id from acc.stock_count_lines l join acc.items i on i.tenant_id = l.tenant_id and i.id = l.item_id where l.tenant_id = t and l.count_id = c.id and l.counted_qty is not null order by l.item_id loop
    -- الكمية الدفترية قد تغيّرت منذ اللقطة؟ نرفض حتى لا تُحسب فروق على أرقام قديمة
    if app.loc_qty(t, c.entity_id, r.item_id, c.wh_id) <> r.system_qty then raise exception 'تغيّرت كمية أحد الأصناف منذ بدء الجرد — أنشئ جردًا جديدًا'; end if;
    diff := r.counted_qty - r.system_qty; continue when diff = 0; ninfo := ninfo + 1;
    if diff > 0 then
      cost := app.stock_move(t, c.entity_id, r.item_id, c.date, 'in', diff, null, c.id, 'جرد فعلي — زيادة'); val := round(diff * cost, 2);
      if val > 0 then jl := jl || jsonb_build_array(jsonb_build_object('account', r.inv_account_id, 'debit', val, 'description', 'زيادة جرد'), jsonb_build_object('account', c.adjust_account_id, 'credit', val, 'description', 'فروق جرد (زيادة)')); total_gain := total_gain + val; end if;
    else
      cost := app.stock_move(t, c.entity_id, r.item_id, c.date, 'out', -diff, null, c.id, 'جرد فعلي — عجز'); val := round(-diff * cost, 2);
      if val > 0 then jl := jl || jsonb_build_array(jsonb_build_object('account', c.adjust_account_id, 'debit', val, 'description', 'فروق جرد (عجز)'), jsonb_build_object('account', r.inv_account_id, 'credit', val, 'description', 'عجز جرد')); total_loss := total_loss + val; end if;
    end if;
    if c.wh_id is not null then
      insert into acc.stock_wh (tenant_id, entity_id, item_id, warehouse_id, qty) values (t, c.entity_id, r.item_id, c.wh_id, r.counted_qty) on conflict (tenant_id, entity_id, item_id, warehouse_id) do update set qty = r.counted_qty;
    end if;
  end loop;
  if jsonb_array_length(jl) > 0 then
    jid := gen_random_uuid();
    insert into acc.journals (tenant_id, id, entity_id, type, date, description, status, source, source_id, created_by) values (t, jid, c.entity_id, 'ADJ', c.date, 'تسوية فروق الجرد الفعلي', 'draft', 'inventory', c.id, auth.uid());
    perform app.put_lines(t, jid, c.entity_id, c.date, jl); j := app.post_journal(jid);
    update acc.stock_moves set journal_id = j.id where tenant_id = t and doc_id = c.id and journal_id is null;
  end if;
  update acc.stock_counts set status = 'posted', journal_id = j.id, posted_by = auth.uid(), posted_at = now() where tenant_id = t and id = c.id;
  perform app.audit('post', 'stock_count', c.id::text, 'ترحيل جرد: ' || ninfo || ' صنف بفروق — زيادة ' || total_gain || ' / عجز ' || total_loss);
  return jsonb_build_object('adjusted', ninfo, 'gain', total_gain, 'loss', total_loss, 'journal', j.id);
end $$;

create or replace function public.count_cancel(p jsonb) returns jsonb language plpgsql security definer set search_path = public, app, acc as $$
declare t uuid := app.need_inv('edit');
begin
  update acc.stock_counts set status = 'cancelled' where tenant_id = t and id = (p->>'id')::uuid and status = 'draft' and entity_id = any(app.ents());
  if not found then raise exception 'الجرد غير موجود أو غير مسودة'; end if; perform app.audit('update', 'stock_count', p->>'id', 'إلغاء جرد'); return jsonb_build_object('ok', true);
end $$;

-- ===== 041_cheques =====
-- مُحكَم للحسابات 1.6 (دفعة 3ج) — سجل الشيكات: متابعة دورة حياة الشيك (استُلم/أُصدر ← أُودع ← تحصّل/صُرف ← مرتجع)
-- تتبّع فقط ولا قيود تلقائية: الدفعة الأصلية وقيدها كما هي. عند ارتداد شيك استخدم إلغاء الدفعة المعتاد إن لزم عكس الأثر.
create table if not exists acc.cheque_events (
  tenant_id uuid not null references acc.tenants(id) on delete cascade, id uuid not null default gen_random_uuid(), payment_id uuid not null,
  status text not null check (status in ('deposited','cleared','bounced','returned')), date date not null, note text not null default '', created_by uuid, created_at timestamptz not null default now(),
  primary key (tenant_id, id), foreign key (tenant_id, payment_id) references acc.payments (tenant_id, id));
create index if not exists cheque_ev_pay on acc.cheque_events (tenant_id, payment_id, created_at);
alter table acc.cheque_events enable row level security;
insert into app.feature_cat (key, name, grp, core, since, sort) values ('cheques', 'سجل الشيكات ومتابعة التحصيل', 'المالية', false, 1, 27)
on conflict (key) do update set name = excluded.name, grp = excluded.grp, core = excluded.core, sort = excluded.sort;

-- الحالة الحالية = آخر حدث، وإلا «معلّق» (لم يُودع بعد)
create or replace function public.cheque_list(p jsonb default '{}') returns jsonb language plpgsql stable security definer set search_path = public, app, acc as $$
declare t uuid := app.need('payments', 'view'); ents uuid[] := app.pick_ents(p); st text := nullif(p->>'status','');
begin
  if not app.feat_on('cheques') then raise exception 'الميزة غير مفعّلة لشركتك'; end if;
  return coalesce((select jsonb_agg(x order by x->>'cheque_date', x->>'date') from (
    select jsonb_build_object('id', y.id, 'kind', y.kind, 'number', y.number, 'date', y.date, 'cheque_no', y.cheque_no, 'cheque_date', y.cheque_date, 'amount', y.amount, 'party', (select name from acc.parties q where q.tenant_id = t and q.id = y.party_id),
      'status', y.cs, 'status_date', y.sd, 'overdue', (y.cs = 'pending' and y.cheque_date is not null and y.cheque_date < current_date)) x
    from (select pm.*, coalesce((select e.status from acc.cheque_events e where e.tenant_id = t and e.payment_id = pm.id order by e.created_at desc limit 1), 'pending') cs,
            (select e.date from acc.cheque_events e where e.tenant_id = t and e.payment_id = pm.id order by e.created_at desc limit 1) sd
          from acc.payments pm where pm.tenant_id = t and pm.entity_id = any(ents) and pm.method = 'cheque' and pm.status = 'posted') y
    where st is null or y.cs = st) q), '[]'::jsonb);
end $$;

create or replace function public.cheque_event(p jsonb) returns jsonb language plpgsql security definer set search_path = public, app, acc as $$
declare t uuid := app.need('payments', 'edit'); pm acc.payments; cur text; ns text := p->>'status'; nid uuid := gen_random_uuid(); d date := coalesce(nullif(p->>'date','')::date, current_date);
begin
  if not app.feat_on('cheques') then raise exception 'الميزة غير مفعّلة لشركتك'; end if;
  select * into pm from acc.payments where tenant_id = t and id = (p->>'payment')::uuid and entity_id = any(app.ents());
  if pm.id is null or pm.method <> 'cheque' or pm.status <> 'posted' then raise exception 'الشيك غير موجود أو دفعته غير مرحّلة'; end if;
  cur := coalesce((select status from acc.cheque_events where tenant_id = t and payment_id = pm.id order by created_at desc limit 1), 'pending');
  if not ((cur = 'pending' and ns in ('deposited','cleared','bounced','returned')) or (cur = 'deposited' and ns in ('cleared','bounced')) or (cur = 'bounced' and ns in ('deposited','returned'))) then
    raise exception 'لا يمكن الانتقال من «%» إلى «%»', cur, ns; end if;
  insert into acc.cheque_events (tenant_id, id, payment_id, status, date, note, created_by) values (t, nid, pm.id, ns, d, coalesce(p->>'note',''), auth.uid());
  perform app.audit('update', 'cheque', pm.id::text, 'شيك ' || pm.cheque_no || ': ' || cur || ' ← ' || ns); return jsonb_build_object('id', nid, 'from', cur, 'to', ns);
end $$;

create or replace function public.cheque_history(p jsonb) returns jsonb language plpgsql stable security definer set search_path = public, app, acc as $$
declare t uuid := app.need('payments', 'view');
begin
  if not exists (select 1 from acc.payments where tenant_id = t and id = (p->>'payment')::uuid and entity_id = any(app.ents())) then raise exception 'الدفعة غير موجودة'; end if;
  return coalesce((select jsonb_agg(jsonb_build_object('status', status, 'date', date, 'note', note, 'at', created_at) order by created_at) from acc.cheque_events where tenant_id = t and payment_id = (p->>'payment')::uuid), '[]'::jsonb);
end $$;

-- ===== 042_custody =====
-- مُحكَم للحسابات 1.6 (دفعة 3د) — العُهد النقدية وصندوق المصروفات (نظام السلفة المستديمة)
-- لكل عهدة حساب أصل مخصّص (مثلاً «عهدة فلان»). التغذية: مدين العهدة / دائن مصدر التمويل. المصروف: مدين المصروف / دائن العهدة. الرصيد = مجموع الحركات ولا يهبط تحت الصفر.
create table if not exists acc.custodies (
  tenant_id uuid not null references acc.tenants(id) on delete cascade, id uuid not null default gen_random_uuid(), entity_id uuid not null, name text not null, holder text not null default '',
  account_id uuid not null, limit_amount numeric(18,2) not null default 0 check (limit_amount >= 0), active boolean not null default true, created_by uuid, created_at timestamptz not null default now(),
  primary key (tenant_id, id), foreign key (tenant_id, entity_id) references acc.entities (tenant_id, id));
create table if not exists acc.custody_tx (
  tenant_id uuid not null, id uuid not null default gen_random_uuid(), custody_id uuid not null, kind text not null check (kind in ('fund','expense','return')), date date not null,
  amount numeric(18,2) not null check (amount > 0), counter_account_id uuid not null, description text not null default '', receipt_no text not null default '', journal_id uuid, created_by uuid, created_at timestamptz not null default now(),
  primary key (tenant_id, id), foreign key (tenant_id, custody_id) references acc.custodies (tenant_id, id));
alter table acc.custodies enable row level security; alter table acc.custody_tx enable row level security;
insert into app.feature_cat (key, name, grp, core, since, sort) values ('custody', 'العُهد النقدية وصندوق المصروفات', 'المالية', false, 1, 28)
on conflict (key) do update set name = excluded.name, grp = excluded.grp, core = excluded.core, sort = excluded.sort;

create or replace function app.custody_bal(t uuid, c uuid) returns numeric language sql stable security definer set search_path = public, acc as $$
  select coalesce(sum(case when kind = 'fund' then amount else -amount end), 0) from acc.custody_tx where tenant_id = t and custody_id = c $$;

create or replace function public.custody_list(p jsonb default '{}') returns jsonb language plpgsql stable security definer set search_path = public, app, acc as $$
declare t uuid := app.need('journals', 'view');
begin
  if not app.feat_on('custody') then raise exception 'الميزة غير مفعّلة لشركتك'; end if;
  return coalesce((select jsonb_agg(to_jsonb(c) - 'tenant_id' || jsonb_build_object('balance', app.custody_bal(t, c.id), 'account', (select code || ' - ' || name from acc.accounts a where a.tenant_id = t and a.id = c.account_id)) order by c.name)
    from acc.custodies c where c.tenant_id = t and c.entity_id = any(app.ents())), '[]'::jsonb);
end $$;

create or replace function public.custody_upsert(p jsonb) returns jsonb language plpgsql security definer set search_path = public, app, acc as $$
declare t uuid := app.need('journals', 'add'); e uuid := (p->>'entity')::uuid; nid uuid := nullif(p->>'id','')::uuid; ac uuid := (p->>'account')::uuid;
begin
  if not app.feat_on('custody') then raise exception 'الميزة غير مفعّلة لشركتك'; end if;
  if e is null or not (e = any(app.ents())) then raise exception 'كيان غير مسموح'; end if;
  if nullif(trim(p->>'name'),'') is null then raise exception 'اسم العهدة مطلوب'; end if;
  if not exists (select 1 from acc.accounts where tenant_id = t and id = ac and not is_group and type = 'asset') then raise exception 'حساب العهدة يجب أن يكون حساب أصل'; end if;
  if nid is null then insert into acc.custodies (tenant_id, entity_id, name, holder, account_id, limit_amount, created_by) values (t, e, trim(p->>'name'), coalesce(p->>'holder',''), ac, coalesce((p->>'limit')::numeric, 0), auth.uid()) returning id into nid;
  else update acc.custodies set name = trim(p->>'name'), holder = coalesce(p->>'holder', holder), account_id = ac, limit_amount = coalesce((p->>'limit')::numeric, limit_amount), active = coalesce((p->>'active')::boolean, active) where tenant_id = t and id = nid and entity_id = any(app.ents()); end if;
  perform app.audit('upsert', 'custody', nid::text, trim(p->>'name')); return jsonb_build_object('id', nid);
end $$;

-- حركة: fund (تغذية) / expense (مصروف) / return (إعادة نقد للمصدر)
create or replace function public.custody_tx_add(p jsonb) returns jsonb language plpgsql security definer set search_path = public, app, acc as $$
declare t uuid := app.need('journals', 'post'); c acc.custodies; k text := p->>'kind'; amt numeric := round((p->>'amount')::numeric, 2); ca uuid := (p->>'counter_account')::uuid; d date := coalesce(nullif(p->>'date','')::date, current_date);
  jid uuid := gen_random_uuid(); j acc.journals; tid uuid := gen_random_uuid(); bal numeric; ds text; cty text;
begin
  if not app.feat_on('custody') then raise exception 'الميزة غير مفعّلة لشركتك'; end if;
  select * into c from acc.custodies where tenant_id = t and id = (p->>'custody')::uuid and entity_id = any(app.ents()) for update;
  if c.id is null or not c.active then raise exception 'العهدة غير موجودة أو موقوفة'; end if;
  if k not in ('fund','expense','return') then raise exception 'نوع حركة غير صالح'; end if; if amt is null or amt <= 0 then raise exception 'المبلغ يجب أن يكون موجبًا'; end if;
  select type into cty from acc.accounts where tenant_id = t and id = ca and not is_group; if cty is null then raise exception 'الحساب المقابل غير صالح'; end if;
  if k = 'expense' and cty <> 'expense' then raise exception 'مصروف العهدة يُحمَّل على حساب مصروف'; end if;
  if k <> 'expense' and cty <> 'asset' then raise exception 'مصدر التغذية أو جهة الإعادة حساب نقد/بنك (أصل)'; end if;
  bal := app.custody_bal(t, c.id);
  if k <> 'fund' and bal < amt then raise exception 'رصيد العهدة (%) لا يكفي', bal; end if;
  if k = 'fund' and c.limit_amount > 0 and bal + amt > c.limit_amount then raise exception 'التغذية تتجاوز سقف العهدة (%)', c.limit_amount; end if;
  ds := case k when 'fund' then 'تغذية عهدة ' when 'expense' then 'مصروف عهدة ' else 'إعادة عهدة ' end || c.name || coalesce(' — ' || nullif(p->>'description',''), '');
  insert into acc.journals (tenant_id, id, entity_id, type, date, description, status, source, source_id, created_by) values (t, jid, c.entity_id, 'GJ', d, ds, 'draft', 'custody', tid, auth.uid());
  perform app.put_lines(t, jid, c.entity_id, d, case when k = 'fund' then jsonb_build_array(jsonb_build_object('account', c.account_id, 'debit', amt, 'description', ds), jsonb_build_object('account', ca, 'credit', amt, 'description', ds))
    else jsonb_build_array(jsonb_build_object('account', ca, 'debit', amt, 'description', ds), jsonb_build_object('account', c.account_id, 'credit', amt, 'description', ds)) end);
  j := app.post_journal(jid);
  insert into acc.custody_tx (tenant_id, id, custody_id, kind, date, amount, counter_account_id, description, receipt_no, journal_id, created_by) values (t, tid, c.id, k, d, amt, ca, coalesce(p->>'description',''), coalesce(p->>'receipt_no',''), j.id, auth.uid());
  perform app.audit('create', 'custody_tx', tid::text, ds || ' — ' || amt); return jsonb_build_object('id', tid, 'journal', j.id, 'balance', app.custody_bal(t, c.id));
end $$;

create or replace function public.custody_tx_list(p jsonb default '{}') returns jsonb language plpgsql stable security definer set search_path = public, app, acc as $$
declare t uuid := app.need('journals', 'view');
begin
  if not app.feat_on('custody') then raise exception 'الميزة غير مفعّلة لشركتك'; end if;
  return coalesce((select jsonb_agg(to_jsonb(x) - 'tenant_id' order by x.date desc, x.created_at desc) from acc.custody_tx x join acc.custodies c on c.tenant_id = x.tenant_id and c.id = x.custody_id
    where x.tenant_id = t and c.entity_id = any(app.ents()) and (nullif(p->>'custody','') is null or x.custody_id = (p->>'custody')::uuid)), '[]'::jsonb);
end $$;

-- الشركات القائمة تبقى مقفولة عن المزايا الجديدة حتى يفتحها البائع من «المزايا والعقد»؛ الشركات الجديدة تأخذها حسب العقد
-- ===== 043_alerts =====
-- مُحكَم للحسابات 1.6 — التنبيهات (الجرس): قراءة فقط، تُحسب لحظيًا من بيانات الشركة وبحسب صلاحيات المستخدم
-- كل عنصر: k مفتاح ثابت يتضمن العدد (إن تغيّر العدد يعود غير مقروء)، sev: urgent|warn|info، to مسار الصفحة
create or replace function public.alerts_list(p jsonb default '{}') returns jsonb language plpgsql stable security definer set search_path = public, app, acc as $$
declare t uuid := app.need(null, null); ents uuid[] := app.ents(); d date := current_date; r jsonb := '[]'::jsonb; n bigint; s numeric; ex date;
begin
  if app.can('journals', 'approve') then
    select count(*) into n from acc.journals where tenant_id = t and entity_id = any(ents) and status = 'pending';
    if n > 0 then r := r || jsonb_build_object('k', 'j-pend:' || n, 'sev', 'warn', 'i', 'BookOpen', 't', n || ' قيد بانتظار الاعتماد', 's', 'راجعها واعتمدها أو أعدها لمُعدّها', 'to', '/journals'); end if;
  end if;
  if app.can('sales', 'approve') then
    select count(*) into n from acc.invoices where tenant_id = t and entity_id = any(ents) and status = 'pending' and kind in ('sales','sales_credit');
    if n > 0 then r := r || jsonb_build_object('k', 'si-pend:' || n, 'sev', 'warn', 'i', 'FileText', 't', n || ' فاتورة/إشعار مبيعات بانتظار الاعتماد', 's', 'من صفحة فواتير المبيعات', 'to', '/invoices/sales'); end if;
  end if;
  if app.can('purchases', 'approve') then
    select count(*) into n from acc.invoices where tenant_id = t and entity_id = any(ents) and status = 'pending' and kind in ('purchase','purchase_debit');
    if n > 0 then r := r || jsonb_build_object('k', 'pi-pend:' || n, 'sev', 'warn', 'i', 'FileText', 't', n || ' فاتورة/إشعار مشتريات بانتظار الاعتماد', 's', 'من صفحة فواتير المشتريات', 'to', '/invoices/purchase'); end if;
  end if;
  if app.can('payments', 'approve') then
    select count(*) into n from acc.payments where tenant_id = t and entity_id = any(ents) and status = 'pending';
    if n > 0 then r := r || jsonb_build_object('k', 'pay-pend:' || n, 'sev', 'warn', 'i', 'Banknote', 't', n || ' سند قبض/صرف بانتظار الاعتماد', 's', 'راجعها واعتمدها', 'to', '/payments/receipt'); end if;
  end if;
  if app.can('sales', 'view') then
    select count(*), coalesce(sum(i.total_base - app.inv_paid(t, i.id)), 0) into n, s from acc.invoices i where i.tenant_id = t and i.entity_id = any(ents) and i.kind = 'sales' and i.status = 'issued' and i.due_date < d and i.total_base > app.inv_paid(t, i.id);
    if n > 0 then r := r || jsonb_build_object('k', 'ar-over:' || n || ':' || round(s), 'sev', 'urgent', 'i', 'AlertCircle', 't', n || ' فاتورة مبيعات متأخرة السداد', 's', 'إجمالي المتأخر ' || to_char(round(s), 'FM999,999,999,990'), 'to', '/reports'); end if;
  end if;
  if app.can('purchases', 'view') then
    select count(*), coalesce(sum(i.total_base - app.inv_paid(t, i.id)), 0) into n, s from acc.invoices i where i.tenant_id = t and i.entity_id = any(ents) and i.kind = 'purchase' and i.status = 'issued' and i.due_date <= d + 7 and i.total_base > app.inv_paid(t, i.id);
    if n > 0 then r := r || jsonb_build_object('k', 'ap-due:' || n || ':' || round(s), 'sev', 'warn', 'i', 'CalendarClock', 't', n || ' فاتورة مورّد مستحقة خلال 7 أيام أو متأخرة', 's', 'الإجمالي ' || to_char(round(s), 'FM999,999,999,990'), 'to', '/reports'); end if;
  end if;
  if app.can('bank', 'view') then
    select count(*) into n from acc.bank_lines x where x.tenant_id = t and x.matched_line_id is null;
    if n > 0 then r := r || jsonb_build_object('k', 'bank-un:' || n, 'sev', 'info', 'i', 'Landmark', 't', n || ' حركة بنكية غير مطابقة', 's', 'طابقها مع القيود من صفحة البنوك', 'to', '/bank'); end if;
  end if;
  if app.can('requests', 'approve') then
    select count(*) into n from acc.requests where tenant_id = t and entity_id = any(ents) and status = 'submitted';
    if n > 0 then r := r || jsonb_build_object('k', 'req:' || n, 'sev', 'warn', 'i', 'Inbox', 't', n || ' طلب موظف بانتظار القرار', 's', 'من صندوق الطلبات', 'to', '/requests'); end if;
  end if;
  if app.feat_on('cheques') and app.can('payments', 'view') then
    select count(*) into n from acc.payments pm where pm.tenant_id = t and pm.entity_id = any(ents) and pm.method = 'cheque' and pm.status = 'posted' and pm.cheque_date < d
      and not exists (select 1 from acc.cheque_events e where e.tenant_id = t and e.payment_id = pm.id);
    if n > 0 then r := r || jsonb_build_object('k', 'chq-over:' || n, 'sev', 'warn', 'i', 'FileCheck2', 't', n || ' شيك حلّ استحقاقه ولم يُتابَع', 's', 'حدّث حالته في سجل الشيكات', 'to', '/cheques'); end if;
  end if;
  if app.sys('settings') then
    select expires_at::date into ex from acc.tenants where id = t;
    if ex is not null and ex - d between 0 and 30 then r := r || jsonb_build_object('k', 'sub:' || ex, 'sev', case when ex - d <= 7 then 'urgent' else 'warn' end, 'i', 'Clock', 't', 'ينتهي اشتراك الشركة خلال ' || (ex - d) || ' يومًا', 's', 'بتاريخ ' || ex || ' — تواصل مع البائع للتجديد', 'to', '/settings'); end if;
  end if;
  return r;
end $$;

do $$ begin
  if not exists (select 1 from app.schema_migrations where version = '1.6.0.1') then  -- مرة واحدة فقط حتى لا يُعاد قفل ما فتحه البائع
    update acc.tenants set features_off = (select coalesce(array_agg(distinct k), '{}') from unnest(coalesce(features_off, '{}') || array['deferrals','warehouses','cheques','custody']) k)  where not (coalesce(settings, '{}'::jsonb) ? 'demo') and created_at < now();
  end if;
end $$;
insert into app.schema_migrations (version, name) values ('1.6.0.1', 'تدقيق قبل/بعد، تعارض مهام، قوالب أدوار، إطفاء، مستودعات وجرد، شيكات، عُهد') on conflict (version) do nothing;
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
