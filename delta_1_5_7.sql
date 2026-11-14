-- مُحكَم 1.5.0.7 — حماية مدير المنصة بالتحقق الثنائي + القبول الإلكتروني + تحسين تقرير التدفقات (آمن للتكرار، لا يمس الروابط ولا البيانات)
-- مُحكَم للحسابات — حماية حساب مدير المنصة: إن كان له تحقق ثنائي مفعّل فكل إجراءات المنصة تتطلبه (aal2)، وحالة الأمان تظهر له
create or replace function app.demo_admin() returns void language plpgsql stable security definer set search_path = public, app, acc as $$
begin
  if not app.is_platform_admin() then raise exception 'للإدارة العليا فقط'; end if;
  if coalesce(auth.jwt()->>'aal', 'aal1') <> 'aal2' and exists (select 1 from auth.mfa_factors where user_id = auth.uid() and status = 'verified') then raise exception 'يلزم التحقق الثنائي'; end if;
end $$;

create or replace function public.platform_security_status(p jsonb default '{}') returns jsonb language plpgsql stable security definer set search_path = public, app, acc as $$
begin
  if not app.is_platform_admin() then raise exception 'للإدارة العليا فقط'; end if;
  return jsonb_build_object('mfa', exists (select 1 from auth.mfa_factors where user_id = auth.uid() and status = 'verified'), 'aal', coalesce(auth.jwt()->>'aal', 'aal1'));
end $$;
-- مُحكَم للحسابات — القبول الإلكتروني لاتفاقية الخدمة وملحق المعالجة والشروط والخصوصية: هوية الموقّع وصفته والإصدار والوقت والعنوان
-- سجل إضافي فقط (لا تعديل ولا حذف عبر الواجهة). يُطلب قبول جديد عند تغيّر الإصدار، وتبقى القبولات السابقة محفوظة كسجل تعديلات.
create table if not exists acc.agreement_acceptance (
  id uuid primary key default gen_random_uuid(), tenant_id uuid not null references acc.tenants(id) on delete cascade,
  doc text not null check (doc in ('agreement','dpa','terms','privacy')), version text not null check (length(version) between 1 and 20),
  signer_name text not null, signer_title text not null, user_id uuid, username text, ip text, ua text not null default '',
  accepted_at timestamptz not null default now());
alter table acc.agreement_acceptance enable row level security;
create index if not exists agreement_acc_t_idx on acc.agreement_acceptance (tenant_id, doc, accepted_at desc);

create or replace function public.agreement_accept(p jsonb) returns jsonb language plpgsql volatile security definer set search_path = public, app, acc as $$
declare t uuid := app.need_sys('settings'); m acc.members; v text := trim(coalesce(p->>'version','')); sn text := trim(coalesce(p->>'signer_name','')); st text := trim(coalesce(p->>'signer_title','')); d text; n int := 0;
begin
  if v = '' or length(v) > 20 then raise exception 'إصدار الوثيقة غير صالح'; end if;
  if length(sn) < 3 or length(sn) > 120 then raise exception 'اسم الموقّع مطلوب (3 أحرف على الأقل)'; end if;
  if length(st) < 2 or length(st) > 120 then raise exception 'صفة الموقّع مطلوبة'; end if;
  if coalesce((p->>'authority')::boolean, false) is not true then raise exception 'يلزم الإقرار بأن الموقّع مخوّل بالتعاقد عن المنشأة'; end if;
  select * into m from acc.members where user_id = auth.uid();
  foreach d in array array['agreement','dpa','terms','privacy'] loop
    insert into acc.agreement_acceptance (tenant_id, doc, version, signer_name, signer_title, user_id, username, ip, ua)
    values (t, d, v, sn, st, auth.uid(), m.username, app.client_ip(), left(coalesce(p->>'ua', ''), 200)); n := n + 1;
  end loop;
  perform app.audit('accept', 'agreement', v, 'قبول إلكتروني لاتفاقية الخدمة وملحق المعالجة والشروط والخصوصية — الموقّع: ' || sn || ' (' || st || ')');
  return jsonb_build_object('ok', true, 'version', v, 'docs', n);
end $$;

-- حالة القبول: هل قبلت المنشأة الإصدار الحالي لكل الوثائق + سجل القبولات
create or replace function public.agreement_status(p jsonb default '{}') returns jsonb language plpgsql stable security definer set search_path = public, app, acc as $$
declare t uuid := app.tenant(); v text := trim(coalesce(p->>'version', '')); ok boolean; h jsonb;
begin
  if t is null then raise exception 'يجب تسجيل الدخول'; end if;
  select not exists (select 1 from unnest(array['agreement','dpa','terms','privacy']) d where not exists (select 1 from acc.agreement_acceptance a where a.tenant_id = t and a.doc = d and a.version = v)) into ok;
  select coalesce(jsonb_agg(to_jsonb(x) order by x.accepted_at desc), '[]'::jsonb) into h from (select doc, version, signer_name, signer_title, username, ip, accepted_at from acc.agreement_acceptance where tenant_id = t order by accepted_at desc limit 100) x;
  return jsonb_build_object('version', v, 'accepted', coalesce(ok, false), 'can_accept', app.is_admin_like(), 'history', h);
end $$;
-- مُحكَم للحسابات — أداء: إعادة صياغة تقرير التدفقات النقدية بلا استعلام IN فرعي (نفس النتيجة تمامًا)
create or replace function public.rpt_cashflow(p jsonb default '{}') returns jsonb language plpgsql stable security definer set search_path = public, app, acc as $$
declare t uuid := app.need('reports','view'); ents uuid[] := app.pick_ents(p); df date := (p->>'from')::date; dt date := (p->>'to')::date; op numeric; cl numeric; rows jsonb;
begin
  if df is null or dt is null then raise exception 'حدّد الفترة'; end if;
  select coalesce(sum(l.debit - l.credit) filter (where l.date < df), 0), coalesce(sum(l.debit - l.credit), 0) into op, cl
    from acc.journal_lines l join acc.accounts a on a.tenant_id = l.tenant_id and a.id = l.account_id where l.tenant_id = t and l.posted and l.entity_id = any(ents) and l.date <= dt and a.subtype in ('cash','bank');
  select coalesce(jsonb_agg(jsonb_build_object('section', s.section, 'account_id', s.account_id, 'code', s.code, 'name', s.name, 'amount', s.amt) order by s.section, s.code), '[]') into rows
  from (with cj as materialized (select distinct l2.journal_id from acc.journal_lines l2 join acc.accounts a2 on a2.tenant_id = l2.tenant_id and a2.id = l2.account_id
          where l2.tenant_id = t and l2.posted and l2.entity_id = any(ents) and l2.date between df and dt and a2.subtype in ('cash','bank'))
    select case when a.cf_class in ('investing','financing') then a.cf_class else 'operating' end section, a.id account_id, a.code, a.name, -sum(l.debit - l.credit) amt
    from cj join acc.journal_lines l on l.tenant_id = t and l.journal_id = cj.journal_id join acc.accounts a on a.tenant_id = l.tenant_id and a.id = l.account_id
    where l.posted and l.entity_id = any(ents) and l.date between df and dt and a.subtype not in ('cash','bank')
    group by 1, 2, 3, 4 having sum(l.debit - l.credit) <> 0) s;
  return jsonb_build_object('opening_cash', op, 'closing_cash', cl, 'rows', rows, 'net_change', cl - op,
    'operating', (select coalesce(sum((r->>'amount')::numeric), 0) from jsonb_array_elements(rows) r where r->>'section' = 'operating'),
    'investing', (select coalesce(sum((r->>'amount')::numeric), 0) from jsonb_array_elements(rows) r where r->>'section' = 'investing'),
    'financing', (select coalesce(sum((r->>'amount')::numeric), 0) from jsonb_array_elements(rows) r where r->>'section' = 'financing'));
end $$;

-- تشديد نهائي (آمن للتكرار): لا يصل الزائر أو المستخدم المسجّل مباشرة لأي دالة داخلية في app/acc
do $$ declare f record; begin
  for f in select p.oid::regprocedure as sig from pg_proc p join pg_namespace n on n.oid = p.pronamespace where n.nspname in ('app','acc') and p.prokind in ('f','p') loop
    begin execute format('revoke execute on function %s from public, anon, authenticated', f.sig); exception when others then null; end; end loop;
  for f in select p.oid::regprocedure as sig from pg_proc p join pg_namespace n on n.oid = p.pronamespace where n.nspname = 'public' and p.prokind = 'f' and p.proname not in ('login_email','register_company','ingest_journal','signup_status','demo_link_open') and pg_get_function_identity_arguments(p.oid) = 'p jsonb' loop
    begin execute format('revoke execute on function %s from public, anon', f.sig); execute format('grant execute on function %s to authenticated', f.sig); exception when others then null; end; end loop;
end $$;
