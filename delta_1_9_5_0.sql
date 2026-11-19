-- 1.9.3.0 → 1.9.5.0 delta (إضافي ومتكرر التشغيل): الاستقطاع + القطاعات + طلبات أصحاب البيانات. الميزتان wht وdsr مقفولتان على الشركات القائمة وتُفتحان من «المزايا والعقد».
-- مُحكَم للحسابات 1.9.3.0 — ضريبة الاستقطاع (المدفوعات لغير المقيمين): فئات ونسب قابلة للتعديل، تسجيل الاستقطاع مع قيد، تقرير شهري، وتوريد للهيئة بقيد.
-- النسب الافتراضية استرشادية فقط وتُراجَع مع الهيئة؛ يعدّلها المالك من الشاشة ولا يُنشأ أي أثر محاسبي بغير تسجيل صريح.
create table if not exists acc.wht_rates (
  tenant_id uuid not null references acc.tenants(id) on delete cascade, code text not null, label text not null, rate numeric(5,2) not null check (rate >= 0 and rate <= 100),
  active boolean not null default true, sort int not null default 0, primary key (tenant_id, code));
create table if not exists acc.wht_entries (
  tenant_id uuid not null references acc.tenants(id) on delete cascade, id uuid not null default gen_random_uuid(), entity_id uuid not null, date date not null,
  payee text not null, payee_ref text not null default '', code text not null, rate numeric(5,2) not null, gross numeric(18,2) not null check (gross > 0), tax numeric(18,2) not null check (tax >= 0),
  net numeric(18,2) not null, expense_account_id uuid not null, payable_account_id uuid not null, wht_account_id uuid not null, description text not null default '',
  journal_id uuid, remitted_on date, remit_journal_id uuid, created_by uuid, created_at timestamptz not null default now(),
  primary key (tenant_id, id), foreign key (tenant_id, entity_id) references acc.entities (tenant_id, id));
alter table acc.wht_rates enable row level security; alter table acc.wht_entries enable row level security;
with ins as (
  insert into app.feature_cat (key, name, grp, core, since, sort) values ('wht', 'ضريبة الاستقطاع', 'الضرائب', false, 1, 31)
  on conflict (key) do nothing returning key)
update acc.tenants set features_off = array_append(features_off, 'wht') where exists (select 1 from ins) and not ('wht' = any(features_off));

create or replace function app.wht_seed(t uuid) returns void language plpgsql security definer set search_path = public, acc as $$
begin
  if exists (select 1 from acc.wht_rates where tenant_id = t) then return; end if;
  insert into acc.wht_rates (tenant_id, code, label, rate, sort) values
   (t, 'dividends', 'أرباح موزعة', 5, 1), (t, 'interest', 'فوائد قروض', 5, 2), (t, 'technical', 'خدمات فنية واستشارية', 5, 3), (t, 'freight', 'تذاكر طيران ونقل بحري/جوي', 5, 4),
   (t, 'telecom', 'اتصالات دولية', 5, 5), (t, 'rent', 'إيجار معدات', 5, 6), (t, 'royalty', 'إتاوات', 15, 7), (t, 'other', 'مدفوعات أخرى', 15, 8), (t, 'management', 'أتعاب إدارة', 20, 9);
end $$;

create or replace function public.wht_rates_list(p jsonb default '{}') returns jsonb language plpgsql security definer set search_path = public, app, acc as $$
declare t uuid := app.need('journals', 'view');
begin
  if not app.feat_on('wht') then raise exception 'الميزة غير مفعّلة لشركتك'; end if;
  perform app.wht_seed(t);
  return jsonb_build_object('note', 'النسب استرشادية وتُراجَع مع هيئة الزكاة والضريبة والجمارك قبل الاعتماد',
    'rates', (select coalesce(jsonb_agg(to_jsonb(r) - 'tenant_id' order by r.sort, r.code), '[]'::jsonb) from acc.wht_rates r where r.tenant_id = t));
end $$;

create or replace function public.wht_rates_save(p jsonb) returns jsonb language plpgsql security definer set search_path = public, app, acc as $$
declare t uuid := app.need('settings', 'edit'); c text := lower(trim(p->>'code')); rt numeric := (p->>'rate')::numeric;
begin
  if not app.feat_on('wht') then raise exception 'الميزة غير مفعّلة لشركتك'; end if;
  if c is null or c !~ '^[a-z0-9_]{2,30}$' then raise exception 'رمز الفئة: حروف إنجليزية صغيرة وأرقام وشرطة سفلية'; end if;
  if rt is null or rt < 0 or rt > 100 then raise exception 'النسبة بين 0 و100'; end if;
  if nullif(trim(p->>'label'),'') is null then raise exception 'اسم الفئة مطلوب'; end if;
  insert into acc.wht_rates (tenant_id, code, label, rate, active, sort) values (t, c, trim(p->>'label'), rt, coalesce((p->>'active')::boolean, true), coalesce((p->>'sort')::int, 50))
  on conflict (tenant_id, code) do update set label = excluded.label, rate = excluded.rate, active = excluded.active;
  perform app.audit('upsert', 'wht_rate', c, trim(p->>'label') || ' ' || rt || '%'); return jsonb_build_object('ok', true);
end $$;

-- معاينة الحساب دون أي أثر
create or replace function public.wht_calc(p jsonb) returns jsonb language plpgsql stable security definer set search_path = public, app, acc as $$
declare t uuid := app.need('journals', 'view'); r acc.wht_rates; g numeric := (p->>'gross')::numeric;
begin
  if not app.feat_on('wht') then raise exception 'الميزة غير مفعّلة لشركتك'; end if;
  select * into r from acc.wht_rates where tenant_id = t and code = p->>'code' and active; if r.code is null then raise exception 'فئة الاستقطاع غير موجودة أو موقوفة'; end if;
  if g is null or g <= 0 then raise exception 'المبلغ الإجمالي يجب أن يكون موجبًا'; end if;
  return jsonb_build_object('rate', r.rate, 'gross', round(g, 2), 'tax', round(g * r.rate / 100, 2), 'net', round(g, 2) - round(g * r.rate / 100, 2));
end $$;

-- تسجيل: مدين المصروف بالإجمالي / دائن المستحق للمستفيد بالصافي / دائن ضريبة الاستقطاع المستحقة بالضريبة
create or replace function public.wht_record(p jsonb) returns jsonb language plpgsql security definer set search_path = public, app, acc as $$
declare t uuid := app.need('journals', 'post'); e uuid := (p->>'entity')::uuid; r acc.wht_rates; g numeric := round((p->>'gross')::numeric, 2); tx numeric; d date := coalesce(nullif(p->>'date','')::date, current_date);
  ea uuid := (p->>'expense_account')::uuid; pa uuid := (p->>'payable_account')::uuid; wa uuid := (p->>'wht_account')::uuid; jid uuid := gen_random_uuid(); wid uuid := gen_random_uuid(); j acc.journals; ds text;
begin
  if not app.feat_on('wht') then raise exception 'الميزة غير مفعّلة لشركتك'; end if;
  if e is null or not (e = any(app.ents())) then raise exception 'كيان غير مسموح'; end if;
  if nullif(trim(p->>'payee'),'') is null then raise exception 'اسم المستفيد مطلوب'; end if;
  if g is null or g <= 0 then raise exception 'المبلغ الإجمالي يجب أن يكون موجبًا'; end if;
  select * into r from acc.wht_rates where tenant_id = t and code = p->>'code' and active; if r.code is null then raise exception 'فئة الاستقطاع غير موجودة أو موقوفة'; end if;
  if not exists (select 1 from acc.accounts where tenant_id = t and id = ea and not is_group and type = 'expense') then raise exception 'حساب المصروف غير صالح'; end if;
  if (select count(*) from acc.accounts where tenant_id = t and not is_group and type = 'liability' and id in (pa, wa)) <> (case when pa = wa then 1 else 2 end) then raise exception 'حسابا المستحق للمستفيد وضريبة الاستقطاع يجب أن يكونا التزامين'; end if;
  if pa = wa then raise exception 'يجب أن يختلف حساب المستحق للمستفيد عن حساب ضريبة الاستقطاع'; end if;
  tx := round(g * r.rate / 100, 2); ds := 'استقطاع ' || r.label || ' — ' || trim(p->>'payee') || coalesce(' — ' || nullif(p->>'description',''), '');
  insert into acc.journals (tenant_id, id, entity_id, type, date, description, status, source, source_id, created_by) values (t, jid, e, 'GJ', d, ds, 'draft', 'wht', wid, auth.uid());
  perform app.put_lines(t, jid, e, d, jsonb_build_array(jsonb_build_object('account', ea, 'debit', g, 'description', ds), jsonb_build_object('account', pa, 'credit', g - tx, 'description', ds, 'party', nullif(p->>'party','')))
    || case when tx > 0 then jsonb_build_array(jsonb_build_object('account', wa, 'credit', tx, 'description', ds, 'party', nullif(p->>'party',''))) else '[]'::jsonb end);
  j := app.post_journal(jid);
  insert into acc.wht_entries (tenant_id, id, entity_id, date, payee, payee_ref, code, rate, gross, tax, net, expense_account_id, payable_account_id, wht_account_id, description, journal_id, created_by)
  values (t, wid, e, d, trim(p->>'payee'), coalesce(p->>'payee_ref',''), r.code, r.rate, g, tx, g - tx, ea, pa, wa, coalesce(p->>'description',''), j.id, auth.uid());
  perform app.audit('create', 'wht', wid::text, ds || ' — ' || g || ' ضريبة ' || tx); return jsonb_build_object('id', wid, 'journal', j.id, 'tax', tx, 'net', g - tx, 'due', (date_trunc('month', d) + interval '1 month' + interval '9 days')::date);
end $$;

create or replace function public.wht_list(p jsonb default '{}') returns jsonb language plpgsql stable security definer set search_path = public, app, acc as $$
declare t uuid := app.need('journals', 'view');
begin
  if not app.feat_on('wht') then raise exception 'الميزة غير مفعّلة لشركتك'; end if;
  return coalesce((select jsonb_agg(to_jsonb(x) - 'tenant_id' || jsonb_build_object('due', (date_trunc('month', x.date) + interval '1 month' + interval '9 days')::date,
      'label', (select label from acc.wht_rates r where r.tenant_id = x.tenant_id and r.code = x.code)) order by x.date desc, x.created_at desc)
    from acc.wht_entries x where x.tenant_id = t and x.entity_id = any(app.ents())
      and (nullif(p->>'from','') is null or x.date >= (p->>'from')::date) and (nullif(p->>'to','') is null or x.date <= (p->>'to')::date)
      and (nullif(p->>'status','') is null or (p->>'status' = 'open' and x.remitted_on is null) or (p->>'status' = 'remitted' and x.remitted_on is not null))), '[]'::jsonb);
end $$;

-- تقرير: بالفئة وبالمستفيد مع المستحق والمورَّد والمتبقي
create or replace function public.wht_report(p jsonb default '{}') returns jsonb language plpgsql stable security definer set search_path = public, app, acc as $$
declare t uuid := app.need('journals', 'view'); f date := coalesce(nullif(p->>'from','')::date, date_trunc('year', current_date)::date); z date := coalesce(nullif(p->>'to','')::date, current_date);
begin
  if not app.feat_on('wht') then raise exception 'الميزة غير مفعّلة لشركتك'; end if;
  return jsonb_build_object('from', f, 'to', z,
    'by_code', coalesce((select jsonb_agg(jsonb_build_object('code', code, 'label', (select label from acc.wht_rates r where r.tenant_id = t and r.code = s.code), 'n', n, 'gross', gross, 'tax', tax, 'open', open) order by code)
       from (select code, count(*) n, sum(gross) gross, sum(tax) tax, sum(tax) filter (where remitted_on is null) open from acc.wht_entries where tenant_id = t and entity_id = any(app.ents()) and date between f and z group by code) s), '[]'::jsonb),
    'by_payee', coalesce((select jsonb_agg(jsonb_build_object('payee', payee, 'n', n, 'gross', gross, 'tax', tax) order by tax desc, payee)
       from (select payee, count(*) n, sum(gross) gross, sum(tax) tax from acc.wht_entries where tenant_id = t and entity_id = any(app.ents()) and date between f and z group by payee) s), '[]'::jsonb),
    'total', (select jsonb_build_object('gross', coalesce(sum(gross),0), 'tax', coalesce(sum(tax),0), 'open', coalesce(sum(tax) filter (where remitted_on is null),0)) from acc.wht_entries where tenant_id = t and entity_id = any(app.ents()) and date between f and z));
end $$;

-- توريد للهيئة: مدين ضريبة الاستقطاع المستحقة / دائن البنك — لمجموعة سجلات مفتوحة من كيان وحساب استقطاع واحد
create or replace function public.wht_remit(p jsonb) returns jsonb language plpgsql security definer set search_path = public, app, acc as $$
declare t uuid := app.need('journals', 'post'); ids uuid[]; n int; ents uuid[]; was uuid[]; tot numeric; d date := coalesce(nullif(p->>'date','')::date, current_date); ba uuid := (p->>'bank_account')::uuid; jid uuid := gen_random_uuid(); j acc.journals; ds text;
begin
  if not app.feat_on('wht') then raise exception 'الميزة غير مفعّلة لشركتك'; end if;
  select array_agg(x::uuid) into ids from jsonb_array_elements_text(coalesce(p->'ids','[]'::jsonb)) x; if ids is null or array_length(ids,1) = 0 then raise exception 'اختر سجلات للتوريد'; end if;
  select count(*), array_agg(distinct entity_id), array_agg(distinct wht_account_id), sum(tax) into n, ents, was, tot from acc.wht_entries where tenant_id = t and id = any(ids) and remitted_on is null and entity_id = any(app.ents());
  if n <> array_length(ids,1) then raise exception 'بعض السجلات غير موجودة أو موردة سابقًا'; end if;
  if array_length(ents,1) > 1 or array_length(was,1) > 1 then raise exception 'التوريد لسجلات كيان واحد وحساب استقطاع واحد'; end if;
  if tot <= 0 then raise exception 'لا ضريبة لتوريدها'; end if;
  if not exists (select 1 from acc.accounts where tenant_id = t and id = ba and not is_group and type = 'asset') then raise exception 'حساب البنك/الصندوق غير صالح'; end if;
  ds := 'توريد ضريبة الاستقطاع (' || n || ' سجل)';
  insert into acc.journals (tenant_id, id, entity_id, type, date, description, status, source, source_id, created_by) values (t, jid, ents[1], 'GJ', d, ds, 'draft', 'wht_remit', jid, auth.uid());
  perform app.put_lines(t, jid, ents[1], d, jsonb_build_array(jsonb_build_object('account', was[1], 'debit', tot, 'description', ds), jsonb_build_object('account', ba, 'credit', tot, 'description', ds)));
  j := app.post_journal(jid);
  update acc.wht_entries set remitted_on = d, remit_journal_id = j.id where tenant_id = t and id = any(ids);
  perform app.audit('remit', 'wht', jid::text, ds || ' — ' || tot); return jsonb_build_object('journal', j.id, 'amount', tot, 'count', n);
end $$;

insert into app.schema_migrations (version, name) values ('1.9.3.0', 'ضريبة الاستقطاع: فئات ونسب قابلة للتعديل، تسجيل بقيد، تقرير شهري، توريد للهيئة بقيد')
on conflict (version) do nothing;
-- مُحكَم للحسابات 1.9.4.0 — تقرير القطاعات التشغيلية (على نهج IFRS 8): إيراد ومصروف ونتيجة وأصول والتزامات لكل قطاع، مع الحدود الكمية 10% والتسوية إلى الإجمالي.
-- القطاع = شركة (افتراضي) أو مركز تكلفة أو مشروع. للقطاعات بحسب البعد (مركز/مشروع) يظهر صف «غير موزّع» لما لا بعد له فتتطابق المجاميع مع القوائم المالية.
-- التقرير تحليلي استرشادي؛ تحديد القطاعات التشغيلية الفعلية حكم إدارة المنشأة ومراجعها.
create or replace function public.rpt_segments(p jsonb default '{}') returns jsonb language plpgsql stable security definer set search_path = public, app, acc as $$
declare t uuid := app.need('reports', 'view'); ents uuid[] := app.pick_ents(p); df date := coalesce(nullif(p->>'from','')::date, date_trunc('year', current_date)::date); dt date := coalesce(nullif(p->>'to','')::date, current_date);
  b text := coalesce(nullif(p->>'basis',''), 'entity'); r jsonb;
begin
  if b not in ('entity', 'cc', 'project') then raise exception 'أساس القطاع: entity أو cc أو project'; end if;
  if df > dt then raise exception 'الفترة غير صالحة'; end if;
  with raw as (
    select case b when 'entity' then l.entity_id::text when 'cc' then coalesce(l.cost_center_id::text, '-') else coalesce(l.project_id::text, '-') end k,
      case b when 'entity' then (select e.name from acc.entities e where e.tenant_id = t and e.id = l.entity_id)
             when 'cc' then coalesce((select d.name from acc.dims d where d.tenant_id = t and d.id = l.cost_center_id), 'غير موزّع')
             else coalesce((select d.name from acc.dims d where d.tenant_id = t and d.id = l.project_id), 'غير موزّع') end nm,
      (j.type = 'CL' or exists (select 1 from acc.journals o where o.tenant_id = j.tenant_id and o.id = j.reversal_of and o.type = 'CL')) closing, a.type ty, l.date d, l.debit, l.credit
    from acc.journal_lines l join acc.journals j on j.tenant_id = l.tenant_id and j.id = l.journal_id join acc.accounts a on a.tenant_id = l.tenant_id and a.id = l.account_id
    where l.tenant_id = t and l.posted and l.entity_id = any(ents) and l.date <= dt and a.type in ('revenue', 'expense', 'asset', 'liability')),
  s as (
    select k, nm,
      coalesce(sum(credit - debit) filter (where ty = 'revenue' and d >= df and not closing), 0) rev,
      coalesce(sum(debit - credit) filter (where ty = 'expense' and d >= df and not closing), 0) exp,
      coalesce(sum(debit - credit) filter (where ty = 'asset'), 0) ast,
      coalesce(sum(credit - debit) filter (where ty = 'liability'), 0) lia
    from raw group by k, nm),
  s2 as (select * from s where rev <> 0 or exp <> 0 or ast <> 0 or lia <> 0),
  tot as (select coalesce(sum(rev), 0) tr, coalesce(sum(exp), 0) te, coalesce(sum(ast), 0) ta, coalesce(sum(lia), 0) tl, coalesce(sum(abs(rev - exp)) filter (where k <> '-'), 0) tpa from s2)
  select jsonb_build_object('basis', b, 'from', df, 'to', dt,
    'rows', coalesce((select jsonb_agg(jsonb_build_object('key', k, 'name', nm, 'revenue', round(rev, 2), 'expense', round(exp, 2), 'result', round(rev - exp, 2), 'assets', round(ast, 2), 'liabilities', round(lia, 2),
      'rev_pct', case when tot.tr <> 0 then round(rev / tot.tr * 100, 1) else 0 end,
      'reportable', k <> '-' and ((tot.tr <> 0 and abs(rev) >= 0.1 * abs(tot.tr)) or (tot.tpa <> 0 and abs(rev - exp) >= 0.1 * tot.tpa) or (tot.ta <> 0 and abs(ast) >= 0.1 * abs(tot.ta))))
      order by (k = '-'), rev desc, nm) from s2, tot), '[]'::jsonb),
    'total', (select jsonb_build_object('revenue', round(tr, 2), 'expense', round(te, 2), 'result', round(tr - te, 2), 'assets', round(ta, 2), 'liabilities', round(tl, 2)) from tot),
    'note', 'الحدّ الكمي 10% (إيراد أو نتيجة أو أصول) استرشادي على نهج IFRS 8؛ تحديد القطاعات المُفصَح عنها قرار إدارة ويُراجع مع المراجع.') into r;
  return r;
end $$;
insert into app.schema_migrations (version, name) values ('1.9.4.0', 'تقرير القطاعات التشغيلية (IFRS 8): بالشركة أو مركز التكلفة أو المشروع مع الحدود الكمية والتسوية')
on conflict (version) do nothing;
-- مُحكَم للحسابات 1.9.5.0 — سجل طلبات أصحاب البيانات (نظام حماية البيانات الشخصية): وصول، تصحيح، محو، نقل، اعتراض، مع مهلة متابعة وسجل تدقيق.
-- السجل تنظيمي لا ينفّذ المحو آليًا؛ المحو الفعلي قرار المسؤول بعد التحقق من الاحتفاظ النظامي والتجميد القانوني. مهلة 30 يومًا استرشادية تُراجع مع المحامي.
create table if not exists acc.dsr_requests (
  tenant_id uuid not null references acc.tenants(id) on delete cascade, id uuid not null default gen_random_uuid(), kind text not null check (kind in ('access','correction','erasure','portability','objection')),
  subject_name text not null, subject_ref text not null default '', details text not null default '', status text not null default 'new' check (status in ('new','in_progress','done','rejected')),
  due_on date not null, response text not null default '', handled_by uuid, closed_at timestamptz, created_by uuid, created_at timestamptz not null default now(), primary key (tenant_id, id));
alter table acc.dsr_requests enable row level security;
with ins as (
  insert into app.feature_cat (key, name, grp, core, since, sort) values ('dsr', 'طلبات أصحاب البيانات', 'الرقابة', false, 1, 41)
  on conflict (key) do nothing returning key)
update acc.tenants set features_off = array_append(features_off, 'dsr') where exists (select 1 from ins) and not ('dsr' = any(features_off));

create or replace function public.dsr_create(p jsonb) returns jsonb language plpgsql security definer set search_path = public, app, acc as $$
declare t uuid := app.need('settings', 'edit'); id uuid := gen_random_uuid(); d int := coalesce((p->>'days')::int, 30);
begin
  if not app.feat_on('dsr') then raise exception 'الميزة غير مفعّلة لشركتك'; end if;
  if p->>'kind' not in ('access','correction','erasure','portability','objection') then raise exception 'نوع الطلب غير صالح'; end if;
  if nullif(trim(p->>'subject_name'),'') is null then raise exception 'اسم صاحب البيانات مطلوب'; end if;
  if d < 1 or d > 120 then raise exception 'المهلة بين 1 و120 يومًا'; end if;
  insert into acc.dsr_requests (tenant_id, id, kind, subject_name, subject_ref, details, due_on, created_by) values (t, id, p->>'kind', trim(p->>'subject_name'), coalesce(p->>'subject_ref',''), coalesce(p->>'details',''), current_date + d, auth.uid());
  perform app.audit('create', 'dsr', id::text, (p->>'kind') || ' — ' || trim(p->>'subject_name')); return jsonb_build_object('id', id, 'due_on', current_date + d);
end $$;

create or replace function public.dsr_list(p jsonb default '{}') returns jsonb language plpgsql stable security definer set search_path = public, app, acc as $$
declare t uuid := app.need('settings', 'view');
begin
  if not app.feat_on('dsr') then raise exception 'الميزة غير مفعّلة لشركتك'; end if;
  return jsonb_build_object('today', current_date, 'rows', coalesce((select jsonb_agg(to_jsonb(r) - 'tenant_id' || jsonb_build_object('overdue', r.status in ('new','in_progress') and r.due_on < current_date) order by (r.status in ('done','rejected')), r.due_on)
    from acc.dsr_requests r where r.tenant_id = t and (nullif(p->>'status','') is null or r.status = p->>'status')), '[]'::jsonb));
end $$;

create or replace function public.dsr_update(p jsonb) returns jsonb language plpgsql security definer set search_path = public, app, acc as $$
declare t uuid := app.need('settings', 'edit'); r acc.dsr_requests; s text := p->>'status';
begin
  if not app.feat_on('dsr') then raise exception 'الميزة غير مفعّلة لشركتك'; end if;
  if s not in ('in_progress','done','rejected') then raise exception 'الحالة غير صالحة'; end if;
  select * into r from acc.dsr_requests where tenant_id = t and id = (p->>'id')::uuid; if r.id is null then raise exception 'الطلب غير موجود'; end if;
  if r.status in ('done','rejected') then raise exception 'الطلب مغلق ولا يُعدَّل'; end if;
  if s in ('done','rejected') and nullif(trim(p->>'response'),'') is null then raise exception 'اكتب الرد أو سبب الرفض عند الإغلاق'; end if;
  update acc.dsr_requests set status = s, response = coalesce(nullif(trim(p->>'response'),''), response), handled_by = auth.uid(), closed_at = case when s in ('done','rejected') then now() end where tenant_id = t and id = r.id;
  perform app.audit('update', 'dsr', r.id::text, r.kind || ' → ' || s); return jsonb_build_object('ok', true);
end $$;
insert into app.schema_migrations (version, name) values ('1.9.5.0', 'سجل طلبات أصحاب البيانات (PDPL): وصول وتصحيح ومحو ونقل واعتراض مع مهلة ورد وتدقيق')
on conflict (version) do nothing;

-- صلاحيات الدوال الجديدة: للمستخدم المسجَّل فقط
grant execute on function public.wht_rates_list(jsonb), public.wht_rates_save(jsonb), public.wht_calc(jsonb), public.wht_record(jsonb), public.wht_list(jsonb), public.wht_report(jsonb), public.wht_remit(jsonb),
  public.rpt_segments(jsonb), public.dsr_create(jsonb), public.dsr_list(jsonb), public.dsr_update(jsonb) to authenticated;
