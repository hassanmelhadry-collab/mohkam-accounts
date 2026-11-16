-- مُحكَم للحسابات 1.7.1.0: إلزام شركات المستخدم + اسم الشركة في ميزان المراجعة + المشاريع/WIP
-- ===== sql/057_user_entities.sql =====
-- مُحكَم للحسابات 1.7.1 — تحديد الشركات المسموحة لكل مستخدم إلزامي عند تعدد الشركات (غير المالك)
-- القاعدة تُفرض في قاعدة البيانات لكل المسارات (الواجهة والـ API). لا تمس المستخدمين القائمين؛ تسري على إضافة مستخدم أو تغيير شركاته من عضو في الحساب نفسه.
create or replace function app.members_entities_chk() returns trigger language plpgsql security definer set search_path = public, acc, app as $$
declare me acc.members;
begin
  if current_setting('app.demo_seed', true) = '1' or app.restore_flag() then return new; end if;
  if new.role = 'owner' or (new.entities is not null and cardinality(new.entities) > 0) then return new; end if;
  if tg_op = 'UPDATE' and old.entities is not distinct from new.entities and old.role is not distinct from new.role then return new; end if;
  select * into me from acc.members where user_id = auth.uid();
  if me.user_id is null or me.tenant_id <> new.tenant_id then return new; end if;  -- تهيئة المنصة/الديمو لا تُقيَّد
  if (select count(*) from acc.entities where tenant_id = new.tenant_id and active) > 1 then
    raise exception 'حدّد الشركات المسموحة لهذا المستخدم — لا يُترك بلا تحديد عند تعدد الشركات';
  end if;
  return new;
end $$;
drop trigger if exists members_entities_chk on acc.members;
create trigger members_entities_chk before insert or update of entities, role on acc.members for each row execute function app.members_entities_chk();
-- ===== sql/058_report_entity.sql =====
-- مُحكَم للحسابات 1.7.1 — ميزان المراجعة يعرض اسم شركة كل حساب (للعرض المجمّع عند فصل الأدلة)
create or replace function public.rpt_trial_balance(p jsonb default '{}') returns jsonb language plpgsql stable security definer set search_path = public, app, acc as $$
declare t uuid := app.need('reports','view'); ents uuid[] := app.pick_ents(p); df date := nullif(p->>'from','')::date; dt date := coalesce(nullif(p->>'to','')::date, current_date); base jsonb; rows jsonb; zero boolean := coalesce((p->>'with_zero')::boolean, false);
  tot jsonb;
begin
  select coalesce(jsonb_agg(jsonb_build_object('account_id', r.account_id, 'opening', r.opening, 'debit', r.debit, 'credit', r.credit)), '[]') into base
    from app.tb_rows(t, ents, df, dt, true, nullif(p->>'cost_center','')::uuid, nullif(p->>'project','')::uuid) r;
  select coalesce(jsonb_agg(jsonb_build_object('id', a.id, 'entity_id', a.entity_id, 'entity', (select e.name from acc.entities e where e.tenant_id = t and e.id = a.entity_id), 'code', a.code, 'name', a.name, 'name_en', a.name_en, 'type', a.type, 'is_group', a.is_group, 'parent_id', a.parent_id,
      'opening', r.opening, 'debit', r.debit, 'credit', r.credit, 'closing', r.opening + r.debit - r.credit) order by a.code), '[]') into rows
  from app.rollup(t, base) r join acc.accounts a on a.tenant_id = t and a.id = r.account_id
  where (zero or r.opening <> 0 or r.debit <> 0 or r.credit <> 0);
  -- المجاميع من الحسابات الورقية فقط (تجنب التكرار)
  select jsonb_build_object('opening', coalesce(sum(r.opening),0), 'debit', coalesce(sum(r.debit),0), 'credit', coalesce(sum(r.credit),0), 'closing', coalesce(sum(r.opening + r.debit - r.credit),0)) into tot from (select (x->>'opening')::numeric opening, (x->>'debit')::numeric debit, (x->>'credit')::numeric credit from jsonb_array_elements(base) x) r;
  return jsonb_build_object('rows', rows, 'totals', tot, 'from', df, 'to', dt);
end $$;
-- ===== sql/059_projects.sql =====
-- مُحكَم للحسابات 1.7.1 — المشاريع وأعمال تحت التنفيذ (WIP) وتحقق الإيراد بنسبة الإنجاز (ميزة اختيارية projects_wip)
-- المشروع = مركز بُعد من نوع project (يُستعمل أصلًا في القيود والفواتير) + عقد وميزانية. التكلفة والإيراد يُحسبان من الأسطر المرحّلة الموسومة بالمشروع،
-- فلا يتعارض مع أي قيد قائم. قيد التسوية يُنشأ مسودة ويمر بدورة الاعتماد المعتادة.
create table if not exists acc.projects (
  tenant_id uuid not null references acc.tenants(id) on delete cascade, dim_id uuid not null, entity_id uuid not null, party_id uuid,
  contract_value numeric(18,2) not null default 0 check (contract_value >= 0), budget_cost numeric(18,2) not null default 0 check (budget_cost >= 0),
  start_date date, end_date date, method text not null default 'poc_cost' check (method in ('poc_cost','completed')),
  status text not null default 'active' check (status in ('active','done','hold')), note text not null default '', created_by uuid, created_at timestamptz not null default now(),
  primary key (tenant_id, dim_id), foreign key (tenant_id, dim_id) references acc.dims (tenant_id, id) on delete cascade,
  foreign key (tenant_id, entity_id) references acc.entities (tenant_id, id), foreign key (tenant_id, party_id) references acc.parties (tenant_id, id));
create index if not exists projects_ent on acc.projects (tenant_id, entity_id);
create table if not exists acc.project_wip_runs (tenant_id uuid not null, dim_id uuid not null, journal_id uuid not null, adjustment numeric(18,2) not null, asof date not null, created_at timestamptz not null default now(),
  primary key (tenant_id, journal_id), foreign key (tenant_id, dim_id) references acc.projects (tenant_id, dim_id) on delete cascade);
alter table acc.projects enable row level security; alter table acc.project_wip_runs enable row level security;
with ins as (
  insert into app.feature_cat (key, name, grp, core, since, sort) values ('projects_wip', 'المشاريع وأعمال تحت التنفيذ (نسبة الإنجاز وتحقق الإيراد)', 'المالية', false, 1, 36)
  on conflict (key) do nothing returning key)
update acc.tenants set features_off = array_append(features_off, 'projects_wip') where exists (select 1 from ins) and not ('projects_wip' = any(features_off));
update app.feature_cat set name = 'المشاريع وأعمال تحت التنفيذ (نسبة الإنجاز وتحقق الإيراد)', grp = 'المالية', core = false, sort = 36 where key = 'projects_wip';

create or replace function app.prj_chk(act text) returns uuid language plpgsql stable security definer set search_path = public, app, acc as $$
begin if not app.feat_on('projects_wip') then raise exception 'الميزة غير مفعّلة لشركتك'; end if; return app.need('costcenters', act); end $$;

-- أرقام المشروع حتى تاريخ: تكلفة، فوترة (إيراد غير تسوية)، تسويات سابقة
create or replace function app.prj_nums(t uuid, d uuid, asof date) returns jsonb language sql stable security definer set search_path = public, app, acc as $$
  select jsonb_build_object(
    'cost', coalesce(sum(case when a.type = 'expense' then l.debit - l.credit end), 0),
    'billed', coalesce(sum(case when a.type = 'revenue' and not exists (select 1 from acc.project_wip_runs w where w.tenant_id = l.tenant_id and w.journal_id = l.journal_id) then l.credit - l.debit end), 0),
    'adjusted', coalesce(sum(case when a.type = 'revenue' and exists (select 1 from acc.project_wip_runs w where w.tenant_id = l.tenant_id and w.journal_id = l.journal_id) then l.credit - l.debit end), 0))
  from acc.journal_lines l join acc.accounts a on a.tenant_id = l.tenant_id and a.id = l.account_id
  where l.tenant_id = t and l.project_id = d and l.posted and l.date <= asof $$;

create or replace function app.prj_calc(t uuid, pr acc.projects, asof date) returns jsonb language plpgsql stable security definer set search_path = public, app, acc as $$
declare n jsonb := app.prj_nums(t, pr.dim_id, asof); cost numeric := (n->>'cost')::numeric; billed numeric := (n->>'billed')::numeric; adj numeric := (n->>'adjusted')::numeric; pct numeric; earned numeric; rec numeric;
begin
  pct := case pr.method when 'completed' then case when pr.status = 'done' then 1 else 0 end else case when pr.budget_cost > 0 then least(cost / pr.budget_cost, 1) else 0 end end;
  earned := round(pr.contract_value * pct, 2); rec := billed + adj;
  return jsonb_build_object('cost', cost, 'billed', billed, 'adjusted', adj, 'pct', round(pct * 100, 2), 'earned', earned, 'recognized', rec, 'adjustment', round(earned - rec, 2),
    'est_profit', pr.contract_value - pr.budget_cost, 'loss_expected', pr.budget_cost > pr.contract_value, 'over_budget', cost > pr.budget_cost and pr.budget_cost > 0,
    'unbilled', greatest(round(earned - rec, 2), 0), 'overbilled', greatest(round(rec - earned, 2), 0));
end $$;

create or replace function public.project_save(p jsonb) returns jsonb language plpgsql security definer set search_path = public, app, acc as $$
declare t uuid; v uuid := nullif(p->>'id','')::uuid; e uuid; c text := trim(coalesce(p->>'code','')); nm text := trim(coalesce(p->>'name',''));
begin
  t := app.prj_chk(case when v is null then 'add' else 'edit' end);
  if v is null then
    e := (p->>'entity')::uuid; perform app.entity_ok(t, e);
    if c = '' or nm = '' then raise exception 'رمز واسم المشروع مطلوبان'; end if;
    v := gen_random_uuid();
    insert into acc.dims (tenant_id, id, kind, code, name, note) values (t, v, 'project', c, nm, coalesce(p->>'note',''));
    insert into acc.projects (tenant_id, dim_id, entity_id, party_id, contract_value, budget_cost, start_date, end_date, method, status, note, created_by)
    values (t, v, e, nullif(p->>'party','')::uuid, coalesce(nullif(p->>'contract_value','')::numeric, 0), coalesce(nullif(p->>'budget_cost','')::numeric, 0), nullif(p->>'start_date','')::date, nullif(p->>'end_date','')::date,
      coalesce(nullif(p->>'method',''), 'poc_cost'), coalesce(nullif(p->>'status',''), 'active'), coalesce(p->>'note',''), auth.uid());
  else
    select entity_id into e from acc.projects where tenant_id = t and dim_id = v; if e is null then raise exception 'المشروع غير موجود'; end if;
    perform app.entity_ok(t, e);
    if nm <> '' then update acc.dims set name = nm, code = coalesce(nullif(c,''), code) where tenant_id = t and id = v; end if;
    update acc.projects set party_id = case when p ? 'party' then nullif(p->>'party','')::uuid else party_id end, contract_value = coalesce(nullif(p->>'contract_value','')::numeric, contract_value), budget_cost = coalesce(nullif(p->>'budget_cost','')::numeric, budget_cost),
      start_date = case when p ? 'start_date' then nullif(p->>'start_date','')::date else start_date end, end_date = case when p ? 'end_date' then nullif(p->>'end_date','')::date else end_date end,
      method = coalesce(nullif(p->>'method',''), method), status = coalesce(nullif(p->>'status',''), status), note = coalesce(p->>'note', note) where tenant_id = t and dim_id = v;
  end if;
  perform app.audit('save', 'project', v::text, c || ' ' || nm);
  return jsonb_build_object('id', v);
exception when unique_violation then raise exception 'رمز المشروع مستخدم من قبل';
end $$;

create or replace function public.project_list(p jsonb default '{}') returns jsonb language plpgsql stable security definer set search_path = public, app, acc as $$
declare t uuid := app.prj_chk('view'); ents uuid[] := app.pick_ents(p); asof date := coalesce(nullif(p->>'asof','')::date, current_date);
begin
  return coalesce((select jsonb_agg(jsonb_build_object('id', pr.dim_id, 'code', d.code, 'name', d.name, 'entity_id', pr.entity_id, 'entity', e.name, 'party_id', pr.party_id, 'party', py.name,
      'contract_value', pr.contract_value, 'budget_cost', pr.budget_cost, 'start_date', pr.start_date, 'end_date', pr.end_date, 'method', pr.method, 'status', pr.status, 'note', pr.note) || app.prj_calc(t, pr, asof) order by d.code)
    from acc.projects pr join acc.dims d on d.tenant_id = pr.tenant_id and d.id = pr.dim_id join acc.entities e on e.tenant_id = pr.tenant_id and e.id = pr.entity_id left join acc.parties py on py.tenant_id = pr.tenant_id and py.id = pr.party_id
    where pr.tenant_id = t and pr.entity_id = any(ents) and (nullif(p->>'status','') is null or pr.status = p->>'status')), '[]'::jsonb);
end $$;

-- تفصيل تكلفة المشروع بالحسابات
create or replace function public.project_get(p jsonb) returns jsonb language plpgsql stable security definer set search_path = public, app, acc as $$
declare t uuid := app.prj_chk('view'); v uuid := (p->>'id')::uuid; pr acc.projects; asof date := coalesce(nullif(p->>'asof','')::date, current_date);
begin
  select * into pr from acc.projects where tenant_id = t and dim_id = v; if pr.dim_id is null then raise exception 'المشروع غير موجود'; end if; perform app.entity_ok(t, pr.entity_id);
  return jsonb_build_object('project', to_jsonb(pr) - 'tenant_id', 'calc', app.prj_calc(t, pr, asof),
    'cost_by_account', coalesce((select jsonb_agg(jsonb_build_object('account', a.code || ' - ' || a.name, 'amount', x.amt) order by x.amt desc) from (select l.account_id, sum(l.debit - l.credit) amt from acc.journal_lines l where l.tenant_id = t and l.project_id = v and l.posted and l.date <= asof group by 1) x join acc.accounts a on a.tenant_id = t and a.id = x.account_id where a.type = 'expense' and x.amt <> 0), '[]'::jsonb),
    'adjustments', coalesce((select jsonb_agg(jsonb_build_object('journal_id', j.id, 'number', j.number, 'date', j.date, 'status', j.status, 'amount', w.adjustment) order by j.date desc) from acc.project_wip_runs w join acc.journals j on j.tenant_id = w.tenant_id and j.id = w.journal_id where w.tenant_id = t and w.dim_id = v), '[]'::jsonb));
end $$;

-- قيد تسوية الإيراد (مسودة): إيراد مستحق غير مفوتر (أصل عقد) أو فوترة زائدة (التزام عقد)
create or replace function public.project_wip_post(p jsonb) returns jsonb language plpgsql security definer set search_path = public, app, acc as $$
declare t uuid := app.prj_chk('view'); v uuid := (p->>'project')::uuid; pr acc.projects; asof date := coalesce(nullif(p->>'asof','')::date, current_date); r jsonb; adj numeric; ra uuid; aa uuid; la uuid; j jsonb; lines jsonb; tp text;
begin
  perform app.need('journals', 'add');
  select * into pr from acc.projects where tenant_id = t and dim_id = v; if pr.dim_id is null then raise exception 'المشروع غير موجود'; end if; perform app.entity_ok(t, pr.entity_id);
  if exists (select 1 from acc.project_wip_runs w join acc.journals j on j.tenant_id = w.tenant_id and j.id = w.journal_id where w.tenant_id = t and w.dim_id = v and j.status not in ('posted','reversed')) then raise exception 'يوجد قيد تسوية لهذا المشروع لم يُرحَّل بعد — رحّله أو احذفه أولًا'; end if;
  r := app.prj_calc(t, pr, asof); adj := (r->>'adjustment')::numeric;
  if abs(adj) < 0.01 then raise exception 'لا فرق للتسوية: الإيراد المعترف به مطابق للمستحق'; end if;
  ra := app.acct_id(t, p->>'revenue_account'); if ra is null or not exists (select 1 from acc.accounts where tenant_id = t and id = ra and type = 'revenue' and not is_group) then raise exception 'حدّد حساب إيراد فرعي'; end if;
  if adj > 0 then
    aa := app.acct_id(t, p->>'asset_account'); if aa is null or not exists (select 1 from acc.accounts where tenant_id = t and id = aa and type = 'asset' and not is_group) then raise exception 'حدّد حساب أصل العقد (إيراد مستحق غير مفوتر)'; end if;
    lines := jsonb_build_array(jsonb_build_object('account', aa, 'debit', adj, 'credit', 0, 'project', v, 'description', 'إيراد مستحق غير مفوتر'), jsonb_build_object('account', ra, 'debit', 0, 'credit', adj, 'project', v, 'description', 'تحقق إيراد بنسبة الإنجاز'));
  else
    la := app.acct_id(t, p->>'liability_account'); if la is null or not exists (select 1 from acc.accounts where tenant_id = t and id = la and type = 'liability' and not is_group) then raise exception 'حدّد حساب التزام العقد (فوترة زائدة)'; end if;
    lines := jsonb_build_array(jsonb_build_object('account', ra, 'debit', -adj, 'credit', 0, 'project', v, 'description', 'تخفيض إيراد (فوترة زائدة)'), jsonb_build_object('account', la, 'debit', 0, 'credit', -adj, 'project', v, 'description', 'فوترة زائدة على المشروع'));
  end if;
  j := public.je_save(jsonb_build_object('entity', pr.entity_id, 'date', asof, 'type', 'ADJ', 'memo', 'تسوية إيراد مشروع ' || (select code || ' ' || name from acc.dims where tenant_id = t and id = v) || ' — نسبة الإنجاز ' || (r->>'pct') || '%', 'lines', lines));
  insert into acc.project_wip_runs (tenant_id, dim_id, journal_id, adjustment, asof) values (t, v, (j->>'id')::uuid, adj, asof);
  perform app.audit('post', 'project_wip', v::text, 'قيد تسوية إيراد ' || adj);
  return jsonb_build_object('journal', j->>'id', 'adjustment', adj, 'pct', r->>'pct');
end $$;

-- جدول WIP للشركات المسموحة: مجاميع
create or replace function public.project_wip_summary(p jsonb default '{}') returns jsonb language plpgsql stable security definer set search_path = public, app, acc as $$
declare rows jsonb := public.project_list(p);
begin
  return jsonb_build_object('rows', rows, 'totals', jsonb_build_object(
    'contract', coalesce((select sum((x->>'contract_value')::numeric) from jsonb_array_elements(rows) x), 0), 'cost', coalesce((select sum((x->>'cost')::numeric) from jsonb_array_elements(rows) x), 0),
    'earned', coalesce((select sum((x->>'earned')::numeric) from jsonb_array_elements(rows) x), 0), 'recognized', coalesce((select sum((x->>'recognized')::numeric) from jsonb_array_elements(rows) x), 0),
    'unbilled', coalesce((select sum((x->>'unbilled')::numeric) from jsonb_array_elements(rows) x), 0), 'overbilled', coalesce((select sum((x->>'overbilled')::numeric) from jsonb_array_elements(rows) x), 0)));
end $$;
