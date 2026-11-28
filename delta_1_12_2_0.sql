-- 1.12.2.0 — مركز العمليات (قراءة فقط): app.ops_card وapp.ops_group وpublic.ops_queue. لا تغيير في أي جدول. المصدر: sql/108_ops_center.sql. التراجع: rollback_1_12_2_0.sql

-- بطاقة واحدة: k مفتاح ثابت، count العدد الكلي، items أعلى 5 عناصر، to مسار الشاشة المرتبطة
create or replace function app.ops_card(k text, n bigint, items jsonb, dest text) returns jsonb language sql immutable set search_path = public, app, acc as $$
  select jsonb_build_object('k', k, 'count', coalesce(n, 0), 'items', coalesce(items, '[]'::jsonb), 'to', dest) $$;
create or replace function app.ops_group(cards jsonb) returns jsonb language sql immutable set search_path = public, app, acc as $$
  select case when jsonb_array_length(cards) = 0 then null
    else jsonb_build_object('count', (select coalesce(sum((c->>'count')::bigint), 0) from jsonb_array_elements(cards) c), 'cards', cards) end $$;

create or replace function public.ops_queue(p jsonb default '{}') returns jsonb language plpgsql stable security definer set search_path = public, app, acc as $$
declare t uuid := app.need(null, null); ents uuid[] := app.pick_ents(p); d date := current_date; n bigint; it jsonb;
  ap jsonb := '[]'; ov jsonb := '[]'; un jsonb := '[]'; cl jsonb := '[]'; co jsonb := '[]'; rc jsonb := '[]';
begin
  -- ===== 1) الموافقات المعلّقة =====
  if app.can('journals', 'approve') then
    with q as (select j.id, 'قيد ' || coalesce(j.number, 'مسودة') || case when j.description <> '' then ' — ' || left(j.description, 60) else '' end lbl, j.total amt, j.date dt from acc.journals j where j.tenant_id = t and j.entity_id = any(ents) and j.status = 'pending')
    select (select count(*) from q), (select jsonb_agg(jsonb_build_object('id', id, 'label', lbl, 'amount', amt, 'date', dt, 'to', '/journals') order by dt, id) from (select * from q order by dt, id limit 5) z) into n, it;
    ap := ap || app.ops_card('journals', n, it, '/journals');
  end if;
  if app.can('sales', 'approve') then
    with q as (select i.id, case i.kind when 'sales' then 'فاتورة مبيعات ' else 'إشعار دائن ' end || coalesce(i.number, 'مسودة') || ' — ' || pa.name lbl, i.total amt, i.date dt from acc.invoices i join acc.parties pa on pa.tenant_id = i.tenant_id and pa.id = i.party_id where i.tenant_id = t and i.entity_id = any(ents) and i.status = 'pending' and i.kind in ('sales', 'sales_credit'))
    select (select count(*) from q), (select jsonb_agg(jsonb_build_object('id', id, 'label', lbl, 'amount', amt, 'date', dt, 'to', '/invoices/sales') order by dt, id) from (select * from q order by dt, id limit 5) z) into n, it;
    ap := ap || app.ops_card('sales_invoices', n, it, '/invoices/sales');
  end if;
  if app.can('purchases', 'approve') then
    with q as (select i.id, case i.kind when 'purchase' then 'فاتورة مشتريات ' else 'إشعار مدين ' end || coalesce(i.number, i.supplier_ref, 'مسودة') || ' — ' || pa.name lbl, i.total amt, i.date dt from acc.invoices i join acc.parties pa on pa.tenant_id = i.tenant_id and pa.id = i.party_id where i.tenant_id = t and i.entity_id = any(ents) and i.status = 'pending' and i.kind in ('purchase', 'purchase_debit'))
    select (select count(*) from q), (select jsonb_agg(jsonb_build_object('id', id, 'label', lbl, 'amount', amt, 'date', dt, 'to', '/invoices/purchase') order by dt, id) from (select * from q order by dt, id limit 5) z) into n, it;
    ap := ap || app.ops_card('purchase_invoices', n, it, '/invoices/purchase');
  end if;
  if app.can('payments', 'approve') then
    with q as (select y.id, case y.kind when 'receipt' then 'سند قبض ' else 'سند صرف ' end || coalesce(y.number, 'مسودة') || coalesce(' — ' || pa.name, '') lbl, y.amount amt, y.date dt, case y.kind when 'receipt' then '/payments/receipt' else '/payments/payment' end dest
      from acc.payments y left join acc.parties pa on pa.tenant_id = y.tenant_id and pa.id = y.party_id where y.tenant_id = t and y.entity_id = any(ents) and y.status = 'pending')
    select (select count(*) from q), (select jsonb_agg(jsonb_build_object('id', id, 'label', lbl, 'amount', amt, 'date', dt, 'to', dest) order by dt, id) from (select * from q order by dt, id limit 5) z) into n, it;
    ap := ap || app.ops_card('payments', n, it, '/payments/receipt');
  end if;
  if app.can('requests', 'approve') then
    with q as (select r.id, r.title || coalesce(' — ' || pa.name, '') lbl, r.amount amt, r.date dt from acc.requests r left join acc.parties pa on pa.tenant_id = r.tenant_id and pa.id = r.party_id where r.tenant_id = t and r.entity_id = any(ents) and r.status = 'submitted')
    select (select count(*) from q), (select jsonb_agg(jsonb_build_object('id', id, 'label', lbl, 'amount', amt, 'date', dt, 'to', '/requests') order by dt, id) from (select * from q order by dt, id limit 5) z) into n, it;
    ap := ap || app.ops_card('requests', n, it, '/requests');
  end if;

  -- ===== 2) المتأخرات والتحصيل =====
  if app.can('sales', 'view') then
    with q as (select i.id, 'فاتورة ' || coalesce(i.number, '—') || ' — ' || pa.name lbl, i.total_base - app.inv_paid(t, i.id) amt, i.due_date dt from acc.invoices i join acc.parties pa on pa.tenant_id = i.tenant_id and pa.id = i.party_id
      where i.tenant_id = t and i.entity_id = any(ents) and i.kind = 'sales' and i.status = 'issued' and i.due_date < d and i.total_base > app.inv_paid(t, i.id))
    select (select count(*) from q), (select jsonb_agg(jsonb_build_object('id', id, 'label', lbl, 'amount', amt, 'date', dt, 'to', '/invoices/sales') order by dt, id) from (select * from q order by dt, id limit 5) z) into n, it;
    ov := ov || app.ops_card('ar_overdue', n, it, '/invoices/sales');
    if app.feat_on('collections', t) then
      -- وعود سداد فات موعدها (آخر وعد لكل عميل) ولا يزال على العميل متأخرات
      with lp as (select distinct on (c.party_id) c.party_id, c.promise_date, c.promise_amount from acc.collection_notes c where c.tenant_id = t and c.kind = 'promise' and c.promise_date is not null order by c.party_id, c.created_at desc),
        q as (select lp.party_id id, pa.name || ' — وعد سداد فات موعده' lbl, lp.promise_amount amt, lp.promise_date dt from lp join acc.parties pa on pa.tenant_id = t and pa.id = lp.party_id
          where lp.promise_date < d and exists (select 1 from acc.invoices i where i.tenant_id = t and i.entity_id = any(ents) and i.party_id = lp.party_id and i.kind = 'sales' and i.status = 'issued' and i.due_date < d and i.total_base > app.inv_paid(t, i.id)))
      select (select count(*) from q), (select jsonb_agg(jsonb_build_object('id', id, 'label', lbl, 'amount', amt, 'date', dt, 'to', '/collections') order by dt, id) from (select * from q order by dt, id limit 5) z) into n, it;
      ov := ov || app.ops_card('broken_promises', n, it, '/collections');
    end if;
  end if;

  -- ===== 3) غير المسوّى =====
  if app.can('bank', 'view') then
    with q as (select b.id, coalesce(nullif(b.description, ''), b.reference, '—') || ' — ' || ba.name lbl, b.amount amt, b.date dt from acc.bank_lines b join acc.bank_accounts ba on ba.tenant_id = b.tenant_id and ba.id = b.bank_account_id
      where b.tenant_id = t and ba.entity_id = any(ents) and b.matched_line_id is null)
    select (select count(*) from q), (select jsonb_agg(jsonb_build_object('id', id, 'label', lbl, 'amount', amt, 'date', dt, 'to', '/bank') order by dt, id) from (select * from q order by dt, id limit 5) z) into n, it;
    un := un || app.ops_card('bank_unmatched', n, it, '/bank');
  end if;
  if app.can('journals', 'view') then
    with q as (select j.id, 'مسودة قيد' || case when j.description <> '' then ' — ' || left(j.description, 60) else '' end lbl, j.total amt, j.date dt from acc.journals j where j.tenant_id = t and j.entity_id = any(ents) and j.status = 'draft')
    select (select count(*) from q), (select jsonb_agg(jsonb_build_object('id', id, 'label', lbl, 'amount', amt, 'date', dt, 'to', '/journals') order by dt, id) from (select * from q order by dt, id limit 5) z) into n, it;
    un := un || app.ops_card('draft_journals', n, it, '/journals');
  end if;
  if app.feat_on('cheques', t) and app.can('payments', 'view') then
    -- شيكات مرحّلة بلا متابعة يحلّ استحقاقها خلال 7 أيام (وتشمل ما فات موعده)
    with q as (select y.id, 'شيك ' || y.cheque_no || coalesce(' — ' || pa.name, '') || case when y.kind = 'receipt' then ' (مستلم)' else ' (مُصدَر)' end lbl, y.amount amt, y.cheque_date dt
      from acc.payments y left join acc.parties pa on pa.tenant_id = y.tenant_id and pa.id = y.party_id
      where y.tenant_id = t and y.entity_id = any(ents) and y.method = 'cheque' and y.status = 'posted' and y.cheque_date is not null and y.cheque_date <= d + 7
        and not exists (select 1 from acc.cheque_events e where e.tenant_id = t and e.payment_id = y.id))
    select (select count(*) from q), (select jsonb_agg(jsonb_build_object('id', id, 'label', lbl, 'amount', amt, 'date', dt, 'to', '/cheques') order by dt, id) from (select * from q order by dt, id limit 5) z) into n, it;
    un := un || app.ops_card('cheques_due', n, it, '/cheques');
  end if;

  -- ===== 4) الإقفال =====
  if app.can('periods', 'view') then
    with q as (select pr.id, e.name || ' — فترة ' || pr.no || ' (' || pr.start_date || ' → ' || pr.end_date || ')' lbl, pr.end_date dt from acc.periods pr join acc.entities e on e.tenant_id = pr.tenant_id and e.id = pr.entity_id
      where pr.tenant_id = t and pr.entity_id = any(ents) and pr.status = 'open' and pr.end_date < d)
    select (select count(*) from q), (select jsonb_agg(jsonb_build_object('id', id, 'label', lbl, 'date', dt, 'to', '/periods') order by dt, id) from (select * from q order by dt, id limit 5) z) into n, it;
    cl := cl || app.ops_card('open_periods', n, it, '/periods');
  end if;
  if app.can('journals', 'view') then
    with q as (select r.id, r.name || ' — ' || e.name lbl, (select coalesce(sum((l->>'debit')::numeric), 0) from jsonb_array_elements(r.lines) l) amt, r.next_date dt
      from acc.recurring r join acc.entities e on e.tenant_id = r.tenant_id and e.id = r.entity_id
      where r.tenant_id = t and r.entity_id = any(ents) and r.active and r.next_date <= d and (r.end_date is null or r.next_date <= r.end_date))
    select (select count(*) from q), (select jsonb_agg(jsonb_build_object('id', id, 'label', lbl, 'amount', amt, 'date', dt, 'to', '/recurring') order by dt, id) from (select * from q order by dt, id limit 5) z) into n, it;
    cl := cl || app.ops_card('recurring_due', n, it, '/recurring');
  end if;

  -- ===== 5) الرقابة =====
  if app.can('controls', 'view') or app.can('reports', 'view') then
    -- فجوات ترقيم الفواتير (لكل كيان/نوع/سنة): العدد = الأرقام المفقودة بين أول رقم وآخر رقم
    with s as (select i.entity_id, split_part(i.number, '-', 1) pre, split_part(i.number, '-', 2) yr, split_part(i.number, '-', 3)::bigint nn from acc.invoices i
        where i.tenant_id = t and i.entity_id = any(ents) and i.number ~ '^[A-Za-z]+-[0-9]{4}-[0-9]{1,12}$'),
      g as (select s.entity_id, s.pre, s.yr, (max(s.nn) - min(s.nn) + 1) - count(distinct s.nn) miss from s group by s.entity_id, s.pre, s.yr),
      q as (select g.entity_id::text || ':' || g.pre || ':' || g.yr id, e.name || ' — ' || g.pre || '-' || g.yr || ': ' || g.miss || ' رقم مفقود' lbl, g.miss from g join acc.entities e on e.tenant_id = t and e.id = g.entity_id where g.miss > 0)
    select (select coalesce(sum(miss), 0) from q), (select jsonb_agg(jsonb_build_object('id', id, 'label', lbl, 'to', '/controls') order by miss desc, id) from (select * from q order by miss desc, id limit 5) z) into n, it;
    co := co || app.ops_card('invoice_gaps', n, it, '/controls');
  end if;
  if app.feat_on('dsr', t) and app.can('settings', 'view') then
    with q as (select r.id, r.subject_name || ' — ' || r.kind lbl, r.due_on dt from acc.dsr_requests r where r.tenant_id = t and r.status in ('new', 'in_progress') and r.due_on < d)
    select (select count(*) from q), (select jsonb_agg(jsonb_build_object('id', id, 'label', lbl, 'date', dt, 'to', '/dsr') order by dt, id) from (select * from q order by dt, id limit 5) z) into n, it;
    co := co || app.ops_card('dsr_overdue', n, it, '/dsr');
  end if;

  -- ===== 6) آخر الأحداث (سجل التدقيق) =====
  if app.sys('audit') then
    select jsonb_agg(jsonb_build_object('id', a.id::text, 'label', coalesce(a.username, '—') || ' · ' || a.action || ' ' || coalesce(a.entity, '') || coalesce(': ' || left(a.details, 80), ''), 'date', a.at, 'to', '/audit') order by a.id desc) into it
      from (select * from acc.audit x where x.tenant_id = t order by x.id desc limit 10) a;
    rc := rc || jsonb_build_object('k', 'audit', 'count', coalesce(jsonb_array_length(it), 0), 'items', coalesce(it, '[]'::jsonb), 'to', '/audit');
  end if;

  return jsonb_strip_nulls(jsonb_build_object('asof', now(), 'approvals', app.ops_group(ap), 'overdue', app.ops_group(ov), 'unmatched', app.ops_group(un), 'close', app.ops_group(cl), 'controls', app.ops_group(co), 'recent', app.ops_group(rc)));
end $$;

do $$ begin
  grant execute on function public.ops_queue(jsonb) to authenticated; revoke execute on function public.ops_queue(jsonb) from anon, public;
end $$;
insert into app.schema_migrations (version, name) values ('1.12.2.0', 'مركز العمليات: ops_queue (قراءة فقط) — بطاقات الموافقات والمتأخرات وغير المسوّى والإقفال والرقابة وآخر الأحداث') on conflict (version) do nothing;
