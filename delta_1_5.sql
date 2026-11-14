-- تحديث 1.5: المخزون وتكلفة البضاعة + تثبيت شركة المحاسب (دلتا فوق أي قاعدة 1.4.x — آمن للتكرار)
-- المخزون وتكلفة البضاعة المباعة (متوسط مرجّح لكل شركة/كيان) — 1.5
create table if not exists acc.items (
  tenant_id uuid not null references acc.tenants(id) on delete cascade, id uuid not null default gen_random_uuid(), code text not null, name text not null, name_en text not null default '',
  unit text not null default 'قطعة', inv_account_id uuid not null, cogs_account_id uuid not null, sale_price numeric(18,4) not null default 0, reorder_qty numeric(18,4) not null default 0,
  active boolean not null default true, created_at timestamptz not null default now(),
  primary key (tenant_id, id), unique (tenant_id, code),
  foreign key (tenant_id, inv_account_id) references acc.accounts (tenant_id, id), foreign key (tenant_id, cogs_account_id) references acc.accounts (tenant_id, id));
create table if not exists acc.stock_bal (
  tenant_id uuid not null, entity_id uuid not null, item_id uuid not null, qty numeric(18,4) not null default 0, avg_cost numeric(18,6) not null default 0,
  primary key (tenant_id, entity_id, item_id), foreign key (tenant_id, item_id) references acc.items (tenant_id, id));
create table if not exists acc.stock_moves (
  tenant_id uuid not null, id uuid not null default gen_random_uuid(), entity_id uuid not null, item_id uuid not null, date date not null, dir text not null check (dir in ('in','out')),
  qty numeric(18,4) not null check (qty > 0), unit_cost numeric(18,6) not null default 0, doc_type text not null default 'invoice', doc_id uuid, journal_id uuid, reversed boolean not null default false,
  note text not null default '', created_at timestamptz not null default now(),
  primary key (tenant_id, id), foreign key (tenant_id, item_id) references acc.items (tenant_id, id));
create index if not exists stock_moves_doc on acc.stock_moves (tenant_id, doc_id);
create index if not exists stock_moves_item on acc.stock_moves (tenant_id, item_id, date);
alter table acc.invoice_lines add column if not exists item_id uuid;
do $$ declare t text; begin foreach t in array array['items','stock_bal','stock_moves'] loop execute format('alter table acc.%I enable row level security', t); end loop; end $$;

create or replace function app.need_inv(action text) returns uuid language plpgsql stable security definer set search_path = public, acc as $$
declare t uuid := app.need(null, null);
begin
  if app.can('inventory', action) or (action = 'view' and (app.can('purchases','view') or app.can('sales','view'))) or (action in ('add','edit') and app.can('purchases','add')) or (action = 'delete' and app.can('purchases','delete')) then return t; end if;
  raise exception 'ليست لديك صلاحية المخزون (%)', action;
end $$;

create or replace function public.item_list(p jsonb default '{}') returns jsonb language plpgsql stable security definer set search_path = public, app, acc as $$
declare t uuid := app.need_inv('view');
begin
  return coalesce((select jsonb_agg(to_jsonb(i) - 'tenant_id' || jsonb_build_object('inv_account', (select code || ' - ' || name from acc.accounts where tenant_id = t and id = i.inv_account_id),
      'qty', coalesce((select sum(b.qty) from acc.stock_bal b where b.tenant_id = t and b.item_id = i.id), 0)) order by i.code) from acc.items i where i.tenant_id = t), '[]'::jsonb);
end $$;

create or replace function public.item_upsert(p jsonb) returns jsonb language plpgsql security definer set search_path = public, app, acc as $$
declare t uuid; v_id uuid := nullif(p->>'id','')::uuid; ia uuid; ca uuid; c text := trim(coalesce(p->>'code','')); nm text := trim(coalesce(p->>'name',''));
begin
  t := app.need_inv(case when v_id is null then 'add' else 'edit' end);
  if c = '' or nm = '' then raise exception 'رمز واسم الصنف مطلوبان'; end if;
  ia := coalesce(app.acct_id(t, nullif(p->>'inv_account','')), (select id from acc.accounts where tenant_id = t and subtype = 'inventory' and active and not is_group order by code limit 1));
  ca := coalesce(app.acct_id(t, nullif(p->>'cogs_account','')), (select id from acc.accounts where tenant_id = t and subtype = 'cogs' and active and not is_group order by code limit 1));
  if ia is null then raise exception 'حدّد حساب المخزون (أو أنشئ حسابًا من نوع «مخزون» في الدليل)'; end if;
  if ca is null then raise exception 'حدّد حساب تكلفة المبيعات (أو أنشئ حسابًا من نوع «تكلفة مبيعات»)'; end if;
  if not exists (select 1 from acc.accounts where tenant_id = t and id = ia and type = 'asset') then raise exception 'حساب المخزون يجب أن يكون من الأصول'; end if;
  if not exists (select 1 from acc.accounts where tenant_id = t and id = ca and type = 'expense') then raise exception 'حساب تكلفة المبيعات يجب أن يكون من المصروفات'; end if;
  if v_id is null then v_id := gen_random_uuid();
    insert into acc.items (tenant_id, id, code, name, name_en, unit, inv_account_id, cogs_account_id, sale_price, reorder_qty) values (t, v_id, c, nm, coalesce(p->>'name_en',''), coalesce(nullif(p->>'unit',''), 'قطعة'), ia, ca, coalesce(nullif(p->>'sale_price','')::numeric, 0), coalesce(nullif(p->>'reorder_qty','')::numeric, 0));
  else
    update acc.items set code = c, name = nm, name_en = coalesce(p->>'name_en', name_en), unit = coalesce(nullif(p->>'unit',''), unit), sale_price = coalesce(nullif(p->>'sale_price','')::numeric, sale_price), reorder_qty = coalesce(nullif(p->>'reorder_qty','')::numeric, reorder_qty),
      active = coalesce((p->>'active')::boolean, active) where tenant_id = t and id = v_id;
    if exists (select 1 from acc.stock_moves where tenant_id = t and item_id = v_id) then
      if (p ? 'inv_account' or p ? 'cogs_account') and (ia <> (select inv_account_id from acc.items where tenant_id = t and id = v_id) or ca <> (select cogs_account_id from acc.items where tenant_id = t and id = v_id)) then raise exception 'لا يمكن تغيير حسابات صنف عليه حركة'; end if;
    else update acc.items set inv_account_id = ia, cogs_account_id = ca where tenant_id = t and id = v_id; end if;
  end if;
  perform app.audit('save','item', v_id::text, c || ' ' || nm);
  return jsonb_build_object('id', v_id);
exception when unique_violation then raise exception 'رمز الصنف مستخدم من قبل';
end $$;

create or replace function public.item_delete(p jsonb) returns jsonb language plpgsql security definer set search_path = public, app, acc as $$
declare t uuid := app.need_inv('delete'); v_id uuid := (p->>'id')::uuid;
begin
  if exists (select 1 from acc.stock_moves where tenant_id = t and item_id = v_id) or exists (select 1 from acc.invoice_lines where tenant_id = t and item_id = v_id) then raise exception 'عليه حركة أو فواتير — أوقفه بدل حذفه'; end if;
  delete from acc.items where tenant_id = t and id = v_id; perform app.audit('delete','item', v_id::text, ''); return jsonb_build_object('ok', true);
end $$;

-- تقرير الأرصدة: كمية ومتوسط تكلفة وقيمة لكل صنف/كيان، مع مطابقة حساب المخزون بالأستاذ
create or replace function public.stock_report(p jsonb default '{}') returns jsonb language plpgsql stable security definer set search_path = public, app, acc as $$
declare t uuid := app.need_inv('view'); ents uuid[] := app.pick_ents(p);
begin
  return jsonb_build_object(
    'rows', coalesce((select jsonb_agg(jsonb_build_object('item_id', i.id, 'code', i.code, 'name', i.name, 'unit', i.unit, 'entity_id', b.entity_id, 'entity', e.name, 'qty', b.qty, 'avg_cost', round(b.avg_cost, 4), 'value', round(b.qty * b.avg_cost, 2),
        'low', i.reorder_qty > 0 and b.qty <= i.reorder_qty) order by i.code, e.code)
      from acc.stock_bal b join acc.items i on i.tenant_id = b.tenant_id and i.id = b.item_id join acc.entities e on e.tenant_id = b.tenant_id and e.id = b.entity_id
      where b.tenant_id = t and b.entity_id = any(ents) and (b.qty <> 0 or b.avg_cost <> 0)), '[]'::jsonb),
    'total_value', coalesce((select round(sum(b.qty * b.avg_cost), 2) from acc.stock_bal b where b.tenant_id = t and b.entity_id = any(ents)), 0),
    'ledger_value', coalesce((select sum(l.debit - l.credit) from acc.journal_lines l where l.tenant_id = t and l.posted and l.entity_id = any(ents) and l.account_id in (select inv_account_id from acc.items where tenant_id = t)), 0));
end $$;

create or replace function public.stock_moves_list(p jsonb default '{}') returns jsonb language plpgsql stable security definer set search_path = public, app, acc as $$
declare t uuid := app.need_inv('view'); ents uuid[] := app.pick_ents(p);
begin
  return coalesce((select jsonb_agg(x order by (x->>'date') desc, (x->>'at') desc) from (
    select jsonb_build_object('id', m.id, 'date', m.date, 'at', m.created_at, 'item', i.code || ' - ' || i.name, 'dir', m.dir, 'qty', m.qty, 'unit_cost', round(m.unit_cost, 4), 'value', round(m.qty * m.unit_cost, 2), 'doc_id', m.doc_id, 'reversed', m.reversed, 'note', m.note) x
    from acc.stock_moves m join acc.items i on i.tenant_id = m.tenant_id and i.id = m.item_id
    where m.tenant_id = t and m.entity_id = any(ents) and (nullif(p->>'item','') is null or m.item_id = (p->>'item')::uuid) order by m.date desc, m.created_at desc limit 500) q), '[]'::jsonb);
end $$;

-- حركة مخزون واحدة (داخل/خارج) بمتوسط مرجّح. يُرجع تكلفة الوحدة المستخدمة
create or replace function app.stock_move(t uuid, e uuid, it uuid, d date, dir text, q numeric, ucost numeric, doc uuid, note text) returns numeric language plpgsql security definer set search_path = public, acc as $$
declare b acc.stock_bal; c numeric; nm text;
begin
  insert into acc.stock_bal (tenant_id, entity_id, item_id) values (t, e, it) on conflict do nothing;
  select * into b from acc.stock_bal where tenant_id = t and entity_id = e and item_id = it for update;
  if dir = 'out' then
    if b.qty < q then select name into nm from acc.items where tenant_id = t and id = it; raise exception 'المخزون لا يكفي للصنف «%» (المتاح % والمطلوب %)', nm, b.qty, q; end if;
    c := coalesce(ucost, b.avg_cost);
    -- عند الصرف بتكلفة محددة (عكس توريد) يُعاد حساب المتوسط حتى تتطابق القيمة مع الأستاذ
    update acc.stock_bal set qty = b.qty - q, avg_cost = case when ucost is not null and b.qty > q then greatest((b.qty * b.avg_cost - q * ucost) / (b.qty - q), 0) else b.avg_cost end where tenant_id = t and entity_id = e and item_id = it;
  else
    c := coalesce(ucost, b.avg_cost);
    update acc.stock_bal set avg_cost = case when b.qty + q <= 0 then c else (greatest(b.qty, 0) * b.avg_cost + q * c) / (greatest(b.qty, 0) + q) end, qty = b.qty + q where tenant_id = t and entity_id = e and item_id = it;
  end if;
  insert into acc.stock_moves (tenant_id, entity_id, item_id, date, dir, qty, unit_cost, doc_id, note) values (t, e, it, d, dir, q, c, doc, coalesce(note, ''));
  return c;
end $$;

-- تأثير الفاتورة على المخزون (يُستدعى بعد ترحيل قيد الفاتورة)
create or replace function app.inv_stock_apply(inv acc.invoices) returns void language plpgsql security definer set search_path = public, app, acc as $$
declare t uuid := inv.tenant_id; r record; c numeric; jid uuid; lines jsonb; j acc.journals; tot numeric; sale boolean := inv.kind in ('sales','sales_credit');
begin
  if not exists (select 1 from acc.invoice_lines where tenant_id = t and invoice_id = inv.id and item_id is not null) then return; end if;
  for r in select l.item_id, sum(l.qty) qty, sum(l.net) net, i.inv_account_id, i.cogs_account_id from acc.invoice_lines l join acc.items i on i.tenant_id = l.tenant_id and i.id = l.item_id
      where l.tenant_id = t and l.invoice_id = inv.id and l.item_id is not null group by l.item_id, i.inv_account_id, i.cogs_account_id order by 1 loop
    if inv.kind = 'purchase' then perform app.stock_move(t, inv.entity_id, r.item_id, inv.date, 'in', r.qty, round(r.net * inv.rate / r.qty, 6), inv.id, 'فاتورة مشتريات ' || coalesce(inv.supplier_ref, ''));
    elsif inv.kind = 'purchase_debit' then perform app.stock_move(t, inv.entity_id, r.item_id, inv.date, 'out', r.qty, null, inv.id, 'إشعار مدين');
    elsif inv.kind = 'sales' then
      c := app.stock_move(t, inv.entity_id, r.item_id, inv.date, 'out', r.qty, null, inv.id, 'فاتورة مبيعات');
      tot := round(r.qty * c, 2);
      if tot > 0 then
        jid := gen_random_uuid();
        insert into acc.journals (tenant_id, id, entity_id, type, date, description, status, source, source_id, created_by) values (t, jid, inv.entity_id, 'GJ', inv.date, 'تكلفة بضاعة مباعة — ' || coalesce(inv.number, ''), 'draft', 'inventory', inv.id, auth.uid());
        perform app.put_lines(t, jid, inv.entity_id, inv.date, jsonb_build_array(jsonb_build_object('account', r.cogs_account_id, 'debit', tot, 'description', 'تكلفة مبيعات'), jsonb_build_object('account', r.inv_account_id, 'credit', tot, 'description', 'صرف من المخزون')));
        j := app.post_journal(jid);
        update acc.stock_moves set journal_id = j.id where tenant_id = t and doc_id = inv.id and item_id = r.item_id and journal_id is null and dir = 'out';
      end if;
    elsif inv.kind = 'sales_credit' then
      c := (select avg_cost from acc.stock_bal where tenant_id = t and entity_id = inv.entity_id and item_id = r.item_id);
      perform app.stock_move(t, inv.entity_id, r.item_id, inv.date, 'in', r.qty, c, inv.id, 'مرتجع مبيعات');
      tot := round(r.qty * coalesce(c, 0), 2);
      if tot > 0 then
        jid := gen_random_uuid();
        insert into acc.journals (tenant_id, id, entity_id, type, date, description, status, source, source_id, created_by) values (t, jid, inv.entity_id, 'GJ', inv.date, 'عكس تكلفة مرتجع — ' || coalesce(inv.number, ''), 'draft', 'inventory', inv.id, auth.uid());
        perform app.put_lines(t, jid, inv.entity_id, inv.date, jsonb_build_array(jsonb_build_object('account', r.inv_account_id, 'debit', tot, 'description', 'عودة للمخزون'), jsonb_build_object('account', r.cogs_account_id, 'credit', tot, 'description', 'عكس تكلفة مبيعات')));
        j := app.post_journal(jid);
        update acc.stock_moves set journal_id = j.id where tenant_id = t and doc_id = inv.id and item_id = r.item_id and journal_id is null and dir = 'in';
      end if;
    end if;
  end loop;
end $$;

-- عكس أثر الفاتورة عند إلغائها
create or replace function app.inv_stock_reverse(inv acc.invoices, d date, reason text) returns void language plpgsql security definer set search_path = public, app, acc as $$
declare t uuid := inv.tenant_id; m record; rj acc.journals;
begin
  for m in select * from acc.stock_moves where tenant_id = t and doc_id = inv.id and not reversed order by created_at desc loop
    if m.dir = 'in' then perform app.stock_move(t, m.entity_id, m.item_id, d, 'out', m.qty, m.unit_cost, inv.id, 'عكس: ' || reason);
    else perform app.stock_move(t, m.entity_id, m.item_id, d, 'in', m.qty, m.unit_cost, inv.id, 'عكس: ' || reason); end if;
    update acc.stock_moves set reversed = true where tenant_id = t and id = m.id;
    if m.journal_id is not null then rj := app.reverse_journal(m.journal_id, d, 'عكس تكلفة بضاعة — ' || reason); end if;
  end loop;
  update acc.stock_moves set reversed = true where tenant_id = t and doc_id = inv.id;
end $$;

-- دوال الفواتير المعدّلة (ربط الأصناف)
create or replace function public.inv_save(p jsonb) returns jsonb language plpgsql security definer set search_path = public, app, acc as $$
declare t uuid; v_id uuid := nullif(p->>'id','')::uuid; e uuid := nullif(p->>'entity','')::uuid; k text := p->>'kind'; inv acc.invoices; pid uuid := nullif(p->>'party','')::uuid; pr acc.parties; d date := nullif(p->>'date','')::date;
  l jsonb; i int := 0; aid uuid; tc acc.tax_codes; q numeric; up numeric; dc numeric; net numeric; tx numeric; sub numeric := 0; disc numeric := 0; taxt numeric := 0; fx numeric := coalesce(nullif(p->>'rate','')::numeric, 1); cur text; tcode text; defk text; itm uuid;
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
    itm := nullif(l->>'item','')::uuid; if itm is not null then perform 1 from acc.items where tenant_id = t and id = itm and active; if not found then raise exception 'السطر %: الصنف غير موجود أو موقوف', i; end if; end if;
    aid := coalesce(app.acct_id(t, nullif(l->>'account','')), app.acct_id(t, nullif(l->>'account_code','')), case when itm is not null and k in ('purchase','purchase_debit') then (select inv_account_id from acc.items where tenant_id = t and id = itm) end, app.acct_id(t, (select code from acc.accounts where tenant_id = t and system_key = defk)));
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
    insert into acc.invoice_lines (tenant_id, invoice_id, line_no, description, qty, unit_price, discount, tax_code, account_id, cost_center_id, project_id, net, tax, item_id)
    values (t, v_id, i, coalesce(l->>'description',''), q, up, dc, tcode, aid, nullif(l->>'cost_center','')::uuid, nullif(l->>'project','')::uuid, net, tx, itm);
    sub := sub + net; taxt := taxt + tx; disc := disc + dc;
  end loop;
  if i = 0 then raise exception 'أضف بندًا واحدًا على الأقل'; end if;
  update acc.invoices set party_id = pid, date = d, due_date = coalesce(nullif(p->>'due_date','')::date, d + pr.terms_days), supplier_ref = coalesce(trim(p->>'supplier_ref'), ''), currency = coalesce(nullif(p->>'currency',''), cur), rate = case when coalesce(nullif(p->>'currency',''), cur) = cur then 1 else fx end,
    subtotal = sub, discount_total = disc, tax_total = taxt, total = sub + taxt, notes = coalesce(p->>'notes',''), terms = coalesce(p->>'terms',''), related_id = nullif(p->>'related_id','')::uuid, updated_at = now() where tenant_id = t and acc.invoices.id = v_id;
  perform app.audit('save','invoice',v_id::text,'مسودة فاتورة (' || k || ') ' || pr.name || ' — ' || (sub + taxt));
  return jsonb_build_object('id', v_id, 'total', sub + taxt);
end $$;

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
  perform app.inv_stock_apply(inv);
  -- أساس الإقرار الضريبي
  sg := case when credit then -1 else 1 end; dirn := case when sale then 'out' else 'in' end;
  for r in select l.tax_code, c.kind, sum(l.net) base, sum(l.tax) tx from acc.invoice_lines l join acc.tax_codes c on c.tenant_id = l.tenant_id and c.code = l.tax_code where l.tenant_id = t and l.invoice_id = inv.id and l.tax_code is not null and c.kind <> 'oos' group by 1, 2 loop
    insert into acc.tax_lines (tenant_id, entity_id, journal_id, date, tax_code, direction, base, tax, party_id, doc_type, doc_id)
    values (t, inv.entity_id, j.id, inv.date, r.tax_code, dirn, sg * round(r.base * fx, 2), sg * round(r.tx * fx, 2), inv.party_id, 'invoice', inv.id);
  end loop;
  update acc.invoices set total_base = tot, journal_id = j.id, number = j.number, status = 'issued', issued_by = auth.uid(), issued_at = now(), updated_at = now() where tenant_id = t and id = inv.id;
  return j;
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
  perform app.inv_stock_reverse(inv, d, trim(p->>'reason'));
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
        'account_name', a.code || ' - ' || a.name, 'cost_center_id', l.cost_center_id, 'project_id', l.project_id, 'net', l.net, 'tax', l.tax, 'item_id', l.item_id) order by l.line_no) from acc.invoice_lines l join acc.accounts a on a.tenant_id = l.tenant_id and a.id = l.account_id where l.tenant_id = t and l.invoice_id = inv.id), '[]'::jsonb),
    'allocations', coalesce((select jsonb_agg(jsonb_build_object('id', x.id, 'kind', x.source_kind, 'source_id', x.source_id, 'amount', x.amount, 'date', x.date,
        'number', case when x.source_kind = 'payment' then (select number from acc.payments where tenant_id = t and id = x.source_id) else (select number from acc.invoices where tenant_id = t and id = x.source_id) end) order by x.date) from acc.allocations x where x.tenant_id = t and x.invoice_id = inv.id and x.active), '[]'::jsonb),
    'attachments', coalesce((select jsonb_agg(jsonb_build_object('id', x.id, 'filename', x.filename, 'mime', x.mime, 'size', x.size, 'path', x.path, 'uploaded_at', x.uploaded_at)) from acc.attachments x where x.tenant_id = t and x.owner_type = 'invoice' and x.owner_id = inv.id), '[]'::jsonb),
    'history', coalesce((select jsonb_agg(jsonb_build_object('at', h.at, 'by', h.username, 'action', h.action, 'details', h.details) order by h.id) from acc.audit h where h.tenant_id = t and h.entity = 'invoice' and h.ref = inv.id::text), '[]'::jsonb));
end $$;


-- صلاحيات التنفيذ
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
      and (p.proname in ('login_email','register_company','ingest_journal','signup_status','demo_link_open') or p.pronargs = 0 or p.proargtypes::text = (select oid::text from pg_type where typname = 'jsonb')) loop
    if f.proname in ('register_company','ingest_journal','login_email','signup_status','demo_link_open') then execute format('grant execute on function %s to anon, authenticated', f.sig);
    else execute format('grant execute on function %s to authenticated', f.sig); end if;
  end loop;
end $$;
-- إغلاق وصول غير المسجَّل: لا يبقى متاحًا للزائر إلا دوال الدخول/التسجيل/الديمو/الاستقبال
do $$ declare f record; begin
  for f in select p.oid::regprocedure as sig from pg_proc p join pg_namespace n on n.oid = p.pronamespace where n.nspname = 'public' and p.prokind = 'f' and p.proowner = (select oid from pg_roles where rolname = current_user)
      and (p.pronargs = 0 or p.proargtypes::text = (select oid::text from pg_type where typname = 'jsonb')) and p.proname not in ('login_email','register_company','ingest_journal','signup_status','demo_link_open') loop
    execute format('revoke execute on function %s from public, anon', f.sig);
  end loop;
end $$;
alter default privileges in schema public revoke execute on functions from public, anon;

notify pgrst, 'reload schema';
