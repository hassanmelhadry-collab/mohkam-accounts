-- تحديث 1.5 (مخزون): آمن — يتوقف بخطأ واضح إن كان المخزون مثبّتًا مسبقًا (ملف 01ج). شغّله مرة واحدة في Supabase SQL Editor.
do $$ begin
  if to_regclass('acc.items') is not null or to_regclass('acc.stock_moves') is not null then
    raise exception 'المخزون مثبّت مسبقًا في هذه القاعدة (ملف 01ج) — لا تشغّل هذا الملف';
  end if;
end $$;
-- مُحكَم للحسابات — المخزون وتكلفة البضاعة بالمتوسط المرجّح المتحرك
-- أصناف، مستودعات، حركات، ربط فاتورة المشتريات بالاستلام وفاتورة المبيعات بقيد تكلفة البضاعة (COGS) تلقائيًا، وتقارير الأرصدة والحركة.
-- لا يعدّل دوال الفواتير: الربط عبر جدول جانبي acc.invoice_stock + مشغّل على تغيّر حالة الفاتورة (إصدار/إلغاء).

create table if not exists acc.warehouses (
  tenant_id uuid not null references acc.tenants(id) on delete cascade, id uuid not null default gen_random_uuid(), entity_id uuid not null, code text not null, name text not null,
  active boolean not null default true, created_at timestamptz not null default now(),
  primary key (tenant_id, id), unique (tenant_id, code), foreign key (tenant_id, entity_id) references acc.entities (tenant_id, id)
);
create table if not exists acc.items (
  tenant_id uuid not null references acc.tenants(id) on delete cascade, id uuid not null default gen_random_uuid(), code text not null, name text not null, name_en text not null default '',
  unit text not null default 'وحدة', sale_price numeric(18,4) not null default 0, reorder_level numeric(18,4) not null default 0,
  inventory_account_id uuid, cogs_account_id uuid, active boolean not null default true, note text not null default '', created_at timestamptz not null default now(),
  primary key (tenant_id, id), unique (tenant_id, code),
  foreign key (tenant_id, inventory_account_id) references acc.accounts (tenant_id, id), foreign key (tenant_id, cogs_account_id) references acc.accounts (tenant_id, id)
);
-- الرصيد الجاري لكل صنف/مستودع (الكمية والقيمة) — متوسط التكلفة = القيمة ÷ الكمية
create table if not exists acc.stock_bal (
  tenant_id uuid not null references acc.tenants(id) on delete cascade, item_id uuid not null, warehouse_id uuid not null, qty numeric(18,4) not null default 0, value numeric(18,2) not null default 0,
  primary key (tenant_id, item_id, warehouse_id), foreign key (tenant_id, item_id) references acc.items (tenant_id, id), foreign key (tenant_id, warehouse_id) references acc.warehouses (tenant_id, id)
);
-- الحركات: الكمية والقيمة بإشارة (+ وارد / − صادر)
create table if not exists acc.stock_moves (
  tenant_id uuid not null references acc.tenants(id) on delete cascade, id uuid not null default gen_random_uuid(), entity_id uuid not null, item_id uuid not null, warehouse_id uuid not null, date date not null,
  reason text not null check (reason in ('opening','purchase','sale','sale_return','purchase_return','adjust','transfer_in','transfer_out','reversal')),
  qty numeric(18,4) not null check (qty <> 0), unit_cost numeric(18,6) not null default 0, value numeric(18,2) not null default 0,
  bal_qty numeric(18,4) not null default 0, bal_value numeric(18,2) not null default 0,
  doc_type text, doc_id uuid, journal_id uuid, reversal_of uuid, memo text not null default '', created_by uuid, created_at timestamptz not null default now(), seq bigint generated always as identity,
  primary key (tenant_id, id), foreign key (tenant_id, item_id) references acc.items (tenant_id, id), foreign key (tenant_id, warehouse_id) references acc.warehouses (tenant_id, id)
);
create index if not exists stock_moves_item on acc.stock_moves (tenant_id, item_id, warehouse_id, date, seq);
create index if not exists stock_moves_doc on acc.stock_moves (tenant_id, doc_type, doc_id);
-- ربط سطر الفاتورة بالصنف والمستودع (رقم السطر يُعاد ربطه بعد كل حفظ للمسودة)
create table if not exists acc.invoice_stock (
  tenant_id uuid not null references acc.tenants(id) on delete cascade, invoice_id uuid not null, line_no int not null, item_id uuid not null, warehouse_id uuid not null,
  primary key (tenant_id, invoice_id, line_no), foreign key (tenant_id, invoice_id) references acc.invoices (tenant_id, id) on delete cascade,
  foreign key (tenant_id, item_id) references acc.items (tenant_id, id), foreign key (tenant_id, warehouse_id) references acc.warehouses (tenant_id, id)
);
do $$ declare t text; begin foreach t in array array['warehouses','items','stock_bal','stock_moves','invoice_stock'] loop execute format('alter table acc.%I enable row level security', t); end loop; end $$;

-- صلاحيات وحدة المخزون للأدوار القائمة (الأدوار الجديدة تُزرع من app.seed_roles)
update acc.roles set perms = perms || '{"inventory":["view","add","edit","delete","post","export"]}'::jsonb where id in ('cfo','chief') and not (perms ? 'inventory');
update acc.roles set perms = perms || '{"inventory":["view","add","edit","export"]}'::jsonb where id in ('acct','ap') and not (perms ? 'inventory');
update acc.roles set perms = perms || '{"inventory":["view"]}'::jsonb where id in ('ar','gm','auditor') and not (perms ? 'inventory');

-- ===== النواة: تطبيق حركة على الرصيد بالمتوسط المرجّح =====
-- qty بإشارة. للوارد: v = القيمة الكلية (إن غابت تُؤخذ unit_cost × qty). للصادر: تُحسب القيمة بمتوسط الرصيد الحالي ما لم يُمرَّر v.
create or replace function app.stock_apply(t uuid, e uuid, itm uuid, wh uuid, d date, q numeric, v numeric, reason text, doc_type text, doc uuid, memo text default '') returns acc.stock_moves language plpgsql security definer set search_path = public, app, acc as $$
declare b acc.stock_bal; val numeric; m acc.stock_moves; nm text;
begin
  if q = 0 then raise exception 'الكمية لا يجوز أن تكون صفرًا'; end if;
  insert into acc.stock_bal (tenant_id, item_id, warehouse_id) values (t, itm, wh) on conflict do nothing;
  select * into b from acc.stock_bal where tenant_id = t and item_id = itm and warehouse_id = wh for update;
  if q > 0 then
    val := round(coalesce(v, 0), 2);
  else
    if b.qty + q < 0 then
      select name into nm from acc.items where tenant_id = t and id = itm;
      raise exception 'الرصيد غير كافٍ للصنف % (المتاح %، المطلوب %)', nm, b.qty, -q;
    end if;
    if v is not null then val := -abs(round(v, 2));
    elsif b.qty + q = 0 then val := -b.value;                       -- تصفير الرصيد يستنفد القيمة كاملة (بلا كسور متبقية)
    else val := -round(-q * b.value / b.qty, 2); end if;
  end if;
  update acc.stock_bal set qty = b.qty + q, value = b.value + val where tenant_id = t and item_id = itm and warehouse_id = wh;
  insert into acc.stock_moves (tenant_id, entity_id, item_id, warehouse_id, date, reason, qty, unit_cost, value, bal_qty, bal_value, doc_type, doc_id, memo, created_by)
  values (t, e, itm, wh, d, reason, q, round(abs(val) / abs(q), 6), val, b.qty + q, b.value + val, doc_type, doc, memo, auth.uid()) returning * into m;
  return m;
end $$;

-- ترحيل قيد تلقائي للمخزون (يعتمد على دوال الدفتر الداخلية)
create or replace function app.stock_journal(t uuid, e uuid, d date, descr text, src_id uuid, lines jsonb) returns acc.journals language plpgsql security definer set search_path = public, app, acc as $$
declare jid uuid := gen_random_uuid();
begin
  insert into acc.journals (tenant_id, id, entity_id, type, date, description, reference, status, source, source_id, created_by) values (t, jid, e, 'GJ', d, descr, '', 'draft', 'inventory', src_id, auth.uid());
  perform app.put_lines(t, jid, e, d, lines);
  return app.post_journal(jid);
end $$;

create or replace function app.item_inv_acct(t uuid, i acc.items) returns uuid language sql stable security definer set search_path = public, acc as $$ select coalesce(i.inventory_account_id, app.sysacct(t, 'INVENTORY')) $$;
create or replace function app.item_cogs_acct(t uuid, i acc.items) returns uuid language sql stable security definer set search_path = public, acc as $$ select coalesce(i.cogs_account_id, app.sysacct(t, 'COGS')) $$;

-- ===== الأصناف والمستودعات =====
create or replace function public.wh_save(p jsonb) returns jsonb language plpgsql security definer set search_path = public, app, acc as $$
declare t uuid; v_id uuid := nullif(p->>'id','')::uuid; e uuid := nullif(p->>'entity','')::uuid;
begin
  t := app.need('inventory', case when v_id is null then 'add' else 'edit' end);
  if coalesce(trim(p->>'code'),'') = '' or coalesce(trim(p->>'name'),'') = '' then raise exception 'رمز واسم المستودع مطلوبان'; end if;
  if v_id is null then perform app.entity_ok(t, e); v_id := gen_random_uuid();
    insert into acc.warehouses (tenant_id, id, entity_id, code, name) values (t, v_id, e, trim(p->>'code'), trim(p->>'name'));
  else
    update acc.warehouses set code = trim(p->>'code'), name = trim(p->>'name'), active = coalesce((p->>'active')::boolean, active) where tenant_id = t and id = v_id; if not found then raise exception 'المستودع غير موجود'; end if;
  end if;
  perform app.audit('upsert','warehouse',v_id::text,(p->>'code') || ' ' || (p->>'name')); return jsonb_build_object('id', v_id);
end $$;
create or replace function public.wh_list(p jsonb default '{}') returns jsonb language plpgsql stable security definer set search_path = public, app, acc as $$
declare t uuid := app.need('inventory','view'); ents uuid[] := app.ents();
begin return coalesce((select jsonb_agg(jsonb_build_object('id', w.id, 'entity_id', w.entity_id, 'code', w.code, 'name', w.name, 'active', w.active) order by w.code) from acc.warehouses w where w.tenant_id = t and w.entity_id = any(ents)), '[]'::jsonb); end $$;

create or replace function public.item_save(p jsonb) returns jsonb language plpgsql security definer set search_path = public, app, acc as $$
declare t uuid; v_id uuid := nullif(p->>'id','')::uuid; ia uuid; ca uuid;
begin
  t := app.need('inventory', case when v_id is null then 'add' else 'edit' end);
  if coalesce(trim(p->>'code'),'') = '' or coalesce(trim(p->>'name'),'') = '' then raise exception 'رمز واسم الصنف مطلوبان'; end if;
  if coalesce(nullif(p->>'sale_price','')::numeric, 0) < 0 or coalesce(nullif(p->>'reorder_level','')::numeric, 0) < 0 then raise exception 'السعر وحد إعادة الطلب لا يكونان سالبين'; end if;
  ia := app.acct_id(t, nullif(p->>'inventory_account','')); ca := app.acct_id(t, nullif(p->>'cogs_account',''));
  if nullif(p->>'inventory_account','') is not null and ia is null then raise exception 'حساب المخزون غير موجود'; end if;
  if nullif(p->>'cogs_account','') is not null and ca is null then raise exception 'حساب تكلفة البضاعة غير موجود'; end if;
  if v_id is null then v_id := gen_random_uuid();
    insert into acc.items (tenant_id, id, code, name, name_en, unit, sale_price, reorder_level, inventory_account_id, cogs_account_id, note)
    values (t, v_id, trim(p->>'code'), trim(p->>'name'), coalesce(p->>'name_en',''), coalesce(nullif(p->>'unit',''),'وحدة'), coalesce(nullif(p->>'sale_price','')::numeric,0), coalesce(nullif(p->>'reorder_level','')::numeric,0), ia, ca, coalesce(p->>'note',''));
  else
    update acc.items set code = trim(p->>'code'), name = trim(p->>'name'), name_en = coalesce(p->>'name_en',''), unit = coalesce(nullif(p->>'unit',''),'وحدة'), sale_price = coalesce(nullif(p->>'sale_price','')::numeric,0),
      reorder_level = coalesce(nullif(p->>'reorder_level','')::numeric,0), active = coalesce((p->>'active')::boolean, active), note = coalesce(p->>'note','')
      , inventory_account_id = case when exists (select 1 from acc.stock_moves m where m.tenant_id = t and m.item_id = v_id) then inventory_account_id else ia end
      , cogs_account_id = ca
    where tenant_id = t and id = v_id; if not found then raise exception 'الصنف غير موجود'; end if;
  end if;
  perform app.audit('upsert','item',v_id::text,(p->>'code') || ' ' || (p->>'name')); return jsonb_build_object('id', v_id);
end $$;
create or replace function public.item_delete(p jsonb) returns jsonb language plpgsql security definer set search_path = public, app, acc as $$
declare t uuid := app.need('inventory','delete'); v_id uuid := (p->>'id')::uuid;
begin
  if exists (select 1 from acc.stock_moves where tenant_id = t and item_id = v_id) or exists (select 1 from acc.invoice_stock where tenant_id = t and item_id = v_id) then raise exception 'للصنف حركات — أوقفه بدل الحذف'; end if;
  delete from acc.stock_bal where tenant_id = t and item_id = v_id; delete from acc.items where tenant_id = t and id = v_id; perform app.audit('delete','item',v_id::text,'حذف صنف'); return jsonb_build_object('ok', true);
end $$;
create or replace function public.item_list(p jsonb default '{}') returns jsonb language plpgsql stable security definer set search_path = public, app, acc as $$
declare t uuid := app.need('inventory','view'); q text := nullif(trim(coalesce(p->>'q','')), '');
begin
  return coalesce((select jsonb_agg(jsonb_build_object('id', i.id, 'code', i.code, 'name', i.name, 'name_en', i.name_en, 'unit', i.unit, 'sale_price', i.sale_price, 'reorder_level', i.reorder_level, 'active', i.active, 'note', i.note,
      'inventory_account_id', i.inventory_account_id, 'cogs_account_id', i.cogs_account_id, 'qty', coalesce(b.qty,0), 'value', coalesce(b.value,0), 'avg_cost', case when coalesce(b.qty,0) > 0 then round(b.value / b.qty, 4) else 0 end,
      'low', coalesce(b.qty,0) <= i.reorder_level and i.reorder_level > 0) order by i.code)
    from acc.items i left join (select sb.item_id, sum(sb.qty) qty, sum(sb.value) value from acc.stock_bal sb join acc.warehouses w on w.tenant_id = sb.tenant_id and w.id = sb.warehouse_id where sb.tenant_id = t and w.entity_id = any(app.ents()) group by 1) b on b.item_id = i.id
    where i.tenant_id = t and (q is null or i.name ilike '%' || q || '%' or i.code ilike '%' || q || '%') and (nullif(p->>'active','') is null or i.active = (p->>'active')::boolean)), '[]'::jsonb);
end $$;

-- ===== حركات يدوية: رصيد افتتاحي / تسوية جرد (بقيد تلقائي مقابل حساب counter) =====
create or replace function public.stock_adjust(p jsonb) returns jsonb language plpgsql security definer set search_path = public, app, acc as $$
declare t uuid := app.need('inventory','post'); w acc.warehouses; i acc.items; d date := nullif(p->>'date','')::date; q numeric := (p->>'qty')::numeric; uc numeric := nullif(p->>'unit_cost','')::numeric; ctr uuid := app.acct_id(app.tenant(), nullif(p->>'counter',''));
  rsn text := coalesce(nullif(p->>'reason',''), 'adjust'); m acc.stock_moves; j acc.journals; ia uuid; amt numeric;
begin
  if rsn not in ('opening','adjust') then raise exception 'نوع الحركة غير صالح'; end if;
  if d is null or q is null or q = 0 then raise exception 'التاريخ والكمية مطلوبان'; end if;
  select * into w from acc.warehouses where tenant_id = t and id = (p->>'warehouse')::uuid and active; if w.id is null then raise exception 'المستودع غير موجود أو موقوف'; end if; perform app.entity_ok(t, w.entity_id);
  select * into i from acc.items where tenant_id = t and id = (p->>'item')::uuid and active; if i.id is null then raise exception 'الصنف غير موجود أو موقوف'; end if;
  if ctr is null then raise exception 'حدّد الحساب المقابل (رأس المال/الأرصدة الافتتاحية أو مصروف/إيراد الجرد)'; end if;
  if q > 0 and (uc is null or uc < 0) then raise exception 'تكلفة الوحدة مطلوبة للوارد'; end if;
  if rsn = 'opening' and q < 0 then raise exception 'الرصيد الافتتاحي كمية موجبة'; end if;
  ia := app.item_inv_acct(t, i);
  m := app.stock_apply(t, w.entity_id, i.id, w.id, d, q, case when q > 0 then q * uc end, rsn, 'adjust', null, coalesce(p->>'memo',''));
  amt := abs(m.value);
  if amt > 0 then
    j := app.stock_journal(t, w.entity_id, d, case rsn when 'opening' then 'رصيد افتتاحي مخزون — ' else 'تسوية جرد — ' end || i.name, m.id,
      case when q > 0 then jsonb_build_array(jsonb_build_object('account', ia, 'debit', amt), jsonb_build_object('account', ctr, 'credit', amt))
        else jsonb_build_array(jsonb_build_object('account', ctr, 'debit', amt), jsonb_build_object('account', ia, 'credit', amt)) end);
    update acc.stock_moves set journal_id = j.id where tenant_id = t and id = m.id;
  end if;
  perform app.audit('adjust','stock',m.id::text, rsn || ' ' || i.code || ' × ' || q || ' = ' || m.value);
  return jsonb_build_object('id', m.id, 'value', m.value, 'journal', j.number);
end $$;

-- تحويل بين مستودعين لنفس الكيان بمتوسط التكلفة (بلا أثر على الدفتر)
create or replace function public.stock_transfer(p jsonb) returns jsonb language plpgsql security definer set search_path = public, app, acc as $$
declare t uuid := app.need('inventory','post'); a acc.warehouses; b acc.warehouses; d date := nullif(p->>'date','')::date; q numeric := (p->>'qty')::numeric; mo acc.stock_moves; tid uuid := gen_random_uuid();
begin
  if d is null or q is null or q <= 0 then raise exception 'التاريخ والكمية الموجبة مطلوبان'; end if;
  select * into a from acc.warehouses where tenant_id = t and id = (p->>'from')::uuid and active; select * into b from acc.warehouses where tenant_id = t and id = (p->>'to')::uuid and active;
  if a.id is null or b.id is null or a.id = b.id then raise exception 'اختر مستودعين مختلفين'; end if;
  if a.entity_id <> b.entity_id then raise exception 'التحويل بين كيانين مختلفين غير مدعوم — استخدم فاتورة بينية'; end if; perform app.entity_ok(t, a.entity_id);
  mo := app.stock_apply(t, a.entity_id, (p->>'item')::uuid, a.id, d, -q, null, 'transfer_out', 'transfer', tid, coalesce(p->>'memo',''));
  perform app.stock_apply(t, b.entity_id, (p->>'item')::uuid, b.id, d, q, -mo.value, 'transfer_in', 'transfer', tid, coalesce(p->>'memo',''));
  perform app.audit('transfer','stock',tid::text,'تحويل ' || q || ' من ' || a.code || ' إلى ' || b.code); return jsonb_build_object('value', -mo.value);
end $$;

-- ===== ربط سطور الفاتورة بالأصناف (للمسودات) =====
-- lines: [{line_no, item, warehouse}] — يستبدل الربط السابق. في فواتير المشتريات والإشعار المدين يُحوَّل حساب السطر إلى حساب مخزون الصنف.
create or replace function public.inv_stock_link(p jsonb) returns jsonb language plpgsql security definer set search_path = public, app, acc as $$
declare t uuid; inv acc.invoices; l jsonb; it acc.items; w acc.warehouses; n int := 0; ln int;
begin
  select * into inv from acc.invoices where tenant_id = app.tenant() and id = (p->>'invoice')::uuid for update; if inv.id is null then raise exception 'الفاتورة غير موجودة'; end if;
  t := app.need(app.inv_module(inv.kind), 'edit'); perform app.need('inventory','view'); perform app.entity_ok(t, inv.entity_id);
  if inv.status <> 'draft' then raise exception 'يُعدَّل ربط المخزون في المسودات فقط'; end if;
  delete from acc.invoice_stock where tenant_id = t and invoice_id = inv.id;
  for l in select * from jsonb_array_elements(coalesce(p->'lines','[]'::jsonb)) loop
    ln := (l->>'line_no')::int;
    if not exists (select 1 from acc.invoice_lines where tenant_id = t and invoice_id = inv.id and line_no = ln) then raise exception 'السطر % غير موجود', ln; end if;
    select * into it from acc.items where tenant_id = t and id = (l->>'item')::uuid and active; if it.id is null then raise exception 'السطر %: الصنف غير موجود أو موقوف', ln; end if;
    select * into w from acc.warehouses where tenant_id = t and id = (l->>'warehouse')::uuid and active and entity_id = inv.entity_id; if w.id is null then raise exception 'السطر %: المستودع غير موجود أو لا يتبع كيان الفاتورة', ln; end if;
    insert into acc.invoice_stock (tenant_id, invoice_id, line_no, item_id, warehouse_id) values (t, inv.id, ln, it.id, w.id);
    if inv.kind in ('purchase','purchase_debit') then update acc.invoice_lines set account_id = app.item_inv_acct(t, it) where tenant_id = t and invoice_id = inv.id and line_no = ln; end if;
    n := n + 1;
  end loop;
  return jsonb_build_object('linked', n);
end $$;
create or replace function public.inv_stock_get(p jsonb) returns jsonb language plpgsql stable security definer set search_path = public, app, acc as $$
declare t uuid := app.need('inventory','view');
begin return coalesce((select jsonb_agg(jsonb_build_object('line_no', s.line_no, 'item_id', s.item_id, 'item', i.code || ' - ' || i.name, 'warehouse_id', s.warehouse_id, 'warehouse', w.name) order by s.line_no)
  from acc.invoice_stock s join acc.items i on i.tenant_id = s.tenant_id and i.id = s.item_id join acc.warehouses w on w.tenant_id = s.tenant_id and w.id = s.warehouse_id where s.tenant_id = t and s.invoice_id = (p->>'invoice')::uuid), '[]'::jsonb); end $$;

-- ===== المشغّل: إصدار الفاتورة ← حركات مخزون + قيد COGS؛ إلغاؤها ← عكسها =====

-- صلاحيات الأدوار الجديدة (الشركات الجديدة)
