-- مُحكَم للحسابات — تحديث 1.6.5.0: دورة المشتريات (أمر شراء ← استلام ← فاتورة ← مطابقة ثلاثية) — يُشغَّل بعد 1.6.4.0

-- ===== sql/052_purchases.sql =====
-- مُحكَم للحسابات 1.6.5 — دورة المشتريات: أمر شراء ← استلام ← فاتورة مشتريات مسودة ← مطابقة ثلاثية (ميزة اختيارية purchase_orders)
-- أمر الشراء والاستلام مستندان غير محاسبيان (لا قيود)؛ الأثر المحاسبي والمخزني يحدث فقط عند إصدار الفاتورة عبر inv_save/inv_issue المعتمدتين.
-- المطابقة الثلاثية: المطلوب (أمر الشراء) ↔ المستلَم (الاستلامات) ↔ المفوتَر (الفواتير غير الملغاة): لا استلام فوق المطلوب، ولا فوترة فوق المستلَم.
create table if not exists acc.po (
  tenant_id uuid not null references acc.tenants(id) on delete cascade, id uuid not null default gen_random_uuid(), entity_id uuid not null, number bigint not null,
  date date not null, expected date, party_id uuid not null, lines jsonb not null, subtotal numeric(18,2) not null default 0, tax_total numeric(18,2) not null default 0, total numeric(18,2) not null default 0,
  status text not null default 'draft' check (status in ('draft','approved','closed','cancelled')), notes text not null default '', approved_by uuid, approved_at timestamptz,
  created_by uuid, created_at timestamptz not null default now(), updated_at timestamptz not null default now(),
  primary key (tenant_id, id), foreign key (tenant_id, entity_id) references acc.entities (tenant_id, id), foreign key (tenant_id, party_id) references acc.parties (tenant_id, id));
create index if not exists po_q on acc.po (tenant_id, entity_id, date desc);
create table if not exists acc.po_receipts (
  tenant_id uuid not null, id uuid not null default gen_random_uuid(), po_id uuid not null, number bigint not null, date date not null, lines jsonb not null, note text not null default '',
  voided boolean not null default false, created_by uuid, created_at timestamptz not null default now(),
  primary key (tenant_id, id), foreign key (tenant_id, po_id) references acc.po (tenant_id, id) on delete cascade);
create table if not exists acc.po_bills (
  tenant_id uuid not null, po_id uuid not null, invoice_id uuid not null, lines jsonb not null, created_at timestamptz not null default now(),
  primary key (tenant_id, po_id, invoice_id), foreign key (tenant_id, po_id) references acc.po (tenant_id, id) on delete cascade,
  foreign key (tenant_id, invoice_id) references acc.invoices (tenant_id, id) on delete cascade);
do $$ declare t text; begin foreach t in array array['po','po_receipts','po_bills'] loop execute format('alter table acc.%I enable row level security', t); end loop; end $$;

with ins as (
  insert into app.feature_cat (key, name, grp, core, since, sort) values ('purchase_orders', 'دورة المشتريات (أوامر الشراء والاستلام والمطابقة الثلاثية)', 'المشتريات', false, 1, 33)
  on conflict (key) do nothing returning key)
update acc.tenants set features_off = array_append(features_off, 'purchase_orders') where exists (select 1 from ins) and not ('purchase_orders' = any(features_off));
update app.feature_cat set name = 'دورة المشتريات (أوامر الشراء والاستلام والمطابقة الثلاثية)', grp = 'المشتريات', core = false, sort = 33 where key = 'purchase_orders';

-- كميات كل سطر: مطلوب/مستلَم/مفوتَر (الاستلامات الملغاة والفواتير الملغاة لا تُحتسب)
create or replace function app.po_qty(t uuid, po uuid) returns jsonb language sql stable security definer set search_path = public, acc as $$
  select coalesce(jsonb_agg(jsonb_build_object('i', g.i, 'ordered', g.q, 'received', coalesce(r.q, 0), 'billed', coalesce(b.q, 0)) order by g.i), '[]'::jsonb)
  from (select (x.ord - 1)::int i, (x.v->>'qty')::numeric q from acc.po p, jsonb_array_elements(p.lines) with ordinality x(v, ord) where p.tenant_id = t and p.id = po) g
  left join (select (y->>'i')::int i, sum((y->>'qty')::numeric) q from acc.po_receipts rc, jsonb_array_elements(rc.lines) y where rc.tenant_id = t and rc.po_id = po and not rc.voided group by 1) r on r.i = g.i
  left join (select (y->>'i')::int i, sum((y->>'qty')::numeric) q from acc.po_bills pb join acc.invoices v on v.tenant_id = pb.tenant_id and v.id = pb.invoice_id and v.status <> 'void', jsonb_array_elements(pb.lines) y where pb.tenant_id = t and pb.po_id = po group by 1) b on b.i = g.i $$;

create or replace function app.po_chk() returns uuid language plpgsql stable security definer set search_path = public, app, acc as $$
begin if not app.feat_on('purchase_orders') then raise exception 'الميزة غير مفعّلة لشركتك'; end if; return app.need('purchases', 'view'); end $$;

create or replace function public.po_save(p jsonb) returns jsonb language plpgsql security definer set search_path = public, app, acc as $$
declare t uuid := app.need('purchases', case when nullif(p->>'id','') is null then 'add' else 'edit' end); v uuid := nullif(p->>'id','')::uuid; e uuid := nullif(p->>'entity','')::uuid; d date := coalesce(nullif(p->>'date','')::date, current_date);
  l jsonb; net numeric; tx numeric; sub numeric := 0; tt numeric := 0; tcode text; tc acc.tax_codes; cur acc.po; ls jsonb := '[]'::jsonb; no bigint; itm uuid; i int := 0;
begin
  if not app.feat_on('purchase_orders') then raise exception 'الميزة غير مفعّلة لشركتك'; end if;
  if jsonb_typeof(p->'lines') <> 'array' or jsonb_array_length(p->'lines') = 0 then raise exception 'أضف سطرًا واحدًا على الأقل'; end if;
  if not exists (select 1 from acc.parties where tenant_id = t and id = nullif(p->>'party','')::uuid and kind in ('supplier','both') and active) then raise exception 'اختر موردًا صالحًا'; end if;
  if v is not null then select * into cur from acc.po where tenant_id = t and id = v and entity_id = any(app.ents()) for update; if cur.id is null then raise exception 'أمر الشراء غير موجود'; end if;
    if cur.status <> 'draft' then raise exception 'يُعدَّل أمر الشراء وهو مسودة فقط'; end if; e := cur.entity_id; end if;
  if e is null or not (e = any(app.ents())) then raise exception 'كيان غير مسموح'; end if;
  for l in select * from jsonb_array_elements(p->'lines') loop
    i := i + 1;
    if coalesce((l->>'qty')::numeric, 0) <= 0 or coalesce((l->>'unit_price')::numeric, -1) < 0 then raise exception 'السطر %: الكمية والسعر غير صالحين', i; end if;
    net := round((l->>'qty')::numeric * (l->>'unit_price')::numeric - coalesce(nullif(l->>'discount','')::numeric, 0), 2); if net < 0 then raise exception 'السطر %: الخصم أكبر من قيمة السطر', i; end if;
    itm := nullif(l->>'item','')::uuid; if itm is not null and not exists (select 1 from acc.items where tenant_id = t and id = itm and active) then raise exception 'السطر %: الصنف غير موجود أو موقوف', i; end if;
    tcode := nullif(l->>'tax_code',''); tx := 0;
    if tcode is not null then select * into tc from acc.tax_codes where tenant_id = t and code = tcode and active; if tc.code is null then raise exception 'السطر %: رمز الضريبة غير موجود', i; end if;
      if tc.kind not in ('input','zero_in','exempt','oos') then raise exception 'السطر %: رمز ضريبة مبيعات على أمر شراء', i; end if; tx := round(net * app.tax_rate_on(t, tc.code, d, tc.rate) / 100, 2); end if;
    sub := sub + net; tt := tt + tx;
    ls := ls || jsonb_build_array(jsonb_build_object('description', coalesce(l->>'description',''), 'qty', (l->>'qty')::numeric, 'unit_price', (l->>'unit_price')::numeric, 'discount', coalesce(nullif(l->>'discount','')::numeric, 0), 'account', nullif(l->>'account',''), 'tax_code', tcode, 'item', itm, 'net', net, 'tax', tx));
  end loop;
  if v is null then
    no := app.next_no(t, e, 'PO', extract(year from d)::int);
    insert into acc.po (tenant_id, entity_id, number, date, expected, party_id, lines, subtotal, tax_total, total, notes, created_by) values (t, e, no, d, nullif(p->>'expected','')::date, (p->>'party')::uuid, ls, sub, tt, sub + tt, coalesce(p->>'notes',''), auth.uid()) returning id into v;
  else update acc.po set date = d, expected = nullif(p->>'expected','')::date, party_id = (p->>'party')::uuid, lines = ls, subtotal = sub, tax_total = tt, total = sub + tt, notes = coalesce(p->>'notes',''), updated_at = now() where tenant_id = t and id = v; end if;
  perform app.audit('upsert', 'po', v::text, 'أمر شراء ' || (sub + tt)); return jsonb_build_object('id', v, 'total', sub + tt);
end $$;

create or replace function app.po_state(t uuid, po acc.po) returns jsonb language plpgsql stable security definer set search_path = public, app, acc as $$
declare q jsonb := app.po_qty(t, po.id); o numeric; r numeric; b numeric;
begin
  select coalesce(sum((x->>'ordered')::numeric),0), coalesce(sum(least((x->>'received')::numeric,(x->>'ordered')::numeric)),0), coalesce(sum(least((x->>'billed')::numeric,(x->>'ordered')::numeric)),0) into o, r, b from jsonb_array_elements(q) x;
  return jsonb_build_object('qty', q, 'recv', case when r = 0 then 'none' when r >= o then 'full' else 'partial' end, 'bill', case when b = 0 then 'none' when b >= o then 'full' else 'partial' end);
end $$;

create or replace function public.po_list(p jsonb default '{}') returns jsonb language plpgsql stable security definer set search_path = public, app, acc as $$
declare t uuid := app.po_chk(); ents uuid[] := app.pick_ents(p);
begin
  return coalesce((select jsonb_agg(to_jsonb(q) - 'tenant_id' - 'lines' || jsonb_build_object('party_name', (select name from acc.parties x where x.tenant_id = t and x.id = q.party_id), 'recv', app.po_state(t, q)->>'recv', 'bill', app.po_state(t, q)->>'bill') order by q.date desc, q.number desc)
    from acc.po q where q.tenant_id = t and q.entity_id = any(ents) and (nullif(p->>'status','') is null or q.status = p->>'status')), '[]'::jsonb);
end $$;

create or replace function public.po_get(p jsonb) returns jsonb language plpgsql stable security definer set search_path = public, app, acc as $$
declare t uuid := app.po_chk(); q acc.po;
begin
  select * into q from acc.po where tenant_id = t and id = (p->>'id')::uuid and entity_id = any(app.ents()); if q.id is null then raise exception 'أمر الشراء غير موجود'; end if;
  return to_jsonb(q) - 'tenant_id' || jsonb_build_object('party_name', (select name from acc.parties x where x.tenant_id = t and x.id = q.party_id), 'state', app.po_state(t, q),
    'receipts', coalesce((select jsonb_agg(jsonb_build_object('id', r.id, 'number', r.number, 'date', r.date, 'voided', r.voided, 'lines', r.lines, 'note', r.note) order by r.number) from acc.po_receipts r where r.tenant_id = t and r.po_id = q.id), '[]'::jsonb),
    'bills', coalesce((select jsonb_agg(jsonb_build_object('invoice_id', b.invoice_id, 'number', v.number, 'status', v.status, 'total', v.total, 'lines', b.lines)) from acc.po_bills b join acc.invoices v on v.tenant_id = b.tenant_id and v.id = b.invoice_id where b.tenant_id = t and b.po_id = q.id), '[]'::jsonb));
end $$;

create or replace function public.po_status(p jsonb) returns jsonb language plpgsql security definer set search_path = public, app, acc as $$
declare t uuid; q acc.po; ns text := p->>'status'; st jsonb;
begin
  select * into q from acc.po where tenant_id = app.tenant() and id = (p->>'id')::uuid and entity_id = any(app.ents()) for update; if q.id is null then raise exception 'أمر الشراء غير موجود'; end if;
  t := app.need('purchases', case when ns = 'approved' then 'approve' else 'edit' end); if not app.feat_on('purchase_orders') then raise exception 'الميزة غير مفعّلة لشركتك'; end if;
  st := app.po_state(t, q);
  if ns = 'approved' and q.status = 'draft' then update acc.po set status = 'approved', approved_by = auth.uid(), approved_at = now(), updated_at = now() where tenant_id = t and id = q.id;
  elsif ns = 'draft' and q.status = 'approved' and st->>'recv' = 'none' and st->>'bill' = 'none' then update acc.po set status = 'draft', approved_by = null, approved_at = null, updated_at = now() where tenant_id = t and id = q.id;
  elsif ns = 'cancelled' and q.status in ('draft','approved') and st->>'recv' = 'none' and st->>'bill' = 'none' then update acc.po set status = 'cancelled', updated_at = now() where tenant_id = t and id = q.id;
  elsif ns = 'closed' and q.status = 'approved' then update acc.po set status = 'closed', updated_at = now() where tenant_id = t and id = q.id;
  else raise exception 'لا يمكن الانتقال من «%» إلى «%» (لا إلغاء بعد استلام/فوترة)', q.status, ns; end if;
  perform app.audit('update', 'po', q.id::text, q.status || ' ← ' || ns); return jsonb_build_object('ok', true);
end $$;

-- استلام (كلي/جزئي): لا يتجاوز المتبقي من المطلوب
create or replace function public.po_receive(p jsonb) returns jsonb language plpgsql security definer set search_path = public, app, acc as $$
declare t uuid := app.need('purchases', 'edit'); q acc.po; l jsonb; qty jsonb; i int; n numeric; rem numeric; no bigint; rid uuid := gen_random_uuid(); ls jsonb := '[]'::jsonb; d date := coalesce(nullif(p->>'date','')::date, current_date);
begin
  if not app.feat_on('purchase_orders') then raise exception 'الميزة غير مفعّلة لشركتك'; end if;
  select * into q from acc.po where tenant_id = t and id = (p->>'id')::uuid and entity_id = any(app.ents()) for update; if q.id is null then raise exception 'أمر الشراء غير موجود'; end if;
  if q.status <> 'approved' then raise exception 'الاستلام على أمر شراء معتمد فقط'; end if;
  qty := app.po_qty(t, q.id);
  for l in select * from jsonb_array_elements(coalesce(p->'lines','[]'::jsonb)) loop
    i := (l->>'i')::int; n := coalesce((l->>'qty')::numeric, 0); if n <= 0 then continue; end if;
    select (x->>'ordered')::numeric - (x->>'received')::numeric into rem from jsonb_array_elements(qty) x where (x->>'i')::int = i; if rem is null then raise exception 'سطر غير موجود (%)', i + 1; end if;
    if n > rem then raise exception 'السطر %: الكمية المستلمة (%) أكبر من المتبقي (%)', i + 1, n, rem; end if;
    ls := ls || jsonb_build_array(jsonb_build_object('i', i, 'qty', n));
  end loop;
  if jsonb_array_length(ls) = 0 then raise exception 'أدخل كمية مستلمة واحدة على الأقل'; end if;
  no := app.next_no(t, q.entity_id, 'GR', extract(year from d)::int);
  insert into acc.po_receipts (tenant_id, id, po_id, number, date, lines, note, created_by) values (t, rid, q.id, no, d, ls, coalesce(p->>'note',''), auth.uid());
  perform app.audit('upsert', 'po_receipt', rid::text, 'استلام على أمر شراء #' || q.number); return jsonb_build_object('id', rid, 'number', no);
end $$;

create or replace function public.po_receipt_void(p jsonb) returns jsonb language plpgsql security definer set search_path = public, app, acc as $$
declare t uuid := app.need('purchases', 'delete'); r acc.po_receipts; q acc.po; qty jsonb; l jsonb; bad boolean := false;
begin
  if not app.feat_on('purchase_orders') then raise exception 'الميزة غير مفعّلة لشركتك'; end if;
  select * into r from acc.po_receipts where tenant_id = t and id = (p->>'id')::uuid for update; if r.id is null or r.voided then raise exception 'الاستلام غير موجود أو ملغى'; end if;
  select * into q from acc.po where tenant_id = t and id = r.po_id and entity_id = any(app.ents()); if q.id is null then raise exception 'غير مسموح'; end if;
  update acc.po_receipts set voided = true where tenant_id = t and id = r.id; qty := app.po_qty(t, q.id);
  if exists (select 1 from jsonb_array_elements(qty) x where (x->>'billed')::numeric > (x->>'received')::numeric) then raise exception 'لا يمكن إلغاء الاستلام: ستصبح الكمية المفوترة أكبر من المستلمة'; end if;
  perform app.audit('void', 'po_receipt', r.id::text, 'إلغاء استلام'); return jsonb_build_object('ok', true);
end $$;

-- فاتورة مشتريات مسودة من المستلَم غير المفوتَر (عبر inv_save فتمرّ بكل ضوابطها)
create or replace function public.po_bill(p jsonb) returns jsonb language plpgsql security definer set search_path = public, app, acc as $$
declare t uuid := app.need('purchases', 'add'); q acc.po; qty jsonb; x jsonb; ls jsonb := '[]'::jsonb; bl jsonb := '[]'::jsonb; src jsonb; n numeric; r jsonb; fully boolean;
begin
  if not app.feat_on('purchase_orders') then raise exception 'الميزة غير مفعّلة لشركتك'; end if;
  select * into q from acc.po where tenant_id = t and id = (p->>'id')::uuid and entity_id = any(app.ents()) for update; if q.id is null then raise exception 'أمر الشراء غير موجود'; end if;
  if q.status not in ('approved','closed') then raise exception 'الفوترة على أمر شراء معتمد فقط'; end if;
  qty := app.po_qty(t, q.id);
  for x in select * from jsonb_array_elements(qty) loop
    n := (x->>'received')::numeric - (x->>'billed')::numeric; if n <= 0 then continue; end if;
    src := q.lines -> (x->>'i')::int;
    ls := ls || jsonb_build_array(jsonb_build_object('description', src->>'description', 'qty', n, 'unit_price', src->'unit_price', 'discount', round(coalesce((src->>'discount')::numeric,0) * n / (src->>'qty')::numeric, 2), 'account', src->>'account', 'tax_code', src->>'tax_code', 'item', src->>'item'));
    bl := bl || jsonb_build_array(jsonb_build_object('i', (x->>'i')::int, 'qty', n));
  end loop;
  if jsonb_array_length(ls) = 0 then raise exception 'لا توجد كميات مستلمة غير مفوترة'; end if;
  r := public.inv_save(jsonb_build_object('kind', 'purchase', 'entity', q.entity_id, 'party', q.party_id, 'date', coalesce(nullif(p->>'date','')::date, current_date), 'supplier_ref', coalesce(p->>'supplier_ref',''), 'notes', 'أمر شراء #' || q.number, 'lines', ls));
  insert into acc.po_bills (tenant_id, po_id, invoice_id, lines) values (t, q.id, (r->>'id')::uuid, bl);
  perform app.audit('update', 'po', q.id::text, 'فاتورة مشتريات مسودة من الاستلام'); return r;
end $$;

-- المطابقة الثلاثية: سطر بسطر + أي انحراف (فوترة فوق المستلَم، أو سعر فاتورة مختلف عن أمر الشراء)
create or replace function public.po_match(p jsonb) returns jsonb language plpgsql stable security definer set search_path = public, app, acc as $$
declare t uuid := app.po_chk(); q acc.po; qty jsonb; out jsonb := '[]'::jsonb; x jsonb; pv numeric; flags jsonb;
begin
  select * into q from acc.po where tenant_id = t and id = (p->>'id')::uuid and entity_id = any(app.ents()); if q.id is null then raise exception 'أمر الشراء غير موجود'; end if;
  qty := app.po_qty(t, q.id);
  for x in select * from jsonb_array_elements(qty) loop
    flags := '[]'::jsonb;
    if (x->>'billed')::numeric > (x->>'received')::numeric then flags := flags || '["billed_over_received"]'::jsonb; end if;
    select max(abs(l.unit_price - (q.lines->((x->>'i')::int)->>'unit_price')::numeric)) into pv from acc.po_bills b join acc.invoices v on v.tenant_id = b.tenant_id and v.id = b.invoice_id and v.status <> 'void'
      join acc.invoice_lines l on l.tenant_id = v.tenant_id and l.invoice_id = v.id and l.line_no = (select ord from jsonb_array_elements(b.lines) with ordinality y(v2, ord) where (y.v2->>'i')::int = (x->>'i')::int limit 1)
      where b.tenant_id = t and b.po_id = q.id;
    if coalesce(pv, 0) > 0 then flags := flags || '["price_variance"]'::jsonb; end if;
    out := out || jsonb_build_array(x || jsonb_build_object('description', q.lines->((x->>'i')::int)->>'description', 'unit_price', q.lines->((x->>'i')::int)->'unit_price', 'flags', flags,
      'ok', jsonb_array_length(flags) = 0 and (x->>'received')::numeric = (x->>'ordered')::numeric and (x->>'billed')::numeric = (x->>'ordered')::numeric));
  end loop;
  return jsonb_build_object('po', q.number, 'lines', out, 'matched', not exists (select 1 from jsonb_array_elements(out) o where not (o->>'ok')::boolean));
end $$;
