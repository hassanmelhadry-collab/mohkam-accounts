-- 1.11.2.0 — (أ) فئة IFRS 18 على الحسابات (إضافة فقط، افتراضيها فارغ، لا تغيّر قيدًا ولا تقريرًا)
--            (ب) تكلفة المخزون المتقدمة: FIFO + تكلفة الاستيراد + القيد الافتتاحي للمخزون
-- ميزتان اختياريتان مقفولتان على الشركات القائمة. FIFO يُفتح لكل شركة بقرارها (stock_cost_method_set)؛ الافتراضي المتوسط المرجّح فلا تتغير تكلفة المبيعات القائمة.
-- متكرر التشغيل. التراجع: rollback_1_11_2_0.sql

alter table acc.accounts add column if not exists ifrs18_cat text;
do $$ begin if not exists (select 1 from pg_constraint where conname = 'accounts_ifrs18_cat_chk') then
  alter table acc.accounts add constraint accounts_ifrs18_cat_chk check (ifrs18_cat is null or ifrs18_cat in ('operating','investing','financing','income_tax','discontinued')); end if; end $$;

with ins as (insert into app.feature_cat (key, name, grp, core, since, sort) values ('ifrs18', 'فئات IFRS 18 للحسابات', 'المالية', false, 1, 43) on conflict (key) do nothing returning key)
update acc.tenants set features_off = array_append(features_off, 'ifrs18') where exists (select 1 from ins) and not ('ifrs18' = any(features_off));
with ins as (insert into app.feature_cat (key, name, grp, core, since, sort) values ('inv_costing', 'تكلفة المخزون المتقدمة (FIFO وتكلفة الاستيراد والقيد الافتتاحي)', 'المخزون', false, 1, 44) on conflict (key) do nothing returning key)
update acc.tenants set features_off = array_append(features_off, 'inv_costing') where exists (select 1 from ins) and not ('inv_costing' = any(features_off));

create table if not exists acc.stock_layers (
  tenant_id uuid not null, id uuid not null default gen_random_uuid(), entity_id uuid not null, item_id uuid not null, date date not null, doc_id uuid,
  qty_in numeric(18,4) not null check (qty_in > 0), qty_left numeric(18,4) not null check (qty_left >= 0), unit_cost numeric(18,6) not null check (unit_cost >= 0), created_at timestamptz not null default now(),
  primary key (tenant_id, id), foreign key (tenant_id, item_id) references acc.items (tenant_id, id));
create index if not exists stock_layers_fifo on acc.stock_layers (tenant_id, entity_id, item_id, date, created_at) where qty_left > 0;
create index if not exists stock_layers_item on acc.stock_layers (tenant_id, item_id);
create table if not exists acc.landed_costs (
  tenant_id uuid not null, id uuid not null default gen_random_uuid(), invoice_id uuid not null, entity_id uuid not null, date date not null, amount numeric(18,2) not null check (amount > 0),
  basis text not null check (basis in ('value','qty')), credit_account_id uuid not null, journal_id uuid, note text not null default '', created_by uuid, created_at timestamptz not null default now(), primary key (tenant_id, id));
alter table acc.stock_layers enable row level security; alter table acc.landed_costs enable row level security;
revoke all on acc.stock_layers, acc.landed_costs from anon, authenticated, public;

create or replace function app.fifo_on(t uuid) returns boolean language sql stable security definer set search_path = public, acc, app as $$
  select app.feat_on('inv_costing', t) and coalesce((select settings->>'cost_method' from acc.tenants where id = t), 'avg') = 'fifo' $$;

-- حركة المخزون: مسار FIFO يُستعمل فقط عند تفعيل الميزة واختيار الشركة؛ وإلا يبقى المسار الأصلي حرفيًا (المتوسط المرجّح)
create or replace function app.stock_move(t uuid, e uuid, it uuid, d date, dir text, q numeric, ucost numeric, doc uuid, note text) returns numeric language plpgsql security definer set search_path = public, acc, app as $$
declare b acc.stock_bal; c numeric; nm text; lf numeric; r record; tk numeric; val numeric := 0; lq numeric; lv numeric;
begin
  insert into acc.stock_bal (tenant_id, entity_id, item_id) values (t, e, it) on conflict do nothing;
  select * into b from acc.stock_bal where tenant_id = t and entity_id = e and item_id = it for update;
  if app.fifo_on(t) then
    if dir = 'out' then
      if b.qty < q then select name into nm from acc.items where tenant_id = t and id = it; raise exception 'المخزون لا يكفي للصنف «%» (المتاح % والمطلوب %)', nm, b.qty, q; end if;
      lf := q;
      for r in select id, qty_left, unit_cost from acc.stock_layers where tenant_id = t and entity_id = e and item_id = it and qty_left > 0
               order by (ucost is not null and doc_id is not distinct from doc) desc, date, created_at, id for update loop
        exit when lf <= 0;
        tk := least(r.qty_left, lf);
        update acc.stock_layers set qty_left = qty_left - tk where tenant_id = t and id = r.id;
        val := val + tk * r.unit_cost; lf := lf - tk;
      end loop;
      if lf > 0 then val := val + lf * b.avg_cost; end if;   -- رصيد سابق بلا طبقات: بسعر المتوسط
      c := coalesce(ucost, round(val / q, 6));
    else
      c := coalesce(ucost, b.avg_cost);
      insert into acc.stock_layers (tenant_id, entity_id, item_id, date, doc_id, qty_in, qty_left, unit_cost) values (t, e, it, d, doc, q, q, c);
    end if;
    select coalesce(sum(qty_left), 0), coalesce(sum(qty_left * unit_cost), 0) into lq, lv from acc.stock_layers where tenant_id = t and entity_id = e and item_id = it and qty_left > 0;
    update acc.stock_bal set qty = case when dir = 'out' then b.qty - q else b.qty + q end, avg_cost = case when lq > 0 then round(lv / lq, 6) else b.avg_cost end where tenant_id = t and entity_id = e and item_id = it;
    insert into acc.stock_moves (tenant_id, entity_id, item_id, date, dir, qty, unit_cost, doc_id, note) values (t, e, it, d, dir, q, c, doc, coalesce(note, ''));
    return c;
  end if;
  if dir = 'out' then
    if b.qty < q then select name into nm from acc.items where tenant_id = t and id = it; raise exception 'المخزون لا يكفي للصنف «%» (المتاح % والمطلوب %)', nm, b.qty, q; end if;
    c := coalesce(ucost, b.avg_cost);
    update acc.stock_bal set qty = b.qty - q, avg_cost = case when ucost is not null and b.qty > q then greatest((b.qty * b.avg_cost - q * ucost) / (b.qty - q), 0) else b.avg_cost end where tenant_id = t and entity_id = e and item_id = it;
  else
    c := coalesce(ucost, b.avg_cost);
    update acc.stock_bal set avg_cost = case when b.qty + q <= 0 then c else (greatest(b.qty, 0) * b.avg_cost + q * c) / (greatest(b.qty, 0) + q) end, qty = b.qty + q where tenant_id = t and entity_id = e and item_id = it;
  end if;
  insert into acc.stock_moves (tenant_id, entity_id, item_id, date, dir, qty, unit_cost, doc_id, note) values (t, e, it, d, dir, q, c, doc, coalesce(note, ''));
  return c;
end $$;

create or replace function public.stock_cost_method_set(p jsonb) returns jsonb language plpgsql security definer set search_path = public, app, acc as $$
declare t uuid := app.need_inv('edit'); m text := lower(coalesce(p->>'method', '')); cur text;
begin
  if not app.feat_on('inv_costing', t) then raise exception 'الميزة غير مفعّلة لشركتك'; end if;
  if m not in ('avg', 'fifo') then raise exception 'الطريقة: avg (متوسط مرجّح) أو fifo'; end if;
  cur := coalesce((select settings->>'cost_method' from acc.tenants where id = t), 'avg');
  if cur = m then return jsonb_build_object('method', m, 'changed', false); end if;
  if m = 'fifo' then
    insert into acc.stock_layers (tenant_id, entity_id, item_id, date, doc_id, qty_in, qty_left, unit_cost) select tenant_id, entity_id, item_id, current_date, null, qty, qty, avg_cost from acc.stock_bal where tenant_id = t and qty > 0;
  else
    delete from acc.stock_layers where tenant_id = t;
  end if;
  update acc.tenants set settings = jsonb_set(settings, '{cost_method}', to_jsonb(m)) where id = t;
  perform app.audit('cost_method', 'tenant', t::text, cur || ' -> ' || m);
  return jsonb_build_object('method', m, 'changed', true);
end $$;

create or replace function public.stock_cost_method_get(p jsonb default '{}') returns jsonb language plpgsql stable security definer set search_path = public, app, acc as $$
declare t uuid := app.need_inv('view');
begin
  return jsonb_build_object('enabled', app.feat_on('inv_costing', t), 'method', coalesce((select settings->>'cost_method' from acc.tenants where id = t), 'avg'));
end $$;

-- القيد الافتتاحي للمخزون: مدين حساب مخزون الصنف / دائن حساب حقوق ملكية؛ مرة واحدة لكل صنف وكيان
create or replace function public.stock_opening(p jsonb) returns jsonb language plpgsql security definer set search_path = public, app, acc as $$
declare t uuid := app.need('journals', 'post'); e uuid := (p->>'entity')::uuid; d date := coalesce(nullif(p->>'date', '')::date, current_date); eq uuid; l jsonb; it acc.items; q numeric; uc numeric; tot numeric := 0; ln numeric;
  doc uuid := gen_random_uuid(); jid uuid := gen_random_uuid(); arr jsonb := '[]'::jsonb; lines jsonb; j acc.journals;
begin
  perform app.need_inv('add');
  if not app.feat_on('inv_costing', t) then raise exception 'الميزة غير مفعّلة لشركتك'; end if;
  if e is null or not (e = any(app.ents())) then raise exception 'كيان غير مسموح'; end if;
  eq := app.acct_id(t, nullif(p->>'equity_account', ''));
  if eq is null or not exists (select 1 from acc.accounts where tenant_id = t and id = eq and type = 'equity' and not is_group and active) then raise exception 'حدّد حساب حقوق ملكية صالحًا للقيد الافتتاحي'; end if;
  if jsonb_typeof(p->'lines') <> 'array' or jsonb_array_length(p->'lines') = 0 then raise exception 'أضف صنفًا واحدًا على الأقل'; end if;
  for l in select * from jsonb_array_elements(p->'lines') loop
    select * into it from acc.items where tenant_id = t and id = nullif(l->>'item', '')::uuid;
    if it.id is null then raise exception 'صنف غير موجود'; end if;
    q := (l->>'qty')::numeric; uc := (l->>'unit_cost')::numeric;
    if q is null or q <= 0 or uc is null or uc < 0 then raise exception 'كمية وتكلفة غير صالحتين للصنف «%»', it.name; end if;
    if exists (select 1 from acc.stock_moves where tenant_id = t and entity_id = e and item_id = it.id and doc_type = 'opening') then raise exception 'للصنف «%» رصيد افتتاحي مسجّل مسبقًا', it.name; end if;
    perform app.stock_move(t, e, it.id, d, 'in', q, uc, doc, 'رصيد افتتاحي');
    ln := round(q * uc, 2); tot := tot + ln;
    arr := arr || jsonb_build_array(jsonb_build_object('a', it.inv_account_id, 'v', ln));
  end loop;
  update acc.stock_moves set doc_type = 'opening' where tenant_id = t and doc_id = doc;
  if tot > 0 then
    insert into acc.journals (tenant_id, id, entity_id, type, date, description, status, source, source_id, created_by) values (t, jid, e, 'GJ', d, 'قيد افتتاحي للمخزون', 'draft', 'inventory', doc, auth.uid());
    select jsonb_agg(jsonb_build_object('account', a, 'debit', v, 'description', 'مخزون افتتاحي')) into lines from (select (x->>'a')::uuid a, sum((x->>'v')::numeric) v from jsonb_array_elements(arr) x group by 1) s;
    lines := lines || jsonb_build_array(jsonb_build_object('account', eq, 'credit', tot, 'description', 'مقابل رصيد المخزون الافتتاحي'));
    perform app.put_lines(t, jid, e, d, lines);
    j := app.post_journal(jid);
    update acc.stock_moves set journal_id = j.id where tenant_id = t and doc_id = doc;
  end if;
  perform app.audit('stock_opening', 'journal', jid::text, 'items=' || jsonb_array_length(p->'lines') || ' total=' || tot);
  return jsonb_build_object('total', tot, 'journal_id', case when tot > 0 then jid end, 'items', jsonb_array_length(p->'lines'));
end $$;

-- تكلفة الاستيراد (الشحن والجمارك…) على فاتورة مشتريات: الجزء المتبقي في المخزون يُرسمل في التكلفة، والجزء المباع يذهب لتكلفة المبيعات
create or replace function public.landed_cost_apply(p jsonb) returns jsonb language plpgsql security definer set search_path = public, app, acc as $$
declare t uuid := app.need('journals', 'post'); inv acc.invoices; amt numeric := round((p->>'amount')::numeric, 2); basis text := coalesce(nullif(p->>'basis', ''), 'value'); ca uuid; d date := coalesce(nullif(p->>'date', '')::date, current_date);
  r record; tot_w numeric; w numeric; used numeric := 0; ex numeric; frac numeric; ip numeric; cp numeric; onh numeric; sl numeric; n int := 0; jid uuid := gen_random_uuid(); lines jsonb; j acc.journals; arr jsonb := '[]'::jsonb; lid uuid := gen_random_uuid();
begin
  perform app.need_inv('edit');
  if not app.feat_on('inv_costing', t) then raise exception 'الميزة غير مفعّلة لشركتك'; end if;
  if amt is null or amt <= 0 then raise exception 'مبلغ التكلفة غير صالح'; end if;
  if basis not in ('value', 'qty') then raise exception 'أساس التوزيع: value أو qty'; end if;
  select * into inv from acc.invoices where tenant_id = t and id = nullif(p->>'invoice', '')::uuid;
  if inv.id is null or inv.kind <> 'purchase' or inv.status <> 'issued' then raise exception 'يلزم فاتورة مشتريات مُصدرة'; end if;
  if not (inv.entity_id = any(app.ents())) then raise exception 'كيان غير مسموح'; end if;
  ca := app.acct_id(t, nullif(p->>'credit_account', ''));
  if ca is null or not exists (select 1 from acc.accounts where tenant_id = t and id = ca and not is_group and active) then raise exception 'حدّد حساب الدائن (مستحقات/نقدية) صالحًا'; end if;
  select sum(case when basis = 'qty' then l.qty else l.net * inv.rate end) into tot_w from acc.invoice_lines l where l.tenant_id = t and l.invoice_id = inv.id and l.item_id is not null;
  if coalesce(tot_w, 0) <= 0 then raise exception 'لا بنود مخزون في الفاتورة'; end if;
  for r in select l.item_id, sum(l.qty) qty, sum(case when basis = 'qty' then l.qty else l.net * inv.rate end) w, i.inv_account_id, i.cogs_account_id, count(*) over () cnt, row_number() over (order by l.item_id) rn
           from acc.invoice_lines l join acc.items i on i.tenant_id = l.tenant_id and i.id = l.item_id where l.tenant_id = t and l.invoice_id = inv.id and l.item_id is not null group by l.item_id, i.inv_account_id, i.cogs_account_id order by l.item_id loop
    n := n + 1;
    ex := case when r.rn = r.cnt then amt - used else round(amt * r.w / tot_w, 2) end; used := used + ex;
    select coalesce(sum(qty_left), 0) into sl from acc.stock_layers where tenant_id = t and doc_id = inv.id and item_id = r.item_id and entity_id = inv.entity_id;
    select coalesce(qty, 0) into onh from acc.stock_bal where tenant_id = t and entity_id = inv.entity_id and item_id = r.item_id;
    if app.fifo_on(t) then frac := least(sl / r.qty, 1); else frac := least(onh / r.qty, 1); end if;
    ip := round(ex * frac, 2); cp := ex - ip;
    if ip > 0 then
      if app.fifo_on(t) and sl > 0 then
        update acc.stock_layers set unit_cost = unit_cost + ip / sl where tenant_id = t and doc_id = inv.id and item_id = r.item_id and entity_id = inv.entity_id and qty_left > 0;
        update acc.stock_bal b set avg_cost = (select round(sum(qty_left * unit_cost) / sum(qty_left), 6) from acc.stock_layers y where y.tenant_id = t and y.entity_id = inv.entity_id and y.item_id = r.item_id and y.qty_left > 0) where b.tenant_id = t and b.entity_id = inv.entity_id and b.item_id = r.item_id;
      elsif onh > 0 then
        update acc.stock_bal set avg_cost = avg_cost + ip / onh where tenant_id = t and entity_id = inv.entity_id and item_id = r.item_id;
      else cp := cp + ip; ip := 0; end if;
    end if;
    arr := arr || jsonb_build_array(jsonb_build_object('a', r.inv_account_id, 'v', ip), jsonb_build_object('a', r.cogs_account_id, 'v', cp));
  end loop;
  insert into acc.journals (tenant_id, id, entity_id, type, date, description, status, source, source_id, created_by) values (t, jid, inv.entity_id, 'GJ', d, 'تكلفة استيراد على فاتورة ' || coalesce(inv.number, ''), 'draft', 'inventory', inv.id, auth.uid());
  select jsonb_agg(jsonb_build_object('account', a, 'debit', v, 'description', 'تكلفة استيراد')) into lines from (select (x->>'a')::uuid a, sum((x->>'v')::numeric) v from jsonb_array_elements(arr) x group by 1 having sum((x->>'v')::numeric) > 0) s;
  lines := lines || jsonb_build_array(jsonb_build_object('account', ca, 'credit', amt, 'description', coalesce(nullif(p->>'note', ''), 'تكلفة استيراد')));
  perform app.put_lines(t, jid, inv.entity_id, d, lines);
  j := app.post_journal(jid);
  insert into acc.landed_costs (tenant_id, id, invoice_id, entity_id, date, amount, basis, credit_account_id, journal_id, note, created_by) values (t, lid, inv.id, inv.entity_id, d, amt, basis, ca, j.id, coalesce(p->>'note', ''), auth.uid());
  perform app.audit('landed_cost', 'invoice', inv.id::text, 'amount=' || amt);
  return jsonb_build_object('id', lid, 'journal_id', j.id, 'items', n);
end $$;

create or replace function public.coa_ifrs18_list(p jsonb default '{}') returns jsonb language plpgsql stable security definer set search_path = public, app, acc as $$
declare t uuid := app.need('coa', 'view');
begin
  if not app.feat_on('ifrs18', t) then raise exception 'الميزة غير مفعّلة لشركتك'; end if;
  return coalesce((select jsonb_agg(jsonb_build_object('id', id, 'code', code, 'name', name, 'type', type, 'ifrs18_cat', ifrs18_cat) order by code) from acc.accounts where tenant_id = t and not is_group and active and type in ('revenue', 'expense')), '[]'::jsonb);
end $$;

create or replace function public.coa_ifrs18_set(p jsonb) returns jsonb language plpgsql security definer set search_path = public, app, acc as $$
declare t uuid := app.need('coa', 'edit'); l jsonb; a uuid; c text; n int := 0;
begin
  if not app.feat_on('ifrs18', t) then raise exception 'الميزة غير مفعّلة لشركتك'; end if;
  if jsonb_typeof(p->'items') <> 'array' then raise exception 'items مطلوبة'; end if;
  for l in select * from jsonb_array_elements(p->'items') loop
    a := app.acct_id(t, coalesce(nullif(l->>'id', ''), nullif(l->>'code', ''))); c := nullif(trim(coalesce(l->>'cat', '')), '');
    if a is null then raise exception 'حساب غير موجود'; end if;
    if c is not null and c not in ('operating', 'investing', 'financing', 'income_tax', 'discontinued') then raise exception 'فئة IFRS 18 غير صالحة'; end if;
    update acc.accounts set ifrs18_cat = c where tenant_id = t and id = a; n := n + 1;
  end loop;
  perform app.audit('ifrs18_cat', 'accounts', t::text, 'n=' || n);
  return jsonb_build_object('updated', n);
end $$;

do $$ declare f text; begin foreach f in array array['stock_cost_method_set', 'stock_cost_method_get', 'stock_opening', 'landed_cost_apply', 'coa_ifrs18_list', 'coa_ifrs18_set'] loop
  execute format('grant execute on function public.%I(jsonb) to authenticated', f); execute format('revoke execute on function public.%I(jsonb) from anon, public', f); end loop; end $$;

insert into app.schema_migrations (version, name) values ('1.11.2.0', 'فئة IFRS 18 للحسابات + تكلفة المخزون المتقدمة (FIFO وتكلفة الاستيراد والقيد الافتتاحي) — ميزتان مقفولتان') on conflict (version) do nothing;
