-- مُحكَم للحسابات — تحديث 1.6.6.0: المخزون المتقدم (دفعات وصلاحية ونقص مخزون) — بعد 1.6.5.0

-- ===== sql/053_lots.sql =====
-- مُحكَم للحسابات 1.6.6 — المخزون المتقدم: دفعات وتواريخ صلاحية + نقص المخزون (ميزة اختيارية inv_lots)
-- طبقة تتبّع فوق المخزون القائم (المتوسط المرجّح لا يتغير ولا قيود جديدة): الدفعة تُسنِد جزءًا من رصيد الصنف الفعلي؛ لا يتجاوز مجموع الدفعات رصيد الصنف في الكيان.
create table if not exists acc.item_lots (
  tenant_id uuid not null references acc.tenants(id) on delete cascade, id uuid not null default gen_random_uuid(), entity_id uuid not null, item_id uuid not null,
  lot_no text not null, expiry date, qty numeric(18,4) not null default 0 check (qty >= 0), received date not null default current_date, note text not null default '', active boolean not null default true,
  created_by uuid, created_at timestamptz not null default now(),
  primary key (tenant_id, id), unique (tenant_id, entity_id, item_id, lot_no),
  foreign key (tenant_id, entity_id) references acc.entities (tenant_id, id), foreign key (tenant_id, item_id) references acc.items (tenant_id, id));
create index if not exists item_lots_q on acc.item_lots (tenant_id, entity_id, item_id, expiry);
alter table acc.item_lots enable row level security;
with ins as (
  insert into app.feature_cat (key, name, grp, core, since, sort) values ('inv_lots', 'المخزون المتقدم (الدفعات والصلاحية ونقص المخزون)', 'المالية', false, 1, 34)
  on conflict (key) do nothing returning key)
update acc.tenants set features_off = array_append(features_off, 'inv_lots') where exists (select 1 from ins) and not ('inv_lots' = any(features_off));
update app.feature_cat set name = 'المخزون المتقدم (الدفعات والصلاحية ونقص المخزون)', grp = 'المالية', core = false, sort = 34 where key = 'inv_lots';

create or replace function app.lot_chk(act text) returns uuid language plpgsql stable security definer set search_path = public, app, acc as $$
begin if not app.feat_on('inv_lots') then raise exception 'الميزة غير مفعّلة لشركتك'; end if; return app.need_inv(act); end $$;

-- الرصيد غير المُسنَد إلى دفعات لصنف في كيان
create or replace function app.lot_free(t uuid, e uuid, it uuid) returns numeric language sql stable security definer set search_path = public, acc as $$
  select coalesce((select qty from acc.stock_bal where tenant_id = t and entity_id = e and item_id = it), 0) - coalesce((select sum(qty) from acc.item_lots where tenant_id = t and entity_id = e and item_id = it and active), 0) $$;

-- تسجيل دفعة (أو زيادتها): لا يتجاوز الرصيد غير المُسنَد
create or replace function public.lot_add(p jsonb) returns jsonb language plpgsql security definer set search_path = public, app, acc as $$
declare t uuid := app.lot_chk('add'); e uuid := (p->>'entity')::uuid; it uuid := (p->>'item')::uuid; n numeric := coalesce((p->>'qty')::numeric, 0); ln text := trim(coalesce(p->>'lot_no','')); v uuid; free numeric;
begin
  if e is null or not (e = any(app.ents())) then raise exception 'كيان غير مسموح'; end if;
  if ln = '' then raise exception 'رقم الدفعة مطلوب'; end if; if n <= 0 then raise exception 'الكمية يجب أن تكون أكبر من صفر'; end if;
  if not exists (select 1 from acc.items where tenant_id = t and id = it and active) then raise exception 'الصنف غير موجود أو موقوف'; end if;
  perform 1 from acc.stock_bal where tenant_id = t and entity_id = e and item_id = it for update;
  free := app.lot_free(t, e, it); if n > free then raise exception 'الكمية (%) أكبر من الرصيد غير المُسنَد إلى دفعات (%)', n, free; end if;
  insert into acc.item_lots (tenant_id, entity_id, item_id, lot_no, expiry, qty, received, note, created_by) values (t, e, it, ln, nullif(p->>'expiry','')::date, n, coalesce(nullif(p->>'received','')::date, current_date), coalesce(p->>'note',''), auth.uid())
  on conflict (tenant_id, entity_id, item_id, lot_no) do update set qty = acc.item_lots.qty + excluded.qty, expiry = coalesce(excluded.expiry, acc.item_lots.expiry), active = true returning id into v;
  perform app.audit('upsert', 'lot', v::text, 'دفعة ' || ln || ' +' || n); return jsonb_build_object('id', v);
end $$;

-- صرف من دفعة محددة، أو تلقائي بالأقرب انتهاءً (FEFO) — يُنقص الدفعات فقط؛ حركة المخزون والتكلفة تتم بالفواتير كالمعتاد
create or replace function public.lot_issue(p jsonb) returns jsonb language plpgsql security definer set search_path = public, app, acc as $$
declare t uuid := app.lot_chk('edit'); e uuid := (p->>'entity')::uuid; it uuid := (p->>'item')::uuid; n numeric := coalesce((p->>'qty')::numeric, 0); r record; take numeric; left_ numeric := n; used jsonb := '[]'::jsonb; lid uuid := nullif(p->>'lot','')::uuid;
begin
  if e is null or not (e = any(app.ents())) then raise exception 'كيان غير مسموح'; end if; if n <= 0 then raise exception 'الكمية يجب أن تكون أكبر من صفر'; end if;
  for r in select * from acc.item_lots where tenant_id = t and entity_id = e and item_id = it and active and qty > 0 and (lid is null or id = lid) order by expiry nulls last, received, lot_no for update loop
    exit when left_ <= 0; take := least(r.qty, left_); update acc.item_lots set qty = qty - take where tenant_id = t and id = r.id; left_ := left_ - take; used := used || jsonb_build_array(jsonb_build_object('lot', r.lot_no, 'qty', take));
  end loop;
  if left_ > 0 then raise exception 'الدفعات لا تكفي (ينقص %)', left_; end if;
  perform app.audit('update', 'lot', it::text, 'صرف من الدفعات ' || n); return jsonb_build_object('used', used);
end $$;

create or replace function public.lot_list(p jsonb default '{}') returns jsonb language plpgsql stable security definer set search_path = public, app, acc as $$
declare t uuid := app.lot_chk('view'); ents uuid[] := app.pick_ents(p); d int := coalesce(nullif(p->>'days','')::int, 60);
begin
  return coalesce((select jsonb_agg(jsonb_build_object('id', l.id, 'entity_id', l.entity_id, 'item_id', l.item_id, 'item', i.code || ' ' || i.name, 'unit', i.unit, 'lot_no', l.lot_no, 'expiry', l.expiry, 'qty', l.qty, 'received', l.received,
      'days_left', case when l.expiry is null then null else l.expiry - current_date end, 'state', case when l.qty = 0 then 'empty' when l.expiry is null then 'ok' when l.expiry < current_date then 'expired' when l.expiry <= current_date + d then 'soon' else 'ok' end) order by l.expiry nulls last, i.code, l.lot_no)
    from acc.item_lots l join acc.items i on i.tenant_id = l.tenant_id and i.id = l.item_id where l.tenant_id = t and l.entity_id = any(ents) and l.active and (coalesce((p->>'all')::boolean, false) or l.qty > 0)), '[]'::jsonb);
end $$;

-- نقص المخزون: الرصيد ≤ حد إعادة الطلب (للأصناف التي حدّها > 0) + الرصيد غير المُسنَد إلى دفعات
create or replace function public.stock_low(p jsonb default '{}') returns jsonb language plpgsql stable security definer set search_path = public, app, acc as $$
declare t uuid := app.lot_chk('view'); ents uuid[] := app.pick_ents(p);
begin
  return coalesce((select jsonb_agg(x order by (x->>'short')::numeric desc) from (
    select jsonb_build_object('entity_id', e, 'item_id', i.id, 'item', i.code || ' ' || i.name, 'unit', i.unit, 'qty', q, 'reorder', i.reorder_qty, 'short', i.reorder_qty - q, 'unassigned', app.lot_free(t, e, i.id)) x
    from acc.items i cross join unnest(ents) e cross join lateral (select coalesce((select qty from acc.stock_bal b where b.tenant_id = t and b.entity_id = e and b.item_id = i.id), 0) q) s
    where i.tenant_id = t and i.active and i.reorder_qty > 0 and q <= i.reorder_qty) z), '[]'::jsonb);
end $$;
