-- مُحكَم للحسابات 1.6 — الدفعات المقدمة (على الحساب) لكل طرف: عرضها وتطبيقها لاحقًا على فواتير مستحقة
-- الدفعة «على الحساب» مسجّلة أصلًا في حساب الطرف بقيد الدفعة؛ التطبيق هنا تسوية تفصيلية فقط (لا قيد جديد) تنشئ تخصيصًا في acc.allocations.
create table if not exists acc.advance_applications (
  tenant_id uuid not null references acc.tenants(id) on delete cascade, id uuid not null default gen_random_uuid(), payment_id uuid not null, invoice_id uuid not null, allocation_id uuid not null,
  amount numeric(18,2) not null check (amount > 0), date date not null, created_by uuid, created_at timestamptz not null default now(),
  primary key (tenant_id, id), foreign key (tenant_id, payment_id) references acc.payments (tenant_id, id), foreign key (tenant_id, invoice_id) references acc.invoices (tenant_id, id));
alter table acc.advance_applications enable row level security;

-- المتاح من دفعة = on_account − ما طُبّق منها (للدفعات المرحّلة فقط)
create or replace function app.advance_free(t uuid, pay uuid) returns numeric language sql stable security definer set search_path = public, acc as $$
  select coalesce((select on_account from acc.payments where tenant_id = t and id = pay and status = 'posted'), 0) - coalesce((select sum(a.amount) from acc.advance_applications a join acc.allocations al on al.tenant_id = a.tenant_id and al.id = a.allocation_id where a.tenant_id = t and a.payment_id = pay and al.active), 0) $$;

create or replace function public.advance_list(p jsonb default '{}') returns jsonb language plpgsql stable security definer set search_path = public, app, acc as $$
declare t uuid := app.need('payments', 'view'); ents uuid[] := app.pick_ents(p); pty uuid := nullif(p->>'party','')::uuid;
begin
  return coalesce((select jsonb_agg(x order by x->>'date' desc) from (
    select jsonb_build_object('payment', pm.id, 'number', pm.number, 'kind', pm.kind, 'date', pm.date, 'party', pm.party_id, 'party_name', pa.name, 'on_account', pm.on_account, 'free', app.advance_free(t, pm.id)) x
    from acc.payments pm join acc.parties pa on pa.tenant_id = t and pa.id = pm.party_id
    where pm.tenant_id = t and pm.entity_id = any(ents) and pm.status = 'posted' and pm.on_account > 0 and (pty is null or pm.party_id = pty) and app.advance_free(t, pm.id) > 0) q), '[]'::jsonb);
end $$;

create or replace function public.advance_apply(p jsonb) returns jsonb language plpgsql security definer set search_path = public, app, acc as $$
declare t uuid := app.need('payments', 'post'); pm acc.payments; inv acc.invoices; amt numeric := round((p->>'amount')::numeric, 2); d date := coalesce(nullif(p->>'date','')::date, current_date); aid uuid := gen_random_uuid(); free numeric;
begin
  select * into pm from acc.payments where tenant_id = t and id = (p->>'payment')::uuid and entity_id = any(app.ents()) for update;
  select * into inv from acc.invoices where tenant_id = t and id = (p->>'invoice')::uuid and entity_id = any(app.ents()) for update;
  if pm.id is null or inv.id is null then raise exception 'الدفعة أو الفاتورة غير موجودة'; end if;
  if pm.status <> 'posted' then raise exception 'الدفعة غير مرحّلة'; end if;
  if inv.status <> 'issued' or inv.party_id <> pm.party_id or inv.entity_id <> pm.entity_id then raise exception 'الفاتورة يجب أن تكون صادرة ولنفس الطرف والشركة'; end if;
  if (pm.kind = 'receipt' and inv.kind <> 'sales') or (pm.kind = 'payment' and inv.kind <> 'purchase') then raise exception 'نوع الفاتورة لا يطابق نوع الدفعة'; end if;
  if amt is null or amt <= 0 then raise exception 'المبلغ غير صالح'; end if;
  free := app.advance_free(t, pm.id);
  if amt > free then raise exception 'المبلغ يتجاوز المتاح من الدفعة (%)', free; end if;
  if amt > inv.total_base - app.inv_paid(t, inv.id) then raise exception 'المبلغ يتجاوز رصيد الفاتورة المفتوح'; end if;
  insert into acc.allocations (tenant_id, id, entity_id, source_kind, source_id, invoice_id, amount, date, active, created_by) values (t, aid, pm.entity_id, 'payment', pm.id, inv.id, amt, d, true, auth.uid());
  insert into acc.advance_applications (tenant_id, payment_id, invoice_id, allocation_id, amount, date, created_by) values (t, pm.id, inv.id, aid, amt, d, auth.uid());
  perform app.audit('update', 'advance', pm.id::text, 'تطبيق دفعة مقدمة ' || coalesce(pm.number, '') || ' على فاتورة ' || coalesce(inv.number, '') || ' بمبلغ ' || amt);
  return jsonb_build_object('allocation', aid, 'free', free - amt);
end $$;

create or replace function public.advance_unapply(p jsonb) returns jsonb language plpgsql security definer set search_path = public, app, acc as $$
declare t uuid := app.need('payments', 'post'); a acc.advance_applications;
begin
  select * into a from acc.advance_applications where tenant_id = t and id = (p->>'id')::uuid;
  if a.id is null or not exists (select 1 from acc.payments where tenant_id = t and id = a.payment_id and entity_id = any(app.ents())) then raise exception 'التطبيق غير موجود'; end if;
  update acc.allocations set active = false where tenant_id = t and id = a.allocation_id;
  delete from acc.advance_applications where tenant_id = t and id = a.id;
  perform app.audit('update', 'advance', a.payment_id::text, 'إلغاء تطبيق دفعة مقدمة بمبلغ ' || a.amount); return jsonb_build_object('ok', true);
end $$;

-- مُحكَم للحسابات 1.6 — عروض الأسعار وأوامر البيع (ميزة اختيارية sales_orders)
-- مستند غير محاسبي (لا قيود): عرض سعر ← أمر بيع ← فاتورة مبيعات مسودة عبر inv_save المعتمدة (فتمرّ بكل ضوابطها). الإجماليات تُحسب في الخادم بنسبة الضريبة السارية.
create table if not exists acc.quotes (
  tenant_id uuid not null references acc.tenants(id) on delete cascade, id uuid not null default gen_random_uuid(), entity_id uuid not null, kind text not null check (kind in ('quote','order')),
  number bigint, date date not null, valid_until date, party_id uuid not null, lines jsonb not null, subtotal numeric(18,2) not null default 0, tax_total numeric(18,2) not null default 0, total numeric(18,2) not null default 0,
  status text not null default 'draft' check (status in ('draft','sent','accepted','rejected','converted','cancelled')), notes text not null default '', parent_id uuid, invoice_id uuid,
  created_by uuid, created_at timestamptz not null default now(), updated_at timestamptz not null default now(),
  primary key (tenant_id, id), foreign key (tenant_id, entity_id) references acc.entities (tenant_id, id), foreign key (tenant_id, party_id) references acc.parties (tenant_id, id));
create index if not exists quotes_q on acc.quotes (tenant_id, entity_id, kind, date desc);
alter table acc.quotes enable row level security;
insert into app.feature_cat (key, name, grp, core, since, sort) values ('sales_orders', 'عروض الأسعار وأوامر البيع', 'المبيعات', false, 1, 30)
on conflict (key) do update set name = excluded.name, grp = excluded.grp, core = excluded.core, sort = excluded.sort;

create or replace function public.quote_save(p jsonb) returns jsonb language plpgsql security definer set search_path = public, app, acc as $$
declare t uuid := app.need('sales', case when nullif(p->>'id','') is null then 'add' else 'edit' end); v uuid := nullif(p->>'id','')::uuid; e uuid := (p->>'entity')::uuid; k text := coalesce(p->>'kind','quote'); d date := coalesce(nullif(p->>'date','')::date, current_date);
  l jsonb; net numeric; tx numeric; sub numeric := 0; tt numeric := 0; tcode text; tc acc.tax_codes; cur acc.quotes; ls jsonb := '[]'::jsonb; no bigint;
begin
  if not app.feat_on('sales_orders') then raise exception 'الميزة غير مفعّلة لشركتك'; end if;
  if e is null or not (e = any(app.ents())) then raise exception 'كيان غير مسموح'; end if;
  if k not in ('quote','order') then raise exception 'نوع غير صالح'; end if;
  if not exists (select 1 from acc.parties where tenant_id = t and id = (p->>'party')::uuid and kind in ('customer','both')) then raise exception 'اختر عميلًا صالحًا'; end if;
  if jsonb_typeof(p->'lines') <> 'array' or jsonb_array_length(p->'lines') = 0 then raise exception 'أضف سطرًا واحدًا على الأقل'; end if;
  for l in select * from jsonb_array_elements(p->'lines') loop
    if coalesce((l->>'qty')::numeric, 0) <= 0 or coalesce((l->>'unit_price')::numeric, -1) < 0 then raise exception 'الكمية والسعر غير صالحين'; end if;
    net := round((l->>'qty')::numeric * (l->>'unit_price')::numeric - coalesce(nullif(l->>'discount','')::numeric, 0), 2); if net < 0 then raise exception 'الخصم أكبر من قيمة السطر'; end if;
    tcode := nullif(l->>'tax_code',''); tx := 0;
    if tcode is not null then select * into tc from acc.tax_codes where tenant_id = t and code = tcode and active; if tc.code is null then raise exception 'رمز ضريبة غير موجود'; end if; tx := round(net * app.tax_rate_on(t, tc.code, d, tc.rate) / 100, 2); end if;
    sub := sub + net; tt := tt + tx; ls := ls || jsonb_build_array(l || jsonb_build_object('net', net, 'tax', tx));
  end loop;
  if v is null then
    no := app.next_no(t, e, case when k = 'quote' then 'QT' else 'SO' end, extract(year from d)::int);
    insert into acc.quotes (tenant_id, entity_id, kind, number, date, valid_until, party_id, lines, subtotal, tax_total, total, notes, parent_id, created_by) values (t, e, k, no, d, nullif(p->>'valid_until','')::date, (p->>'party')::uuid, ls, sub, tt, sub + tt, coalesce(p->>'notes',''), nullif(p->>'parent','')::uuid, auth.uid()) returning id into v;
  else
    select * into cur from acc.quotes where tenant_id = t and id = v and entity_id = any(app.ents()) for update; if cur.id is null then raise exception 'المستند غير موجود'; end if;
    if cur.status not in ('draft','sent') then raise exception 'لا يُعدَّل مستند بعد قبوله أو تحويله'; end if;
    update acc.quotes set date = d, valid_until = nullif(p->>'valid_until','')::date, party_id = (p->>'party')::uuid, lines = ls, subtotal = sub, tax_total = tt, total = sub + tt, notes = coalesce(p->>'notes',''), updated_at = now() where tenant_id = t and id = v;
  end if;
  perform app.audit('upsert', 'quote', v::text, case when k = 'quote' then 'عرض سعر ' else 'أمر بيع ' end || sub + tt); return jsonb_build_object('id', v, 'total', sub + tt);
end $$;

create or replace function public.quote_list(p jsonb default '{}') returns jsonb language plpgsql stable security definer set search_path = public, app, acc as $$
declare t uuid := app.need('sales', 'view'); ents uuid[] := app.pick_ents(p); k text := nullif(p->>'kind','');
begin
  if not app.feat_on('sales_orders') then raise exception 'الميزة غير مفعّلة لشركتك'; end if;
  return coalesce((select jsonb_agg(to_jsonb(q) - 'tenant_id' - 'lines' || jsonb_build_object('party_name', (select name from acc.parties x where x.tenant_id = t and x.id = q.party_id), 'expired', (q.status in ('draft','sent') and q.valid_until is not null and q.valid_until < current_date)) order by q.date desc, q.number desc)
    from acc.quotes q where q.tenant_id = t and q.entity_id = any(ents) and (k is null or q.kind = k)), '[]'::jsonb);
end $$;

create or replace function public.quote_get(p jsonb) returns jsonb language plpgsql stable security definer set search_path = public, app, acc as $$
declare t uuid := app.need('sales', 'view'); q acc.quotes;
begin
  select * into q from acc.quotes where tenant_id = t and id = (p->>'id')::uuid and entity_id = any(app.ents()); if q.id is null then raise exception 'المستند غير موجود'; end if;
  return to_jsonb(q) - 'tenant_id' || jsonb_build_object('party_name', (select name from acc.parties x where x.tenant_id = t and x.id = q.party_id));
end $$;

create or replace function public.quote_status(p jsonb) returns jsonb language plpgsql security definer set search_path = public, app, acc as $$
declare t uuid := app.need('sales', 'edit'); q acc.quotes; ns text := p->>'status';
begin
  select * into q from acc.quotes where tenant_id = t and id = (p->>'id')::uuid and entity_id = any(app.ents()) for update; if q.id is null then raise exception 'المستند غير موجود'; end if;
  if not ((q.status = 'draft' and ns in ('sent','cancelled')) or (q.status = 'sent' and ns in ('accepted','rejected','cancelled','draft')) or (q.status = 'accepted' and ns = 'cancelled')) then raise exception 'لا يمكن الانتقال من «%» إلى «%»', q.status, ns; end if;
  update acc.quotes set status = ns, updated_at = now() where tenant_id = t and id = q.id; perform app.audit('update', 'quote', q.id::text, q.status || ' ← ' || ns); return jsonb_build_object('ok', true);
end $$;

-- تحويل: عرض مقبول → أمر بيع، أو عرض/أمر مقبول → فاتورة مبيعات مسودة (عبر inv_save فتمرّ بضوابطها ودورة الاعتماد)
create or replace function public.quote_convert(p jsonb) returns jsonb language plpgsql security definer set search_path = public, app, acc as $$
declare t uuid := app.need('sales', 'add'); q acc.quotes; to_ text := p->>'to'; r jsonb; ls jsonb;
begin
  select * into q from acc.quotes where tenant_id = t and id = (p->>'id')::uuid and entity_id = any(app.ents()) for update; if q.id is null then raise exception 'المستند غير موجود'; end if;
  if q.status <> 'accepted' then raise exception 'يجب أن يكون المستند «مقبولًا» قبل التحويل'; end if;
  if to_ = 'order' then
    if q.kind <> 'quote' then raise exception 'التحويل إلى أمر بيع من عرض سعر فقط'; end if;
    r := public.quote_save(jsonb_build_object('entity', q.entity_id, 'kind', 'order', 'party', q.party_id, 'date', current_date, 'lines', q.lines, 'notes', q.notes, 'parent', q.id));
    update acc.quotes set status = 'converted', updated_at = now() where tenant_id = t and id = q.id;
    update acc.quotes set status = 'accepted' where tenant_id = t and id = (r->>'id')::uuid;
    return r;
  elsif to_ = 'invoice' then
    select jsonb_agg(jsonb_build_object('description', x->>'description', 'qty', x->'qty', 'unit_price', x->'unit_price', 'discount', coalesce(x->'discount', '0'::jsonb), 'account', x->>'account', 'tax_code', x->>'tax_code', 'item', x->>'item')) into ls from jsonb_array_elements(q.lines) x;
    r := public.inv_save(jsonb_build_object('kind', 'sales', 'entity', q.entity_id, 'party', q.party_id, 'date', current_date, 'notes', q.notes, 'lines', ls));
    update acc.quotes set status = 'converted', invoice_id = (r->>'id')::uuid, updated_at = now() where tenant_id = t and id = q.id;
    perform app.audit('update', 'quote', q.id::text, 'تحويل إلى فاتورة مبيعات مسودة'); return r;
  end if;
  raise exception 'وجهة التحويل غير صالحة';
end $$;

do $$ begin
  if not exists (select 1 from app.schema_migrations where version = '1.6.1.0') then  -- مرة واحدة: تقفل الميزة الجديدة على الشركات القائمة (غير التجريبية)
    update acc.tenants set features_off = (select coalesce(array_agg(distinct k), '{}') from unnest(coalesce(features_off, '{}') || array['sales_orders']) k) where not (coalesce(settings, '{}'::jsonb) ? 'demo') and created_at < now();
  end if;
end $$;
insert into app.schema_migrations (version, name) values ('1.6.1.0', 'الدفعات المقدمة، عروض الأسعار وأوامر البيع') on conflict (version) do nothing;
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
