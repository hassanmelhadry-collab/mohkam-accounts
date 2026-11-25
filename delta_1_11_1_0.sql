-- 1.11.1.0 — دورة حياة الكيانات الستة (قرار 21 نوفمبر): حذف إن لم تكن عليها حركة وإلا إيقاف؛ المسودة تُحذف وما بعدها يُلغى بسبب مكتوب. كله في سجل التدقيق.
-- إضافة فقط (دوال جديدة + سماح بحالة «inactive» للموازنة).
alter table acc.budgets drop constraint if exists budgets_status_check;
alter table acc.budgets add constraint budgets_status_check check (status in ('draft','approved','inactive'));

-- المستودع
create or replace function public.wh_delete(p jsonb) returns jsonb language plpgsql security definer set search_path = public, app, acc as $$
declare t uuid := app.need_inv('delete'); w acc.warehouses; used boolean;
begin
  if not app.feat_on('warehouses') then raise exception 'الميزة غير مفعّلة لشركتك'; end if;
  select * into w from acc.warehouses where tenant_id = t and id = nullif(p->>'id','')::uuid and entity_id = any(app.ents()) for update;
  if w.id is null then raise exception 'المستودع غير موجود'; end if;
  used := exists (select 1 from acc.stock_wh where tenant_id = t and warehouse_id = w.id)
       or exists (select 1 from acc.stock_transfers where tenant_id = t and (from_wh = w.id or to_wh = w.id))
       or exists (select 1 from acc.stock_counts where tenant_id = t and wh_id = w.id);
  if used then
    update acc.warehouses set active = false where tenant_id = t and id = w.id;
    perform app.audit('deactivate', 'warehouse', w.id::text, w.code || ' — عليه حركة فأُوقف ولم يُحذف');
    return jsonb_build_object('action', 'deactivated');
  end if;
  delete from acc.warehouses where tenant_id = t and id = w.id;
  perform app.audit('delete', 'warehouse', w.id::text, w.code || ' — ' || w.name);
  return jsonb_build_object('action', 'deleted');
end $$;

-- المشروع
create or replace function public.project_delete(p jsonb) returns jsonb language plpgsql security definer set search_path = public, app, acc as $$
declare t uuid := app.tenant(); d acc.dims; pr acc.projects; used boolean;
begin
  perform app.prj_chk('edit');
  select * into pr from acc.projects where tenant_id = t and dim_id = nullif(p->>'id','')::uuid and entity_id = any(app.ents()) for update;
  if pr.dim_id is null then raise exception 'المشروع غير موجود'; end if;
  select * into d from acc.dims where tenant_id = t and id = pr.dim_id;
  used := exists (select 1 from acc.journal_lines where tenant_id = t and project_id = pr.dim_id)
       or exists (select 1 from acc.project_wip_runs where tenant_id = t and dim_id = pr.dim_id);
  if used then
    update acc.dims set active = false where tenant_id = t and id = pr.dim_id;
    update acc.projects set status = 'done' where tenant_id = t and dim_id = pr.dim_id;
    perform app.audit('deactivate', 'project', pr.dim_id::text, d.code || ' — عليه حركة فأُوقف ولم يُحذف');
    return jsonb_build_object('action', 'deactivated');
  end if;
  delete from acc.dims where tenant_id = t and id = pr.dim_id;
  perform app.audit('delete', 'project', pr.dim_id::text, d.code || ' — ' || d.name);
  return jsonb_build_object('action', 'deleted');
end $$;

-- الحساب البنكي
create or replace function public.bank_delete(p jsonb) returns jsonb language plpgsql security definer set search_path = public, app, acc as $$
declare t uuid := app.need('bank', 'edit'); b acc.bank_accounts; used boolean;
begin
  select * into b from acc.bank_accounts where tenant_id = t and id = nullif(p->>'id','')::uuid and entity_id = any(app.ents()) for update;
  if b.id is null then raise exception 'الحساب البنكي غير موجود'; end if;
  used := exists (select 1 from acc.bank_lines where tenant_id = t and bank_account_id = b.id)
       or exists (select 1 from acc.journal_lines where tenant_id = t and account_id = b.account_id);
  if used then
    update acc.bank_accounts set active = false where tenant_id = t and id = b.id;
    perform app.audit('deactivate', 'bank_account', b.id::text, b.name || ' — عليه حركة فأُوقف ولم يُحذف');
    return jsonb_build_object('action', 'deactivated');
  end if;
  delete from acc.bank_accounts where tenant_id = t and id = b.id;
  perform app.audit('delete', 'bank_account', b.id::text, b.name);
  return jsonb_build_object('action', 'deleted');
end $$;

-- الموازنة: المسودة تُحذف، والمعتمدة تُوقف
create or replace function public.budget_delete(p jsonb) returns jsonb language plpgsql security definer set search_path = public, app, acc as $$
declare t uuid := app.need('budgets', 'edit'); b acc.budgets;
begin
  select * into b from acc.budgets where tenant_id = t and id = nullif(p->>'id','')::uuid and entity_id = any(app.ents()) for update;
  if b.id is null then raise exception 'الموازنة غير موجودة'; end if;
  if b.status = 'inactive' then raise exception 'الموازنة موقوفة أصلًا'; end if;
  if b.status = 'draft' then
    delete from acc.budgets where tenant_id = t and id = b.id;
    perform app.audit('delete', 'budget', b.id::text, b.name);
    return jsonb_build_object('action', 'deleted');
  end if;
  update acc.budgets set status = 'inactive' where tenant_id = t and id = b.id;
  perform app.audit('deactivate', 'budget', b.id::text, b.name || ' — معتمدة فأُوقفت');
  return jsonb_build_object('action', 'deactivated');
end $$;

-- عرض السعر: المسودة تُحذف، وما بعدها يُلغى بسبب مكتوب
create or replace function public.quote_delete(p jsonb) returns jsonb language plpgsql security definer set search_path = public, app, acc as $$
declare t uuid := app.need('sales', 'edit'); q acc.quotes; rs text := trim(coalesce(p->>'reason',''));
begin
  select * into q from acc.quotes where tenant_id = t and id = nullif(p->>'id','')::uuid and entity_id = any(app.ents()) for update;
  if q.id is null then raise exception 'المستند غير موجود'; end if;
  if q.status = 'draft' then
    delete from acc.quotes where tenant_id = t and id = q.id;
    perform app.audit('delete', 'quote', q.id::text, 'مسودة رقم ' || q.number);
    return jsonb_build_object('action', 'deleted');
  end if;
  if q.status not in ('sent', 'accepted') then raise exception 'لا يمكن إلغاء مستند في حالة «%»', q.status; end if;
  if length(rs) < 3 then raise exception 'سبب الإلغاء مطلوب'; end if;
  update acc.quotes set status = 'cancelled', updated_at = now() where tenant_id = t and id = q.id;
  perform app.audit('cancel', 'quote', q.id::text, q.status || ' ← cancelled — ' || rs);
  return jsonb_build_object('action', 'cancelled');
end $$;

-- أمر الشراء
create or replace function public.po_delete(p jsonb) returns jsonb language plpgsql security definer set search_path = public, app, acc as $$
declare t uuid := app.need('purchases', 'edit'); q acc.po; rs text := trim(coalesce(p->>'reason',''));
begin
  if not app.feat_on('purchase_orders') then raise exception 'الميزة غير مفعّلة لشركتك'; end if;
  select * into q from acc.po where tenant_id = t and id = nullif(p->>'id','')::uuid and entity_id = any(app.ents()) for update;
  if q.id is null then raise exception 'أمر الشراء غير موجود'; end if;
  if q.status = 'draft' then
    delete from acc.po where tenant_id = t and id = q.id;
    perform app.audit('delete', 'po', q.id::text, 'مسودة رقم ' || q.number);
    return jsonb_build_object('action', 'deleted');
  end if;
  if q.status <> 'approved' then raise exception 'لا يمكن إلغاء أمر في حالة «%»', q.status; end if;
  if exists (select 1 from acc.po_receipts where tenant_id = t and po_id = q.id) or exists (select 1 from acc.po_bills where tenant_id = t and po_id = q.id) then raise exception 'عليه استلام أو فواتير — لا يُلغى'; end if;
  if length(rs) < 3 then raise exception 'سبب الإلغاء مطلوب'; end if;
  update acc.po set status = 'cancelled', updated_at = now() where tenant_id = t and id = q.id;
  perform app.audit('cancel', 'po', q.id::text, 'approved ← cancelled — ' || rs);
  return jsonb_build_object('action', 'cancelled');
end $$;

do $$ declare f text; begin foreach f in array array['wh_delete','project_delete','bank_delete','budget_delete','quote_delete','po_delete'] loop
  execute format('grant execute on function public.%I(jsonb) to authenticated', f); execute format('revoke execute on function public.%I(jsonb) from anon, public', f); end loop; end $$;

insert into app.schema_migrations (version, name) values ('1.11.1.0', 'دورة حياة المستودع والمشروع والبنك والموازنة وعرض السعر وأمر الشراء (حذف/إيقاف/إلغاء بسبب)') on conflict (version) do nothing;
