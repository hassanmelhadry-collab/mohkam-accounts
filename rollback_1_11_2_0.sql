-- يعيد app.stock_move إلى المسار الأصلي (المتوسط المرجّح) ثم يحذف الإضافات. لا يمس القيود المرحّلة سابقًا.
-- لا تنفّذه إن كانت شركة تستعمل FIFO وبقيت أرصدة؛ أعدها أولًا إلى avg عبر stock_cost_method_set.
create or replace function app.stock_move(t uuid, e uuid, it uuid, d date, dir text, q numeric, ucost numeric, doc uuid, note text) returns numeric language plpgsql security definer set search_path = public, acc as $$
declare b acc.stock_bal; c numeric; nm text;
begin
  insert into acc.stock_bal (tenant_id, entity_id, item_id) values (t, e, it) on conflict do nothing;
  select * into b from acc.stock_bal where tenant_id = t and entity_id = e and item_id = it for update;
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
drop function if exists public.stock_cost_method_set(jsonb); drop function if exists public.stock_cost_method_get(jsonb); drop function if exists public.stock_opening(jsonb);
drop function if exists public.landed_cost_apply(jsonb); drop function if exists public.coa_ifrs18_list(jsonb); drop function if exists public.coa_ifrs18_set(jsonb);
drop function if exists app.fifo_on(uuid);
drop table if exists acc.stock_layers; drop table if exists acc.landed_costs;
update acc.stock_moves set doc_type = 'invoice' where doc_type = 'opening';
update acc.tenants set settings = settings - 'cost_method';
alter table acc.accounts drop constraint if exists accounts_ifrs18_cat_chk; alter table acc.accounts drop column if exists ifrs18_cat;
delete from app.feature_cat where key in ('ifrs18', 'inv_costing'); update acc.tenants set features_off = array_remove(array_remove(features_off, 'ifrs18'), 'inv_costing');
delete from app.schema_migrations where version = '1.11.2.0';
