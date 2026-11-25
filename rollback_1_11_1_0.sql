-- تراجع 1.11.1.0
drop function if exists public.wh_delete(jsonb); drop function if exists public.project_delete(jsonb); drop function if exists public.bank_delete(jsonb);
drop function if exists public.budget_delete(jsonb); drop function if exists public.quote_delete(jsonb); drop function if exists public.po_delete(jsonb);
update acc.budgets set status = 'approved' where status = 'inactive';
alter table acc.budgets drop constraint if exists budgets_status_check;
alter table acc.budgets add constraint budgets_status_check check (status in ('draft','approved'));
delete from app.schema_migrations where version = '1.11.1.0';
