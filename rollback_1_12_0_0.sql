-- تراجع 1.12.0.0: يعيد feat_on/features_off إلى تعريفهما السابق (features_off فقط) ثم يحذف الكائنات الجديدة
create or replace function app.feat_on(k text, t uuid default null) returns boolean language sql stable security definer set search_path = public, acc, app as $$
  select coalesce((select not (k = any(x.features_off)) and coalesce((select c.since from app.feature_cat c where c.key = k), 1) <= x.release from acc.tenants x where x.id = coalesce(t, app.tenant())), true) $$;
create or replace function app.features_off(t uuid) returns jsonb language sql stable security definer set search_path = public, acc, app as $$
  select coalesce((select jsonb_agg(c.key order by c.sort) from app.feature_cat c, acc.tenants x where x.id = t and not c.core and (c.key = any(x.features_off) or c.since > x.release)), '[]'::jsonb) $$;
drop function if exists public.my_entitlements(jsonb); drop function if exists public.platform_plan_save(jsonb); drop function if exists public.platform_plans_list(jsonb); drop function if exists public.platform_tenant_plan_set(jsonb);
drop function if exists public.platform_tenant_feature_set(jsonb); drop function if exists public.platform_entitlements_get(jsonb); drop function if exists app.entitlements(uuid);
alter table acc.tenants drop column if exists plan_code; drop table if exists acc.tenant_features; drop table if exists app.plans;
alter table acc.tenants drop constraint if exists tenants_kind_chk; alter table acc.tenants drop column if exists kind;
delete from app.schema_migrations where version = '1.12.0.0';
