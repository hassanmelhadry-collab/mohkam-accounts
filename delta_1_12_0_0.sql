-- 1.11.7.0 → 1.12.0.0 delta (إضافي ومتكرر التشغيل): نموذج التراخيص — المرحلة 1
-- 1.12.0.0 (المرحلة 1 من الوحدة المشتركة) — نموذج التراخيص: نوع الشركة + الباقة + إضافات/إيقافات بتاريخ + دالة استحقاق واحدة.
-- الناتج = الباقة + الإضافات − الإيقافات. شركة بلا باقة (plan_code فارغ) تعمل كما هي اليوم تمامًا (features_off)؛ فلا يتغيّر سلوك أي شركة قائمة.
-- الفرض في الخادم: app.feat_on هي المصدر الوحيد، وتستعملها كل دالة ميزة. الحدود تُنسخ من الباقة إلى max_users/max_entities عند التعيين فيبقى فحص الحد كما هو.
-- متكرر التشغيل. التراجع: rollback_1_12_0_0.sql
create table if not exists app.plans (
  code text primary key check (code ~ '^[a-z0-9_-]{2,30}$'), name text not null, features text[] not null default '{}', max_users int check (max_users is null or max_users >= 1), max_entities int check (max_entities is null or max_entities >= 1),
  active boolean not null default true, created_at timestamptz not null default now());
alter table app.plans enable row level security;
alter table acc.tenants add column if not exists kind text not null default 'licensed';
do $$ begin if not exists (select 1 from pg_constraint where conname = 'tenants_kind_chk') then alter table acc.tenants add constraint tenants_kind_chk check (kind in ('vendor', 'licensed', 'demo')); end if; end $$;
update acc.tenants set kind = 'demo' where settings ? 'demo' and kind = 'licensed';
alter table acc.tenants add column if not exists plan_code text references app.plans(code);
create index if not exists tenants_plan_code_idx on acc.tenants (plan_code);
create table if not exists acc.tenant_features (
  tenant_id uuid not null references acc.tenants(id) on delete cascade, id uuid not null default gen_random_uuid(), feature_key text not null, mode text not null check (mode in ('add', 'remove')),
  starts_on date, ends_on date, note text not null default '', created_by uuid, created_at timestamptz not null default now(), primary key (tenant_id, id), check (ends_on is null or starts_on is null or ends_on >= starts_on));
create index if not exists tenant_features_idx on acc.tenant_features (tenant_id, feature_key);
alter table acc.tenant_features enable row level security;

-- المصدر الوحيد لقرار الميزة: بوابة الإصدار ← الأساسية مفتوحة ← بلا باقة (السلوك القديم) ← الباقة + الإضافات الفعّالة − الإيقافات الفعّالة
create or replace function app.feat_on(k text, t uuid default null) returns boolean language sql stable security definer set search_path = public, acc, app as $$
  select coalesce((select case
      when coalesce((select c.since from app.feature_cat c where c.key = k), 1) > x.release then false
      when coalesce((select c.core from app.feature_cat c where c.key = k), false) then true
      when x.plan_code is null then not (k = any(x.features_off))
      else (k = any(coalesce(p.features, '{}')) or exists (select 1 from acc.tenant_features f where f.tenant_id = x.id and f.feature_key = k and f.mode = 'add' and (f.starts_on is null or f.starts_on <= current_date) and (f.ends_on is null or f.ends_on >= current_date)))
        and not exists (select 1 from acc.tenant_features f where f.tenant_id = x.id and f.feature_key = k and f.mode = 'remove' and (f.starts_on is null or f.starts_on <= current_date) and (f.ends_on is null or f.ends_on >= current_date))
    end from acc.tenants x left join app.plans p on p.code = x.plan_code where x.id = coalesce(t, app.tenant())), true) $$;
create or replace function app.features_off(t uuid) returns jsonb language sql stable security definer set search_path = public, acc, app as $$
  select coalesce((select jsonb_agg(c.key order by c.sort) from app.feature_cat c where not c.core and exists (select 1 from acc.tenants x where x.id = t) and not app.feat_on(c.key, t)), '[]'::jsonb) $$;

-- الاستحقاق الكامل لشركة (للبائع وللواجهة)
create or replace function app.entitlements(t uuid) returns jsonb language sql stable security definer set search_path = public, acc, app as $$
  select jsonb_build_object('kind', x.kind, 'plan', x.plan_code, 'max_users', x.max_users, 'max_entities', x.max_entities, 'release', x.release,
    'features', coalesce((select jsonb_agg(jsonb_build_object('key', c.key, 'name', c.name, 'grp', c.grp, 'core', c.core, 'on', app.feat_on(c.key, t),
        'source', case when c.core then 'core' when x.plan_code is null then 'legacy' when exists (select 1 from acc.tenant_features f where f.tenant_id = x.id and f.feature_key = c.key and f.mode = 'remove' and (f.starts_on is null or f.starts_on <= current_date) and (f.ends_on is null or f.ends_on >= current_date)) then 'removed'
          when c.key = any(coalesce(p.features, '{}')) then 'plan' when app.feat_on(c.key, t) then 'addon' else 'none' end) order by c.sort) from app.feature_cat c), '[]'::jsonb),
    'overrides', coalesce((select jsonb_agg(jsonb_build_object('id', f.id, 'feature', f.feature_key, 'mode', f.mode, 'starts_on', f.starts_on, 'ends_on', f.ends_on, 'note', f.note) order by f.created_at) from acc.tenant_features f where f.tenant_id = x.id), '[]'::jsonb))
  from acc.tenants x left join app.plans p on p.code = x.plan_code where x.id = t $$;
create or replace function public.my_entitlements(p jsonb default '{}') returns jsonb language sql stable security definer set search_path = public, acc, app as $$ select app.entitlements(app.tenant()) $$;

-- أدوات البائع (تسجَّل كلها في سجل المنصة)
create or replace function public.platform_plan_save(p jsonb) returns jsonb language plpgsql security definer set search_path = public, app, acc as $$
declare c text := lower(trim(p->>'code')); f text[] := coalesce((select array_agg(distinct x) from jsonb_array_elements_text(coalesce(p->'features', '[]')) x), '{}'); mu int := nullif(p->>'max_users', '')::int; me int := nullif(p->>'max_entities', '')::int; bad text[];
begin
  perform app.demo_admin();
  if c is null or c !~ '^[a-z0-9_-]{2,30}$' then raise exception 'رمز الباقة: حروف إنجليزية صغيرة وأرقام (2–30)'; end if;
  if length(trim(coalesce(p->>'name', ''))) < 2 then raise exception 'اسم الباقة مطلوب'; end if;
  select array_agg(x) into bad from unnest(f) x where not exists (select 1 from app.feature_cat k where k.key = x and not k.core);
  if bad is not null then raise exception 'ميزات غير معروفة أو أساسية: %', array_to_string(bad, ','); end if;
  if (mu is not null and mu < 1) or (me is not null and me < 1) then raise exception 'الحدود أرقام موجبة (أو فارغة = بلا حد)'; end if;
  insert into app.plans (code, name, features, max_users, max_entities, active) values (c, trim(p->>'name'), f, mu, me, coalesce((p->>'active')::boolean, true))
    on conflict (code) do update set name = excluded.name, features = excluded.features, max_users = excluded.max_users, max_entities = excluded.max_entities, active = excluded.active;
  perform app.padmin_log('plan_save', c, left(p::text, 400));
  return jsonb_build_object('ok', true, 'code', c);
end $$;
create or replace function public.platform_plans_list(p jsonb default '{}') returns jsonb language plpgsql stable security definer set search_path = public, app, acc as $$
begin perform app.demo_admin();
  return coalesce((select jsonb_agg(jsonb_build_object('code', p.code, 'name', p.name, 'features', to_jsonb(p.features), 'max_users', p.max_users, 'max_entities', p.max_entities, 'active', p.active, 'tenants', (select count(*) from acc.tenants t where t.plan_code = p.code)) order by p.code) from app.plans p), '[]'::jsonb);
end $$;
-- تعيين باقة لشركة (null = العودة إلى السلوك القديم). apply_limits (افتراضي true) تنسخ حدود الباقة إلى الشركة.
create or replace function public.platform_tenant_plan_set(p jsonb) returns jsonb language plpgsql security definer set search_path = public, app, acc as $$
declare t acc.tenants; pl app.plans; pc text := nullif(trim(coalesce(p->>'plan', '')), '');
begin
  perform app.demo_admin();
  select * into t from acc.tenants where code = p->>'code' for update; if t.id is null then raise exception 'الشركة غير موجودة'; end if;
  if pc is not null then select * into pl from app.plans where code = pc and active; if pl.code is null then raise exception 'الباقة غير موجودة أو غير فعّالة'; end if; end if;
  update acc.tenants set plan_code = pc where id = t.id;
  if pc is not null and coalesce((p->>'apply_limits')::boolean, true) then update acc.tenants set max_users = pl.max_users, max_entities = pl.max_entities where id = t.id; end if;
  perform app.padmin_log('tenant_plan_set', t.code, 'الباقة: ' || coalesce(t.plan_code, '—') || ' ← ' || coalesce(pc, '—') || case when pc is not null and coalesce((p->>'apply_limits')::boolean, true) then ' | الحدود: مستخدمون ' || coalesce(pl.max_users::text, '∞') || '، كيانات ' || coalesce(pl.max_entities::text, '∞') else '' end);
  return app.entitlements(t.id);
end $$;
-- إضافة/إيقاف ميزة مفردة لشركة بتاريخ اختياري؛ mode = add | remove | clear (يحذف تجاوزات تلك الميزة)
create or replace function public.platform_tenant_feature_set(p jsonb) returns jsonb language plpgsql security definer set search_path = public, app, acc as $$
declare t acc.tenants; k text := p->>'feature'; m text := p->>'mode'; s date := nullif(p->>'starts_on', '')::date; e date := nullif(p->>'ends_on', '')::date;
begin
  perform app.demo_admin();
  select * into t from acc.tenants where code = p->>'code' for update; if t.id is null then raise exception 'الشركة غير موجودة'; end if;
  if t.plan_code is null then raise exception 'عيّن باقة للشركة أولًا (الإضافات والإيقافات تعمل فوق الباقة)'; end if;
  if not exists (select 1 from app.feature_cat c where c.key = k and not c.core) then raise exception 'ميزة غير معروفة أو أساسية'; end if;
  if m not in ('add', 'remove', 'clear') then raise exception 'النوع: add أو remove أو clear'; end if;
  if e is not null and s is not null and e < s then raise exception 'تاريخ النهاية قبل البداية'; end if;
  if m = 'clear' then delete from acc.tenant_features where tenant_id = t.id and feature_key = k;
  else insert into acc.tenant_features (tenant_id, feature_key, mode, starts_on, ends_on, note, created_by) values (t.id, k, m, s, e, left(coalesce(p->>'note', ''), 300), auth.uid()); end if;
  perform app.padmin_log('tenant_feature_' || m, t.code, k || ' | ' || coalesce(s::text, '—') || ' → ' || coalesce(e::text, '—'));
  return app.entitlements(t.id);
end $$;
create or replace function public.platform_entitlements_get(p jsonb) returns jsonb language plpgsql stable security definer set search_path = public, app, acc as $$
declare t uuid; begin perform app.demo_admin(); select id into t from acc.tenants where code = p->>'code'; if t is null then raise exception 'الشركة غير موجودة'; end if; return app.entitlements(t); end $$;
do $$ declare f text; begin foreach f in array array['public.my_entitlements(jsonb)', 'public.platform_plan_save(jsonb)', 'public.platform_plans_list(jsonb)', 'public.platform_tenant_plan_set(jsonb)', 'public.platform_tenant_feature_set(jsonb)', 'public.platform_entitlements_get(jsonb)'] loop
  execute 'grant execute on function ' || f || ' to authenticated'; execute 'revoke execute on function ' || f || ' from anon, public'; end loop; end $$;
insert into app.schema_migrations (version, name) values ('1.12.0.0', 'نموذج التراخيص (المرحلة 1): نوع الشركة والباقة والإضافات/الإيقافات بتاريخ ودالة الاستحقاق الواحدة') on conflict (version) do nothing;
