-- مُحكَم للحسابات — تحديث 1.6.7.0: عزل الكيانات (إصلاح item_list) + صلاحية مؤقتة للمفتش + تسجيل تبديل الشركة — بعد 1.6.6.0

-- ===== sql/054_isolation.sql =====
-- مُحكَم للحسابات 1.6.7 — إغلاق ثغرة عزل واحدة وجدها اختبار التسرّب الشامل (entity_isolation):
-- item_list كانت تجمع رصيد الصنف عبر كل الكيانات حتى لمستخدم محصور على كيان واحد. الآن تجمع كيانات المستخدم المسموحة فقط.
create or replace function public.item_list(p jsonb default '{}') returns jsonb language plpgsql stable security definer set search_path = public, app, acc as $$
declare t uuid := app.need_inv('view'); ents uuid[] := app.pick_ents(p);
begin
  return coalesce((select jsonb_agg(to_jsonb(i) - 'tenant_id' || jsonb_build_object('inv_account', (select code || ' - ' || name from acc.accounts where tenant_id = t and id = i.inv_account_id),
      'qty', coalesce((select sum(b.qty) from acc.stock_bal b where b.tenant_id = t and b.item_id = i.id and b.entity_id = any(ents)), 0)) order by i.code) from acc.items i where i.tenant_id = t), '[]'::jsonb);
end $$;

-- ===== sql/055_entity_access.sql =====
-- مُحكَم للحسابات 1.6.7 — صلاحية دخول مؤقتة (للمفتش/الزائر) + تسجيل تبديل الشركة في سجل التدقيق
-- الفصل بين الشركات يبقى في الخادم عبر members.entities (محصور على كيانات محددة)؛ هذا الملف يضيف تاريخ انتهاء للعضوية وسجل التبديل.
alter table acc.members add column if not exists expires_at date;

-- العضوية الفعّالة = active وغير منتهية (كل بوابات الدوال تمرّ بهذه الدالة)
create or replace function app.me() returns acc.members language sql stable security definer set search_path = public, acc as
$$ select m.* from acc.members m where m.user_id = auth.uid() and m.active and (m.expires_at is null or m.expires_at >= current_date) $$;

create or replace function public.my_profile(p jsonb default '{}') returns jsonb language plpgsql stable security definer set search_path = public, app, acc as $$
declare m acc.members; t acc.tenants;
begin
  select * into m from acc.members where user_id = auth.uid();
  if m.user_id is not null and m.expires_at is not null and m.expires_at < current_date then
    return jsonb_build_object('member', null, 'expired', true, 'platform_admin', app.is_platform_admin(), 'aal', coalesce(auth.jwt()->>'aal','aal1')); end if;
  if m.user_id is null then return jsonb_build_object('member', null, 'platform_admin', app.is_platform_admin(), 'aal', coalesce(auth.jwt()->>'aal','aal1')); end if;
  select * into t from acc.tenants where id = m.tenant_id;
  return jsonb_build_object('member', to_jsonb(m), 'tenant', to_jsonb(t) - 'created_ip', 'role', (select jsonb_build_object('id', r.id, 'name', r.name, 'locked', r.locked, 'perms', r.perms, 'sys', r.sys) from acc.roles r where r.tenant_id = m.tenant_id and r.id = m.role),
    'entities', (select coalesce(jsonb_agg(to_jsonb(e) order by e.code), '[]'::jsonb) from acc.entities e where e.tenant_id = m.tenant_id and e.active and (m.entities is null or e.id = any(m.entities))),
    'policy', jsonb_build_object('journals', app.policy('journals'), 'invoices', app.policy('invoices'), 'payments', app.policy('payments')),
    'platform_admin', app.is_platform_admin(), 'aal', coalesce(auth.jwt()->>'aal','aal1'), 'ok', app.tenant_ok(m.tenant_id), 'features_off', app.features_off(m.tenant_id));
end $$;

-- تحديد/إلغاء تاريخ انتهاء صلاحية مستخدم (مفتش مؤقت مثلًا). مدير المستخدمين فقط؛ المالك لا يُقيَّد بتاريخ؛ لا يعدّل نفسه
create or replace function public.member_set_expiry(p jsonb) returns jsonb language plpgsql security definer set search_path = public, app, acc as $$
declare t uuid := app.need_sys('users'); m acc.members; d date := nullif(p->>'expires_at','')::date;
begin
  select * into m from acc.members where tenant_id = t and user_id = (p->>'user_id')::uuid; if m.user_id is null then raise exception 'المستخدم غير موجود'; end if;
  if m.user_id = auth.uid() then raise exception 'لا يمكنك تقييد صلاحية حسابك بنفسك'; end if;
  if m.role = 'owner' and d is not null then raise exception 'لا يُقيَّد المالك بتاريخ انتهاء'; end if;
  if d is not null and d < current_date then raise exception 'تاريخ الانتهاء يجب ألا يكون في الماضي'; end if;
  update acc.members set expires_at = d where tenant_id = t and user_id = m.user_id;
  perform app.audit('update','user',m.user_id::text, case when d is null then 'إلغاء تاريخ انتهاء صلاحية ' || m.username else 'انتهاء صلاحية ' || m.username || ' في ' || d end);
  return jsonb_build_object('ok', true);
end $$;

-- قائمة المستخدمين تُظهر تاريخ الانتهاء
create or replace function public.members_list(p jsonb default '{}') returns jsonb language plpgsql stable security definer set search_path = public, app, acc as $$
declare t uuid := app.need(null, null);
begin
  if not (app.sys('users') or app.sys('audit')) then raise exception 'ليست لديك صلاحية'; end if;
  return coalesce((select jsonb_agg(jsonb_build_object('user_id', m.user_id, 'username', m.username, 'name', m.name, 'role', m.role, 'entities', m.entities, 'active', m.active, 'must_change', m.must_change, 'expires_at', m.expires_at,
    'last_login', m.last_login, 'created_at', m.created_at, 'mfa', exists (select 1 from auth.mfa_factors f where f.user_id = m.user_id and f.status = 'verified')) order by m.created_at) from acc.members m where m.tenant_id = t), '[]'::jsonb);
exception when undefined_table then
  return coalesce((select jsonb_agg(jsonb_build_object('user_id', m.user_id, 'username', m.username, 'name', m.name, 'role', m.role, 'entities', m.entities, 'active', m.active, 'must_change', m.must_change, 'expires_at', m.expires_at, 'last_login', m.last_login, 'created_at', m.created_at, 'mfa', false) order by m.created_at) from acc.members m where m.tenant_id = t), '[]'::jsonb);
end $$;

-- تسجيل اختيار/تبديل الشركة (من، متى، إلى أي شركة) — للمراجعة والتفتيش
create or replace function public.entity_switch(p jsonb) returns jsonb language plpgsql security definer set search_path = public, app, acc as $$
declare t uuid := app.need(null, null); e uuid := nullif(p->>'entity','')::uuid; nm text;
begin
  if e is null then nm := 'كل الشركات';
  else if not (e = any(app.ents())) then raise exception 'الكيان غير موجود أو غير مسموح لك به'; end if; select name into nm from acc.entities where tenant_id = t and id = e; end if;
  perform app.audit('switch','entity', coalesce(e::text, 'all'), 'اختيار الشركة: ' || coalesce(nm, ''));
  return jsonb_build_object('ok', true);
end $$;
