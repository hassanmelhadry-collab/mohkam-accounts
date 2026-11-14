-- مُحكَم 1.5.0.4 — توثيق قبول الشروط وسياسة الخصوصية (آمن للتكرار)
-- مُحكَم للحسابات — توثيق قبول الشروط وسياسة الخصوصية عند تسجيل الشركة (الإصدار والوقت والعنوان)
create or replace function public.register_company(p jsonb) returns jsonb language plpgsql security definer set search_path = public, app, acc as $$
declare t uuid := gen_random_uuid(); u uuid; c text := lower(trim(coalesce(p->>'code',''))); ip text := app.client_ip(); un text := lower(trim(coalesce(p->>'username',''))); e uuid := gen_random_uuid();
  country text := upper(coalesce(nullif(p->>'country',''), 'SA')); cur text := upper(coalesce(nullif(p->>'currency',''), 'SAR')); tpl text := coalesce(nullif(p->>'template',''), 'general'); fy date := coalesce(nullif(p->>'fy_start','')::date, make_date(extract(year from current_date)::int, 1, 1));
begin
  perform app.signup_gate(p);
  if c !~ '^[a-z0-9][a-z0-9-]{2,30}$' then raise exception 'رمز الشركة: 3 إلى 31 حرفًا إنجليزيًا صغيرًا أو أرقامًا أو شرطة'; end if;
  if exists (select 1 from acc.tenants where code = c) then raise exception 'رمز الشركة مستخدم — اختر رمزًا آخر'; end if;
  if coalesce(trim(p->>'name'),'') = '' or un = '' then raise exception 'اسم الشركة واسم الدخول مطلوبان'; end if;
  if un !~ '^[a-z0-9._-]{3,40}$' then raise exception 'اسم الدخول بالإنجليزية (حروف وأرقام ونقطة وشرطة)'; end if;
  perform app.check_pw(p->>'password');
  if (select count(*) from acc.tenants where created_at > now() - interval '1 hour') > 60 then raise exception 'محاولات كثيرة — حاول لاحقًا'; end if;
  if ip <> 'unknown' and (select count(*) from acc.tenants where created_ip = ip and created_at > now() - interval '1 hour') >= 5 then raise exception 'محاولات كثيرة من نفس الجهاز — حاول لاحقًا'; end if;
  insert into acc.tenants (id, code, name, name_en, cr, vat_no, country, currency, contact_phone, contact_email, plan, max_users, max_entities, created_ip, settings)
  values (t, c, trim(p->>'name'), coalesce(p->>'name_en',''), coalesce(p->>'cr',''), coalesce(p->>'vat_no',''), country, cur, coalesce(p->>'phone',''), coalesce(p->>'email',''), 'P', 200, 100, ip, app.default_settings());
  insert into acc.entities (tenant_id, id, code, name, name_en, vat_no, cr) values (t, e, 'E1', trim(p->>'name'), coalesce(p->>'name_en',''), coalesce(p->>'vat_no',''), coalesce(p->>'cr',''));
  perform app.seed_roles(t);
  if tpl <> 'none' then perform app.apply_template(t, tpl); end if;
  perform app.seed_tax(t, country);
  perform app.make_fy(t, e, fy);
  u := app.make_auth_user(app.login_email(c, un), p->>'password', coalesce(nullif(p->>'display',''), un));
  insert into acc.members (user_id, tenant_id, username, name, role) values (u, t, un, coalesce(nullif(trim(p->>'display'),''), un), 'owner');
  update acc.tenants set settings = settings || jsonb_build_object('terms', jsonb_build_object('v', left(coalesce(nullif(p->>'terms',''), 'none'), 20), 'at', now(), 'ip', ip)) where id = t;
  perform app.audit_for(t, u, un, 'system', 'tenant', t::text, 'تسجيل الشركة وبدء التجربة — قبول الشروط وسياسة الخصوصية: ' || left(coalesce(nullif(p->>'terms',''), 'لم يُسجَّل'), 20));
  return jsonb_build_object('tenant', t, 'email', app.login_email(c, un));
end $$;
