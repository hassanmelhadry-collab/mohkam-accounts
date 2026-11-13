-- تحديث 1.3: قفل التسجيل + RLS + النسخ التجريبية (دلتا فوق التثبيت السابق — آمن للتكرار)

-- إعدادات المنصة + بوابة التسجيل العام (تُغلق عند الإطلاق الفعلي)
create table if not exists app.platform_cfg (key text primary key, value text not null, updated_at timestamptz not null default now());
alter table app.platform_cfg enable row level security;
-- يُرفض التسجيل إذا كان signup_closed=1 إلا برمز دعوة صحيح (signup_invite_hash = sha256 للرمز)
create or replace function app.signup_gate(p jsonb) returns void language plpgsql stable security definer set search_path = public, app as $$
declare closed text; ih text;
begin
  if current_setting('app.demo_seed', true) = '1' then return; end if;
  select value into closed from app.platform_cfg where key = 'signup_closed';
  if coalesce(closed,'0') <> '1' then return; end if;
  select value into ih from app.platform_cfg where key = 'signup_invite_hash';
  if ih is not null and ih <> '' and encode(sha256(convert_to(coalesce(p->>'invite',''), 'UTF8')), 'hex') = ih then return; end if;
  raise exception 'التسجيل العام مغلق — تواصل مع الإدارة للحصول على دعوة';
end $$;

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
  perform app.audit_for(t, u, un, 'system', 'tenant', t::text, 'تسجيل الشركة وبدء التجربة');
  return jsonb_build_object('tenant', t, 'email', app.login_email(c, un));
end $$;
create or replace function app.audit_guard() returns trigger language plpgsql as $$
begin if tg_op = 'DELETE' and current_setting('app.demo_wipe', true) = '1' then return old; end if; raise exception 'سجل التدقيق للإضافة فقط — لا يجوز التعديل أو الحذف'; end $$;
create or replace function app.lines_guard() returns trigger language plpgsql as $$
begin
  if tg_op = 'DELETE' and current_setting('app.demo_wipe', true) = '1' then return old; end if;
  if tg_op = 'INSERT' then
    if exists (select 1 from acc.journals j where j.tenant_id = new.tenant_id and j.id = new.journal_id and j.status in ('posted','reversed')) then
      raise exception 'القيد مرحّل — لا يجوز إضافة أسطر'; end if;
    return new;
  elsif tg_op = 'UPDATE' then
    if old.posted and (to_jsonb(new) - 'reconciled_id') is distinct from (to_jsonb(old) - 'reconciled_id') then raise exception 'القيد مرحّل ولا يجوز تعديل أسطره'; end if;
    return new;
  else
    if old.posted then raise exception 'القيد مرحّل ولا يجوز حذف أسطره'; end if;
    return old;
  end if;
end $$;
create or replace function app.journals_guard() returns trigger language plpgsql as $$
declare d numeric; c numeric;
begin
  if tg_op = 'DELETE' and current_setting('app.demo_wipe', true) = '1' then return old; end if;
  if tg_op = 'DELETE' then
    if old.status <> 'draft' then raise exception 'لا يجوز حذف قيد غير مسودة'; end if;
    return old;
  end if;
  if old.status in ('posted','reversed') then
    if old.status = 'posted' and new.status = 'reversed' and new.reversed_by is not null
       and (to_jsonb(new) - 'status' - 'reversed_by' - 'updated_at') = (to_jsonb(old) - 'status' - 'reversed_by' - 'updated_at') then return new; end if;
    raise exception 'القيد مرحّل ولا يجوز تعديله — استخدم عكس القيد';
  end if;
  if new.status = 'posted' then
    select coalesce(sum(debit),0), coalesce(sum(credit),0) into d, c from acc.journal_lines where tenant_id = new.tenant_id and journal_id = new.id;
    if d <> c or d = 0 then raise exception 'القيد غير متوازن (مدين % / دائن %)', d, c; end if;
    if new.number is null or new.period_id is null or new.hash is null then raise exception 'بيانات الترحيل ناقصة'; end if;
  end if;
  return new;
end $$;
-- تشديد أمني: RLS لجدول القوالب + التحكم في التسجيل العام من لوحة المنصة
alter table app.coa_templates enable row level security;

create or replace function public.platform_signup_set(p jsonb) returns jsonb language plpgsql security definer set search_path = public, app, acc as $$
declare inv text := nullif(trim(coalesce(p->>'invite','')), '');
begin
  if not app.is_platform_admin() then raise exception 'للإدارة العليا فقط'; end if;
  if coalesce((auth.jwt()->>'aal'),'aal1') <> 'aal2' and exists (select 1 from auth.mfa_factors where user_id = auth.uid() and status = 'verified') then raise exception 'يلزم التحقق الثنائي'; end if;
  insert into app.platform_cfg (key, value) values ('signup_closed', case when coalesce((p->>'closed')::boolean, true) then '1' else '0' end)
    on conflict (key) do update set value = excluded.value, updated_at = now();
  if p ? 'invite' then
    if inv is not null and length(inv) < 8 then raise exception 'رمز الدعوة 8 أحرف على الأقل'; end if;
    insert into app.platform_cfg (key, value) values ('signup_invite_hash', coalesce(encode(sha256(convert_to(inv, 'UTF8')), 'hex'), ''))
      on conflict (key) do update set value = excluded.value, updated_at = now();
  end if;
  return public.platform_signup_get('{}');
end $$;
create or replace function public.platform_signup_get(p jsonb default '{}') returns jsonb language plpgsql stable security definer set search_path = public, app, acc as $$
begin
  if not app.is_platform_admin() then raise exception 'للإدارة العليا فقط'; end if;
  return jsonb_build_object('closed', coalesce((select value from app.platform_cfg where key='signup_closed'),'0') = '1',
    'has_invite', coalesce((select value from app.platform_cfg where key='signup_invite_hash'),'') <> '');
end $$;
-- حالة التسجيل العلنية (لواجهة الدخول): هل التسجيل مفتوح؟
create or replace function public.signup_status(p jsonb default '{}') returns jsonb language sql stable security definer set search_path = public, app as $$
  select jsonb_build_object('closed', coalesce((select value from app.platform_cfg where key='signup_closed'),'0') = '1', 'invite', coalesce((select value from app.platform_cfg where key='signup_invite_hash'),'') <> '') $$;

-- النسخ التجريبية: بيانات مجموعة بخمسة كيانات، إعادة ضبط دورية، وإصدار نسخ باسم الطالب لمدة 1 إلى 3 أيام.
-- تحذير: دوال app.demo_* داخلية؛ الدوال العامة تتطلب مدير منصة (acc.platform_admins).
create or replace function app.demo_seed(p_code text, p_name text, p_pwd text, p_days int, p_for text) returns uuid language plpgsql security definer set search_path = public, app, acc as $$
declare
  old_sub text;
  r jsonb; t uuid; owner_id uuid; v jsonb; i int; k int; d date; inv uuid; tot numeric; n int;
  ents uuid[] := '{}'; e uuid; ecode text;
  bank text; bank2 text; cap text; sal text; rent text; util text; fees text; mat text; vin text; vout text; fa_acc text; fa_acc2 text; ac_acc text; ac_acc2 text; dep text;
  custs uuid[]; sups uuid[]; bid uuid;
  -- الكيانات: الرمز | الاسم | الرقم الضريبي | السجل | نشاط | حساب الإيراد | حساب التكلفة | معامل الحجم
  prof text[][] := array[
    ['F1','مصنع الشرق للصناعات الغذائية','300111222300003','1010111222','manufacturing','4101','5201','1.0'],
    ['T1','شركة النخبة للتجارة العامة','300222333400003','1010222333','trading','4101','5104','0.8'],
    ['C1','شركة البنيان للمقاولات','300333444500003','1010333444','contracting','4103','5105','1.4'],
    ['S1','شركة سحاب للحلول التقنية','300444555600003','1010444555','services','4102','5102','0.6'],
    ['R1','شركة الواحة للعقارات والضيافة','300555666700003','1010555666','realestate','4102','5102','0.9']];
  cn text[][] := array[
    ['شركة الأفق للمقاولات','مؤسسة النخبة التجارية','مجموعة الرياض للتطوير','شركة واحة الخليج','مؤسسة البناء الذكي','مكتب الفارس الهندسي'],
    ['مؤسسة الندى للتوزيع','شركة الصفوة للأسواق','مؤسسة الريان التجارية','شركة المدار للتجزئة','مؤسسة الجود للتموين','شركة الأثير للتسويق'],
    ['شركة الإعمار الحديثة','مؤسسة الواحات العقارية','شركة الخليج للتطوير','مؤسسة الرواد للإنشاء','شركة السهم للمشاريع','مؤسسة التقدم الوطنية'],
    ['شركة الأفكار للتجارة','مؤسسة الجسور للأعمال','شركة النمو للاستثمار','مؤسسة الوعد للخدمات','شركة المرتكز للأنظمة','مؤسسة الإتقان للتسويق'],
    ['شركة ضيافة المدينة','مؤسسة الراحة للفنادق','شركة السفر الذهبي','مؤسسة اللقاء للفعاليات','شركة الأمان للتشغيل','مؤسسة الرحاب للسكن']];
  sn text[][] := array[
    ['مؤسسة الحبوب الوطنية','شركة العبوات المتحدة','مورد الطاقة والكهرباء','شركة الألواح والتغليف','مؤسسة النقل واللوجستيات'],
    ['شركة الاستيراد الأولى','مؤسسة الجملة المركزية','شركة الشحن السريع','مؤسسة التخزين الآمن','شركة الأصناف المتنوعة'],
    ['مؤسسة الحديد الوطنية','شركة الخرسانة المتحدة','شركة الأدوات الصناعية','مؤسسة النقل الثقيل','شركة الدهانات الحديثة'],
    ['شركة الخوادم والسحابة','مؤسسة التراخيص الرقمية','شركة الأجهزة المتقدمة','مؤسسة الاتصالات','شركة الاستشارات التقنية'],
    ['شركة الصيانة الشاملة','مؤسسة المفروشات الفاخرة','شركة النظافة والتشغيل','مؤسسة الطاقة والمياه','شركة الأمن والحراسة']];
  att jsonb; emp_user uuid; emp_party uuid; pf numeric; sc numeric; rev text; cogs text; sdesc text[]; pdesc text; base_sal numeric; base_rent numeric; ob numeric; pr text[];
begin
  perform set_config('app.demo_seed','1',true); old_sub := current_setting('request.jwt.claim.sub', true);
  r := public.register_company(jsonb_build_object('code',p_code,'name',p_name,'username','owner','display','المالك — نسخة تجريبية','password',p_pwd,'template','manufacturing','country','SA','currency','SAR'));
  t := (r->>'tenant')::uuid; update acc.tenants set created_ip = 'demo' where id = t;
  select user_id into owner_id from acc.members where tenant_id = t and role = 'owner';
  update acc.tenants set max_users = null, max_entities = null, status = 'trial', expires_at = case when p_days is null then current_date + 36500 else current_date + p_days - 7 end,
    settings = settings || jsonb_build_object('demo', jsonb_build_object('for', coalesce(p_for,''), 'days', p_days, 'issued', now())) where id = t;
  perform set_config('request.jwt.claim.sub', owner_id::text, true);

  select settings->'controls'->'attach' into att from acc.tenants where id = t;
  perform public.settings_set(jsonb_build_object('settings', jsonb_build_object('controls', jsonb_build_object('attach', jsonb_build_object('journal',-1,'purchase',-1,'sales',-1,'payment',-1,'receipt',-1)))));
  select code into cap from acc.accounts where tenant_id = t and system_key = 'CAPITAL';
  select code into sal from acc.accounts where tenant_id = t and system_key = 'SALARIES';
  select code into mat from acc.accounts where tenant_id = t and system_key = 'PURCHASES';
  select code into dep from acc.accounts where tenant_id = t and system_key = 'DEP_EXP';
  select code into bank from acc.accounts where tenant_id = t and code = '110103';
  select code into bank2 from acc.accounts where tenant_id = t and code = '110104';
  select code into vin from acc.tax_codes where tenant_id = t and kind = 'input' order by code limit 1;
  select code into vout from acc.tax_codes where tenant_id = t and kind = 'output' order by code limit 1;
  for i in 5..9 loop v := public.coa_upsert(jsonb_build_object('code','11011' || (i-4),'name','البنك — حساب كيان ' || (i-4),'type','asset','subtype','bank','parent_code','1101','is_group',false)); end loop;
  rent := '6105'; util := '6106'; fees := '6116';

  for k in 1..5 loop
    pr := array[prof[k][1],prof[k][2],prof[k][3],prof[k][4],prof[k][5],prof[k][6],prof[k][7],prof[k][8]];
    sc := pr[8]::numeric; pf := (array[1.55,1.4,1.65,1.9,1.8])[k]; rev := pr[6]; cogs := pr[7];
    if k = 1 then select id into e from acc.entities where tenant_id = t order by code limit 1;
      v := public.entity_upsert(jsonb_build_object('id', e, 'code', pr[1], 'name', pr[2], 'vat_no', pr[3], 'cr', pr[4], 'active', true));
    else
      v := public.entity_upsert(jsonb_build_object('code', pr[1], 'name', pr[2], 'vat_no', pr[3], 'cr', pr[4], 'active', true)); e := (v->>'id')::uuid;
      perform app.make_fy(t, e, date '2026-01-01');
    end if;
    ents := ents || e;
    -- حساب بنكي لكل كيان
    v := public.bank_upsert(jsonb_build_object('entity', e, 'name', 'الحساب الجاري — ' || pr[1], 'account', '11011' || k, 'bank_name', case k when 1 then 'بنك الخليج الوطني' when 2 then 'بنك الرياض التجاري' when 3 then 'بنك الأفق' when 4 then 'بنك النخيل' else 'بنك المدينة' end, 'iban', 'SA' || lpad((k * 1111111)::text, 22, '0')));
    bid := (v->>'id')::uuid;
    bank := '11011' || k;

    -- رأس المال والرصيد الافتتاحي
    ob := round(900000 * sc, 0);
    v := public.je_save(jsonb_build_object('entity',e,'type','OB','date','2026-01-01','description','رصيد افتتاحي — رأس المال والبنك','lines',jsonb_build_array(
      jsonb_build_object('account',bank,'debit',ob,'credit',0), jsonb_build_object('account',cap,'debit',0,'credit',ob))));
    perform public.je_post(jsonb_build_object('id', v->>'id'));

    -- الأطراف
    custs := '{}'; sups := '{}';
    for i in 1..6 loop v := public.party_upsert(jsonb_build_object('name', cn[k][i], 'kind','customer','credit_limit', round(300000 * sc, 0), 'vat_no', '3' || lpad((k*100+i)::text, 14, '0'))); custs := custs || (v->>'id')::uuid; end loop;
    for i in 1..5 loop v := public.party_upsert(jsonb_build_object('name', sn[k][i], 'kind','supplier', 'vat_no', '3' || lpad((k*1000+i)::text, 14, '0'))); sups := sups || (v->>'id')::uuid; end loop;

    sdesc := case pr[5] when 'manufacturing' then array['بيع منتجات غذائية معبأة','بيع منتجات نصف مصنعة']
      when 'trading' then array['بيع بضاعة جملة','بيع بضاعة تجزئة'] when 'contracting' then array['مستخلص أعمال مدنية','مستخلص تشطيبات وتركيبات']
      when 'services' then array['اشتراك منصة سحابية','خدمات تطوير وتكامل'] else array['إيرادات إيجار وحدات','إيرادات ضيافة وفعاليات'] end;
    pdesc := case pr[5] when 'manufacturing' then 'مواد خام وتعبئة' when 'trading' then 'شراء بضاعة للبيع' when 'contracting' then 'مواد ومقاولو باطن' when 'services' then 'تراخيص واستضافة' else 'صيانة وتشغيل وتجهيزات' end;

    -- مبيعات وتحصيلات (يناير–أكتوبر)
    n := 28 + k;
    for i in 1..n loop
      d := date '2026-01-04' + ((i * 10) % 300);
      v := public.inv_save(jsonb_build_object('kind','sales','entity',e,'party',custs[1 + (i + k) % 6],'date',d,'lines',jsonb_build_array(
        jsonb_build_object('description',sdesc[1],'account',rev,'qty',1 + i % 5,'unit_price',round((2800 + (i * 437) % 9000) * sc * pf, 0),'tax_code',vout),
        jsonb_build_object('description',sdesc[2],'account',rev,'qty',2,'unit_price',round((1500 + (i * 211) % 3000) * sc * pf, 0),'tax_code',vout))));
      inv := (v->>'id')::uuid; perform public.inv_issue(jsonb_build_object('id',inv));
      tot := (public.inv_get(jsonb_build_object('id',inv))->>'total')::numeric;
      if i % 4 <> 0 and d + 20 < current_date then
        v := public.pay_save(jsonb_build_object('kind','receipt','entity',e,'party',custs[1 + (i + k) % 6],'date',least(d + 12 + i % 20, current_date - 1),'amount',case when i % 3 = 0 then round(tot * 0.6, 2) else tot end,'cash_account',bank,
          'allocations',jsonb_build_array(jsonb_build_object('invoice',inv,'amount',case when i % 3 = 0 then round(tot * 0.6, 2) else tot end))));
        perform public.pay_post(jsonb_build_object('id', v->>'id'));
      end if;
    end loop;

    -- مشتريات ومدفوعات
    for i in 1..(14 + k) loop
      d := date '2026-01-08' + ((i * 19) % 290);
      v := public.inv_save(jsonb_build_object('kind','purchase','entity',e,'party',sups[1 + (i + k) % 5],'date',d,'supplier_ref','S' || k || '-' || (1000 + i),'lines',jsonb_build_array(
        jsonb_build_object('description',pdesc,'account',cogs,'qty',3 + i % 4,'unit_price',round((2400 + (i * 331) % 5000) * sc, 0),'tax_code',vin))));
      inv := (v->>'id')::uuid; perform public.inv_issue(jsonb_build_object('id',inv));
      tot := (public.inv_get(jsonb_build_object('id',inv))->>'total')::numeric;
      if i % 3 <> 0 and d + 15 < current_date then
        v := public.pay_save(jsonb_build_object('kind','payment','entity',e,'party',sups[1 + (i + k) % 5],'date',least(d + 10, current_date - 1),'amount',tot,'cash_account',bank,
          'allocations',jsonb_build_array(jsonb_build_object('invoice',inv,'amount',tot))));
        perform public.pay_post(jsonb_build_object('id', v->>'id'));
      end if;
    end loop;

    -- مصروفات شهرية
    base_sal := round(52000 * sc, 0); base_rent := round(9000 * sc, 0);
    for i in 1..10 loop
      v := public.je_save(jsonb_build_object('entity',e,'type','GJ','date',make_date(2026,i,27),'description','رواتب شهر ' || i,'lines',jsonb_build_array(
        jsonb_build_object('account',sal,'debit',base_sal + (i % 3) * 800,'credit',0), jsonb_build_object('account',bank,'debit',0,'credit',base_sal + (i % 3) * 800))));
      perform public.je_post(jsonb_build_object('id', v->>'id'));
      v := public.je_save(jsonb_build_object('entity',e,'type','GJ','date',make_date(2026,i,28),'description','إيجار ومرافق — شهر ' || i,'lines',jsonb_build_array(
        jsonb_build_object('account',rent,'debit',base_rent,'credit',0), jsonb_build_object('account',util,'debit',round(base_rent * 0.18, 0),'credit',0),
        jsonb_build_object('account',fees,'debit',350,'credit',0), jsonb_build_object('account',bank,'debit',0,'credit',base_rent + round(base_rent * 0.18, 0) + 350))));
      perform public.je_post(jsonb_build_object('id', v->>'id'));
    end loop;

    -- أصول ثابتة وإهلاك
    perform public.asset_upsert(jsonb_build_object('entity',e,'code','FA-' || pr[1] || '-1','name', case pr[5] when 'manufacturing' then 'خط تعبئة آلي' when 'contracting' then 'معدات حفر ورافعة' when 'realestate' then 'مبنى إداري وفندقي' when 'services' then 'خوادم ومعدات شبكات' else 'معدات تخزين ونقل' end,
      'acquisition_date','2026-01-02','cost',round(420000 * sc, 0),'salvage',round(20000 * sc, 0),'life_months',96,'asset_account','120103','accum_account','120202','expense_account',dep));
    perform public.asset_upsert(jsonb_build_object('entity',e,'code','FA-' || pr[1] || '-2','name','سيارات ومركبات','acquisition_date','2026-03-01','cost',round(150000 * sc, 0),'salvage',0,'life_months',60,'asset_account','120105','accum_account','120204','expense_account',dep));
    perform public.asset_depreciate(jsonb_build_object('entity', e, 'upto', '2026-10-31'));

    -- كشف حساب بنكي مستورد (إيداعات وسحوبات) ومطابقة آلية
    perform public.bank_import(jsonb_build_object('bank', bid, 'rows', jsonb_build_array(
      jsonb_build_object('date','2026-10-02','amount', round(48000 * sc, 0), 'description','إيداع تحصيل عميل'),
      jsonb_build_object('date','2026-10-15','amount', -round(23500 * sc, 0), 'description','تحويل مورد'),
      jsonb_build_object('date','2026-10-28','amount', -base_sal, 'description','رواتب'),
      jsonb_build_object('date','2026-10-30','amount', -350, 'description','رسوم بنكية'))));
    perform public.bank_auto_match(jsonb_build_object('bank', bid));
  end loop;
  if att is not null then perform public.settings_set(jsonb_build_object('settings', jsonb_build_object('controls', jsonb_build_object('attach', att)))); end if;

  -- مستخدمو الأدوار (للدخول السريع في النسخة التجريبية) — بعد ترحيل البيانات لتعمل دورة الاعتماد
  perform public.admin_create_users(jsonb_build_object('users', jsonb_build_array(
    jsonb_build_object('username','gm','name','المدير العام','role','gm','password',p_pwd,'must_change',false),
    jsonb_build_object('username','cfo','name','المدير المالي','role','cfo','password',p_pwd,'must_change',false),
    jsonb_build_object('username','chief','name','رئيس الحسابات','role','chief','password',p_pwd,'must_change',false),
    jsonb_build_object('username','acct','name','محاسب','role','acct','password',p_pwd,'must_change',false),
    jsonb_build_object('username','ar','name','محاسب العملاء والمبيعات','role','ar','password',p_pwd,'must_change',false),
    jsonb_build_object('username','ap','name','محاسب الموردين والمشتريات','role','ap','password',p_pwd,'must_change',false),
    jsonb_build_object('username','cashier','name','أمين الصندوق والبنوك','role','cashier','password',p_pwd,'must_change',false),
    jsonb_build_object('username','auditor','name','المراجع الداخلي','role','auditor','password',p_pwd,'must_change',false),
    jsonb_build_object('username','employee','name','موظف — بوابة الموظف','role','employee','password',p_pwd,'must_change',false),
    jsonb_build_object('username','viewer','name','مستخدم قراءة فقط','role','viewer','password',p_pwd,'must_change',false))));
  select user_id into emp_user from acc.members where tenant_id = t and username = 'employee';
  v := public.party_upsert(jsonb_build_object('name','موظف — بوابة الموظف','kind','employee')); emp_party := (v->>'id')::uuid;
  insert into acc.employee_links (tenant_id, user_id, party_id) values (t, emp_user, emp_party) on conflict do nothing;
  perform set_config('request.jwt.claim.sub', coalesce(old_sub,''), true); perform set_config('app.demo_seed','0',true);
  return t;
end $$;

-- حذف شركة تجريبية بالكامل (مع مستخدميها). يتجاوز حراس عدم الحذف عبر متغير جلسة داخلي لا تصله واجهة التطبيق.
create or replace function app.demo_wipe(p_code text) returns void language plpgsql security definer set search_path = public, app, acc as $$
declare t uuid; r record; done boolean; pass int; uids uuid[];
begin
  select id into t from acc.tenants where code = p_code and (p_code = 'group5' or settings ? 'demo');
  if t is null then return; end if;
  perform set_config('app.demo_wipe', '1', true);
  uids := array(select user_id from acc.members where tenant_id = t);
  -- حذف الجداول التابعة بالتكرار حتى تُحلّ علاقات المفاتيح الأجنبية (دون الحاجة لصلاحية superuser)
  for pass in 1..10 loop
    done := true;
    for r in select c.table_name from information_schema.columns c join information_schema.tables x on x.table_schema = c.table_schema and x.table_name = c.table_name and x.table_type = 'BASE TABLE'
      where c.table_schema = 'acc' and c.column_name = 'tenant_id' and c.table_name not in ('tenants') loop
      begin execute format('delete from acc.%I where tenant_id = $1', r.table_name) using t;
      exception when foreign_key_violation then done := false; end;
    end loop;
    exit when done;
  end loop;
  delete from auth.users where id = any(uids);
  delete from acc.tenants where id = t;
  perform set_config('app.demo_wipe', '0', true);
end $$;

-- إعادة المجموعة التجريبية الثابتة إلى حالتها الأصلية (تُجدول كل 12 ساعة).
create or replace function app.demo_reset_group() returns uuid language plpgsql security definer set search_path = public, app, acc as $$
begin
  perform app.demo_wipe('group5');
  return app.demo_seed('group5', 'مجموعة الأفق القابضة (نسخة تجريبية)', 'Group#Demo2026x', null, 'عرض عام');
end $$;

-- تنظيف النسخ المُصدرة المنتهية
create or replace function app.demo_cleanup() returns int language plpgsql security definer set search_path = public, app, acc as $$
declare r record; n int := 0;
begin
  for r in select code from acc.tenants where settings ? 'demo' and code <> 'group5' and (settings->'demo'->>'days') is not null and expires_at + 7 < current_date - 1 loop
    perform app.demo_wipe(r.code); n := n + 1; end loop;
  return n;
end $$;

create or replace function app.demo_admin() returns void language plpgsql stable security definer set search_path = public, app, acc as $$
begin if not app.is_platform_admin() then raise exception 'للإدارة العليا فقط'; end if; end $$;

-- إصدار نسخة تجريبية باسم الطالب: {name, days: 1|2|3}
create or replace function public.demo_issue(p jsonb) returns jsonb language plpgsql security definer set search_path = public, app, acc as $$
declare nm text := trim(coalesce(p->>'name','')); d int := coalesce(nullif(p->>'days','')::int, 1); code text; pwd text; t uuid; alphabet text := 'abcdefghjkmnpqrstuvwxyz23456789'; i int;
begin
  perform app.demo_admin();
  if nm = '' or length(nm) > 80 then raise exception 'اسم الطالب مطلوب (حتى 80 حرفًا)'; end if;
  if d not in (1, 2, 3) then raise exception 'المدة 1 أو 2 أو 3 أيام'; end if;
  code := 'demo-'; for i in 1..5 loop code := code || substr(alphabet, 1 + floor(random() * length(alphabet))::int, 1); end loop;
  pwd := 'Dm'; for i in 1..8 loop pwd := pwd || substr(alphabet, 1 + floor(random() * length(alphabet))::int, 1); end loop; pwd := pwd || '#7';
  t := app.demo_seed(code, 'نسخة تجريبية — ' || nm, pwd, d, nm);
  return jsonb_build_object('code', code, 'password', pwd, 'for', nm, 'days', d, 'expires', current_date + d,
    'users', jsonb_build_array('owner','gm','cfo','chief','acct','ar','ap','cashier','auditor','employee','viewer'));
end $$;

create or replace function public.demo_list(p jsonb default '{}') returns jsonb language plpgsql stable security definer set search_path = public, app, acc as $$
begin
  perform app.demo_admin();
  return coalesce((select jsonb_agg(jsonb_build_object('code', code, 'name', name, 'for', settings->'demo'->>'for', 'days', settings->'demo'->'days', 'issued', settings->'demo'->>'issued',
    'expires', case when (settings->'demo'->>'days') is null then null else (expires_at + 7)::text end, 'permanent', (settings->'demo'->>'days') is null) order by created_at desc)
    from acc.tenants where settings ? 'demo'), '[]'::jsonb);
end $$;

create or replace function public.demo_delete(p jsonb) returns jsonb language plpgsql security definer set search_path = public, app, acc as $$
begin perform app.demo_admin(); if coalesce(p->>'code','') = 'group5' then raise exception 'استخدم إعادة الضبط للمجموعة الثابتة'; end if;
  if not exists (select 1 from acc.tenants where code = p->>'code' and settings ? 'demo') then raise exception 'ليست نسخة تجريبية'; end if;
  perform app.demo_wipe(p->>'code'); return jsonb_build_object('ok', true); end $$;

create or replace function public.demo_reset(p jsonb default '{}') returns jsonb language plpgsql security definer set search_path = public, app, acc as $$
begin perform app.demo_admin(); perform app.demo_reset_group(); return jsonb_build_object('ok', true); end $$;

-- جدولة: إعادة الضبط كل 12 ساعة (منتصف الليل والظهر بتوقيت الرياض = 21:00 و09:00 UTC) وتنظيف المنتهية يوميًا
do $$ begin
  begin
    create extension if not exists pg_cron;
    perform cron.unschedule(jobid) from cron.job where jobname in ('mohkam-demo-reset', 'mohkam-demo-cleanup');
    perform cron.schedule('mohkam-demo-reset', '0 9,21 * * *', 'select app.demo_reset_group()');
    perform cron.schedule('mohkam-demo-cleanup', '30 21 * * *', 'select app.demo_cleanup()');
  exception when others then raise notice 'pg_cron غير متاح: جدولة إعادة الضبط يدويًا (%).', sqlerrm; end;
end $$;

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
-- لوحة البائع: كل الشركات المشتركة (للمنصة فقط، بلا اطلاع على بيانات الشركات)
create or replace function public.platform_tenants(p jsonb default '{}') returns jsonb language plpgsql stable security definer set search_path = public, app, acc as $$
begin
  perform app.demo_admin();
  return coalesce((select jsonb_agg(jsonb_build_object('code', t.code, 'name', t.name, 'plan', t.plan, 'status', t.status, 'expires_at', (t.expires_at + case when t.settings ? 'demo' then 7 else 0 end)::text,
    'users', (select count(*) from acc.members m where m.tenant_id = t.id), 'max_users', t.max_users, 'entities', (select count(*) from acc.entities e where e.tenant_id = t.id), 'max_entities', t.max_entities,
    'last_login', (select max(m.last_login) from acc.members m where m.tenant_id = t.id), 'demo', t.settings ? 'demo') order by t.created_at desc) from acc.tenants t), '[]'::jsonb);
end $$;

do $$ declare f record; begin
  for f in select p.oid::regprocedure as sig, p.proname from pg_proc p join pg_namespace n on n.oid = p.pronamespace where n.nspname = 'public' and p.prokind = 'f' and p.proowner = (select oid from pg_roles where rolname = current_user)
      and (p.proname in ('login_email','register_company','ingest_journal','signup_status') or p.pronargs = 0 or p.proargtypes::text = (select oid::text from pg_type where typname = 'jsonb')) loop
    if f.proname in ('register_company','ingest_journal','login_email','signup_status') then execute format('grant execute on function %s to anon, authenticated', f.sig);
    else execute format('grant execute on function %s to authenticated', f.sig); end if;
  end loop;
end $$;
alter default privileges in schema public revoke execute on functions from public, anon;
