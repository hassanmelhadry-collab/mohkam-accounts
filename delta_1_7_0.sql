-- مُحكَم للحسابات — تحديث 1.7.0.0: فصل بيانات الشركات (دليل حسابات وعملاء وأصناف ومراكز مستقلة لكل شركة) — بعد 1.6.7.0

-- ===== sql/056_scoped_masters.sql =====
-- مُحكَم للحسابات 1.7.0 — فصل بيانات الشركات: دليل حسابات وعملاء وموردون وأصناف ومراكز تكلفة مستقلة لكل شركة
-- المبدأ: عمود entity_id على السجلات الرئيسية (null = مشترك قديم). لا يتغير شيء لأي حساب قائم حتى يفعّل المالك «الفصل» (acc.tenants.isolate_masters).
-- عند التفعيل: كل سجل جديد يُنسب لشركة، القوائم تعرض شركة المستخدم فقط، وصمّامات تمنع خلط شركتين في قيد/فاتورة/حركة مخزون.
alter table acc.tenants add column if not exists isolate_masters boolean not null default false;
alter table acc.accounts add column if not exists entity_id uuid;
alter table acc.parties  add column if not exists entity_id uuid;
alter table acc.items    add column if not exists entity_id uuid;
alter table acc.dims     add column if not exists entity_id uuid;
do $$ declare t text; c text; begin
  foreach t in array array['accounts','parties','items','dims'] loop
    execute format('alter table acc.%I drop constraint if exists %I', t, t || '_ent_fk');
    execute format('alter table acc.%I add constraint %I foreign key (tenant_id, entity_id) references acc.entities (tenant_id, id)', t, t || '_ent_fk');
    -- استبدال قيد (المستأجر + الرمز) بقيد (المستأجر + الشركة + الرمز)
    for c in select con.conname from pg_constraint con where con.conrelid = ('acc.' || t)::regclass and con.contype = 'u' loop
      execute format('alter table acc.%I drop constraint %I', t, c);
    end loop;
  end loop;
end $$;
create unique index if not exists accounts_code_scope on acc.accounts (tenant_id, coalesce(entity_id, '00000000-0000-0000-0000-000000000000'::uuid), code);
create unique index if not exists parties_code_scope  on acc.parties  (tenant_id, coalesce(entity_id, '00000000-0000-0000-0000-000000000000'::uuid), code);
create unique index if not exists items_code_scope    on acc.items    (tenant_id, coalesce(entity_id, '00000000-0000-0000-0000-000000000000'::uuid), code);
create unique index if not exists dims_code_scope     on acc.dims     (tenant_id, coalesce(entity_id, '00000000-0000-0000-0000-000000000000'::uuid), kind, code);
drop index if exists acc.accounts_syskey;
create unique index if not exists accounts_syskey_scope on acc.accounts (tenant_id, coalesce(entity_id, '00000000-0000-0000-0000-000000000000'::uuid), system_key) where system_key is not null;
create index if not exists accounts_ent on acc.accounts (tenant_id, entity_id);
create index if not exists parties_ent on acc.parties (tenant_id, entity_id);

-- ===== دوال السياق =====
create or replace function app.iso(t uuid) returns boolean language sql stable security definer set search_path = public, acc as
$$ select coalesce((select isolate_masters from acc.tenants where id = t), false) $$;
create or replace function app.cur_ent() returns uuid language sql stable as
$$ select nullif(current_setting('app.cur_ent', true), '')::uuid $$;
-- كل مسار كتابة يستدعي entity_ok مع شركته؛ نثبّت هنا سياق الشركة لباقي العملية (داخل المعاملة فقط)
create or replace function app.entity_ok(t uuid, e uuid) returns void language plpgsql volatile security definer set search_path = public, acc as $$
begin
  if e is null or not (e = any(app.ents())) then raise exception 'الكيان غير موجود أو غير مسموح لك به'; end if;
  perform set_config('app.cur_ent', e::text, true);
end $$;
-- يحدد شركة العملية من الطلب: entity، أو entities بعنصر واحد، أو الشركة الوحيدة المسموحة للمستخدم عند تفعيل الفصل
create or replace function app.set_ent(t uuid, p jsonb) returns uuid language plpgsql volatile security definer set search_path = public, acc, app as $$
declare e uuid; a uuid[];
begin
  if t is null then return null; end if;
  if nullif(p->>'entity','') is not null then e := (p->>'entity')::uuid;
  elsif jsonb_typeof(p->'entities') = 'array' and jsonb_array_length(p->'entities') = 1 then e := (p->'entities'->>0)::uuid;
  elsif app.iso(t) then a := app.ents(); if coalesce(array_length(a, 1), 0) = 1 then e := a[1]; end if; end if;
  if e is null then perform set_config('app.cur_ent', '', true); return null; end if;
  perform app.entity_ok(t, e); return e;
end $$;
-- سجل يخص الشركة الحالية (للبحث بالرمز عند الكتابة). عند إيقاف الفصل: كل شيء مرئي
create or replace function app.own(t uuid, e uuid) returns boolean language sql stable security definer set search_path = public, acc, app as
$$ select case when not app.iso(t) then true else e is not distinct from app.cur_ent() end $$;
-- سجل ظاهر في قائمة الشركات المحددة (المشترك القديم يظهر للجميع حتى يُنسب)
create or replace function app.vis(t uuid, e uuid, ents uuid[]) returns boolean language sql stable security definer set search_path = public, acc, app as
$$ select case when not app.iso(t) then true else e is null or e = any(ents) end $$;

-- أولوية حسابات الشركة الحالية ثم المشتركة عند الحل بالرمز / المفتاح النظامي
create or replace function app.acct_id(t uuid, ref text) returns uuid language plpgsql stable security definer set search_path = public, acc, app as $$
declare r uuid; cur uuid := app.cur_ent(); n int;
begin
  if ref is null or ref = '' then return null; end if;
  if ref ~* '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$' then select id into r from acc.accounts where tenant_id = t and id = ref::uuid; return r; end if;
  if not app.iso(t) then select id into r from acc.accounts where tenant_id = t and code = ref order by (entity_id is null) desc limit 1; return r; end if;
  if cur is not null then select id into r from acc.accounts where tenant_id = t and code = ref and (entity_id = cur or entity_id is null) order by (entity_id is null) limit 1; return r; end if;
  select count(*) into n from acc.accounts where tenant_id = t and code = ref and entity_id = any(app.ents());
  if n > 1 then raise exception 'رمز الحساب % موجود في أكثر من شركة — حدّد الشركة', ref; end if;
  select id into r from acc.accounts where tenant_id = t and code = ref and (entity_id = any(app.ents()) or entity_id is null) order by (entity_id is null) limit 1; return r;
end $$;
create or replace function app.sysacct(t uuid, k text) returns uuid language plpgsql stable security definer set search_path = public, acc, app as $$
declare r uuid; cur uuid := app.cur_ent();
begin
  if not app.iso(t) then select id into r from acc.accounts where tenant_id = t and system_key = k and active limit 1;
  else select id into r from acc.accounts where tenant_id = t and system_key = k and active and (entity_id = cur or entity_id is null) order by (entity_id is null) limit 1; end if;
  if r is null then raise exception 'لم يُحدَّد الحساب الافتراضي (%) — اربطه من الإعدادات ← ربط الحسابات', k; end if; return r; end $$;
-- حساب الضريبة: حساب رمز الضريبة إن كان مشتركًا أو لنفس الشركة، وإلا الحساب النظامي للشركة
create or replace function app.vat_acct(t uuid, acct uuid, k text) returns uuid language plpgsql stable security definer set search_path = public, acc, app as $$
declare e uuid;
begin
  if acct is not null then
    if not app.iso(t) then return acct; end if;
    select entity_id into e from acc.accounts where tenant_id = t and id = acct;
    if e is null or e is not distinct from app.cur_ent() then return acct; end if;
  end if;
  return app.sysacct(t, k);
end $$;

-- ترقيم العملاء/الموردين لكل شركة من جديد (أكبر رقم موجود + 1)
create or replace function app.party_seq(t uuid, k text) returns int language plpgsql volatile security definer set search_path = public, acc, app as $$
declare pre text := case when k = 'supplier' then 'S-' when k = 'employee' then 'EMP-' else 'C-' end; e uuid := app.cur_ent(); n int;
begin
  perform pg_advisory_xact_lock(hashtext(t::text || coalesce(e::text, '') || pre));
  select coalesce(max(substring(code from '[0-9]+$')::int), 0) + 1 into n from acc.parties where tenant_id = t and entity_id is not distinct from e and code ~ ('^' || pre || '[0-9]+$');
  return n;
end $$;

-- ===== الصمّامات =====
create or replace function app.scope_stamp() returns trigger language plpgsql security definer set search_path = public, acc, app as $$
begin
  if new.entity_id is null and app.iso(new.tenant_id) and not app.restore_flag() then
    new.entity_id := app.cur_ent();
    if new.entity_id is null then raise exception 'اختر شركة محددة أولًا — لا يمكن الإنشاء في «كل الشركات»'; end if;
  end if;
  return new;
end $$;
create or replace function app.scope_guard() returns trigger language plpgsql security definer set search_path = public, acc, app as $$
declare c uuid;
begin
  if current_setting('app.demo_wipe', true) = '1' or app.restore_flag() then return coalesce(new, old); end if;
  if tg_op = 'DELETE' and pg_trigger_depth() > 1 then return old; end if;
  if old.entity_id is not null and app.iso(old.tenant_id) then
    c := app.cur_ent();
    if tg_op = 'UPDATE' and new.entity_id is distinct from old.entity_id then raise exception 'لا يجوز نقل سجل بين الشركات'; end if;
    if c is not null then
      if old.entity_id <> c then raise exception 'هذا السجل يخص شركة أخرى'; end if;
    elsif not (old.entity_id = any(app.ents())) then raise exception 'هذا السجل يخص شركة أخرى'; end if;
  end if;
  return coalesce(new, old);
end $$;
do $$ declare t text; begin
  foreach t in array array['accounts','parties','items','dims'] loop
    execute format('drop trigger if exists scope_stamp on acc.%I', t);
    execute format('create trigger scope_stamp before insert on acc.%I for each row execute function app.scope_stamp()', t);
    execute format('drop trigger if exists scope_guard on acc.%I', t);
    execute format('create trigger scope_guard before update or delete on acc.%I for each row execute function app.scope_guard()', t);
  end loop;
end $$;

-- لا يُستعمل حساب/طرف/مركز/صنف شركة في مستند أو قيد شركة أخرى
create or replace function app.scope_chk(t uuid, e uuid, tbl text, id uuid, what text) returns void language plpgsql stable security definer set search_path = public, acc, app as $$
declare x uuid; nm text;
begin
  if id is null then return; end if;
  execute format('select entity_id, name from acc.%I where tenant_id = $1 and id = $2', tbl) into x, nm using t, id;
  if x is not null and x is distinct from e then raise exception '% «%» يخص شركة أخرى ولا يجوز استعماله هنا', what, nm; end if;
end $$;
create or replace function app.scope_lines() returns trigger language plpgsql security definer set search_path = public, acc, app as $$
begin
  if app.restore_flag() or not app.iso(new.tenant_id) then return new; end if;
  perform app.scope_chk(new.tenant_id, new.entity_id, 'accounts', new.account_id, 'الحساب');
  perform app.scope_chk(new.tenant_id, new.entity_id, 'parties', new.party_id, 'الطرف');
  perform app.scope_chk(new.tenant_id, new.entity_id, 'dims', new.cost_center_id, 'مركز التكلفة');
  perform app.scope_chk(new.tenant_id, new.entity_id, 'dims', new.project_id, 'المشروع');
  return new;
end $$;
drop trigger if exists scope_lines on acc.journal_lines;
create trigger scope_lines before insert or update of account_id, party_id, cost_center_id, project_id, entity_id on acc.journal_lines for each row execute function app.scope_lines();
create or replace function app.scope_doc() returns trigger language plpgsql security definer set search_path = public, acc, app as $$
begin
  if app.restore_flag() or not app.iso(new.tenant_id) then return new; end if;
  perform app.scope_chk(new.tenant_id, new.entity_id, 'parties', new.party_id, 'الطرف');
  return new;
end $$;
drop trigger if exists scope_doc on acc.invoices; create trigger scope_doc before insert or update of party_id, entity_id on acc.invoices for each row execute function app.scope_doc();
drop trigger if exists scope_doc on acc.payments; create trigger scope_doc before insert or update of party_id, entity_id on acc.payments for each row execute function app.scope_doc();
create or replace function app.scope_invl() returns trigger language plpgsql security definer set search_path = public, acc, app as $$
declare e uuid;
begin
  if app.restore_flag() or not app.iso(new.tenant_id) then return new; end if;
  select entity_id into e from acc.invoices where tenant_id = new.tenant_id and id = new.invoice_id;
  perform app.scope_chk(new.tenant_id, e, 'accounts', new.account_id, 'الحساب');
  perform app.scope_chk(new.tenant_id, e, 'items', new.item_id, 'الصنف');
  return new;
end $$;
drop trigger if exists scope_invl on acc.invoice_lines; create trigger scope_invl before insert or update of account_id, item_id on acc.invoice_lines for each row execute function app.scope_invl();
create or replace function app.scope_stock() returns trigger language plpgsql security definer set search_path = public, acc, app as $$
begin
  if app.restore_flag() or not app.iso(new.tenant_id) then return new; end if;
  perform app.scope_chk(new.tenant_id, new.entity_id, 'items', new.item_id, 'الصنف');
  return new;
end $$;
drop trigger if exists scope_stock on acc.stock_moves; create trigger scope_stock before insert on acc.stock_moves for each row execute function app.scope_stock();


-- ===== دوال الكتابة (تثبّت سياق الشركة ثم تنفّذ الأصل) =====
-- coa_upsert (من 051_coa_flex.sql)
create or replace function app.coa_upsert_core(p jsonb) returns jsonb language plpgsql security definer set search_path = public, app, acc as $$
declare t uuid; v_id uuid := nullif(p->>'id','')::uuid; par uuid := app.acct_id(app.tenant(), coalesce(nullif(p->>'parent_id',''), nullif(p->>'parent_code',''))); ty text := p->>'type'; sub text := coalesce(nullif(p->>'subtype',''),'general');
  sk text := nullif(p->>'system_key',''); isg boolean := coalesce((p->>'is_group')::boolean, false); old acc.accounts; rp boolean; rc boolean;
begin
  t := app.need('coa', case when nullif(p->>'id','') is null then 'add' else 'edit' end);
  if coalesce(trim(p->>'code'),'') = '' or coalesce(trim(p->>'name'),'') = '' then raise exception 'رمز واسم الحساب مطلوبان'; end if;
  if par is not null then select type into ty from acc.accounts where tenant_id = t and id = par; end if;
  if par is not null and exists (select 1 from acc.accounts x where x.tenant_id = t and x.id = par and x.system_key is not null) and par is distinct from (select a0.parent_id from acc.accounts a0 where a0.tenant_id = t and a0.id = nullif(p->>'id','')::uuid) then
    raise exception 'الحساب النظامي الافتراضي لا يُفرَّع — اختر أبًا تجميعيًا آخر أو انقل صفة الحساب النظامي أولًا'; end if;
  if ty is null then raise exception 'نوع الحساب مطلوب (أصل/التزام/حقوق ملكية/إيراد/مصروف)'; end if;
  rp := coalesce((p->>'requires_party')::boolean, sub in ('receivable','payable')); rc := coalesce((p->>'requires_cc')::boolean, false);
  if sk is not null then
    if isg then raise exception 'الحساب الافتراضي النظامي يجب أن يكون حسابًا فرعيًا (غير تجميعي)'; end if;
    update acc.accounts a2 set system_key = null where a2.tenant_id = t and app.own(t, a2.entity_id) and a2.system_key = sk and a2.id is distinct from (nullif(p->>'id','')::uuid);
  end if;
  if v_id is null then
    v_id := gen_random_uuid();
    insert into acc.accounts (tenant_id, id, code, name, name_en, parent_id, type, subtype, is_group, cf_class, requires_party, requires_cc, system_key, active, note, created_by)
    values (t, v_id, trim(p->>'code'), trim(p->>'name'), coalesce(p->>'name_en',''), par, ty, sub, isg, coalesce(nullif(p->>'cf_class',''), app.default_cf(ty, sub)), rp, rc, sk, coalesce((p->>'active')::boolean, true), coalesce(p->>'note',''), auth.uid());
    perform app.audit('create','account',v_id::text,'إنشاء حساب ' || (p->>'code') || ' ' || (p->>'name'));
  else
    select * into old from acc.accounts where tenant_id = t and acc.accounts.id = v_id;
    if old.id is null then raise exception 'الحساب غير موجود'; end if;
    update acc.accounts set code = trim(p->>'code'), name = trim(p->>'name'), name_en = coalesce(p->>'name_en',''), parent_id = par, type = ty, subtype = sub, is_group = isg,
      cf_class = coalesce(nullif(p->>'cf_class',''), app.default_cf(ty, sub)), requires_party = rp, requires_cc = rc, system_key = sk, active = coalesce((p->>'active')::boolean, active), note = coalesce(p->>'note','')
    where tenant_id = t and acc.accounts.id = v_id;
    -- تغيير النوع (أو النقل تحت أب من نوع آخر) يسري على كل الفروع مستوًى بعد مستوى؛ ويُرفض إن كانت على أي منها حركات
    if old.type is distinct from ty and exists (select 1 from acc.accounts where tenant_id = t and parent_id = v_id) then
      if exists (with recursive d as (select id from acc.accounts where tenant_id = t and parent_id = v_id union all select a.id from acc.accounts a join d on a.parent_id = d.id where a.tenant_id = t)
                 select 1 from acc.journal_lines l join d on l.account_id = d.id where l.tenant_id = t limit 1) then
        raise exception 'لا يجوز تغيير نوع حساب تحته فروع عليها حركات'; end if;
      loop
        update acc.accounts c set type = ty where c.tenant_id = t and c.type is distinct from ty and c.parent_id in (select id from acc.accounts where tenant_id = t and type = ty and (id = v_id or id in (with recursive d as (select id from acc.accounts where tenant_id = t and parent_id = v_id union all select a.id from acc.accounts a join d on a.parent_id = d.id where a.tenant_id = t) select id from d)));
        exit when not found;
      end loop;
    end if;
    perform app.audit('update','account',v_id::text,'تعديل حساب ' || (p->>'code') || ' ' || (p->>'name'));
  end if;
  return jsonb_build_object('id', v_id);
end $$;

create or replace function public.coa_upsert(p jsonb) returns jsonb language plpgsql security definer set search_path = public, app, acc as $$
begin perform app.set_ent(app.tenant(), p); return app.coa_upsert_core(p); end $$;

-- coa_import (من 003_api_ledger.sql)
create or replace function app.coa_import_core(p jsonb) returns jsonb language plpgsql security definer set search_path = public, app, acc as $$
declare t uuid := app.need('coa','add'); r jsonb; i int := 0; errs jsonb := '[]'::jsonb; dry boolean := coalesce((p->>'dry')::boolean, false); created int := 0; updated int := 0;
  v_code text; ty text; par text; pass int; todo jsonb := coalesce(p->'rows','[]'::jsonb); left_ jsonb; progressed boolean; pid uuid; nm text; isg boolean;
  codes text[] := '{}'; pars text[] := '{}'; rowsd jsonb := '[]'::jsonb; ex acc.accounts; sub text;
begin
  perform app.need('import','add');
  if jsonb_array_length(todo) = 0 then raise exception 'الملف فارغ'; end if;
  if jsonb_array_length(todo) > 5000 then raise exception 'الحد الأقصى 5000 حساب في المرة'; end if;
  -- فحص أولي
  for r in select * from jsonb_array_elements(todo) loop
    i := i + 1; v_code := trim(coalesce(r->>'code','')); nm := trim(coalesce(r->>'name',''));
    if v_code = '' or nm = '' then errs := errs || jsonb_build_object('row', i, 'msg', 'الرمز والاسم مطلوبان'); continue; end if;
    if v_code !~ '^[0-9A-Za-z._-]{1,20}$' then errs := errs || jsonb_build_object('row', i, 'msg', 'رمز غير صالح: ' || v_code); continue; end if;
    if v_code = any(codes) then errs := errs || jsonb_build_object('row', i, 'msg', 'رمز مكرر في الملف: ' || v_code); continue; end if;
    codes := codes || v_code; par := nullif(trim(coalesce(r->>'parent_code','')), ''); pars := pars || coalesce(par, '');
    if par is not null and par = v_code then errs := errs || jsonb_build_object('row', i, 'msg', 'حساب أب لنفسه: ' || v_code); end if;
    ty := nullif(r->>'type','');
    if ty is not null and ty not in ('asset','liability','equity','revenue','expense') then errs := errs || jsonb_build_object('row', i, 'msg', 'نوع غير صالح: ' || ty); end if;
    if par is null and ty is null then errs := errs || jsonb_build_object('row', i, 'msg', 'الحساب الرئيسي ' || v_code || ' يحتاج نوعًا'); end if;
    if par is not null and not (par = any(codes) or exists (select 1 from jsonb_array_elements(todo) x where trim(x->>'code') = par) or exists (select 1 from acc.accounts where tenant_id = t and app.own(t, acc.accounts.entity_id) and acc.accounts.code = par)) then
      errs := errs || jsonb_build_object('row', i, 'msg', 'الحساب الأب غير موجود: ' || par); end if;
  end loop;
  if jsonb_array_length(errs) > 0 or dry then return jsonb_build_object('ok', jsonb_array_length(errs) = 0, 'errors', errs, 'count', jsonb_array_length(todo)); end if;
  -- إدخال متعدد الجولات: الآباء أولًا
  left_ := todo;
  for pass in 1..12 loop
    progressed := false;
    for r in select * from jsonb_array_elements(left_) loop
      v_code := trim(r->>'code'); par := nullif(trim(coalesce(r->>'parent_code','')), '');
      pid := null;
      if par is not null then select a3.id into pid from acc.accounts a3 where a3.tenant_id = t and app.own(t, a3.entity_id) and a3.code = par; if pid is null then continue; end if; end if;
      ty := coalesce(nullif(r->>'type',''), (select a4.type from acc.accounts a4 where a4.tenant_id = t and a4.id = pid));
      sub := coalesce(nullif(r->>'subtype',''), 'general');
      isg := coalesce((r->>'is_group')::boolean, exists (select 1 from jsonb_array_elements(todo) x where trim(coalesce(x->>'parent_code','')) = v_code));
      select * into ex from acc.accounts a5 where a5.tenant_id = t and app.own(t, a5.entity_id) and a5.code = v_code;
      if ex.id is null then
        insert into acc.accounts (tenant_id, code, name, name_en, parent_id, type, subtype, is_group, cf_class, requires_party, requires_cc, system_key, created_by)
        values (t, v_code, trim(r->>'name'), coalesce(r->>'name_en',''), pid, ty, sub, isg, coalesce(nullif(r->>'cf_class',''), app.default_cf(ty, sub)),
          coalesce((r->>'requires_party')::boolean, sub in ('receivable','payable')), coalesce((r->>'requires_cc')::boolean, false), nullif(r->>'system_key',''), auth.uid());
        created := created + 1;
      else
        update acc.accounts a6 set name = trim(r->>'name'), name_en = coalesce(r->>'name_en', a6.name_en), parent_id = pid, subtype = sub, is_group = isg where a6.tenant_id = t and a6.id = ex.id;
        updated := updated + 1;
      end if;
      left_ := (select coalesce(jsonb_agg(x), '[]'::jsonb) from jsonb_array_elements(left_) x where trim(x->>'code') <> v_code);
      progressed := true;
    end loop;
    exit when jsonb_array_length(left_) = 0 or not progressed;
  end loop;
  if jsonb_array_length(left_) > 0 then raise exception 'تعذّر ترتيب % حسابًا (حلقة أو أب مفقود)', jsonb_array_length(left_); end if;
  perform app.audit('import','account','', 'استيراد شجرة حسابات: ' || created || ' جديد، ' || updated || ' محدّث');
  return jsonb_build_object('ok', true, 'created', created, 'updated', updated, 'errors', '[]'::jsonb);
end $$;

create or replace function public.coa_import(p jsonb) returns jsonb language plpgsql security definer set search_path = public, app, acc as $$
begin perform app.set_ent(app.tenant(), p); return app.coa_import_core(p); end $$;

-- coa_apply_template (من 012_flex.sql)
create or replace function app.coa_apply_template_core(p jsonb) returns jsonb language plpgsql security definer set search_path = public, app, acc as $$
declare t uuid := app.need('coa','add'); rows jsonb; r jsonb; pid uuid; ty text; sub text; n int := 0; skipped int := 0; got int;
begin
  select tpl.rows into rows from app.coa_templates tpl where tpl.key = p->>'key'; if rows is null then raise exception 'القالب غير موجود'; end if;
  for r in select * from jsonb_array_elements(rows) loop
    pid := null; if nullif(r->>'parent_code','') is not null then select a.id into pid from acc.accounts a where a.tenant_id = t and app.own(t, a.entity_id) and a.code = r->>'parent_code'; end if;
    ty := coalesce(r->>'type', (select a.type from acc.accounts a where a.tenant_id = t and a.id = pid)); sub := coalesce(nullif(r->>'subtype',''), 'general');
    insert into acc.accounts (tenant_id, code, name, name_en, parent_id, type, subtype, is_group, cf_class, requires_party, requires_cc, system_key, created_by)
    values (t, r->>'code', r->>'name', coalesce(r->>'name_en',''), pid, ty, sub, coalesce((r->>'is_group')::boolean, false), coalesce(nullif(r->>'cf_class',''), app.default_cf(ty, sub)), sub in ('receivable','payable'), false,
      case when exists (select 1 from acc.accounts a where a.tenant_id = t and app.own(t, a.entity_id) and a.system_key = nullif(r->>'system_key','')) then null else nullif(r->>'system_key','') end, auth.uid())
    on conflict do nothing;
    get diagnostics got = row_count; if got = 1 then n := n + 1; else skipped := skipped + 1; end if;
  end loop;
  perform app.audit('template','account',p->>'key','دمج قالب ' || (p->>'key') || ': ' || n || ' جديد، ' || skipped || ' موجود'); return jsonb_build_object('added', n, 'skipped', skipped);
end $$;

create or replace function public.coa_apply_template(p jsonb) returns jsonb language plpgsql security definer set search_path = public, app, acc as $$
begin perform app.set_ent(app.tenant(), p); return app.coa_apply_template_core(p); end $$;

-- party_upsert (من 006_docs.sql)
create or replace function app.party_upsert_core(p jsonb) returns jsonb language plpgsql security definer set search_path = public, app, acc as $$
declare t uuid; v_id uuid := nullif(p->>'id','')::uuid; k text := coalesce(nullif(p->>'kind',''), 'customer'); c text := nullif(trim(coalesce(p->>'code','')), '');
begin
  t := app.need('parties', case when v_id is null then 'add' else 'edit' end);
  if coalesce(trim(p->>'name'),'') = '' then raise exception 'اسم العميل/المورد مطلوب'; end if;
  if k not in ('customer','supplier','both','employee','other') then raise exception 'نوع غير صالح'; end if;
  if nullif(p->>'vat_no','') is not null and (p->>'vat_no') !~ '^[0-9A-Za-z-]{5,20}$' then raise exception 'الرقم الضريبي غير صالح'; end if;
  if v_id is null then
    v_id := gen_random_uuid();
    if c is null then c := case when k = 'supplier' then 'S-' when k = 'employee' then 'EMP-' else 'C-' end || lpad(case when app.iso(t) then app.party_seq(t, k)::text else app.next_no(t, null, 'party_' || k, 0)::text end, 5, '0'); end if;
    insert into acc.parties (tenant_id, id, kind, code, name, name_en, vat_no, cr, phone, email, address, city, country, contact, credit_limit, terms_days, note, created_by)
    values (t, v_id, k, c, trim(p->>'name'), coalesce(p->>'name_en',''), coalesce(p->>'vat_no',''), coalesce(p->>'cr',''), coalesce(p->>'phone',''), coalesce(p->>'email',''), coalesce(p->>'address',''), coalesce(p->>'city',''),
      coalesce(nullif(p->>'country',''), 'SA'), coalesce(p->>'contact',''), coalesce(nullif(p->>'credit_limit','')::numeric, 0), coalesce(nullif(p->>'terms_days','')::int, 30), coalesce(p->>'note',''), auth.uid());
    perform app.audit('create','party',v_id::text,'إنشاء ' || c || ' ' || (p->>'name'));
  else
    update acc.parties set kind = k, code = coalesce(c, code), name = trim(p->>'name'), name_en = coalesce(p->>'name_en',''), vat_no = coalesce(p->>'vat_no',''), cr = coalesce(p->>'cr',''), phone = coalesce(p->>'phone',''),
      email = coalesce(p->>'email',''), address = coalesce(p->>'address',''), city = coalesce(p->>'city',''), country = coalesce(nullif(p->>'country',''), country), contact = coalesce(p->>'contact',''),
      credit_limit = coalesce(nullif(p->>'credit_limit','')::numeric, 0), terms_days = coalesce(nullif(p->>'terms_days','')::int, 30), active = coalesce((p->>'active')::boolean, active), note = coalesce(p->>'note','')
    where tenant_id = t and acc.parties.id = v_id;
    if not found then raise exception 'الطرف غير موجود'; end if;
    perform app.audit('update','party',v_id::text,'تعديل ' || (p->>'name'));
  end if;
  return jsonb_build_object('id', v_id, 'code', (select code from acc.parties where tenant_id = t and acc.parties.id = v_id));
end $$;

create or replace function public.party_upsert(p jsonb) returns jsonb language plpgsql security definer set search_path = public, app, acc as $$
begin perform app.set_ent(app.tenant(), p); return app.party_upsert_core(p); end $$;

-- party_import (من 012_flex.sql)
create or replace function app.party_import_core(p jsonb) returns jsonb language plpgsql security definer set search_path = public, app, acc as $$
declare t uuid := app.need('parties','add'); r jsonb; n int := 0; u int := 0; k text; c text; ex uuid; errs jsonb := '[]'::jsonb; i int := 0; dry boolean := coalesce((p->>'dry')::boolean, false);
begin
  perform app.need('import','add'); if jsonb_array_length(coalesce(p->'rows','[]'::jsonb)) > 5000 then raise exception 'الحد الأقصى 5000 صف'; end if;
  for r in select * from jsonb_array_elements(coalesce(p->'rows','[]'::jsonb)) loop
    i := i + 1; k := coalesce(nullif(r->>'kind',''), 'customer'); c := nullif(trim(coalesce(r->>'code','')), '');
    if coalesce(trim(r->>'name'),'') = '' then errs := errs || jsonb_build_object('row', i, 'error', 'الاسم مطلوب'); continue; end if;
    if k not in ('customer','supplier','both','employee','other') then errs := errs || jsonb_build_object('row', i, 'error', 'نوع غير صالح: ' || k); continue; end if;
    select id into ex from acc.parties where tenant_id = t and code = c and app.own(t, entity_id);
    if ex is not null then if not dry then update acc.parties set name = trim(r->>'name'), vat_no = coalesce(r->>'vat_no', vat_no), phone = coalesce(r->>'phone', phone), email = coalesce(r->>'email', email), city = coalesce(r->>'city', city), credit_limit = coalesce(nullif(r->>'credit_limit','')::numeric, credit_limit), terms_days = coalesce(nullif(r->>'terms_days','')::int, terms_days) where tenant_id = t and id = ex; end if; u := u + 1;
    else if not dry then
      if c is null then c := case when k = 'supplier' then 'S-' when k = 'employee' then 'EMP-' else 'C-' end || lpad(case when app.iso(t) then app.party_seq(t, k)::text else app.next_no(t, null, 'party_' || k, 0)::text end, 5, '0'); end if;
      insert into acc.parties (tenant_id, kind, code, name, name_en, vat_no, phone, email, city, credit_limit, terms_days, created_by) values (t, k, c, trim(r->>'name'), coalesce(r->>'name_en',''), coalesce(r->>'vat_no',''), coalesce(r->>'phone',''), coalesce(r->>'email',''), coalesce(r->>'city',''), coalesce(nullif(r->>'credit_limit','')::numeric, 0), coalesce(nullif(r->>'terms_days','')::int, 30), auth.uid()); end if; n := n + 1; end if;
  end loop;
  if not dry then perform app.audit('import','party','bulk','استيراد أطراف: ' || n || ' جديد، ' || u || ' محدّث'); end if;
  return jsonb_build_object('created', n, 'updated', u, 'errors', errs, 'dry', dry);
end $$;

create or replace function public.party_import(p jsonb) returns jsonb language plpgsql security definer set search_path = public, app, acc as $$
begin perform app.set_ent(app.tenant(), p); return app.party_import_core(p); end $$;

-- dim_upsert (من 006_docs.sql)
create or replace function app.dim_upsert_core(p jsonb) returns jsonb language plpgsql security definer set search_path = public, app, acc as $$
declare t uuid; v_id uuid := nullif(p->>'id','')::uuid;
begin
  t := app.need('costcenters', case when v_id is null then 'add' else 'edit' end);
  if p->>'kind' not in ('cc','project') or coalesce(trim(p->>'code'),'') = '' or coalesce(trim(p->>'name'),'') = '' then raise exception 'النوع والرمز والاسم مطلوبة'; end if;
  if v_id is null then v_id := gen_random_uuid();
    insert into acc.dims (tenant_id, id, kind, code, name, parent_id, note) values (t, v_id, p->>'kind', trim(p->>'code'), trim(p->>'name'), nullif(p->>'parent_id','')::uuid, coalesce(p->>'note',''));
  else update acc.dims set code = trim(p->>'code'), name = trim(p->>'name'), parent_id = nullif(p->>'parent_id','')::uuid, active = coalesce((p->>'active')::boolean, active), note = coalesce(p->>'note','') where tenant_id = t and acc.dims.id = v_id; end if;
  perform app.audit('upsert','dim',v_id::text,(p->>'code') || ' ' || (p->>'name')); return jsonb_build_object('id', v_id);
end $$;

create or replace function public.dim_upsert(p jsonb) returns jsonb language plpgsql security definer set search_path = public, app, acc as $$
begin perform app.set_ent(app.tenant(), p); return app.dim_upsert_core(p); end $$;

-- item_upsert (من 020_inventory.sql)
create or replace function app.item_upsert_core(p jsonb) returns jsonb language plpgsql security definer set search_path = public, app, acc as $$
declare t uuid; v_id uuid := nullif(p->>'id','')::uuid; ia uuid; ca uuid; c text := trim(coalesce(p->>'code','')); nm text := trim(coalesce(p->>'name',''));
begin
  t := app.need_inv(case when v_id is null then 'add' else 'edit' end);
  if c = '' or nm = '' then raise exception 'رمز واسم الصنف مطلوبان'; end if;
  ia := coalesce(app.acct_id(t, nullif(p->>'inv_account','')), (select id from acc.accounts where tenant_id = t and app.own(t, entity_id) and subtype = 'inventory' and active and not is_group order by code limit 1));
  ca := coalesce(app.acct_id(t, nullif(p->>'cogs_account','')), (select id from acc.accounts where tenant_id = t and app.own(t, entity_id) and subtype = 'cogs' and active and not is_group order by code limit 1));
  if ia is null then raise exception 'حدّد حساب المخزون (أو أنشئ حسابًا من نوع «مخزون» في الدليل)'; end if;
  if ca is null then raise exception 'حدّد حساب تكلفة المبيعات (أو أنشئ حسابًا من نوع «تكلفة مبيعات»)'; end if;
  if not exists (select 1 from acc.accounts where tenant_id = t and id = ia and type = 'asset') then raise exception 'حساب المخزون يجب أن يكون من الأصول'; end if;
  if not exists (select 1 from acc.accounts where tenant_id = t and id = ca and type = 'expense') then raise exception 'حساب تكلفة المبيعات يجب أن يكون من المصروفات'; end if;
  if v_id is null then v_id := gen_random_uuid();
    insert into acc.items (tenant_id, id, code, name, name_en, unit, inv_account_id, cogs_account_id, sale_price, reorder_qty) values (t, v_id, c, nm, coalesce(p->>'name_en',''), coalesce(nullif(p->>'unit',''), 'قطعة'), ia, ca, coalesce(nullif(p->>'sale_price','')::numeric, 0), coalesce(nullif(p->>'reorder_qty','')::numeric, 0));
  else
    update acc.items set code = c, name = nm, name_en = coalesce(p->>'name_en', name_en), unit = coalesce(nullif(p->>'unit',''), unit), sale_price = coalesce(nullif(p->>'sale_price','')::numeric, sale_price), reorder_qty = coalesce(nullif(p->>'reorder_qty','')::numeric, reorder_qty),
      active = coalesce((p->>'active')::boolean, active) where tenant_id = t and id = v_id;
    if exists (select 1 from acc.stock_moves where tenant_id = t and item_id = v_id) then
      if (p ? 'inv_account' or p ? 'cogs_account') and (ia <> (select inv_account_id from acc.items where tenant_id = t and id = v_id) or ca <> (select cogs_account_id from acc.items where tenant_id = t and id = v_id)) then raise exception 'لا يمكن تغيير حسابات صنف عليه حركة'; end if;
    else update acc.items set inv_account_id = ia, cogs_account_id = ca where tenant_id = t and id = v_id; end if;
  end if;
  perform app.audit('save','item', v_id::text, c || ' ' || nm);
  return jsonb_build_object('id', v_id);
exception when unique_violation then raise exception 'رمز الصنف مستخدم من قبل';
end $$;

create or replace function public.item_upsert(p jsonb) returns jsonb language plpgsql security definer set search_path = public, app, acc as $$
begin perform app.set_ent(app.tenant(), p); return app.item_upsert_core(p); end $$;

-- inv_post: حساب الضريبة بحسب الشركة
create or replace function app.inv_post(inv_id uuid) returns acc.journals language plpgsql security definer set search_path = public, app, acc as $$
declare t uuid := app.tenant(); inv acc.invoices; jid uuid := gen_random_uuid(); ty text; sale boolean; credit boolean; ctl uuid; fx numeric; lines jsonb := '[]'::jsonb; r record; amt numeric; tot numeric := 0; j acc.journals; vat uuid; dirn text; sg int;
begin
  select * into inv from acc.invoices where tenant_id = t and id = inv_id for update;
  sale := inv.kind in ('sales','sales_credit'); credit := inv.kind in ('sales_credit','purchase_debit'); fx := inv.rate;
  ty := case inv.kind when 'sales' then 'SI' when 'purchase' then 'PI' when 'sales_credit' then 'SC' else 'PD' end;
  ctl := app.sysacct(t, case when sale then 'AR' else 'AP' end);
  insert into acc.journals (tenant_id, id, entity_id, type, date, description, reference, status, source, source_id, created_by)
  values (t, jid, inv.entity_id, ty, inv.date, (case inv.kind when 'sales' then 'فاتورة مبيعات' when 'purchase' then 'فاتورة مشتريات' when 'sales_credit' then 'إشعار دائن' else 'إشعار مدين' end) || ' — ' || (select name from acc.parties where tenant_id = t and id = inv.party_id), inv.supplier_ref, 'draft', 'invoice', inv.id, auth.uid());
  -- بنود الإيراد/المصروف
  for r in select account_id, cost_center_id, project_id, sum(net) net from acc.invoice_lines where tenant_id = t and invoice_id = inv.id group by 1, 2, 3 order by 1 loop
    amt := round(r.net * fx, 2); if amt = 0 then continue; end if;
    lines := lines || jsonb_build_object('account', r.account_id, 'cost_center', r.cost_center_id, 'project', r.project_id, case when (sale and not credit) or (not sale and credit) then 'credit' else 'debit' end, amt, 'description', 'بنود ' || case when sale then 'المبيعات' else 'المشتريات' end);
    tot := tot + case when (sale and not credit) or (not sale and credit) then amt else amt end;
  end loop;
  -- الضريبة
  for r in select l.tax_code, c.kind, c.account_id, sum(l.tax) tx, sum(l.net) base from acc.invoice_lines l join acc.tax_codes c on c.tenant_id = l.tenant_id and c.code = l.tax_code where l.tenant_id = t and l.invoice_id = inv.id and l.tax_code is not null group by 1, 2, 3 loop
    amt := round(r.tx * fx, 2);
    if amt > 0 then
      vat := app.vat_acct(t, r.account_id, case when sale then 'VAT_OUT' else 'VAT_IN' end);
      lines := lines || jsonb_build_object('account', vat, case when (sale and not credit) or (not sale and credit) then 'credit' else 'debit' end, amt, 'description', 'ضريبة ' || r.tax_code);
      tot := tot + amt;
    end if;
  end loop;
  -- حساب الذمم (طرف مقابل)
  lines := lines || jsonb_build_object('account', ctl, 'party', inv.party_id, case when (sale and not credit) or (not sale and credit) then 'debit' else 'credit' end, tot, 'due_date', inv.due_date,
    'currency', case when inv.rate <> 1 then inv.currency end, 'fc_amount', case when inv.rate <> 1 then inv.total end, 'rate', case when inv.rate <> 1 then inv.rate end, 'description', 'ذمم ' || coalesce(inv.supplier_ref,''));
  perform app.put_lines(t, jid, inv.entity_id, inv.date, lines);
  j := app.post_journal(jid);
  perform app.inv_stock_apply(inv);
  -- أساس الإقرار الضريبي
  sg := case when credit then -1 else 1 end; dirn := case when sale then 'out' else 'in' end;
  for r in select l.tax_code, c.kind, sum(l.net) base, sum(l.tax) tx from acc.invoice_lines l join acc.tax_codes c on c.tenant_id = l.tenant_id and c.code = l.tax_code where l.tenant_id = t and l.invoice_id = inv.id and l.tax_code is not null and c.kind <> 'oos' group by 1, 2 loop
    insert into acc.tax_lines (tenant_id, entity_id, journal_id, date, tax_code, direction, base, tax, party_id, doc_type, doc_id)
    values (t, inv.entity_id, j.id, inv.date, r.tax_code, dirn, sg * round(r.base * fx, 2), sg * round(r.tx * fx, 2), inv.party_id, 'invoice', inv.id);
  end loop;
  update acc.invoices set total_base = tot, journal_id = j.id, number = j.number, status = 'issued', issued_by = auth.uid(), issued_at = now(), updated_at = now() where tenant_id = t and id = inv.id;
  return j;
end $$;

-- pay_post: حساب الضريبة بحسب الشركة
create or replace function public.pay_post(p jsonb) returns jsonb language plpgsql security definer set search_path = public, app, acc as $$
declare t uuid := app.need('payments','post'); pay acc.payments; pol jsonb := app.policy('payments'); jid uuid := gen_random_uuid(); lines jsonb := '[]'::jsonb; rcpt boolean; ctl uuid; r record; j acc.journals; a numeric; inv acc.invoices; ty text; party_amt numeric;
begin
  select * into pay from acc.payments where tenant_id = t and id = (p->>'id')::uuid for update; if pay.id is null then raise exception 'السند غير موجود'; end if; perform app.entity_ok(t, pay.entity_id);
  if pay.status not in ('draft','pending','approved') then raise exception 'السند مرحّل أو ملغى'; end if;
  if pay.status = 'draft' then perform app.need_attach(t, pay.kind, 'payment', pay.id, pay.amount, 'إيصال/إشعار التحويل/الشيك'); end if;
  if (pol->>'required')::boolean and pay.amount >= (pol->>'threshold')::numeric and pay.status <> 'approved' then raise exception 'السند يتطلب اعتمادًا قبل الترحيل'; end if;
  rcpt := pay.kind = 'receipt';
  -- إعادة التحقق من أرصدة الفواتير تحت القفل
  for r in select al.id, al.invoice_id, al.amount from acc.allocations al where al.tenant_id = t and al.source_kind = 'payment' and al.source_id = pay.id loop
    select * into inv from acc.invoices where tenant_id = t and id = r.invoice_id for update;
    if inv.status <> 'issued' or r.amount > inv.total_base - app.inv_paid(t, inv.id) then raise exception 'تسوية على الفاتورة % تتجاوز رصيدها المفتوح', inv.number; end if;
  end loop;
  -- جهة النقد
  lines := lines || jsonb_build_object('account', pay.cash_account_id, case when rcpt then 'debit' else 'credit' end, pay.amount, 'description', coalesce(nullif(pay.reference,''), 'سند'));
  party_amt := pay.amount - coalesce((select sum(amount + tax) from acc.payment_lines where tenant_id = t and payment_id = pay.id), 0);
  if party_amt > 0 then
    ctl := app.sysacct(t, case when rcpt then 'AR' else 'AP' end);
    lines := lines || jsonb_build_object('account', ctl, 'party', pay.party_id, case when rcpt then 'credit' else 'debit' end, party_amt, 'description', case when pay.on_account > 0 then 'سداد ودفعة على الحساب' else 'سداد' end);
  end if;
  for r in select l.account_id, l.description, l.amount, l.tax_code, l.tax, l.cost_center_id, l.project_id, c.account_id tax_acct from acc.payment_lines l left join acc.tax_codes c on c.tenant_id = l.tenant_id and c.code = l.tax_code where l.tenant_id = t and l.payment_id = pay.id order by l.line_no loop
    lines := lines || jsonb_build_object('account', r.account_id, 'cost_center', r.cost_center_id, 'project', r.project_id, case when rcpt then 'credit' else 'debit' end, r.amount, 'description', r.description);
    if r.tax > 0 then lines := lines || jsonb_build_object('account', app.vat_acct(t, r.tax_acct, case when rcpt then 'VAT_OUT' else 'VAT_IN' end), case when rcpt then 'credit' else 'debit' end, r.tax, 'description', 'ضريبة ' || r.tax_code); end if;
  end loop;
  ty := case when rcpt then 'RV' else 'PV' end;
  insert into acc.journals (tenant_id, id, entity_id, type, date, description, reference, status, source, source_id, created_by)
  values (t, jid, pay.entity_id, ty, pay.date, (case when rcpt then 'سند قبض' else 'سند صرف' end) || coalesce(' — ' || (select name from acc.parties where tenant_id = t and id = pay.party_id), ''), pay.reference, 'draft', 'payment', pay.id, auth.uid());
  perform app.put_lines(t, jid, pay.entity_id, pay.date, lines);
  j := app.post_journal(jid);
  insert into acc.tax_lines (tenant_id, entity_id, journal_id, date, tax_code, direction, base, tax, party_id, doc_type, doc_id)
  select t, pay.entity_id, j.id, pay.date, l.tax_code, case when rcpt then 'out' else 'in' end, l.amount, l.tax, pay.party_id, 'payment', pay.id from acc.payment_lines l where l.tenant_id = t and l.payment_id = pay.id and l.tax_code is not null;
  update acc.allocations set active = true where tenant_id = t and source_kind = 'payment' and source_id = pay.id;
  update acc.payments set status = 'posted', number = j.number, journal_id = j.id, posted_by = auth.uid(), posted_at = now(), updated_at = now() where tenant_id = t and id = pay.id;
  perform app.audit('post','payment',pay.id::text,'ترحيل ' || j.number || ' — ' || pay.amount);
  return jsonb_build_object('number', j.number, 'journal_id', j.id);
end $$;

-- ===== القوائم بحسب الشركة =====
create or replace function public.coa_list(p jsonb default '{}') returns jsonb language plpgsql stable security definer set search_path = public, app, acc as $$
declare t uuid := app.need('coa', 'view'); ents uuid[] := app.pick_ents(p); asof date := coalesce(nullif(p->>'to','')::date, current_date + 36500);
  fromd date := nullif(p->>'from','')::date; with_bal boolean := coalesce((p->>'balances')::boolean, false);
begin
  return coalesce((select jsonb_agg(jsonb_build_object('id', a.id, 'entity_id', a.entity_id, 'code', a.code, 'name', a.name, 'name_en', a.name_en, 'parent_id', a.parent_id, 'type', a.type, 'subtype', a.subtype,
      'is_group', a.is_group, 'normal', a.normal, 'cf_class', a.cf_class, 'requires_party', a.requires_party, 'requires_cc', a.requires_cc, 'system_key', a.system_key, 'active', a.active, 'note', a.note,
      'balance', case when with_bal then coalesce(b.bal, 0) end, 'has_postings', coalesce(b.n, 0) > 0) order by a.code)
    from acc.accounts a left join (select account_id, sum(debit - credit) bal, count(*) n from acc.journal_lines where tenant_id = t and posted and entity_id = any(ents) and date <= asof and (fromd is null or date >= fromd) group by 1) b on b.account_id = a.id
    where a.tenant_id = t and app.vis(t, a.entity_id, ents)), '[]'::jsonb);
end $$;
create or replace function public.party_list(p jsonb default '{}') returns jsonb language plpgsql stable security definer set search_path = public, app, acc as $$
declare t uuid := app.need('parties','view'); ents uuid[] := case when app.iso(app.tenant()) then app.pick_ents(p) else app.ents() end; q text := nullif(trim(coalesce(p->>'q','')), ''); lim int := least(coalesce(nullif(p->>'limit','')::int, 200), 2000);
begin
  return coalesce((select jsonb_agg(jsonb_build_object('id', x.id, 'entity_id', x.entity_id, 'code', x.code, 'kind', x.kind, 'name', x.name, 'name_en', x.name_en, 'vat_no', x.vat_no, 'phone', x.phone, 'email', x.email, 'city', x.city, 'credit_limit', x.credit_limit,
      'terms_days', x.terms_days, 'active', x.active, 'ar', coalesce(b.ar, 0), 'ap', coalesce(b.ap, 0)) order by x.code)
    from (select * from acc.parties where tenant_id = t and app.vis(t, entity_id, ents) and (nullif(p->>'kind','') is null or kind = p->>'kind' or kind = 'both' and p->>'kind' in ('customer','supplier')) and (q is null or name ilike '%' || q || '%' or code ilike '%' || q || '%' or vat_no ilike '%' || q || '%' or phone ilike '%' || q || '%')
      and (nullif(p->>'active','') is null or active = (p->>'active')::boolean) order by code limit lim) x
    left join (select l.party_id, sum(case when a.subtype = 'receivable' then l.debit - l.credit else 0 end) ar, sum(case when a.subtype = 'payable' then l.credit - l.debit else 0 end) ap
      from acc.journal_lines l join acc.accounts a on a.tenant_id = l.tenant_id and a.id = l.account_id where l.tenant_id = t and l.posted and l.party_id is not null and l.entity_id = any(ents) group by 1) b on b.party_id = x.id), '[]'::jsonb);
end $$;
create or replace function public.party_get(p jsonb) returns jsonb language plpgsql stable security definer set search_path = public, app, acc as $$
declare t uuid := app.need('parties','view'); r acc.parties;
begin
  select * into r from acc.parties where tenant_id = t and id = (p->>'id')::uuid; if r.id is null or (r.entity_id is not null and app.iso(t) and not (r.entity_id = any(app.ents()))) then raise exception 'الطرف غير موجود'; end if;
  return to_jsonb(r) || jsonb_build_object('attachments', coalesce((select jsonb_agg(jsonb_build_object('id', x.id, 'filename', x.filename, 'path', x.path, 'size', x.size)) from acc.attachments x where x.tenant_id = t and x.owner_type = 'party' and x.owner_id = r.id), '[]'::jsonb));
end $$;
create or replace function public.dim_list(p jsonb default '{}') returns jsonb language plpgsql stable security definer set search_path = public, app, acc as $$
declare t uuid := app.need(null, null); ents uuid[] := case when app.iso(app.tenant()) then app.pick_ents(p) else app.ents() end;
begin return coalesce((select jsonb_agg(to_jsonb(d) - 'tenant_id' order by d.kind, d.code) from acc.dims d where d.tenant_id = t and app.vis(t, d.entity_id, ents) and (nullif(p->>'kind','') is null or d.kind = p->>'kind')), '[]'::jsonb); end $$;

create or replace function public.item_list(p jsonb default '{}') returns jsonb language plpgsql stable security definer set search_path = public, app, acc as $$
declare t uuid := app.need_inv('view'); ents uuid[] := app.pick_ents(p);
begin
  return coalesce((select jsonb_agg(to_jsonb(i) - 'tenant_id' || jsonb_build_object('inv_account', (select code || ' - ' || name from acc.accounts where tenant_id = t and id = i.inv_account_id),
      'qty', coalesce((select sum(b.qty) from acc.stock_bal b where b.tenant_id = t and b.item_id = i.id and b.entity_id = any(ents)), 0)) order by i.code) from acc.items i where i.tenant_id = t and app.vis(t, i.entity_id, ents)), '[]'::jsonb);
end $$;
-- تفريغ الشجرة: شجرة الشركة الحالية فقط عند الفصل
create or replace function public.coa_reset(p jsonb) returns jsonb language plpgsql security definer set search_path = public, app, acc as $$
declare t uuid := app.need_sys('settings'); n int; iso boolean; e uuid;
begin
  if not app.can('coa','delete') then raise exception 'ليست لديك صلاحية'; end if;
  iso := app.iso(t); e := app.set_ent(t, p);
  if iso and e is null then raise exception 'اختر شركة محددة أولًا'; end if;
  if exists (select 1 from acc.journal_lines where tenant_id = t and (not iso or entity_id = e) limit 1) or exists (select 1 from acc.invoice_lines l join acc.invoices i on i.tenant_id = l.tenant_id and i.id = l.invoice_id where l.tenant_id = t and (not iso or i.entity_id = e) limit 1)
  then raise exception 'توجد حركات — لا يمكن تفريغ الشجرة'; end if;
  if iso then
    update acc.accounts set parent_id = null where tenant_id = t and entity_id = e; delete from acc.accounts where tenant_id = t and entity_id = e;
  else
    update acc.accounts set parent_id = null where tenant_id = t; delete from acc.tax_codes where tenant_id = t; delete from acc.accounts where tenant_id = t;
  end if;
  get diagnostics n = row_count;
  perform app.audit('reset','account','all','تفريغ شجرة الحسابات (' || n || ')'); return jsonb_build_object('deleted', n);
end $$;

-- ===== إدارة الفصل =====
-- ميزة اختيارية يفتحها البائع لكل شركة (مغلقة للحسابات القائمة، مفتوحة للجديدة)
with ins as (
  insert into app.feature_cat (key, name, grp, core, since, sort) values ('entity_isolation', 'فصل بيانات الشركات (دليل حسابات وعملاء وأصناف مستقلة لكل شركة)', 'المجموعة', false, 1, 35)
  on conflict (key) do nothing returning key)
update acc.tenants set features_off = array_append(features_off, 'entity_isolation') where exists (select 1 from ins) and not ('entity_isolation' = any(features_off));
update app.feature_cat set name = 'فصل بيانات الشركات (دليل حسابات وعملاء وأصناف مستقلة لكل شركة)', grp = 'المجموعة', core = false, sort = 35 where key = 'entity_isolation';

-- حالة الفصل: كم سجلًا مشتركًا قديمًا، وكم لكل شركة
create or replace function public.isolation_status(p jsonb default '{}') returns jsonb language plpgsql stable security definer set search_path = public, app, acc as $$
declare t uuid := app.need_sys('settings');
begin
  return jsonb_build_object('on', app.iso(t), 'entities', (select count(*) from acc.entities where tenant_id = t),
    'shared', jsonb_build_object('accounts', (select count(*) from acc.accounts where tenant_id = t and entity_id is null), 'parties', (select count(*) from acc.parties where tenant_id = t and entity_id is null),
       'items', (select count(*) from acc.items where tenant_id = t and entity_id is null), 'dims', (select count(*) from acc.dims where tenant_id = t and entity_id is null)),
    'by_entity', coalesce((select jsonb_agg(jsonb_build_object('entity_id', e.id, 'name', e.name,
        'accounts', (select count(*) from acc.accounts x where x.tenant_id = t and x.entity_id = e.id), 'parties', (select count(*) from acc.parties x where x.tenant_id = t and x.entity_id = e.id),
        'items', (select count(*) from acc.items x where x.tenant_id = t and x.entity_id = e.id), 'dims', (select count(*) from acc.dims x where x.tenant_id = t and x.entity_id = e.id)) order by e.code)
      from acc.entities e where e.tenant_id = t), '[]'::jsonb));
end $$;

-- ينسب كل السجلات المشتركة لشركة بعينها (آمن فقط إن كانت كل حركاتها من هذه الشركة)
create or replace function app.iso_assign(t uuid, e uuid, include_unused boolean) returns jsonb language plpgsql security definer set search_path = public, app, acc as $$
declare na int := 0; np int := 0; ni int := 0; nd int := 0; skipped int := 0; r record;
begin
  -- الحسابات: غير مؤهل = عليه حركة شركة أخرى أو أحد فروعه كذلك
  create temp table _bad (id uuid primary key) on commit drop;
  insert into _bad select distinct account_id from acc.journal_lines where tenant_id = t and entity_id <> e on conflict do nothing;
  insert into _bad select distinct l.account_id from acc.invoice_lines l join acc.invoices i on i.tenant_id = l.tenant_id and i.id = l.invoice_id where l.tenant_id = t and i.entity_id <> e on conflict do nothing;
  insert into _bad select inv_account_id from acc.items where tenant_id = t and entity_id is null and id in (select item_id from acc.stock_moves where tenant_id = t and entity_id <> e) on conflict do nothing;
  insert into _bad select cogs_account_id from acc.items where tenant_id = t and entity_id is null and id in (select item_id from acc.stock_moves where tenant_id = t and entity_id <> e) on conflict do nothing;
  loop
    insert into _bad select a.parent_id from acc.accounts a join _bad b on b.id = a.id where a.parent_id is not null on conflict do nothing;
    exit when not found;
  end loop;
  if not include_unused then  -- غير المستعمل لا يُنسب تلقائيًا: يُترك مشتركًا
    insert into _bad select id from acc.accounts where tenant_id = t and not exists (select 1 from acc.journal_lines l where l.tenant_id = t and l.account_id = acc.accounts.id) and not exists (select 1 from acc.invoice_lines l where l.tenant_id = t and l.account_id = acc.accounts.id) on conflict do nothing;
  end if;
  update acc.accounts set entity_id = e where tenant_id = t and entity_id is null and id not in (select id from _bad); get diagnostics na = row_count;
  select count(*) into skipped from acc.accounts where tenant_id = t and entity_id is null;
  update acc.parties set entity_id = e where tenant_id = t and entity_id is null
    and not exists (select 1 from acc.journal_lines l where l.tenant_id = t and l.party_id = acc.parties.id and l.entity_id <> e)
    and not exists (select 1 from acc.invoices x where x.tenant_id = t and x.party_id = acc.parties.id and x.entity_id <> e)
    and not exists (select 1 from acc.payments x where x.tenant_id = t and x.party_id = acc.parties.id and x.entity_id <> e)
    and (include_unused or exists (select 1 from acc.journal_lines l where l.tenant_id = t and l.party_id = acc.parties.id) or exists (select 1 from acc.invoices x where x.tenant_id = t and x.party_id = acc.parties.id)); get diagnostics np = row_count;
  update acc.items set entity_id = e where tenant_id = t and entity_id is null
    and not exists (select 1 from acc.stock_moves m where m.tenant_id = t and m.item_id = acc.items.id and m.entity_id <> e)
    and (include_unused or exists (select 1 from acc.stock_moves m where m.tenant_id = t and m.item_id = acc.items.id)) and inv_account_id not in (select id from _bad) and cogs_account_id not in (select id from _bad); get diagnostics ni = row_count;
  update acc.dims set entity_id = e where tenant_id = t and entity_id is null
    and not exists (select 1 from acc.journal_lines l where l.tenant_id = t and (l.cost_center_id = acc.dims.id or l.project_id = acc.dims.id) and l.entity_id <> e)
    and (include_unused or exists (select 1 from acc.journal_lines l where l.tenant_id = t and (l.cost_center_id = acc.dims.id or l.project_id = acc.dims.id))); get diagnostics nd = row_count;
  drop table _bad;
  return jsonb_build_object('accounts', na, 'parties', np, 'items', ni, 'dims', nd);
end $$;

create or replace function public.isolation_set(p jsonb) returns jsonb language plpgsql security definer set search_path = public, app, acc as $$
declare t uuid := app.need_sys('settings'); want boolean := coalesce((p->>'on')::boolean, true); n int; e uuid; res jsonb := '{}'::jsonb;
begin
  if (app.me()).user_id is null or (app.me()).role <> 'owner' then raise exception 'تفعيل الفصل للمالك فقط'; end if;
  select count(*), min(id::text)::uuid into n, e from acc.entities where tenant_id = t;
  if want then
    if not app.feat_on('entity_isolation') then raise exception 'الميزة غير مفعّلة لشركتك — اطلب تفعيلها من مزوّد الخدمة'; end if;
    update acc.tenants set isolate_masters = true where id = t;
    -- شركة واحدة: كل السجلات القائمة تخصها بلا ريب
    if n = 1 then res := app.iso_assign(t, e, true); end if;
  else
    if n > 1 then raise exception 'لا يمكن إيقاف الفصل بعد تعدد الشركات'; end if;
    update acc.tenants set isolate_masters = false where id = t;
  end if;
  perform app.audit('settings','isolation', t::text, case when want then 'تفعيل فصل بيانات الشركات' else 'إيقاف فصل بيانات الشركات' end);
  return jsonb_build_object('on', want, 'assigned', res);
end $$;

-- ينسب المشترك القديم لشركة (ما كانت حركاته من هذه الشركة وحدها)
create or replace function public.isolation_assign(p jsonb) returns jsonb language plpgsql security definer set search_path = public, app, acc as $$
declare t uuid := app.need_sys('settings'); e uuid := (p->>'entity')::uuid; res jsonb;
begin
  if not app.iso(t) then raise exception 'فعّل فصل البيانات أولًا'; end if;
  if (app.me()).role <> 'owner' then raise exception 'للمالك فقط'; end if;
  if not exists (select 1 from acc.entities where tenant_id = t and id = e) then raise exception 'الشركة غير موجودة'; end if;
  res := app.iso_assign(t, e, coalesce((p->>'include_unused')::boolean, false));
  perform app.audit('settings','isolation', e::text, 'نسب السجلات المشتركة إلى شركة: ' || res::text);
  return res;
end $$;

-- نسخ دليل الحسابات (وعند الطلب العملاء/الموردين/الأصناف/المراكز) من شركة إلى أخرى — بيانات رئيسية فقط، بلا أرصدة ولا حركات
create or replace function public.entity_seed(p jsonb) returns jsonb language plpgsql security definer set search_path = public, app, acc as $$
declare t uuid := app.need('coa','add'); src uuid := nullif(p->>'from','')::uuid; dst uuid := (p->>'entity')::uuid; na int := 0; np int := 0; ni int := 0; nd int := 0;
begin
  if not app.iso(t) then raise exception 'فعّل فصل بيانات الشركات أولًا'; end if;
  if src is not null then perform app.entity_ok(t, src); end if; perform app.entity_ok(t, dst);
  if src = dst then raise exception 'المصدر والهدف شركة واحدة'; end if;
  if exists (select 1 from acc.accounts where tenant_id = t and entity_id = dst) then raise exception 'للشركة دليل حسابات بالفعل — لا يُنسخ فوقه'; end if;
  create temp table _map (old_id uuid primary key, new_id uuid not null) on commit drop;
  insert into _map select id, gen_random_uuid() from acc.accounts where tenant_id = t and entity_id is not distinct from src and (src is not null or entity_id is null);
  insert into acc.accounts (tenant_id, id, entity_id, code, name, name_en, parent_id, type, subtype, is_group, cf_class, requires_party, requires_cc, system_key, active, note, created_by)
    select t, m.new_id, dst, a.code, a.name, a.name_en, null, a.type, a.subtype, a.is_group, a.cf_class, a.requires_party, a.requires_cc, a.system_key, a.active, a.note, auth.uid() from acc.accounts a join _map m on m.old_id = a.id;
  get diagnostics na = row_count;
  update acc.accounts c set parent_id = pm.new_id from acc.accounts o join _map om on om.old_id = o.id join _map pm on pm.old_id = o.parent_id where c.tenant_id = t and c.id = om.new_id and o.parent_id is not null;
  if coalesce((p->>'parties')::boolean, false) then
    insert into acc.parties (tenant_id, entity_id, kind, code, name, name_en, vat_no, cr, phone, email, address, city, country, contact, credit_limit, terms_days, active, note, created_by)
      select t, dst, kind, code, name, name_en, vat_no, cr, phone, email, address, city, country, contact, credit_limit, terms_days, active, note, auth.uid() from acc.parties where tenant_id = t and entity_id is not distinct from src and (src is not null or entity_id is null);
    get diagnostics np = row_count;
  end if;
  if coalesce((p->>'dims')::boolean, false) then
    create temp table _dm (old_id uuid primary key, new_id uuid not null) on commit drop;
    insert into _dm select id, gen_random_uuid() from acc.dims where tenant_id = t and entity_id is not distinct from src and (src is not null or entity_id is null);
    insert into acc.dims (tenant_id, id, entity_id, kind, code, name, parent_id, active, note) select t, m.new_id, dst, d.kind, d.code, d.name, null, d.active, d.note from acc.dims d join _dm m on m.old_id = d.id; get diagnostics nd = row_count;
    update acc.dims c set parent_id = pm.new_id from acc.dims o join _dm om on om.old_id = o.id join _dm pm on pm.old_id = o.parent_id where c.tenant_id = t and c.id = om.new_id and o.parent_id is not null;
  end if;
  if coalesce((p->>'items')::boolean, false) then
    insert into acc.items (tenant_id, entity_id, code, name, name_en, unit, inv_account_id, cogs_account_id, sale_price, reorder_qty, active)
      select t, dst, i.code, i.name, i.name_en, i.unit, mi.new_id, mc.new_id, i.sale_price, i.reorder_qty, i.active from acc.items i join _map mi on mi.old_id = i.inv_account_id join _map mc on mc.old_id = i.cogs_account_id
      where i.tenant_id = t and i.entity_id is not distinct from src and (src is not null or i.entity_id is null); get diagnostics ni = row_count;
  end if;
  perform app.audit('seed','entity', dst::text, 'نسخ بيانات رئيسية: ' || na || ' حساب، ' || np || ' طرف، ' || ni || ' صنف، ' || nd || ' مركز');
  return jsonb_build_object('accounts', na, 'parties', np, 'items', ni, 'dims', nd);
end $$;
