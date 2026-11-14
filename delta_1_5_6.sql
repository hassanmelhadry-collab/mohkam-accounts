-- مُحكَم 1.5.0.6 — استرجاع الكوارث من نسخة احتياطية (آمن للتكرار، لا يمس الروابط ولا البيانات)
-- مُحكَم للحسابات — الاسترجاع من نسخة احتياطية (استرجاع الكوارث) — لمدير المنصة فقط
-- 1) النسخة الاحتياطية تتضمّن الآن بيانات الشركة نفسها (tenant). 2) الاسترجاع ينشئ شركة جديدة (موقوفة) بنفس معرّفات السجلات، ثم يتحقق من التطابق.
create or replace function app.restore_flag() returns boolean language sql stable as $$ select coalesce(current_setting('app.restore', true), '') = '1' $$;

create or replace function app.accounts_guard() returns trigger language plpgsql as $$
declare pt text; has_post boolean;
begin
  if tg_op = 'INSERT' and app.restore_flag() then return new; end if;
  if new.parent_id is not null then
    select type into pt from acc.accounts where tenant_id = new.tenant_id and id = new.parent_id;
    if pt is distinct from new.type then raise exception 'نوع الحساب يجب أن يطابق نوع الحساب الأب'; end if;
    if new.parent_id = new.id then raise exception 'الحساب لا يكون أبًا لنفسه'; end if;
    if exists (select 1 from acc.journal_lines where tenant_id = new.tenant_id and account_id = new.parent_id limit 1) then raise exception 'الحساب الأب عليه حركات — لا يجوز إضافة حسابات فرعية تحته'; end if;
    update acc.accounts set is_group = true where tenant_id = new.tenant_id and id = new.parent_id and not is_group and tg_op <> 'xx';
  end if;
  if tg_op = 'UPDATE' then
    select exists (select 1 from acc.journal_lines where tenant_id = old.tenant_id and account_id = old.id limit 1) into has_post;
    if has_post and (new.type is distinct from old.type) then raise exception 'لا يجوز تغيير نوع حساب عليه حركات'; end if;
    if has_post and new.is_group and not old.is_group then raise exception 'لا يجوز تحويل حساب عليه حركات إلى حساب تجميعي'; end if;
    if new.parent_id is distinct from old.parent_id then
      if exists (with recursive d as (select id from acc.accounts where tenant_id = old.tenant_id and parent_id = old.id union all select a.id from acc.accounts a join d on a.parent_id = d.id where a.tenant_id = old.tenant_id) select 1 from d where id = new.parent_id) then
        raise exception 'لا يجوز نقل الحساب تحت أحد أبنائه'; end if;
    end if;
  end if;
  return new;
end $$;

create or replace function app.lines_guard() returns trigger language plpgsql as $$
begin
  if tg_op = 'DELETE' and current_setting('app.demo_wipe', true) = '1' then return old; end if;
  if tg_op = 'INSERT' then
    if app.restore_flag() then return new; end if;
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

create or replace function public.backup_export(p jsonb default '{}') returns jsonb language plpgsql volatile security definer set search_path = public, app, acc as $$
declare t uuid := app.need_sys('backup'); r jsonb := '{}'::jsonb; x record; j jsonb; n jsonb := '{}'::jsonb; c bigint; meta jsonb;
begin
  for x in select tb.table_name from information_schema.tables tb join information_schema.columns c on c.table_schema = tb.table_schema and c.table_name = tb.table_name and c.column_name = 'tenant_id'
           where tb.table_schema = 'acc' and tb.table_type = 'BASE TABLE' and tb.table_name not in ('api_keys', 'demo_links', 'ingest_log', 'client_errors') order by 1 loop
    execute format('select coalesce(jsonb_agg(to_jsonb(q)), ''[]''::jsonb), count(*) from acc.%I q where q.tenant_id = $1', x.table_name) into j, c using t;
    r := r || jsonb_build_object(x.table_name, j); n := n || jsonb_build_object(x.table_name, c);
  end loop;
  select to_jsonb(z) - 'id' - 'created_ip' into meta from acc.tenants z where z.id = t;
  perform app.audit('export', 'backup', t::text, 'تصدير نسخة احتياطية كاملة');
  return jsonb_build_object('app', 'mohkam-accounts', 'format', 1, 'exported_at', now(), 'tenant_id', t, 'tenant', meta, 'counts', n, 'tables', r);
end $$;

create or replace function public.platform_restore_backup(p jsonb) returns jsonb language plpgsql volatile security definer set search_path = public, app, acc as $$
declare b jsonb := p->'backup'; c text := lower(trim(coalesce(p->>'code',''))); nt uuid := gen_random_uuid(); ord text[] := '{}'; tn text; x record; cols text; j jsonb; cnt bigint; res jsonb := '{}'::jsonb; skipped bigint := 0;
  bd numeric; bc numeric; rd numeric; rc numeric; tabs text[];
begin
  perform app.demo_admin();
  if b is null or b->>'app' <> 'mohkam-accounts' or (b->>'format')::int <> 1 or jsonb_typeof(b->'tables') <> 'object' or b->'tenant' is null then raise exception 'ملف النسخة الاحتياطية غير صالح أو قديم (ينقصه بيانات الشركة) — أعد تصديره من الإصدار الحالي'; end if;
  if c !~ '^[a-z0-9][a-z0-9-]{2,30}$' then raise exception 'رمز الشركة الجديد غير صالح'; end if;
  if exists (select 1 from acc.tenants where code = c) then raise exception 'رمز الشركة مستخدم — اختر رمزًا آخر للاسترجاع'; end if;
  -- ترتيب الجداول بحسب المفاتيح الأجنبية (الآباء أولًا)
  with recursive tb as (select jsonb_object_keys(b->'tables') as n),
  dep as (select distinct cr.relname::text as child, pr.relname::text as parent from pg_constraint k join pg_class cr on cr.oid = k.conrelid join pg_class pr on pr.oid = k.confrelid
          where k.contype = 'f' and cr.relnamespace = 'acc'::regnamespace and pr.relnamespace = 'acc'::regnamespace and cr.oid <> pr.oid),
  lvl as (select n, 0 as l from tb where not exists (select 1 from dep where child = tb.n and parent in (select n from tb) and parent <> 'tenants')
          union all select tb.n, lvl.l + 1 from tb join dep on dep.child = tb.n join lvl on lvl.n = dep.parent where lvl.l < 12)
  select array_agg(n order by m) into ord from (select n, max(l) m from lvl group by n) s;
  if coalesce(array_length(ord, 1), 0) <> (select count(*) from jsonb_object_keys(b->'tables')) then raise exception 'تعذّر ترتيب الجداول للاسترجاع'; end if;
  perform set_config('app.restore', '1', true);
  insert into acc.tenants select * from jsonb_populate_record(null::acc.tenants, (b->'tenant') || jsonb_build_object('id', nt, 'code', c, 'status', 'suspended', 'suspend_msg', 'قيد الاسترجاع — راجع البيانات ثم فعّل الشركة'));
  foreach tn in array ord loop
    select string_agg(format('%I', column_name), ',' order by ordinal_position) into cols from information_schema.columns where table_schema = 'acc' and table_name = tn and is_generated = 'NEVER' and is_identity = 'NO' and coalesce(column_default, '') not like 'nextval%';
    j := (select coalesce(jsonb_agg(e || jsonb_build_object('tenant_id', nt) order by (case when tn = 'audit' then (e->>'id')::bigint end)), '[]'::jsonb) from jsonb_array_elements(b->'tables'->tn) e);
    if tn in ('members', 'employee_links') then
      -- لا يُسترجع المستخدم إلا إن كان حسابه موجودًا في نظام الدخول وغير مرتبط بشركة أخرى (عند فقد الشركة الأصلية يُسترجع كل المستخدمين)
      select count(*) into cnt from jsonb_array_elements(j) e where not exists (select 1 from auth.users u where u.id = (e->>'user_id')::uuid) or exists (select 1 from acc.members m where m.user_id = (e->>'user_id')::uuid);
      skipped := skipped + cnt;
      j := (select coalesce(jsonb_agg(e), '[]'::jsonb) from jsonb_array_elements(j) e where exists (select 1 from auth.users u where u.id = (e->>'user_id')::uuid) and not exists (select 1 from acc.members m where m.user_id = (e->>'user_id')::uuid));
    end if;
    execute format('insert into acc.%I (%s) select %s from jsonb_populate_recordset(null::acc.%I, $1)', tn, cols, cols, tn) using j;
    get diagnostics cnt = row_count;
    res := res || jsonb_build_object(tn, cnt);
  end loop;
  -- التحقق: تطابق عدد السجلات ومجموع المدين/الدائن
  for x in select key as n, value::bigint as v from jsonb_each_text(b->'counts') loop
    if x.n in ('members', 'employee_links') then continue; end if;
    if (res->>x.n)::bigint is distinct from x.v then raise exception 'عدم تطابق في جدول %: متوقع % ومُسترجع %', x.n, x.v, res->>x.n; end if;
  end loop;
  select coalesce(sum((e->>'debit')::numeric), 0), coalesce(sum((e->>'credit')::numeric), 0) into bd, bc from jsonb_array_elements(b->'tables'->'journal_lines') e where (e->>'posted')::boolean;
  select coalesce(sum(debit), 0), coalesce(sum(credit), 0) into rd, rc from acc.journal_lines where tenant_id = nt and posted;
  if bd <> rd or bc <> rc or rd <> rc then raise exception 'عدم تطابق في مجاميع القيود المرحّلة'; end if;
  perform app.padmin_log('restore', c, 'استرجاع نسخة احتياطية — ' || (b->'tenant'->>'name'));
  return jsonb_build_object('tenant', nt, 'code', c, 'restored', res, 'users_skipped', skipped, 'posted_debit', rd, 'posted_credit', rc, 'status', 'suspended');
end $$;

-- تشديد نهائي (آمن للتكرار): لا يصل الزائر أو المستخدم المسجّل مباشرة لأي دالة داخلية في app/acc
do $$ declare f record; begin
  for f in select p.oid::regprocedure as sig from pg_proc p join pg_namespace n on n.oid = p.pronamespace where n.nspname in ('app','acc') and p.prokind in ('f','p') loop
    begin execute format('revoke execute on function %s from public, anon, authenticated', f.sig); exception when others then null; end; end loop;
  for f in select p.oid::regprocedure as sig from pg_proc p join pg_namespace n on n.oid = p.pronamespace where n.nspname = 'public' and p.prokind = 'f' and p.proname not in ('login_email','register_company','ingest_journal','signup_status','demo_link_open') and pg_get_function_identity_arguments(p.oid) = 'p jsonb' loop
    begin execute format('revoke execute on function %s from public, anon', f.sig); execute format('grant execute on function %s to authenticated', f.sig); exception when others then null; end; end loop;
end $$;
