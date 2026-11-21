-- تراجع 1.11.0.0: يعيد دوال الروابط إلى التعريفات السابقة، ويعيد مهمة المخزون، ويزيل org_uid. (مولَّد من التعريفات المثبّتة في 019/023/048)
create or replace function public.demo_link_create(p jsonb) returns jsonb language plpgsql security definer set search_path = public, app, acc as $$
declare nm text := trim(coalesce(p->>'label','')); h int := coalesce(nullif(p->>'hours','')::int, 48); vcode text; vpwd text; tok text; alphabet text := 'abcdefghjkmnpqrstuvwxyz23456789'; i int; pl record; fast boolean := false;
begin
  perform app.demo_admin();
  if nm = '' or length(nm) > 80 then raise exception 'الاسم مطلوب (حتى 80 حرفًا)'; end if;
  if h not in (24, 48, 72, 168, 336, 720) then raise exception 'المدة: يوم أو يومان أو 3 أيام أو أسبوع أو أسبوعان أو 30 يومًا'; end if;
  -- حجز شركة جاهزة (تخطّي الصفوف المحجوزة لدى طلب آخر متزامن)
  for pl in select * from acc.demo_pool order by created_at for update skip locked loop
    if exists (select 1 from acc.tenants t where t.code = pl.code) then
      vcode := pl.code; vpwd := pl.pwd; delete from acc.demo_pool where demo_pool.code = pl.code; fast := true; exit;
    else delete from acc.demo_pool where demo_pool.code = pl.code; end if;
  end loop;
  if fast then
    update acc.tenants set name = 'نسخة تجريبية — ' || nm, settings = jsonb_set(settings, '{demo,for}', to_jsonb(nm)) where acc.tenants.code = vcode;
  else
    vcode := 'demo-'; for i in 1..5 loop vcode := vcode || substr(alphabet, 1 + floor(random() * length(alphabet))::int, 1); end loop;
    vpwd := 'Dm'; for i in 1..8 loop vpwd := vpwd || substr(alphabet, 1 + floor(random() * length(alphabet))::int, 1); end loop; vpwd := vpwd || '#7';
    perform app.demo_seed(vcode, 'نسخة تجريبية — ' || nm, vpwd, 7, nm);
  end if;
  tok := 'k' || substr(replace(gen_random_uuid()::text || gen_random_uuid()::text, '-', ''), 1, 20);
  insert into acc.demo_links (token, label, hours, code, pwd) values (tok, nm, h, vcode, vpwd);
  perform app.padmin_log('demo_create', vcode, nm || ' / ' || h || ' ساعة' || case when fast then ' (جاهزة)' else '' end);
  return jsonb_build_object('token', tok, 'fast', fast);
end $$;

create or replace function public.demo_link_open(p jsonb) returns jsonb language plpgsql security definer set search_path = public, app, acc as $$
declare l acc.demo_links;
begin
  select * into l from acc.demo_links where token = coalesce(p->>'token', '') for update;
  if l.token is null or l.revoked then raise exception 'الرابط غير صالح أو أُلغي'; end if;
  if l.first_open is null then
    if l.created_at < now() - interval '60 days' then raise exception 'انتهت صلاحية الرابط — تواصل مع البائع'; end if;
    update acc.demo_links set first_open = now(), expires_at = now() + make_interval(hours => l.hours), opens = opens + 1 where token = l.token returning * into l;
    update acc.tenants set expires_at = (l.expires_at at time zone 'UTC')::date - 7,
      settings = case when jsonb_typeof(settings->'demo') = 'object' then settings || jsonb_build_object('demo', (settings->'demo') || jsonb_build_object('until', l.expires_at)) else settings end
      where code = l.code;
  else
    if l.expires_at < now() then raise exception 'انتهت مدة هذا الرابط — تواصل مع البائع للتمديد'; end if;
    update acc.demo_links set opens = opens + 1 where token = l.token;
  end if;
  return jsonb_build_object('code', l.code, 'username', 'owner', 'password', l.pwd, 'expires', l.expires_at);
end $$;

create or replace function public.demo_link_extend(p jsonb) returns jsonb language plpgsql security definer set search_path = public, app, acc as $$
declare l acc.demo_links; h int := coalesce(nullif(p->>'hours','')::int, 0); ne timestamptz;
begin
  perform app.demo_admin();
  if h not in (24, 48, 72, 168, 336, 720) then raise exception 'مدة التمديد: يوم أو يومان أو 3 أيام أو أسبوع أو أسبوعان أو 30 يومًا'; end if;
  select * into l from acc.demo_links where token = coalesce(p->>'token', '') for update;
  if l.token is null then raise exception 'الرابط غير موجود'; end if;
  if l.revoked then raise exception 'الرابط مُلغى — أنشئ رابطًا جديدًا'; end if;
  if not exists (select 1 from acc.tenants where code = l.code) then raise exception 'حُذفت بيانات هذه النسخة بعد انتهاء مدة الاحتفاظ — أنشئ رابطًا جديدًا'; end if;
  if l.first_open is null then
    update acc.demo_links set created_at = now() where token = l.token;  -- لم يُفتح بعد: تُجدَّد صلاحية الفتح، وتبدأ المدة عند أول فتح
    perform app.padmin_log('demo_extend', l.code, 'رابط لم يُفتح: تجديد صلاحية الفتح');
    return jsonb_build_object('state', 'new', 'expires_at', null);
  end if;
  ne := greatest(l.expires_at, now()) + make_interval(hours => h);
  update acc.demo_links set expires_at = ne where token = l.token;
  update acc.tenants set status = 'active', expires_at = (ne at time zone 'UTC')::date - 7,
    settings = case when jsonb_typeof(settings->'demo') = 'object' then settings || jsonb_build_object('demo', (settings->'demo') || jsonb_build_object('until', ne)) else settings end
    where code = l.code;
  perform app.padmin_log('demo_extend', l.code, l.label || ' +' || h || ' ساعة');
  return jsonb_build_object('state', 'active', 'expires_at', ne);
end $$;

create or replace function public.demo_link_revoke(p jsonb) returns jsonb language plpgsql security definer set search_path = public, app, acc as $$
declare l acc.demo_links;
begin
  perform app.demo_admin();
  update acc.demo_links set revoked = true where token = p->>'token' returning * into l;
  if l.token is null then raise exception 'الرابط غير موجود'; end if;
  if exists (select 1 from acc.tenants where code = l.code and settings ? 'demo') then perform app.demo_wipe(l.code); end if;
  perform app.padmin_log('demo_revoke', l.code, l.label);
  return jsonb_build_object('ok', true);
end $$;

create or replace function public.demo_link_delete(p jsonb) returns jsonb language plpgsql security definer set search_path = public, app, acc as $$
declare l acc.demo_links;
begin
  perform app.demo_admin();
  select * into l from acc.demo_links where token = p->>'token';
  if l.token is null then raise exception 'الرابط غير موجود'; end if;
  if exists (select 1 from acc.tenants where code = l.code and settings ? 'demo') then perform app.demo_wipe(l.code); end if;
  delete from acc.demo_links where token = l.token;
  return jsonb_build_object('ok', true);
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

drop index if exists acc.tenants_org_uid_u;
alter table acc.tenants drop column if exists org_uid;
do $$ begin perform cron.unschedule(jobid) from cron.job where jobname = 'mohkam-demo-pool'; perform cron.schedule('mohkam-demo-pool', '*/5 * * * *', 'select app.demo_pool_topup(3)'); exception when others then null; end $$;
delete from app.schema_migrations where version = '1.11.0.0';
