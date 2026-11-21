-- 1.10.1.0 → 1.10.2.0 delta (إضافي ومتكرر التشغيل): تشديد أمني + فهارس المرحلة 1 (19) + مفتاح acc.seq. المرحلة 2: delta_1_10_2_1_phase2.sql. التراجع: rollback_1_10_2_0.sql
-- مُحكَم للحسابات 1.10.2.0 (أ) — تشديد أمني بعد المراجعة (أمر عمل 2026-11-20). إضافي ومتكرر التشغيل؛ لا يغيّر بيانات ولا سياسات RLS.
-- 1) الزائر (anon): قائمة بيضاء صريحة من 12 دالة مقصودة للعامة، وأي دالة عامة أخرى تُسحب منها صلاحية التنفيذ.
-- 2) ingest_journal: حد معدل لكل مفتاح (كان api_call وحدها محدودة المعدل).
-- 3) search_path ثابت لكل دالة في app/acc/public (كانت 29 دالة في app بلا تثبيت).
-- 4) settings_get: لا تُرجِع عقد البائع (contract: سعر الاتفاق وملاحظاته) ولا عنوان IP لقبول الشروط لأي مستخدم في الشركة.
-- ملاحظة: «حماية كلمات المرور المسرّبة» (Leaked Password Protection) إعداد في لوحة Supabase Auth وليست SQL؛ يفعّلها المالك بنفسه (انظر SECURITY.md).

-- (2) حد المعدل للإدخال الخارجي
create or replace function public.ingest_journal(p jsonb) returns jsonb language plpgsql security definer set search_path = public, app, acc as $$
declare k acc.api_keys; h text := encode(sha256(convert_to(coalesce(p->>'key',''), 'UTF8')), 'hex'); jid uuid := gen_random_uuid(); d date := (p->>'date')::date; src text := coalesce(nullif(trim(p->>'source'),''), 'external'); ext text := trim(coalesce(p->>'external_id',''));
  per acc.periods; dr numeric; cr numeric; ex uuid; l jsonb; tot numeric; cnt int;
begin
  select * into k from acc.api_keys where key_hash = h and active and (expires_at is null or expires_at > now());
  if k.id is null or not ('ingest_journal' = any(k.scopes)) then raise exception 'مفتاح غير صالح'; end if;
  if not app.tenant_ok(k.tenant_id) or not app.feat_on('connectors', k.tenant_id) then raise exception 'الخدمة غير مفعّلة لهذه الشركة'; end if;
  -- حد المعدل (091): 120 طلبًا في الدقيقة لكل مفتاح، بنفس جدول api_call؛ يمنع إغراق قيود «بانتظار الاعتماد»
  insert into acc.api_rate (key_id, minute, n) values (k.id, date_trunc('minute', now()), 1) on conflict (key_id, minute) do update set n = acc.api_rate.n + 1 returning n into cnt;
  if cnt > 120 then raise exception 'تجاوزت حد الطلبات (120 في الدقيقة) — أعد المحاولة بعد قليل'; end if;
  if random() < 0.02 then delete from acc.api_rate where minute < now() - interval '1 hour'; end if;
  if ext = '' or length(ext) > 100 or length(src) > 40 then raise exception 'المعرّف الخارجي والمصدر مطلوبان'; end if;
  if d is null then raise exception 'التاريخ مطلوب'; end if;
  if jsonb_array_length(coalesce(p->'lines','[]'::jsonb)) < 2 or jsonb_array_length(p->'lines') > 500 then raise exception 'سطران إلى 500 سطر'; end if;
  select journal_id into ex from acc.ingest_log where tenant_id = k.tenant_id and source = src and external_id = ext;
  if found then return jsonb_build_object('duplicate', true, 'journal_id', ex); end if;
  select * into per from acc.periods where tenant_id = k.tenant_id and entity_id = k.entity_id and d between start_date and end_date; if per.id is null or per.status = 'closed' then raise exception 'لا توجد فترة مفتوحة للتاريخ %', d; end if;
  select coalesce(sum(coalesce(nullif(x->>'debit','')::numeric,0)),0), coalesce(sum(coalesce(nullif(x->>'credit','')::numeric,0)),0) into dr, cr from jsonb_array_elements(p->'lines') x;
  if round(dr,2) <> round(cr,2) or dr = 0 then raise exception 'القيد غير متوازن (مدين % / دائن %)', dr, cr; end if;
  insert into acc.journals (tenant_id, id, entity_id, type, date, description, reference, status, source, created_by, submitted_at, total)
  values (k.tenant_id, jid, k.entity_id, 'GJ', d, left(coalesce(p->>'description','قيد من ' || src), 500), left(ext, 100), 'pending', 'connector', null, now(), round(dr, 2));
  perform app.put_lines(k.tenant_id, jid, k.entity_id, d, p->'lines');
  insert into acc.ingest_log (tenant_id, key_id, source, external_id, journal_id) values (k.tenant_id, k.id, src, ext, jid);
  update acc.api_keys set last_used_at = now(), use_count = use_count + 1 where id = k.id and tenant_id = k.tenant_id;
  perform app.audit_for(k.tenant_id, null, 'connector:' || k.name, 'ingest', 'journal', jid::text, src || ' / ' || ext || ' — ' || round(dr,2));
  return jsonb_build_object('journal_id', jid, 'status', 'pending');
end $$;

-- (3) تثبيت search_path لكل دالة ودالة ترجع (مشغّلات وأدوات داخلية وعامة)
do $$ declare f record; begin
  for f in select p.oid::regprocedure as sig from pg_proc p join pg_namespace n on n.oid = p.pronamespace
    where n.nspname in ('app', 'acc', 'public') and p.prokind in ('f', 'p')
      and not exists (select 1 from unnest(coalesce(p.proconfig, '{}'::text[])) c where c like 'search_path=%')
      and not exists (select 1 from pg_depend d where d.objid = p.oid and d.deptype = 'e') loop  -- لا نمس دوال الإضافات
    execute format('alter function %s set search_path = public, app, acc', f.sig);
  end loop;
end $$;

-- (4) settings_get بلا بيانات داخلية للبائع
create or replace function public.settings_get(p jsonb default '{}') returns jsonb language plpgsql stable security definer set search_path = public, app, acc as $$
declare t uuid := app.need(null, null);
begin return (select to_jsonb(x) - 'created_ip' - 'id' - 'contract'
    || jsonb_build_object('settings', app.jsonb_merge(app.default_settings(), x.settings) #- '{terms,ip}') from acc.tenants x where x.id = t); end $$;

-- (1) الزائر: قائمة بيضاء حصرية. أي دالة public أخرى تُسحب من anon وpublic ثم تُمنح للمسجَّل إن كانت من دوال الواجهة.
do $$ declare f record; wl text[] := array['api_call','api_catalog','demo_link_open','ingest_journal','legal_published','login_email','register_company','share_open','share_path_ok','share_peek','share_receipt','signup_status'];
begin
  for f in select p.oid::regprocedure as sig, p.proname, p.pronargs, pg_get_function_identity_arguments(p.oid) args from pg_proc p join pg_namespace n on n.oid = p.pronamespace
    where n.nspname = 'public' and p.prokind in ('f', 'p') and not exists (select 1 from pg_depend d where d.objid = p.oid and d.deptype = 'e') loop
    if f.proname = any(wl) then
      execute format('revoke execute on function %s from public', f.sig); execute format('grant execute on function %s to anon, authenticated', f.sig);
    else
      execute format('revoke execute on function %s from public, anon', f.sig);
    end if;
  end loop;
  for f in select p.oid::regprocedure as sig from pg_proc p join pg_namespace n on n.oid = p.pronamespace where n.nspname in ('app', 'acc') and p.prokind in ('f', 'p') and not exists (select 1 from pg_depend d where d.objid = p.oid and d.deptype = 'e') loop
    execute format('revoke execute on function %s from public, anon, authenticated', f.sig);
  end loop;
end $$;

-- (5) دالة تستعملها سياسة حذف التخزين (075): المنح موجود في القاعدة الحية أصلًا؛ هذا السطر يوحّد مسار التثبيت من الصفر (999 كان يسحبه).
grant execute on function public.att_registered(text) to authenticated;

-- مُحكَم للحسابات 1.10.2.0 (ب) — أداء: فهارس مغطّية (المرحلة 1: الأهم — 19 فهرسًا على جداول التقارير) للمفاتيح الأجنبية المركّبة (tenant_id, x_id) التي بلا فهرس (69 مفتاحًا) + مفتاح أساسي لـ acc.seq.
-- السبب: حذف/تحديث الصف الأب يفحص الجدول الابن كاملًا، وربط journal_lines/invoice_lines/payments... بالحسابات والمراكز والمشاريع يعتمد على هذه الأعمدة.
-- الأعمدة التي تقبل null (مراكز التكلفة والمشاريع والأطراف الاختيارية...) فهارسها جزئية (where col is not null) لتقليل كلفة الكتابة (25 فهرسًا)؛ المقارنة بالمساواة وفحص المفتاح الأجنبي يستفيدان منها.
-- إضافي ومتكرر التشغيل (create index if not exists). الأسماء بادئتها ixfk_. الفهارس الخمسة غير المستخدمة لا تُحذف الآن (قرار الأمر).
-- مفاتيح مولَّدة من فحص المخطط؛ اختبار hardening.mjs يفشل إن ظهر مفتاح أجنبي جديد بلا فهرس مغطٍّ.
-- المرحلة 1 = جداول القراءة الثقيلة (journal_lines, invoice_lines, payments, allocations, tax_lines, journals, periods...). الباقي في 093 (مؤجَّل حتى يثبت احتياج).
create index if not exists ixfk_allocations_invoice_id on acc.allocations (tenant_id, invoice_id);
create index if not exists ixfk_invoice_lines_account_id on acc.invoice_lines (tenant_id, account_id);
create index if not exists ixfk_invoice_lines_cost_center_id on acc.invoice_lines (tenant_id, cost_center_id) where cost_center_id is not null;
create index if not exists ixfk_invoice_lines_invoice_id on acc.invoice_lines (tenant_id, invoice_id);
create index if not exists ixfk_invoice_lines_project_id on acc.invoice_lines (tenant_id, project_id) where project_id is not null;
create index if not exists ixfk_invoices_journal_id on acc.invoices (tenant_id, journal_id) where journal_id is not null;
create index if not exists ixfk_journal_lines_account_id on acc.journal_lines (tenant_id, account_id);
create index if not exists ixfk_journal_lines_cost_center_id on acc.journal_lines (tenant_id, cost_center_id) where cost_center_id is not null;
create index if not exists ixfk_journal_lines_party_id on acc.journal_lines (tenant_id, party_id) where party_id is not null;
create index if not exists ixfk_journal_lines_project_id on acc.journal_lines (tenant_id, project_id) where project_id is not null;
create index if not exists ixfk_journals_period_id on acc.journals (tenant_id, period_id) where period_id is not null;
create index if not exists ixfk_payment_lines_account_id on acc.payment_lines (tenant_id, account_id);
create index if not exists ixfk_payment_lines_payment_id on acc.payment_lines (tenant_id, payment_id);
create index if not exists ixfk_payments_cash_account_id on acc.payments (tenant_id, cash_account_id);
create index if not exists ixfk_payments_journal_id on acc.payments (tenant_id, journal_id) where journal_id is not null;
create index if not exists ixfk_payments_party_id on acc.payments (tenant_id, party_id) where party_id is not null;
create index if not exists ixfk_periods_fy_id on acc.periods (tenant_id, fy_id);
create index if not exists ixfk_stock_wh_item_id on acc.stock_wh (tenant_id, item_id);
create index if not exists ixfk_tax_lines_journal_id on acc.tax_lines (tenant_id, journal_id);


-- acc.seq: الفهرس الفريد seq_u يعتمد تعبيرًا (coalesce(entity_id, صفر)) لأن entity_id قد يكون null (تسلسل على مستوى الشركة)،
-- فلا يصلح مفتاحًا أساسيًا مباشرًا؛ نضيف مفتاحًا بديلًا تلقائيًا (identity) دون المساس بسلوك ON CONFLICT الحالي.
-- الاسترجاع (028_restore) يستثني أعمدة identity أصلًا، فلا يتأثر النسخ الاحتياطي/الاسترجاع.
do $$ begin
  if not exists (select 1 from pg_constraint where conrelid = 'acc.seq'::regclass and contype = 'p') then
    alter table acc.seq add column if not exists id bigint generated always as identity;
    alter table acc.seq add constraint seq_pkey primary key (id);
  end if;
end $$;

insert into app.schema_migrations (version, name) values ('1.10.2.0', 'تشديد أمني (قائمة بيضاء للزائر، حد معدل للإدخال الخارجي، search_path ثابت، settings_get بلا عقد البائع) + فهارس المفاتيح الأجنبية + مفتاح acc.seq')
on conflict (version) do nothing;
