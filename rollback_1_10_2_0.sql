-- تراجع 1.10.2.0 → 1.10.1.0 (إضافي ومتكرر التشغيل). يُشغَّل يدويًا عند الحاجة فقط، ويُنفَّذ كله داخل معاملة واحدة.
-- يعيد: ingest_journal وsettings_get لنصّيهما السابقين، يزيل تثبيت search_path عن الـ29 دالة، يحذف فهارس ixfk_ ومفتاح acc.seq (id/seq_pkey)،
-- ويحذف صف الإصدار. لا يعيد صلاحيات الزائر (anon) الواسعة عمدًا: سحبها قرار أمني لا يُتراجَع عنه؛ إن لزم فصراحةً:
--   grant execute on function public.<name> to anon;   (لكل دالة تحتاجها فقط)
-- المعايير: الفهارس تُحذف بـ drop index if exists (لا قفل طويل)؛ لا يمس البيانات.
begin;
create or replace function public.ingest_journal(p jsonb) returns jsonb language plpgsql security definer set search_path = public, app, acc as $$
declare k acc.api_keys; h text := encode(sha256(convert_to(coalesce(p->>'key',''), 'UTF8')), 'hex'); jid uuid := gen_random_uuid(); d date := (p->>'date')::date; src text := coalesce(nullif(trim(p->>'source'),''), 'external'); ext text := trim(coalesce(p->>'external_id',''));
  per acc.periods; dr numeric; cr numeric; ex uuid; l jsonb; tot numeric;
begin
  select * into k from acc.api_keys where key_hash = h and active and (expires_at is null or expires_at > now());
  if k.id is null or not ('ingest_journal' = any(k.scopes)) then raise exception 'مفتاح غير صالح'; end if;
  if not app.tenant_ok(k.tenant_id) or not app.feat_on('connectors', k.tenant_id) then raise exception 'الخدمة غير مفعّلة لهذه الشركة'; end if;
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

create or replace function public.settings_get(p jsonb default '{}') returns jsonb language plpgsql stable security definer set search_path = public, app, acc as $$
declare t uuid := app.need(null, null);
begin return (select to_jsonb(x) - 'created_ip' - 'id' || jsonb_build_object('settings', app.jsonb_merge(app.default_settings(), x.settings)) from acc.tenants x where x.id = t); end $$;

-- إزالة تثبيت search_path عن الـ29 دالة التي ثبّتها 091 (ما كانت تملكه قبلًا يبقى كما هو)
do $$ declare r record; begin
  for r in select p.oid::regprocedure s from pg_proc p join pg_namespace n on n.oid=p.pronamespace where (n.nspname||'.'||p.proname) = any(array[
    'app.xml_esc',
    'app.cur_ent',
    'app.accounts_guard',
    'app.vault_blob_ok',
    'app.jsonb_merge',
    'app.zatca_seed',
    'app.type_prefix',
    'app.fin_ratios_of',
    'app.default_cf',
    'app.client_ip',
    'app.audit_guard',
    'app.role_template_defs',
    'app.restore_flag',
    'app.n',
    'app.div',
    'app.login_email',
    'app.default_settings',
    'app.rv',
    'app.kb_norm',
    'app.kb_query',
    'app.lines_guard',
    'app.share_ctx',
    'app.check_pw',
    'app.journals_guard',
    'app.xml_amt',
    'app.sha256_b64',
    'app.zatca_guard',
    'app.inv_module',
    'acc.published_docs_immutable'
  ]) loop execute format('alter function %s reset search_path', r.s); end loop;
end $$;

-- حذف فهارس المفاتيح الأجنبية (ixfk_*) ومفتاح acc.seq البديل
do $$ declare r record; begin
  for r in select schemaname, indexname from pg_indexes where schemaname='acc' and indexname like 'ixfk\_%' loop
    execute format('drop index if exists %I.%I', r.schemaname, r.indexname);
  end loop;
  if exists (select 1 from pg_constraint where conrelid='acc.seq'::regclass and conname='seq_pkey') then
    alter table acc.seq drop constraint seq_pkey; end if;
  alter table acc.seq drop column if exists id;
end $$;

delete from app.schema_migrations where version = '1.10.2.0';
commit;
