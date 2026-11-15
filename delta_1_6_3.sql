-- مُحكَم للحسابات 1.6.3.0 — تحديث تراكمي فوق 1.6.2.0 (إضافي ومتكرر التشغيل): الاتفاقيات والوثائق المنشورة + الإصدارات والتحديثات
-- شغّله مرة واحدة في Supabase SQL Editor.
-- مُحكَم للحسابات 1.6.3 — «الاتفاقيات والوثائق» و«الإصدارات والتحديثات» في لوحة البائع (بنمط HR)
-- إضافي ومتكرر التشغيل: لا يغيّر بيانات القبول القائمة ولا صلاحيات الشركات. الوثيقة المنشورة سجل لا يُعدَّل ولا يُحذف.
-- الاتفاقية الثابتة في الكود تبقى الأصل؛ تتقدّم الإصدار فقط عند نشر وثيقة «إعادة قبول» أحدث.

-- ===== الوثائق المنشورة =====
create table if not exists acc.published_docs (
  id uuid primary key default gen_random_uuid(),
  kind text not null check (kind in ('agreement','dpa','terms','privacy','staff','other')),
  title text not null check (length(title) between 2 and 160),
  version text not null check (length(version) between 1 and 20),
  change_type text not null check (change_type in ('reaccept','notice')),
  summary text not null default '' check (length(summary) <= 600),
  body text not null check (length(body) between 20 and 200000),
  published_by uuid, published_at timestamptz not null default now(),
  unique (kind, version));
alter table acc.published_docs enable row level security;
create index if not exists published_docs_kind_idx on acc.published_docs (kind, published_at desc);

-- لا تعديل ولا حذف (سجل للمساءلة)
create or replace function acc.published_docs_immutable() returns trigger language plpgsql as $$
begin raise exception 'الوثيقة المنشورة لا تُعدَّل ولا تُحذف؛ انشر إصدارًا جديدًا'; end $$;
drop trigger if exists published_docs_ro on acc.published_docs;
create trigger published_docs_ro before update or delete on acc.published_docs for each row execute function acc.published_docs_immutable();

-- نشر وثيقة (البائع فقط)
create or replace function public.platform_docs_publish(p jsonb) returns jsonb language plpgsql volatile security definer set search_path = public, app, acc as $$
declare k text := trim(coalesce(p->>'kind','')); v text := trim(coalesce(p->>'version','')); ti text := trim(coalesce(p->>'title','')); ct text := coalesce(nullif(p->>'change_type',''), 'reaccept'); b text := trim(coalesce(p->>'body','')); r acc.published_docs;
begin
  perform app.demo_admin();
  if k not in ('agreement','dpa','terms','privacy','staff','other') then raise exception 'نوع الوثيقة غير صالح'; end if;
  if ct not in ('reaccept','notice') then raise exception 'نوع التغيير غير صالح'; end if;
  if v = '' or length(v) > 20 then raise exception 'رقم الإصدار مطلوب (حتى 20 حرفًا)'; end if;
  if length(ti) < 2 or length(ti) > 160 then raise exception 'عنوان الوثيقة مطلوب'; end if;
  if length(b) < 20 then raise exception 'نص الوثيقة قصير جدًا'; end if;
  if length(b) > 200000 then raise exception 'نص الوثيقة طويل جدًا'; end if;
  if exists (select 1 from acc.published_docs where kind = k and version = v) then raise exception 'هذا الإصدار منشور مسبقًا لنفس الوثيقة؛ استعمل رقمًا جديدًا'; end if;
  insert into acc.published_docs (kind, title, version, change_type, summary, body, published_by) values (k, ti, v, ct, left(trim(coalesce(p->>'summary','')), 600), b, auth.uid()) returning * into r;
  perform app.padmin_log('doc_publish', '', k || ' ' || v || ' (' || ct || ') — ' || ti);
  return jsonb_build_object('ok', true, 'id', r.id, 'kind', k, 'version', v, 'change_type', ct);
end $$;

-- قائمة المنشور للبائع (بلا النص الكامل) + عدد الشركات التي قبلت كل إصدار
create or replace function public.platform_docs_list(p jsonb default '{}') returns jsonb language plpgsql stable security definer set search_path = public, app, acc as $$
declare res jsonb; real_n int;
begin
  perform app.demo_admin();
  select count(*) into real_n from acc.tenants where not (settings ? 'demo');
  select coalesce(jsonb_agg(x order by (x->>'published_at') desc), '[]'::jsonb) into res from (
    select jsonb_build_object('id', d.id, 'kind', d.kind, 'title', d.title, 'version', d.version, 'change_type', d.change_type, 'summary', d.summary, 'published_at', d.published_at, 'chars', length(d.body),
      'accepted', (select count(distinct a.tenant_id) from acc.agreement_acceptance a join acc.tenants t on t.id = a.tenant_id where a.version = d.version and a.doc = d.kind and not (t.settings ? 'demo')), 'tenants', real_n,
      'current', d.id = (select id from acc.published_docs z where z.kind = d.kind order by z.published_at desc, z.id desc limit 1)) as x
    from acc.published_docs d order by d.published_at desc limit 200) q;
  return jsonb_build_object('rows', res, 'current_version', public.legal_current_version());
end $$;

-- الإصدار القانوني الحالي المطلوب قبوله: أحدث وثيقة «إعادة قبول» من الأنواع الأربعة، وإلا فالإصدار الثابت في الواجهة (يُمرَّر)
create or replace function public.legal_current_version(p jsonb default '{}') returns text language sql stable security definer set search_path = public, app, acc as $$
  select version from acc.published_docs where change_type = 'reaccept' and kind in ('agreement','dpa','terms','privacy') order by published_at desc, id desc limit 1 $$;

-- قراءة الوثائق المنشورة (نص قانوني عام): أحدث إصدار لكل نوع + إشعارات التغيير الأخيرة
create or replace function public.legal_published(p jsonb default '{}') returns jsonb language sql stable security definer set search_path = public, app, acc as $$
  select jsonb_build_object(
    'version', public.legal_current_version(),
    'docs', coalesce((select jsonb_agg(jsonb_build_object('kind', d.kind, 'title', d.title, 'version', d.version, 'change_type', d.change_type, 'summary', d.summary, 'body', d.body, 'published_at', d.published_at)) from (
      select distinct on (kind) * from acc.published_docs order by kind, published_at desc, id desc) d), '[]'::jsonb),
    'notices', coalesce((select jsonb_agg(jsonb_build_object('kind', n.kind, 'title', n.title, 'version', n.version, 'summary', n.summary, 'published_at', n.published_at)) from (
      select kind, title, version, summary, published_at from acc.published_docs where change_type = 'notice' and published_at > now() - interval '60 days' order by published_at desc limit 10) n), '[]'::jsonb)) $$;
grant execute on function public.legal_published(jsonb) to anon, authenticated;
grant execute on function public.legal_current_version(jsonb) to authenticated;

-- ===== الإصدارات والتحديثات =====
create table if not exists app.releases (
  n int primary key check (n >= 1), label text not null check (length(label) between 1 and 40), notes text not null default '' check (length(notes) <= 4000),
  published_at timestamptz not null default now(), published_by uuid);
alter table app.releases enable row level security;
insert into app.releases (n, label, notes) values (1, '1.0 — الأساس', 'كل المزايا المتاحة عند بدء نظام الإصدارات') on conflict (n) do nothing;

-- آخر إصدار منشور (كان ثابتًا = 1)
create or replace function app.latest_release() returns int language sql stable security definer set search_path = app, public as $$ select coalesce((select max(n) from app.releases), 1) $$;

-- الشركة الجديدة تبدأ بآخر إصدار منشور
create or replace function acc.tenant_release_default() returns trigger language plpgsql security definer set search_path = public, app, acc as $$
begin new.release := app.latest_release(); return new; end $$;
drop trigger if exists tenants_release_ins on acc.tenants;
create trigger tenants_release_ins before insert on acc.tenants for each row execute function acc.tenant_release_default();

-- الإصدارات للبائع: كل إصدار بمزاياه وعدد الشركات عليه + مزايا مجهّزة (since أعلى من الأخير) + الشركات المتأخرة
create or replace function public.platform_releases_list(p jsonb default '{}') returns jsonb language plpgsql stable security definer set search_path = public, app, acc as $$
declare lr int := app.latest_release();
begin
  perform app.demo_admin();
  return jsonb_build_object('latest', lr,
    'releases', coalesce((select jsonb_agg(jsonb_build_object('n', r.n, 'label', r.label, 'notes', r.notes, 'published_at', r.published_at,
        'features', coalesce((select jsonb_agg(jsonb_build_object('key', c.key, 'name', c.name) order by c.sort) from app.feature_cat c where c.since = r.n and r.n > 1), '[]'::jsonb),
        'tenants', (select count(*) from acc.tenants t where t.release = r.n and not (t.settings ? 'demo'))) order by r.n desc) from app.releases r), '[]'::jsonb),
    'staged', coalesce((select jsonb_agg(jsonb_build_object('key', c.key, 'name', c.name, 'since', c.since) order by c.sort) from app.feature_cat c where c.since > lr), '[]'::jsonb),
    'behind', (select count(*) from acc.tenants t where t.release < lr and not (t.settings ? 'demo') and t.status in ('trial','active')));
end $$;

-- نشر إصدار جديد: يرفع رقم الإصدار ويجعل المزايا المجهّزة (since أعلى) جزءًا منه. لا يصل أي شركة شيء حتى يضغط البائع «تحديث».
create or replace function public.platform_release_publish(p jsonb) returns jsonb language plpgsql volatile security definer set search_path = public, app, acc as $$
declare lr int; nr int; lb text := trim(coalesce(p->>'label','')); nt text := trim(coalesce(p->>'notes','')); k int;
begin
  perform app.demo_admin();
  perform pg_advisory_xact_lock(hashtext('acc_release_publish'));
  lr := app.latest_release(); nr := lr + 1;
  if length(lb) < 1 or length(lb) > 40 then raise exception 'اسم/رقم الإصدار مطلوب (حتى 40 حرفًا)'; end if;
  if length(nt) > 4000 then raise exception 'ملاحظات الإصدار طويلة'; end if;
  insert into app.releases (n, label, notes, published_by) values (nr, lb, nt, auth.uid());
  update app.feature_cat set since = nr where since > lr; get diagnostics k = row_count;
  perform app.padmin_log('release_publish', '', 'إصدار ' || nr || ' — ' || lb || ' | مزايا: ' || k);
  return jsonb_build_object('ok', true, 'release', nr, 'features', k);
end $$;

-- دفع الإصدار الأحدث لعدة شركات دفعة واحدة (المقفول عقديًا يبقى مقفولًا؛ لا يمسّ الروابط ولا البيانات)
create or replace function public.platform_release_push_many(p jsonb) returns jsonb language plpgsql volatile security definer set search_path = public, app, acc as $$
declare lr int := app.latest_release(); codes text[]; c text; n int := 0; t acc.tenants;
begin
  perform app.demo_admin();
  if coalesce((p->>'all')::boolean, false) then select coalesce(array_agg(code), '{}') into codes from acc.tenants where release < lr and not (settings ? 'demo') and status in ('trial','active');
  else select coalesce(array_agg(x), '{}') into codes from jsonb_array_elements_text(coalesce(p->'codes', '[]'::jsonb)) x; end if;
  if coalesce(array_length(codes, 1), 0) > 500 then raise exception 'عدد الشركات كبير؛ ادفع على دفعات'; end if;
  foreach c in array codes loop
    select * into t from acc.tenants where code = c and not (settings ? 'demo') and release < lr for update;
    if t.id is not null then update acc.tenants set release = lr where id = t.id; perform app.padmin_log('release_push', t.code, 'من إصدار ' || t.release || ' إلى ' || lr); n := n + 1; end if;
  end loop;
  return jsonb_build_object('ok', true, 'pushed', n, 'release', lr);
end $$;

insert into app.schema_migrations (version, name) values ('1.6.3.0', 'الاتفاقيات والوثائق المنشورة + الإصدارات والتحديثات في لوحة البائع') on conflict (version) do nothing;


-- إعادة تطبيق الصلاحيات (آمن للتكرار)
-- كل دوال الواجهة (التي تأخذ jsonb) متاحة للمستخدم المسجَّل فقط
do $$ declare f record; begin
  for f in select p.oid::regprocedure as sig, p.proname from pg_proc p join pg_namespace n on n.oid = p.pronamespace where n.nspname = 'public' and p.prokind = 'f' and p.proowner = (select oid from pg_roles where rolname = current_user)
      and (p.proname in ('login_email','register_company','ingest_journal','api_call','api_catalog','signup_status','demo_link_open','legal_published') or p.pronargs = 0 or p.proargtypes::text = (select oid::text from pg_type where typname = 'jsonb')) loop
    if f.proname in ('register_company','ingest_journal','api_call','api_catalog','login_email','signup_status','demo_link_open','legal_published') then execute format('grant execute on function %s to anon, authenticated', f.sig);
    else execute format('grant execute on function %s to authenticated', f.sig); end if;
  end loop;
end $$;
alter default privileges in schema public revoke execute on functions from public, anon;

-- تشديد نهائي (آمن للتكرار): لا يصل الزائر أو المستخدم المسجّل مباشرة لأي دالة داخلية في app/acc
do $$ declare f record; begin
  for f in select p.oid::regprocedure as sig from pg_proc p join pg_namespace n on n.oid = p.pronamespace where n.nspname in ('app','acc') and p.prokind in ('f','p') loop
    begin execute format('revoke execute on function %s from public, anon, authenticated', f.sig); exception when others then null; end; end loop;
  for f in select p.oid::regprocedure as sig from pg_proc p join pg_namespace n on n.oid = p.pronamespace where n.nspname = 'public' and p.prokind = 'f' and p.proname not in ('login_email','register_company','ingest_journal','api_call','api_catalog','signup_status','demo_link_open','legal_published') and pg_get_function_identity_arguments(p.oid) = 'p jsonb' loop
    begin execute format('revoke execute on function %s from public, anon', f.sig); execute format('grant execute on function %s to authenticated', f.sig); exception when others then null; end; end loop;
end $$;
