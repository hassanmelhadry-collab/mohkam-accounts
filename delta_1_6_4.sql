-- مُحكَم للحسابات — تحديث 1.6.4.0 (تراكمي): مطابقة الشركات الشقيقة + خزنة المنصات + مرونة دليل الحسابات
-- يُشغَّل على القاعدة الحية بعد 1.6.2.x؛ كله قابل لإعادة التشغيل (create if not exists / create or replace) ولا يغيّر البيانات.

-- ===== sql/049_interco.sql =====
-- مُحكَم للحسابات 1.6.3 — مطابقة الشركات الشقيقة (المعاملات بين الكيانات) — ميزة اختيارية interco
-- معاملة واحدة تنشئ قيدين مرحّلين متقابلين في كيانين مختلفين (ذمة مدينة عند المُعطي / ذمة دائنة عند المُستلِم) برقم ربط واحد،
-- وتقرير مطابقة يقارن أرصدة حسابات «الشركات الشقيقة» في الدفاتر مع المعاملات المرتبطة، ويُظهر ما لم يُربط (قيود يدوية على الحسابات البينية).
create table if not exists acc.ic_links (
  tenant_id uuid not null references acc.tenants(id) on delete cascade, id uuid not null default gen_random_uuid(), ref_no bigint not null,
  from_entity uuid not null, to_entity uuid not null, purpose text not null default 'advance' check (purpose in ('advance','repay')),
  date date not null, amount numeric(18,2) not null check (amount > 0), description text not null default '',
  from_journal uuid, to_journal uuid, status text not null default 'active' check (status in ('active','voided')), voided_at timestamptz, void_reason text not null default '',
  created_by uuid, created_at timestamptz not null default now(),
  primary key (tenant_id, id), check (from_entity <> to_entity),
  foreign key (tenant_id, from_entity) references acc.entities (tenant_id, id), foreign key (tenant_id, to_entity) references acc.entities (tenant_id, id));
create index if not exists ic_links_q on acc.ic_links (tenant_id, date desc);
alter table acc.ic_links enable row level security;

-- تسجيل الميزة: الشركات القائمة تُقفل عنها مرة واحدة فقط عند أول تسجيل (لا تُعاد عند إعادة التشغيل فتلغي فتح البائع)
with ins as (
  insert into app.feature_cat (key, name, grp, core, since, sort) values ('interco', 'مطابقة الشركات الشقيقة (المعاملات بين الكيانات)', 'المالية', false, 1, 31)
  on conflict (key) do nothing returning key)
update acc.tenants set features_off = array_append(features_off, 'interco') where exists (select 1 from ins) and not ('interco' = any(features_off));
update app.feature_cat set name = 'مطابقة الشركات الشقيقة (المعاملات بين الكيانات)', grp = 'المالية', core = false, sort = 31 where key = 'interco';

-- صافي الذمة (مدين − دائن) على حسابات subtype=intercompany لكيان حتى تاريخ
create or replace function app.ic_gl_net(t uuid, e uuid, asof date) returns numeric language sql stable security definer set search_path = public, acc as $$
  select coalesce(sum(l.debit - l.credit), 0) from acc.journal_lines l join acc.accounts a on a.tenant_id = l.tenant_id and a.id = l.account_id
  where l.tenant_id = t and l.entity_id = e and l.posted and a.subtype = 'intercompany' and l.date <= asof $$;

create or replace function app.ic_default_acct(t uuid, ty text) returns uuid language sql stable security definer set search_path = public, acc as $$
  select id from acc.accounts where tenant_id = t and subtype = 'intercompany' and type = ty and not is_group order by code limit 1 $$;

-- معاملة بين كيانين. purpose='advance': from يُعطي to (from: مدين ذمة شقيقة / دائن مقابل ؛ to: مدين مقابل / دائن ذمة شقيقة)
-- purpose='repay': from يسدّد لـ to (from: مدين ذمة شقيقة دائنة / دائن مقابل ؛ to: مدين مقابل / دائن ذمة شقيقة مدينة)
create or replace function public.ic_post(p jsonb) returns jsonb language plpgsql security definer set search_path = public, app, acc as $$
declare t uuid := app.need('journals', 'post'); fe uuid := (p->>'from')::uuid; te uuid := (p->>'to')::uuid; amt numeric := round((p->>'amount')::numeric, 2);
  d date := coalesce(nullif(p->>'date','')::date, current_date); pu text := coalesce(nullif(p->>'purpose',''), 'advance'); fc uuid := (p->>'from_account')::uuid; tc uuid := (p->>'to_account')::uuid;
  ra uuid; pa uuid; fi uuid; ti uuid; fj acc.journals; tj acc.journals; fjid uuid := gen_random_uuid(); tjid uuid := gen_random_uuid(); lid uuid := gen_random_uuid(); rn bigint; ds text; fn text; tn text;
begin
  if not app.feat_on('interco') then raise exception 'الميزة غير مفعّلة لشركتك'; end if;
  if fe is null or te is null or fe = te then raise exception 'اختر كيانين مختلفين'; end if;
  if not (fe = any(app.ents()) and te = any(app.ents())) then raise exception 'ليست لديك صلاحية على أحد الكيانين'; end if;
  if pu not in ('advance','repay') then raise exception 'نوع معاملة غير صالح'; end if;
  if amt is null or amt <= 0 then raise exception 'المبلغ يجب أن يكون موجبًا'; end if;
  if not exists (select 1 from acc.accounts where tenant_id = t and id = fc and not is_group and subtype <> 'intercompany') then raise exception 'الحساب المقابل للكيان المُعطي غير صالح'; end if;
  if not exists (select 1 from acc.accounts where tenant_id = t and id = tc and not is_group and subtype <> 'intercompany') then raise exception 'الحساب المقابل للكيان المستلِم غير صالح'; end if;
  ra := coalesce(nullif(p->>'receivable_account','')::uuid, app.ic_default_acct(t, 'asset')); pa := coalesce(nullif(p->>'payable_account','')::uuid, app.ic_default_acct(t, 'liability'));
  if ra is null or pa is null then raise exception 'لا يوجد حساب «الشركات الشقيقة» (مدين/دائن) في دليل الحسابات — أضفه بنوع intercompany'; end if;
  if not exists (select 1 from acc.accounts where tenant_id = t and id = ra and type = 'asset' and subtype = 'intercompany' and not is_group) then raise exception 'حساب الشقيقة المدين غير صالح'; end if;
  if not exists (select 1 from acc.accounts where tenant_id = t and id = pa and type = 'liability' and subtype = 'intercompany' and not is_group) then raise exception 'حساب الشقيقة الدائن غير صالح'; end if;
  select name into fn from acc.entities where tenant_id = t and id = fe; select name into tn from acc.entities where tenant_id = t and id = te;
  rn := app.next_no(t, null, 'ic', 0);
  ds := 'IC-' || lpad(rn::text, 5, '0') || case pu when 'advance' then ' تحويل من ' else ' سداد من ' end || fn || ' إلى ' || tn || coalesce(' — ' || nullif(p->>'description',''), '');
  insert into acc.journals (tenant_id, id, entity_id, type, date, description, reference, status, source, source_id, created_by) values (t, fjid, fe, 'GJ', d, ds, 'IC-' || lpad(rn::text, 5, '0'), 'draft', 'interco', lid, auth.uid());
  insert into acc.journals (tenant_id, id, entity_id, type, date, description, reference, status, source, source_id, created_by) values (t, tjid, te, 'GJ', d, ds, 'IC-' || lpad(rn::text, 5, '0'), 'draft', 'interco', lid, auth.uid());
  if pu = 'advance' then
    perform app.put_lines(t, fjid, fe, d, jsonb_build_array(jsonb_build_object('account', ra, 'debit', amt, 'description', ds), jsonb_build_object('account', fc, 'credit', amt, 'description', ds)));
    perform app.put_lines(t, tjid, te, d, jsonb_build_array(jsonb_build_object('account', tc, 'debit', amt, 'description', ds), jsonb_build_object('account', pa, 'credit', amt, 'description', ds)));
  else
    perform app.put_lines(t, fjid, fe, d, jsonb_build_array(jsonb_build_object('account', pa, 'debit', amt, 'description', ds), jsonb_build_object('account', fc, 'credit', amt, 'description', ds)));
    perform app.put_lines(t, tjid, te, d, jsonb_build_array(jsonb_build_object('account', tc, 'debit', amt, 'description', ds), jsonb_build_object('account', ra, 'credit', amt, 'description', ds)));
  end if;
  fj := app.post_journal(fjid); tj := app.post_journal(tjid);
  insert into acc.ic_links (tenant_id, id, ref_no, from_entity, to_entity, purpose, date, amount, description, from_journal, to_journal, created_by)
  values (t, lid, rn, fe, te, pu, d, amt, coalesce(p->>'description',''), fj.id, tj.id, auth.uid());
  perform app.audit('create', 'ic_link', lid::text, ds || ' — ' || amt);
  return jsonb_build_object('id', lid, 'ref', 'IC-' || lpad(rn::text, 5, '0'), 'from_journal', fj.id, 'to_journal', tj.id);
end $$;

-- إلغاء معاملة: عكس القيدين معًا (يُرفض إن أُقفلت فترة أحدهما)
create or replace function public.ic_void(p jsonb) returns jsonb language plpgsql security definer set search_path = public, app, acc as $$
declare t uuid := app.need('journals', 'post'); l acc.ic_links; d date := coalesce(nullif(p->>'date','')::date, current_date);
begin
  if not app.feat_on('interco') then raise exception 'الميزة غير مفعّلة لشركتك'; end if;
  select * into l from acc.ic_links where tenant_id = t and id = (p->>'id')::uuid for update;
  if l.id is null then raise exception 'المعاملة غير موجودة'; end if;
  if not (l.from_entity = any(app.ents()) and l.to_entity = any(app.ents())) then raise exception 'ليست لديك صلاحية على أحد الكيانين'; end if;
  if l.status = 'voided' then raise exception 'المعاملة ملغاة مسبقًا'; end if;
  if d < l.date then d := l.date; end if;
  perform app.reverse_journal(l.from_journal, d, 'إلغاء معاملة شقيقة'); perform app.reverse_journal(l.to_journal, d, 'إلغاء معاملة شقيقة');
  update acc.ic_links set status = 'voided', voided_at = now(), void_reason = coalesce(p->>'reason','') where tenant_id = t and id = l.id;
  perform app.audit('reverse', 'ic_link', l.id::text, 'إلغاء معاملة شقيقة IC-' || lpad(l.ref_no::text, 5, '0')); return jsonb_build_object('ok', true);
end $$;

create or replace function public.ic_list(p jsonb default '{}') returns jsonb language plpgsql stable security definer set search_path = public, app, acc as $$
declare t uuid := app.need('journals', 'view');
begin
  if not app.feat_on('interco') then raise exception 'الميزة غير مفعّلة لشركتك'; end if;
  return coalesce((select jsonb_agg(to_jsonb(l) - 'tenant_id' || jsonb_build_object('ref', 'IC-' || lpad(l.ref_no::text, 5, '0'),
      'from_name', (select name from acc.entities e where e.tenant_id = t and e.id = l.from_entity), 'to_name', (select name from acc.entities e where e.tenant_id = t and e.id = l.to_entity)) order by l.date desc, l.ref_no desc)
    from acc.ic_links l where l.tenant_id = t and l.from_entity = any(app.ents()) and l.to_entity = any(app.ents())), '[]'::jsonb);
end $$;

-- تقرير المطابقة حتى تاريخ: لكل كيان صافي الذمة في الدفاتر مقابل صافي المعاملات المرتبطة والفرق غير المرتبط، وأرصدة الأزواج (دائن ← مدين)
create or replace function public.ic_recon(p jsonb default '{}') returns jsonb language plpgsql stable security definer set search_path = public, app, acc as $$
declare t uuid := app.need('reports', 'view'); asof date := coalesce(nullif(p->>'asof','')::date, current_date); ents uuid[] := app.ents(); ent_rows jsonb; pairs jsonb; tot_gl numeric; tot_un numeric;
begin
  if not app.feat_on('interco') then raise exception 'الميزة غير مفعّلة لشركتك'; end if;
  with net as (
    select x.eid, sum(x.v) v from (
      select l.from_entity eid, l.amount v from acc.ic_links l where l.tenant_id = t and l.status = 'active' and l.date <= asof
      union all
      select l.to_entity, -l.amount from acc.ic_links l where l.tenant_id = t and l.status = 'active' and l.date <= asof) x group by x.eid)
  select coalesce(jsonb_agg(jsonb_build_object('id', e.id, 'name', e.name, 'gl_net', g.v, 'linked_net', coalesce(n.v, 0), 'unlinked', round(g.v - coalesce(n.v, 0), 2)) order by e.name), '[]'::jsonb),
    coalesce(sum(g.v), 0), coalesce(sum(round(g.v - coalesce(n.v, 0), 2)), 0)
  into ent_rows, tot_gl, tot_un
  from acc.entities e cross join lateral (select app.ic_gl_net(t, e.id, asof) v) g left join net n on n.eid = e.id where e.tenant_id = t and e.id = any(ents);
  select coalesce(jsonb_agg(jsonb_build_object('creditor', c.name, 'debtor', d.name, 'creditor_id', q.cr, 'debtor_id', q.db, 'amount', q.amt) order by c.name, d.name), '[]'::jsonb) into pairs
  from (select cr, db, sum(amt) amt from (
      select case l.purpose when 'advance' then l.from_entity else l.to_entity end cr, case l.purpose when 'advance' then l.to_entity else l.from_entity end db, case l.purpose when 'advance' then l.amount else -l.amount end amt from acc.ic_links l where l.tenant_id = t and l.status = 'active' and l.date <= asof
    ) z group by cr, db) q join acc.entities c on c.tenant_id = t and c.id = q.cr join acc.entities d on d.tenant_id = t and d.id = q.db where q.amt <> 0;
  return jsonb_build_object('asof', asof, 'entities', ent_rows, 'pairs', pairs, 'gl_total', round(tot_gl, 2), 'unlinked_total', round(tot_un, 2), 'balanced', abs(tot_gl) < 0.005);
end $$;

-- ===== sql/050_vault.sql =====
-- مُحكَم للحسابات 1.6.3 — خزنة المنصات (نفس آلية خزنة الموارد البشرية)
-- التشفير يتم بالكامل في المتصفح (AES-256-GCM بمفتاح مشتق PBKDF2 من «كلمة سر الخزنة»)؛ الخادم لا يرى كلمات المرور ولا يعرف كلمة سر الخزنة.
-- يُخزَّن فقط: ملح المفتاح + عيّنة تحقق مشفّرة + بنود (اسم المنصة/الفئة/الرابط/اسم الدخول/كلمة المرور مشفّرة/جوال التحقق/ملاحظات).
create table if not exists acc.vault_meta (
  tenant_id uuid primary key references acc.tenants(id) on delete cascade, salt text not null, check_blob text not null,
  created_by uuid, created_at timestamptz not null default now(), updated_by uuid, updated_at timestamptz not null default now());
create table if not exists acc.vault_items (
  tenant_id uuid not null references acc.tenants(id) on delete cascade, id uuid not null default gen_random_uuid(), name text not null, category text not null default 'أخرى',
  url text not null default '', username text not null default '', pw_enc text not null, phone text not null default '', notes text not null default '',
  created_by uuid, created_at timestamptz not null default now(), updated_by uuid, updated_at timestamptz not null default now(), primary key (tenant_id, id));
alter table acc.vault_meta enable row level security; alter table acc.vault_items enable row level security;
-- الشركات القائمة غير مقفولة عنها (الميزة للمالك مباشرة)؛ يحجبها البائع عند الحاجة من «المزايا والعقد»
insert into app.feature_cat (key, name, grp, core, since, sort) values ('vault', 'خزنة المنصات وكلمات المرور', 'الشؤون الإدارية', false, 1, 32)
on conflict (key) do update set name = excluded.name, grp = excluded.grp, core = excluded.core, sort = excluded.sort;

-- صيغة النص المشفّر: iv.ciphertext بـ base64 فقط (يمنع تخزين نص صريح بالخطأ)
create or replace function app.vault_blob_ok(b text) returns boolean language sql immutable as $$ select b ~ '^[A-Za-z0-9+/]+={0,2}\.[A-Za-z0-9+/]+={0,2}$' and length(b) between 20 and 4000 $$;

create or replace function public.vault_get(p jsonb default '{}') returns jsonb language plpgsql stable security definer set search_path = public, app, acc as $$
declare t uuid := app.need('vault', 'view'); m acc.vault_meta;
begin
  select * into m from acc.vault_meta where tenant_id = t;
  if m.tenant_id is null then return jsonb_build_object('exists', false, 'items', '[]'::jsonb); end if;
  return jsonb_build_object('exists', true, 'salt', m.salt, 'check', m.check_blob, 'items', coalesce((select jsonb_agg(jsonb_build_object('id', i.id, 'name', i.name, 'category', i.category, 'url', i.url, 'user', i.username,
    'pw', i.pw_enc, 'phone', i.phone, 'notes', i.notes) order by i.created_at, i.name) from acc.vault_items i where i.tenant_id = t), '[]'::jsonb));
end $$;

create or replace function public.vault_init(p jsonb) returns jsonb language plpgsql security definer set search_path = public, app, acc as $$
declare t uuid := app.need('vault', 'add');
begin
  if exists (select 1 from acc.vault_meta where tenant_id = t) then raise exception 'الخزنة موجودة مسبقًا'; end if;
  if coalesce(p->>'salt','') !~ '^[A-Za-z0-9+/]+={0,2}$' or length(p->>'salt') < 16 then raise exception 'ملح الخزنة غير صالح'; end if;
  if not app.vault_blob_ok(p->>'check') then raise exception 'عيّنة التحقق غير صالحة'; end if;
  insert into acc.vault_meta (tenant_id, salt, check_blob, created_by, updated_by) values (t, p->>'salt', p->>'check', auth.uid(), auth.uid());
  perform app.audit('create', 'vault', '', 'إنشاء الخزنة'); return jsonb_build_object('ok', true);
end $$;

create or replace function public.vault_save(p jsonb) returns jsonb language plpgsql security definer set search_path = public, app, acc as $$
declare t uuid := app.need('vault', case when nullif(p->>'id','') is null then 'add' else 'edit' end); v uuid := nullif(p->>'id','')::uuid; nm text := trim(coalesce(p->>'name','')); u text := trim(coalesce(p->>'url','')); old acc.vault_items; pwch boolean := false;
begin
  if not exists (select 1 from acc.vault_meta where tenant_id = t) then raise exception 'أنشئ الخزنة أولًا'; end if;
  if nm = '' or length(nm) > 200 then raise exception 'اسم المنصة مطلوب (حتى 200 حرف)'; end if;
  if u <> '' and u !~* '^https?://[^\s]+$' then raise exception 'الرابط يجب أن يبدأ بـ http:// أو https://'; end if;
  if length(u) > 500 or length(coalesce(p->>'user','')) > 300 or length(coalesce(p->>'phone','')) > 100 or length(coalesce(p->>'notes','')) > 2000 or length(coalesce(p->>'category','')) > 100 then raise exception 'أحد الحقول أطول من المسموح'; end if;
  if not app.vault_blob_ok(p->>'pw') then raise exception 'كلمة المرور يجب أن تصل مشفّرة'; end if;
  if v is null then
    insert into acc.vault_items (tenant_id, name, category, url, username, pw_enc, phone, notes, created_by, updated_by)
    values (t, nm, coalesce(nullif(trim(p->>'category'),''), 'أخرى'), u, trim(coalesce(p->>'user','')), p->>'pw', trim(coalesce(p->>'phone','')), coalesce(p->>'notes',''), auth.uid(), auth.uid()) returning id into v;
  else
    select * into old from acc.vault_items where tenant_id = t and id = v for update; if old.id is null then raise exception 'المنصة غير موجودة'; end if;
    pwch := old.pw_enc is distinct from p->>'pw';
    update acc.vault_items set name = nm, category = coalesce(nullif(trim(p->>'category'),''), 'أخرى'), url = u, username = trim(coalesce(p->>'user','')), pw_enc = p->>'pw', phone = trim(coalesce(p->>'phone','')), notes = coalesce(p->>'notes',''),
      updated_by = auth.uid(), updated_at = now() where tenant_id = t and id = v;
  end if;
  perform app.audit(case when nullif(p->>'id','') is null then 'create' else 'update' end, 'vault', v::text, nm || case when pwch then ' — تحديث كلمة المرور' else '' end);
  return jsonb_build_object('id', v);
end $$;

create or replace function public.vault_delete(p jsonb) returns jsonb language plpgsql security definer set search_path = public, app, acc as $$
declare t uuid := app.need('vault', 'delete'); nm text;
begin
  delete from acc.vault_items where tenant_id = t and id = (p->>'id')::uuid returning name into nm;
  if nm is null then raise exception 'المنصة غير موجودة'; end if;
  perform app.audit('delete', 'vault', p->>'id', nm); return jsonb_build_object('ok', true);
end $$;

-- تغيير كلمة سر الخزنة: يعيد المتصفح تشفير كل البنود بالمفتاح الجديد ويرسلها دفعة واحدة؛ تُرفض إن لم تغطِّ كل البنود (حتى لا يبقى بند بالمفتاح القديم)
create or replace function public.vault_rekey(p jsonb) returns jsonb language plpgsql security definer set search_path = public, app, acc as $$
declare t uuid := app.need('vault', 'edit'); x jsonb; n int; c int := 0;
begin
  if not exists (select 1 from acc.vault_meta where tenant_id = t) then raise exception 'أنشئ الخزنة أولًا'; end if;
  if coalesce(p->>'salt','') !~ '^[A-Za-z0-9+/]+={0,2}$' or length(p->>'salt') < 16 then raise exception 'ملح الخزنة غير صالح'; end if;
  if not app.vault_blob_ok(p->>'check') then raise exception 'عيّنة التحقق غير صالحة'; end if;
  if jsonb_typeof(coalesce(p->'items','[]'::jsonb)) <> 'array' then raise exception 'قائمة البنود غير صالحة'; end if;
  select count(*) into n from acc.vault_items where tenant_id = t;
  if jsonb_array_length(coalesce(p->'items','[]'::jsonb)) <> n then raise exception 'يجب إرسال كل بنود الخزنة (%) مُعاد تشفيرها', n; end if;
  for x in select * from jsonb_array_elements(coalesce(p->'items','[]'::jsonb)) loop
    if not app.vault_blob_ok(x->>'pw') then raise exception 'كلمة مرور غير مشفّرة في إحدى المنصات'; end if;
    update acc.vault_items set pw_enc = x->>'pw', updated_by = auth.uid(), updated_at = now() where tenant_id = t and id = (x->>'id')::uuid;
    if not found then raise exception 'منصة غير موجودة في الخزنة'; end if; c := c + 1;
  end loop;
  update acc.vault_meta set salt = p->>'salt', check_blob = p->>'check', updated_by = auth.uid(), updated_at = now() where tenant_id = t;
  perform app.audit('update', 'vault', '', 'تغيير كلمة سر الخزنة وإعادة تشفير ' || c || ' منصة'); return jsonb_build_object('ok', true, 'items', c);
end $$;

-- ===== sql/051_coa_flex.sql =====
-- مُحكَم للحسابات 1.6.3 — مرونة دليل الحسابات: تفرّع بلا حد، تغيير النوع يسري على الفروع، منع إلغاء التجميع لحساب له فروع، ومنع تفريع الحساب النظامي الافتراضي
-- إعادة تعريف للدالتين الحاليتين (create or replace) — لا تغيير في البيانات ولا في الجداول.
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
    if not new.is_group and old.is_group and exists (select 1 from acc.accounts where tenant_id = old.tenant_id and parent_id = old.id limit 1) then raise exception 'له حسابات فرعية — يجب أن يبقى حسابًا تجميعيًا'; end if;
    if new.parent_id is distinct from old.parent_id then
      if exists (with recursive d as (select id from acc.accounts where tenant_id = old.tenant_id and parent_id = old.id union all select a.id from acc.accounts a join d on a.parent_id = d.id where a.tenant_id = old.tenant_id) select 1 from d where id = new.parent_id) then
        raise exception 'لا يجوز نقل الحساب تحت أحد أبنائه'; end if;
    end if;
  end if;
  return new;
end $$;

create or replace function public.coa_upsert(p jsonb) returns jsonb language plpgsql security definer set search_path = public, app, acc as $$
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
    update acc.accounts a2 set system_key = null where a2.tenant_id = t and a2.system_key = sk and a2.id is distinct from (nullif(p->>'id','')::uuid);
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
