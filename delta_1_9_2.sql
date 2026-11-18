-- مُحكَم للحسابات — دلتا 1.9.2.0 (من 1.9.0.1): تسليم آمن لحزم المدقق + جاهزية ربط الموارد البشرية
-- مُحكَم للحسابات 077 — تسليم آمن مؤقت لحزم المدقق/المفتش + سجل استلام
-- الفكرة: الحزمة تُرفع إلى دلو خاص (acc-shares) ويُولَّد رابط سري بانتهاء وعدد مرات فتح محدود وقابل للإلغاء؛
-- المستلم الخارجي لا يحتاج حسابًا؛ كل فتح/رفض/إقرار استلام يُسجَّل، وتُعرض بصمة SHA-256 ليتحقق من سلامة الملف.
create table if not exists acc.audit_shares (
  tenant_id uuid not null references acc.tenants(id) on delete cascade, id uuid not null default gen_random_uuid(),
  token text not null unique, path text not null, filename text not null default '', size bigint not null default 0, sha256 text not null default '',
  label text not null default '', recipient text not null default '', note text not null default '',
  ready boolean not null default false, revoked boolean not null default false, revoked_at timestamptz,
  expires_at timestamptz not null, max_downloads int not null default 3 check (max_downloads between 1 and 50), downloads int not null default 0,
  last_open_at timestamptz, receipt_name text, receipt_at timestamptz, created_by uuid, created_at timestamptz not null default now(),
  primary key (tenant_id, id)
);
create table if not exists acc.audit_share_events (
  tenant_id uuid not null, id uuid not null default gen_random_uuid(), share_id uuid not null, at timestamptz not null default now(),
  kind text not null check (kind in ('open','denied','receipt','revoke')), detail text not null default '',
  primary key (tenant_id, id), foreign key (tenant_id, share_id) references acc.audit_shares (tenant_id, id) on delete cascade
);
create index if not exists audit_share_events_s on acc.audit_share_events (tenant_id, share_id, at);
alter table acc.audit_shares enable row level security; alter table acc.audit_share_events enable row level security;

-- صلاحية المسار للقراءة المجهولة: ملف جاهز، غير ملغى، غير منتهٍ، وفُتح الرابط (وحُسب) خلال آخر 15 دقيقة فقط
create or replace function public.share_path_ok(p text) returns boolean language sql stable security definer set search_path = public, acc as $$
  select exists (select 1 from acc.audit_shares s where s.path = p and s.ready and not s.revoked and s.expires_at > now() and s.last_open_at > now() - interval '15 minutes')
$$;

create or replace function app.share_need() returns uuid language plpgsql stable security definer set search_path = public, app, acc as $$
declare t uuid := app.need('reports', 'view');
begin if not app.can('attachments', 'view') then raise exception 'ليس لديك صلاحية عرض المستندات'; end if; return t; end $$;

create or replace function public.share_prepare(p jsonb) returns jsonb language plpgsql security definer set search_path = public, app, acc as $$
declare t uuid := app.share_need(); tk text := replace(gen_random_uuid()::text || gen_random_uuid()::text, '-', ''); d int := coalesce(nullif(p->>'days', '')::int, 7); m int := coalesce(nullif(p->>'max_downloads', '')::int, 3); id uuid;
begin
  if d < 1 or d > 30 then raise exception 'مدة الرابط من 1 إلى 30 يومًا'; end if;
  if m < 1 or m > 50 then raise exception 'عدد مرات الفتح من 1 إلى 50'; end if;
  if length(trim(coalesce(p->>'recipient', ''))) < 2 then raise exception 'اذكر اسم الجهة أو الشخص المستلم'; end if;
  insert into acc.audit_shares (tenant_id, token, path, filename, label, recipient, note, expires_at, max_downloads, created_by)
  values (t, tk, t::text || '/' || tk || '.zip', left(coalesce(p->>'filename', 'pack.zip'), 200), left(coalesce(p->>'label', ''), 200), left(trim(p->>'recipient'), 200), left(coalesce(p->>'note', ''), 500), now() + (d || ' days')::interval, m, auth.uid()) returning acc.audit_shares.id into id;
  return jsonb_build_object('id', id, 'token', tk, 'path', t::text || '/' || tk || '.zip');
end $$;

create or replace function public.share_finalize(p jsonb) returns jsonb language plpgsql security definer set search_path = public, app, acc as $$
declare t uuid := app.share_need(); s acc.audit_shares;
begin
  select * into s from acc.audit_shares where tenant_id = t and id = (p->>'id')::uuid and created_by = auth.uid() and not ready; if s.id is null then raise exception 'الرابط غير موجود أو جاهز مسبقًا'; end if;
  if coalesce(p->>'sha256', '') !~ '^[0-9a-f]{64}$' then raise exception 'بصمة SHA-256 غير صالحة'; end if;
  update acc.audit_shares set ready = true, sha256 = p->>'sha256', size = coalesce((p->>'size')::bigint, 0) where tenant_id = t and id = s.id;
  perform app.audit('share', 'audit_pack', s.id::text, 'تسليم آمن لـ ' || s.recipient || ' — ' || s.filename || ' — ينتهي ' || to_char(s.expires_at, 'YYYY-MM-DD') || ' — حتى ' || s.max_downloads || ' مرات فتح — SHA-256 ' || left(p->>'sha256', 12));
  return jsonb_build_object('ok', true);
end $$;

create or replace function public.share_list(p jsonb default '{}') returns jsonb language plpgsql stable security definer set search_path = public, app, acc as $$
declare t uuid := app.share_need();
begin
  return coalesce((select jsonb_agg(jsonb_build_object('id', s.id, 'token', s.token, 'filename', s.filename, 'label', s.label, 'recipient', s.recipient, 'size', s.size, 'sha256', s.sha256, 'created_at', s.created_at, 'expires_at', s.expires_at,
      'max_downloads', s.max_downloads, 'downloads', s.downloads, 'revoked', s.revoked, 'ready', s.ready, 'receipt_name', s.receipt_name, 'receipt_at', s.receipt_at,
      'status', case when s.revoked then 'revoked' when not s.ready then 'pending' when s.expires_at <= now() then 'expired' when s.downloads >= s.max_downloads then 'exhausted' else 'active' end,
      'by', coalesce((select m.name from acc.members m where m.user_id = s.created_by), '—'),
      'events', coalesce((select jsonb_agg(jsonb_build_object('at', e.at, 'kind', e.kind, 'detail', e.detail) order by e.at desc) from (select * from acc.audit_share_events where tenant_id = t and share_id = s.id order by at desc limit 30) e), '[]')) order by s.created_at desc)
    from (select * from acc.audit_shares where tenant_id = t order by created_at desc limit 100) s), '[]');
end $$;

create or replace function public.share_revoke(p jsonb) returns jsonb language plpgsql security definer set search_path = public, app, acc as $$
declare t uuid := app.share_need(); s acc.audit_shares;
begin
  update acc.audit_shares set revoked = true, revoked_at = now() where tenant_id = t and id = (p->>'id')::uuid and not revoked returning * into s; if s.id is null then raise exception 'الرابط غير موجود أو أُلغي مسبقًا'; end if;
  insert into acc.audit_share_events (tenant_id, share_id, kind, detail) values (t, s.id, 'revoke', 'أُلغي بواسطة ' || coalesce((select name from acc.members where user_id = auth.uid()), '—'));
  perform app.audit('revoke', 'audit_pack', s.id::text, 'إلغاء رابط التسليم الآمن لـ ' || s.recipient); return jsonb_build_object('ok', true);
end $$;

-- ===== واجهة المستلم الخارجي (بلا حساب): المعرّف السري هو الرمز الطويل نفسه =====
create or replace function app.share_ctx() returns text language plpgsql stable as $$
declare h jsonb;
begin
  begin h := current_setting('request.headers', true)::jsonb; exception when others then h := null; end;
  return left(coalesce('IP ' || split_part(coalesce(h->>'x-forwarded-for', h->>'cf-connecting-ip', ''), ',', 1), '') || ' | ' || coalesce(h->>'user-agent', ''), 250);
end $$;

create or replace function public.share_peek(p jsonb) returns jsonb language plpgsql stable security definer set search_path = public, acc as $$
declare s acc.audit_shares; stt text;
begin
  select * into s from acc.audit_shares where token = coalesce(p->>'token', '');
  if s.id is null or not s.ready then raise exception 'الرابط غير صالح'; end if;
  stt := case when s.revoked then 'revoked' when s.expires_at <= now() then 'expired' when s.downloads >= s.max_downloads then 'exhausted' else 'active' end;
  return jsonb_build_object('status', stt, 'filename', s.filename, 'size', s.size, 'sha256', s.sha256, 'expires_at', s.expires_at, 'remaining', greatest(s.max_downloads - s.downloads, 0), 'company', (select name from acc.tenants where id = s.tenant_id), 'recipient', s.recipient, 'receipt_at', s.receipt_at, 'receipt_name', s.receipt_name);
end $$;

create or replace function public.share_open(p jsonb) returns jsonb language plpgsql security definer set search_path = public, acc as $$
declare s acc.audit_shares;
begin
  select * into s from acc.audit_shares where token = coalesce(p->>'token', '') for update;
  if s.id is null or not s.ready then raise exception 'الرابط غير صالح أو منتهٍ'; end if;
  if s.revoked or s.expires_at <= now() or s.downloads >= s.max_downloads then
    insert into acc.audit_share_events (tenant_id, share_id, kind, detail) values (s.tenant_id, s.id, 'denied', case when s.revoked then 'مُلغى' when s.expires_at <= now() then 'منتهٍ' else 'استُنفدت مرات الفتح' end || ' — ' || app.share_ctx());
    return jsonb_build_object('ok', false, 'error', 'الرابط غير صالح أو منتهٍ أو استُنفدت مرات الفتح'); -- لا استثناء: حتى لا يتراجع تسجيل المحاولة المرفوضة
  end if;
  update acc.audit_shares set downloads = downloads + 1, last_open_at = now() where id = s.id and tenant_id = s.tenant_id;
  insert into acc.audit_share_events (tenant_id, share_id, kind, detail) values (s.tenant_id, s.id, 'open', 'فتح رقم ' || (s.downloads + 1) || ' — ' || app.share_ctx());
  return jsonb_build_object('ok', true, 'path', s.path, 'filename', s.filename, 'sha256', s.sha256, 'size', s.size, 'remaining', s.max_downloads - s.downloads - 1);
end $$;

create or replace function public.share_receipt(p jsonb) returns jsonb language plpgsql security definer set search_path = public, acc as $$
declare s acc.audit_shares; nm text := trim(coalesce(p->>'name', ''));
begin
  select * into s from acc.audit_shares where token = coalesce(p->>'token', '') and ready and not revoked and downloads > 0; if s.id is null then raise exception 'الرابط غير صالح'; end if;
  if length(nm) < 3 or length(nm) > 120 then raise exception 'اكتب اسمك الكامل لإقرار الاستلام'; end if;
  update acc.audit_shares set receipt_name = nm, receipt_at = now() where id = s.id and tenant_id = s.tenant_id;
  insert into acc.audit_share_events (tenant_id, share_id, kind, detail) values (s.tenant_id, s.id, 'receipt', 'إقرار استلام من ' || nm || ' — ' || app.share_ctx());
  return jsonb_build_object('ok', true);
end $$;

revoke execute on function public.share_path_ok(text), public.share_prepare(jsonb), public.share_finalize(jsonb), public.share_list(jsonb), public.share_revoke(jsonb), public.share_peek(jsonb), public.share_open(jsonb), public.share_receipt(jsonb), app.share_need(), app.share_ctx() from public, anon;
grant execute on function public.share_prepare(jsonb), public.share_finalize(jsonb), public.share_list(jsonb), public.share_revoke(jsonb) to authenticated;
-- المستلم الخارجي بلا حساب: هذه الدوال الأربع وحدها متاحة للزائر، وكلها محروسة بالرمز السري
grant execute on function public.share_path_ok(text), public.share_peek(jsonb), public.share_open(jsonb), public.share_receipt(jsonb) to anon, authenticated;

do $$ begin
  if exists (select 1 from information_schema.schemata where schema_name = 'storage') then
    insert into storage.buckets (id, name, public, file_size_limit) values ('acc-shares', 'acc-shares', false, 52428800) on conflict (id) do update set public = false, file_size_limit = 52428800;
    drop policy if exists acc_shares_insert on storage.objects; drop policy if exists acc_shares_read on storage.objects; drop policy if exists acc_shares_read_link on storage.objects; drop policy if exists acc_shares_read_own on storage.objects;
    create policy acc_shares_insert on storage.objects for insert to authenticated with check (bucket_id = 'acc-shares' and (storage.foldername(name))[1] = public.tenant_folder());
    -- سياستان منفصلتان: الزائر لا يملك صلاحية دالة tenant_folder فلا يجوز أن تظهر في سياسته
    create policy acc_shares_read_link on storage.objects for select to anon, authenticated using (bucket_id = 'acc-shares' and public.share_path_ok(name));
    create policy acc_shares_read_own on storage.objects for select to authenticated using (bucket_id = 'acc-shares' and (storage.foldername(name))[1] = public.tenant_folder());
  end if;
end $$;

insert into app.schema_migrations (version, name) values ('1.9.1.0', 'تسليم آمن مؤقت لحزم المدقق (رابط سري بانتهاء وعدد فتح) + سجل استلام')
on conflict (version) do nothing;
-- مُحكَم للحسابات 078 — جاهزية الربط مع نظام الموارد البشرية (أو أي نظام موظفين): مزامنة موظف عبر بوابة الـAPI
-- المبدأ: النظام الخارجي (مثل hr-cloud) يرسل بيانات الموظف برقمه الوظيفي (ext_ref)، فيُنشأ/يُحدَّث «طرف موظف» في المحاسبة بلا تكرار.
-- التعطيل: إنهاء الخدمة يعطّل طرف الموظف دائمًا، ولا يعطّل حساب دخوله إلا بطلب صريح (deactivate_user) وبصلاحية إدارة المستخدمين.
alter table acc.parties add column if not exists ext_ref text not null default '';
create unique index if not exists parties_ext_ref_u on acc.parties (tenant_id, ext_ref) where ext_ref <> '';

create or replace function public.hr_employee_sync(p jsonb) returns jsonb language plpgsql security definer set search_path = public, app, acc as $$
declare t uuid := app.need('parties', 'edit'); ref text := trim(coalesce(p->>'ext_ref', '')); nm text := trim(coalesce(p->>'name', '')); act boolean := coalesce((p->>'active')::boolean, true);
  pr acc.parties; created boolean := false; un text := lower(trim(coalesce(p->>'username', ''))); mu uuid; deact boolean := coalesce((p->>'deactivate_user')::boolean, false); nlink int := 0;
begin
  if ref !~ '^[A-Za-z0-9._/-]{1,40}$' then raise exception 'الرقم الوظيفي (ext_ref) مطلوب: حروف إنجليزية وأرقام ونقطة وشرطة فقط (حتى 40)'; end if;
  select * into pr from acc.parties where tenant_id = t and ext_ref = ref and kind = 'employee';
  if pr.id is null then
    if nm = '' then raise exception 'اسم الموظف مطلوب عند الإنشاء'; end if;
    insert into acc.parties (tenant_id, kind, code, name, email, phone, active, ext_ref, created_by)
    values (t, 'employee', 'EMP-' || lpad(app.next_no(t, null, 'party_employee', 0)::text, 5, '0'), left(nm, 200), left(coalesce(p->>'email', ''), 200), left(coalesce(p->>'phone', ''), 50), act, ref, auth.uid()) returning * into pr; created := true;
  else
    update acc.parties set name = coalesce(nullif(left(nm, 200), ''), name), email = case when p ? 'email' then left(coalesce(p->>'email', ''), 200) else email end, phone = case when p ? 'phone' then left(coalesce(p->>'phone', ''), 50) else phone end, active = act
     where tenant_id = t and id = pr.id returning * into pr;
  end if;
  if un <> '' then
    select user_id into mu from acc.members where tenant_id = t and username = un; if mu is null then raise exception 'اسم الدخول % غير موجود في المحاسبة', un; end if;
    if exists (select 1 from acc.employee_links where tenant_id = t and party_id = pr.id and user_id <> mu) then raise exception 'هذا الموظف مربوط بحساب دخول آخر'; end if;
    delete from acc.employee_links where tenant_id = t and user_id = mu and party_id <> pr.id;
    insert into acc.employee_links (tenant_id, user_id, party_id) values (t, mu, pr.id) on conflict do nothing; nlink := 1;
  end if;
  if not act and deact then
    perform app.need_sys('users');
    update acc.members set active = false where tenant_id = t and user_id in (select user_id from acc.employee_links where tenant_id = t and party_id = pr.id) and role = 'employee';
  end if;
  perform app.audit(case when created then 'create' else 'update' end, 'employee_sync', pr.id::text, 'مزامنة موظف ' || ref || ' — ' || pr.name || case when not act then ' (إنهاء خدمة)' else '' end);
  return jsonb_build_object('id', pr.id, 'code', pr.code, 'created', created, 'active', pr.active, 'linked', nlink = 1);
end $$;

insert into app.api_ops (op, fn, writes, descr) values ('hr_employee_sync', 'hr_employee_sync', true, 'مزامنة موظف من نظام الموارد البشرية: ext_ref (الرقم الوظيفي) + name + email + active [+ username لربطه بحساب دخوله]')
on conflict (op) do update set fn = excluded.fn, writes = excluded.writes, descr = excluded.descr;

revoke execute on function public.hr_employee_sync(jsonb) from public, anon; grant execute on function public.hr_employee_sync(jsonb) to authenticated;

insert into app.schema_migrations (version, name) values ('1.9.2.0', 'جاهزية الربط مع الموارد البشرية: مزامنة موظف عبر بوابة الـAPI (hr_employee_sync) بلا تكرار')
on conflict (version) do nothing;

-- صلاحية مسار التسليم الآمن للمستلم الخارجي (من 999_grants)
grant execute on function public.share_path_ok(text) to anon, authenticated;
