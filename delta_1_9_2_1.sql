-- مُحكَم للحسابات 1.9.2.1 — تنظيف ملفات روابط التسليم المنتهية/الملغاة + إمكانية الوصول (WCAG، واجهة)
alter table acc.audit_shares add column if not exists purged_at timestamptz;

-- لا يُحذف ملف حزمة من التخزين إلا إذا كان رابطه منتهيًا أو ملغى (الرابط الساري محمي)
create or replace function public.share_deletable(p text) returns boolean language sql stable security definer set search_path = public, acc as $$
  select exists (select 1 from acc.audit_shares s where s.path = p and not s.purged_at is not null and (s.revoked or s.expires_at <= now()))
$$;

do $$ begin
  if exists (select 1 from information_schema.schemata where schema_name = 'storage') then
    drop policy if exists acc_shares_delete on storage.objects;
    create policy acc_shares_delete on storage.objects for delete to authenticated using (bucket_id = 'acc-shares' and (storage.foldername(name))[1] = public.tenant_folder() and public.share_deletable(name));
  end if;
end $$;

-- قائمة الملفات الجاهزة للتنظيف
create or replace function public.share_purge_list(p jsonb default '{}') returns jsonb language plpgsql stable security definer set search_path = public, app, acc as $$
declare t uuid := app.share_need();
begin
  return coalesce((select jsonb_agg(jsonb_build_object('id', s.id, 'path', s.path)) from acc.audit_shares s where s.tenant_id = t and s.ready and s.purged_at is null and (s.revoked or s.expires_at <= now())), '[]');
end $$;

-- تسجيل أن ملفات هذه الروابط حُذفت من التخزين (يُستدعى بعد نجاح الحذف)
create or replace function public.share_purge_mark(p jsonb) returns jsonb language plpgsql security definer set search_path = public, app, acc as $$
declare t uuid := app.share_need(); n int;
begin
  update acc.audit_shares set purged_at = now() where tenant_id = t and purged_at is null and (revoked or expires_at <= now()) and id in (select (x)::uuid from jsonb_array_elements_text(coalesce(p->'ids', '[]')) x);
  get diagnostics n = row_count; if n > 0 then perform app.audit('purge', 'audit_pack', null, 'حذف ملفات ' || n || ' حزمة تسليم منتهية أو ملغاة من التخزين'); end if;
  return jsonb_build_object('ok', true, 'count', n);
end $$;

revoke execute on function public.share_deletable(text), public.share_purge_list(jsonb), public.share_purge_mark(jsonb) from public, anon;
grant execute on function public.share_deletable(text), public.share_purge_list(jsonb), public.share_purge_mark(jsonb) to authenticated;

insert into app.schema_migrations (version, name) values ('1.9.2.1', 'تنظيف ملفات روابط التسليم المنتهية + تحسينات إمكانية الوصول WCAG (واجهة)')
on conflict (version) do nothing;

grant execute on function public.share_deletable(text) to authenticated;
