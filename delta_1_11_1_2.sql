-- 1.11.1.2 — قفل مؤقت للحساب بعد محاولات دخول فاشلة (Auth Hook: Password verification attempt). متكرر التشغيل، لا يغيّر الصلاحيات.
-- 8 محاولات فاشلة خلال 15 دقيقة => رفض كل المحاولات 15 دقيقة (تنتهي تلقائيًا، لا قفل دائم). الرد عام ولا يكشف وجود الحساب.
create table if not exists app.login_guard (user_id uuid primary key, fails int not null default 0, first_fail timestamptz, locked_until timestamptz, updated_at timestamptz not null default now());
alter table app.login_guard enable row level security;
revoke all on app.login_guard from anon, authenticated, public;

create or replace function app.pw_hook(event jsonb) returns jsonb language plpgsql security definer set search_path = app, public as $$
declare uid uuid; ok boolean; g app.login_guard%rowtype; maxf constant int := 8; win constant interval := '15 minutes'; lk constant interval := '15 minutes';
begin
  begin
    uid := (event->>'user_id')::uuid; ok := coalesce((event->>'valid')::boolean, false);
    if uid is null then return jsonb_build_object('decision','continue'); end if;
    select * into g from app.login_guard where user_id = uid for update;
    if found and g.locked_until is not null and g.locked_until > now() then
      return jsonb_build_object('decision','reject','message','Invalid login credentials');
    end if;
    if ok then
      delete from app.login_guard where user_id = uid;
    else
      insert into app.login_guard (user_id, fails, first_fail, updated_at) values (uid, 1, now(), now())
      on conflict (user_id) do update set
        fails = case when app.login_guard.first_fail is null or app.login_guard.first_fail < now() - win then 1 else app.login_guard.fails + 1 end,
        first_fail = case when app.login_guard.first_fail is null or app.login_guard.first_fail < now() - win then now() else app.login_guard.first_fail end,
        updated_at = now();
      update app.login_guard set locked_until = now() + lk, fails = 0, first_fail = null where user_id = uid and fails >= maxf;
    end if;
  exception when others then
    return jsonb_build_object('decision','continue');   -- لا نمنع الدخول لعطل داخلي
  end;
  return jsonb_build_object('decision','continue');
end $$;
do $$ begin if exists (select 1 from pg_roles where rolname = 'supabase_auth_admin') then
  grant usage on schema app to supabase_auth_admin;
  grant execute on function app.pw_hook(jsonb) to supabase_auth_admin;
end if; end $$;
revoke execute on function app.pw_hook(jsonb) from authenticated, anon, public;

insert into app.schema_migrations (version, name) values ('1.11.1.2', 'قفل مؤقت للحساب بعد محاولات دخول فاشلة (Auth Hook)') on conflict (version) do nothing;
