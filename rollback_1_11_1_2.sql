-- عطّل الـ Hook من لوحة Auth أولًا (Auth > Hooks) ثم نفّذ:
drop function if exists app.pw_hook(jsonb);
drop table if exists app.login_guard;
delete from app.schema_migrations where version = '1.11.1.2';
