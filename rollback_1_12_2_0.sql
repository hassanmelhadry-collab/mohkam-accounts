-- تراجع 1.12.2.0 (مركز العمليات): دوال قراءة فقط، لا بيانات تُفقد.
drop function if exists public.ops_queue(jsonb);
drop function if exists app.ops_group(jsonb);
drop function if exists app.ops_card(text, bigint, jsonb, text);
delete from app.schema_migrations where version = '1.12.2.0';
