-- يعيد check_pw إلى شكلها الأصلي؛ استدعاءات الدوال بالوسيط الثاني تبقى صالحة لأن التوقيع الثاني يُحذف مع إعادة تعريفها من 005/025.
create or replace function app.check_pw(p text) returns void language plpgsql immutable as $$
begin if length(coalesce(p,'')) < 10 or p !~ '[0-9]' or p !~ '[A-Za-z؀-ۿ]' then raise exception 'كلمة المرور 10 أحرف على الأقل وتحتوي حروفًا وأرقامًا'; end if; end $$;
-- يُبقي التوقيع ذا الوسيطين (تستدعيه الدوال الثلاث) بالقاعدة الأصلية فقط، ثم يحذف القائمة
create or replace function app.check_pw(p text, ident text[]) returns void language sql immutable as $$ select app.check_pw(p) $$;
drop table if exists app.weak_passwords;
delete from app.schema_migrations where version = '1.11.1.3';
