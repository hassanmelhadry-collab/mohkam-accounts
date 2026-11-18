-- مُحكَم للحسابات 1.9.0.1 — إعادة تنظيم القائمة الجانبية (واجهة فقط)
insert into app.schema_migrations (version, name) values ('1.9.0.1', 'إعادة تنظيم القائمة الجانبية حسب مسار العمل (13 مجموعة) — واجهة فقط')
on conflict (version) do nothing;
