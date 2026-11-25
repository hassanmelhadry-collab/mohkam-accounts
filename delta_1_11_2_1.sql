-- 1.11.2.1 — واجهة فقط: شاشات تكلفة المخزون المتقدمة وفئات IFRS 18 (ميزتان مقفولتان). لا تغيير في القاعدة غير سجل الإصدار.
insert into app.schema_migrations (version, name) values ('1.11.2.1', 'واجهة فقط: شاشات تكلفة المخزون المتقدمة وفئات IFRS 18') on conflict (version) do nothing;
