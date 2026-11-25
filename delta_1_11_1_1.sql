-- 1.11.1.1 — قيود CHECK على الأسعار والكميات والمبالغ والنسب (NOT VALID: تسري على الجديد فقط). متكرر التشغيل، لا يمس الصلاحيات.
do $$ declare r record; begin
for r in select * from (values
 ('invoice_lines','ck_invl_price','unit_price >= 0'),
 ('invoice_lines','ck_invl_qty','qty >= 0'),
 ('journal_lines','ck_jl_rate','rate > 0'),
 ('tax_codes','ck_taxc_rate','rate >= 0'),
 ('tax_rates','ck_taxr_rate','rate >= 0'),
 ('wht_rates','ck_whtr_rate','rate >= 0'),
 ('stock_moves','ck_stm_cost','unit_cost >= 0'),
 ('stock_count_lines','ck_scl_cost','unit_cost >= 0'),
 ('payments','ck_pay_amount','amount >= 0'),
 ('payment_lines','ck_payl_amount','amount >= 0')
) v(t,n,e) loop
  if not exists (select 1 from pg_constraint where conname = r.n and conrelid = ('acc.'||r.t)::regclass) then
    execute format('alter table acc.%I add constraint %I check (%s) not valid', r.t, r.n, r.e);
  end if;
end loop; end $$;
insert into app.schema_migrations (version, name) values ('1.11.1.1', 'قيود CHECK للأسعار والكميات والمبالغ والنسب (NOT VALID)') on conflict (version) do nothing;
