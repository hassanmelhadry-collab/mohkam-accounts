do $$ declare r record; begin
for r in select conrelid::regclass t, conname from pg_constraint where conname in ('ck_invl_price','ck_invl_qty','ck_jl_rate','ck_taxc_rate','ck_taxr_rate','ck_whtr_rate','ck_stm_cost','ck_scl_cost','ck_pay_amount','ck_payl_amount') loop
  execute format('alter table %s drop constraint %I', r.t, r.conname); end loop; end $$;
delete from app.schema_migrations where version = '1.11.1.1';
