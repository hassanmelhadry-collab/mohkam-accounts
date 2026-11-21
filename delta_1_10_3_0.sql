-- مُحكَم للحسابات 1.10.3.0 — إعادة ملء مخزون الديمو من الخلفية (pg_cron) بدل الضغط على زر الإنشاء أو فتح اللوحة.
-- السبب: ملء شركة كاملة يستغرق ثوانٍ ويزاحم طلبات اللوحة بعد كل إنشاء فتبدو بطيئة. إضافي ومتكرر التشغيل.
create or replace function app.demo_pool_topup(tg int default 3) returns jsonb language plpgsql security definer set search_path = public, app, acc as $$
declare have int; vcode text; vpwd text; alphabet text := 'abcdefghjkmnpqrstuvwxyz23456789'; i int;
begin
  tg := least(greatest(coalesce(tg, 3), 1), 5);
  if not pg_try_advisory_xact_lock(7770148) then return jsonb_build_object('ready', (select count(*) from acc.demo_pool), 'busy', true); end if;
  select count(*) into have from acc.demo_pool;
  if have < tg then
    vcode := 'demo-'; for i in 1..5 loop vcode := vcode || substr(alphabet, 1 + floor(random() * length(alphabet))::int, 1); end loop;
    vpwd := 'Dm'; for i in 1..8 loop vpwd := vpwd || substr(alphabet, 1 + floor(random() * length(alphabet))::int, 1); end loop; vpwd := vpwd || '#7';
    perform app.demo_seed(vcode, 'نسخة تجريبية', vpwd, 7, '');
    insert into acc.demo_pool (code, pwd) values (vcode, vpwd); have := have + 1;
  end if;
  return jsonb_build_object('ready', have, 'target', tg, 'busy', false);
end $$;
revoke all on function app.demo_pool_topup(int) from public, anon, authenticated;

create or replace function public.demo_pool_fill(p jsonb default '{}') returns jsonb language plpgsql security definer set search_path = public, app, acc as $$
begin
  perform app.demo_admin();
  return app.demo_pool_topup(coalesce(nullif(p->>'target','')::int, 3));
end $$;

do $$ begin
  create extension if not exists pg_cron;
  perform cron.unschedule(jobid) from cron.job where jobname = 'mohkam-demo-pool';
  perform cron.schedule('mohkam-demo-pool', '*/5 * * * *', 'select app.demo_pool_topup(3)');
exception when others then raise notice 'pg_cron غير متاح: املأ المخزون يدويًا (%).', sqlerrm; end $$;

insert into app.schema_migrations (version, name) values ('1.10.3.0', 'ملء مخزون الديمو من الخلفية (cron) وإزالته من مسار الإنشاء وفتح اللوحة')
  on conflict (version) do nothing;
