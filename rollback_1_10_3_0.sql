-- تراجع 1.10.3.0: يعيد demo_pool_fill إلى سلوكه السابق (target=2) ويوقف مهمة cron ويحذف الدالة الداخلية وصف الإصدار.
create or replace function public.demo_pool_fill(p jsonb default '{}') returns jsonb language plpgsql security definer set search_path = public, app, acc as $$
declare tg int := least(greatest(coalesce(nullif(p->>'target','')::int, 2), 1), 5); have int; vcode text; vpwd text; alphabet text := 'abcdefghjkmnpqrstuvwxyz23456789'; i int;
begin
  perform app.demo_admin();
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
do $$ begin perform cron.unschedule(jobid) from cron.job where jobname = 'mohkam-demo-pool'; exception when others then null; end $$;
drop function if exists app.demo_pool_topup(int);
delete from app.schema_migrations where version = '1.10.3.0';
