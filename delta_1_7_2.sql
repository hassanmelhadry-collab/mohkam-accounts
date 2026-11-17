-- مُحكَم للحسابات 1.7.2.0: سيناريوهات ماذا لو (scenario_run)
-- مُحكَم 1.7.2 — سيناريوهات «ماذا لو»: حساب فوري بلا جداول جديدة، على بيانات الفترة الفعلية للشركات المسموحة.
-- كل سيناريو: نسب تغيير للإيراد والتكلفة المتغيرة والتشغيلية والفوائد، مع خيار ربط تكلفة المبيعات بالإيراد.
create or replace function public.scenario_run(p jsonb) returns jsonb language plpgsql stable security definer set search_path = public, app, acc as $$
declare t uuid := app.need('reports','view'); ents uuid[] := app.pick_ents(p);
  dt date := coalesce(nullif(p->>'to','')::date, current_date); df date := coalesce(nullif(p->>'from','')::date, date_trunc('year', dt)::date);
  b jsonb; sc jsonb; res jsonb := '[]'::jsonb; base jsonb;
  rev numeric; cogs numeric; opex numeric; intr numeric; tax numeric; roth numeric; oth numeric;
  rp numeric; cp numeric; op numeric; ip numeric; link boolean; taxr numeric;
  nrev numeric; ncogs numeric; nopex numeric; nint numeric; ntax numeric; ngross numeric; nebit numeric; nnet numeric; pre numeric; i int := 0;
begin
  if jsonb_typeof(p->'scenarios') is distinct from 'array' or jsonb_array_length(p->'scenarios') = 0 then raise exception 'أضف سيناريو واحدًا على الأقل'; end if;
  if jsonb_array_length(p->'scenarios') > 6 then raise exception 'الحد الأقصى 6 سيناريوهات'; end if;
  b := app.fin_base(t, ents, df, dt);
  rev := app.n(b,'revenue'); cogs := app.n(b,'cogs'); opex := app.n(b,'opex'); intr := app.n(b,'interest'); tax := app.n(b,'tax'); roth := app.n(b,'other_income'); oth := app.n(b,'other_exp');
  pre := rev + roth - cogs - opex - intr - oth;
  base := jsonb_build_object('name', 'الفعلي', 'revenue', rev, 'cogs', cogs, 'gross', rev - cogs, 'opex', opex, 'ebit', rev - cogs - opex, 'interest', intr, 'tax', tax, 'net', pre - tax,
    'gross_margin', case when rev <> 0 then round((rev - cogs) / rev * 100, 2) end, 'net_margin', case when rev <> 0 then round((pre - tax) / rev * 100, 2) end);
  for sc in select * from jsonb_array_elements(p->'scenarios') loop
    i := i + 1;
    rp := coalesce(nullif(sc->>'revenue_pct','')::numeric, 0); cp := coalesce(nullif(sc->>'cogs_pct','')::numeric, 0); op := coalesce(nullif(sc->>'opex_pct','')::numeric, 0); ip := coalesce(nullif(sc->>'interest_pct','')::numeric, 0);
    link := coalesce((sc->>'cogs_follows_revenue')::boolean, true);
    if abs(rp) > 1000 or abs(cp) > 1000 or abs(op) > 1000 or abs(ip) > 1000 then raise exception 'نسبة التغيير خارج المعقول'; end if;
    nrev := rev * (1 + rp / 100);
    ncogs := cogs * (case when link then (1 + rp / 100) else 1 end) * (1 + cp / 100);
    nopex := opex * (1 + op / 100); nint := intr * (1 + ip / 100);
    ngross := nrev - ncogs; nebit := ngross - nopex;
    -- الضريبة: تُحتسب بنفس النسبة الفعلية إلى الربح قبل الضريبة (إن وُجد ربح)، وإلا تبقى كما هي
    taxr := case when pre > 0 then tax / pre end;
    pre := nebit + roth - nint - oth;
    ntax := case when taxr is not null and pre > 0 then pre * taxr when taxr is null then tax else 0 end;
    nnet := pre - ntax;
    res := res || jsonb_build_array(jsonb_build_object('name', coalesce(nullif(sc->>'name',''), 'سيناريو ' || i),
      'inputs', jsonb_build_object('revenue_pct', rp, 'cogs_pct', cp, 'opex_pct', op, 'interest_pct', ip, 'cogs_follows_revenue', link),
      'revenue', round(nrev, 2), 'cogs', round(ncogs, 2), 'gross', round(ngross, 2), 'opex', round(nopex, 2), 'ebit', round(nebit, 2), 'interest', round(nint, 2), 'tax', round(ntax, 2), 'net', round(nnet, 2),
      'gross_margin', case when nrev <> 0 then round(ngross / nrev * 100, 2) end, 'net_margin', case when nrev <> 0 then round(nnet / nrev * 100, 2) end,
      'net_delta', round(nnet - (app.n(base,'net')), 2)));
    pre := rev + roth - cogs - opex - intr - oth;
  end loop;
  return jsonb_build_object('from', df, 'to', dt, 'base', base, 'scenarios', res);
end $$;
