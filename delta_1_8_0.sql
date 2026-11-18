-- مُحكَم للحسابات — تحديث 1.8.0.0 (068-072): المراجعة الشاملة، ECL، SAF-T، حقوق الملكية
-- مُحكَم للحسابات — المراجعة الشاملة: فحوص محاسبية ورقابية وضريبية مربوطة بمعايير عالمية (IFRS / COSO / ISO 27001 / ZATCA)
-- للقراءة فقط: لا تعدّل شيئًا. تعطي درجة 0–100 وقائمة فحوص لكل فحص معياره وخطورته وتلميح للإصلاح.
create or replace function app.rv(k text, g text, std text, sev text, ok boolean, cnt bigint, det text, hint text, lnk text) returns jsonb language sql immutable as
$$ select jsonb_build_object('key', k, 'group', g, 'standard', std, 'severity', sev, 'ok', ok, 'count', cnt, 'detail', det, 'hint', hint, 'link', lnk) $$;

create or replace function public.system_review(p jsonb default '{}') returns jsonb language plpgsql stable security definer set search_path = public, app, acc as $$
declare t uuid := app.need('reports', 'view'); ents uuid[] := app.pick_ents(p); asof date := coalesce(nullif(p->>'asof', '')::date, current_date);
  res jsonb := '[]'::jsonb; h jsonb; hc jsonb; n bigint; x numeric; y numeric; cur_ccy text; st jsonb; ag jsonb; ecl numeric; allw numeric; rates jsonb;
  hi int := 0; me int := 0; lo int := 0; ps int := 0; sc int; nent int;
begin
  select settings, currency into st, cur_ccy from acc.tenants where id = t; nent := coalesce(array_length(ents, 1), 0);
  if nent = 0 then raise exception 'لا توجد شركات متاحة للمراجعة'; end if;

  -- 1) سلامة الدفاتر (IAS 1 / القيد المزدوج)
  select count(*) into n from (select l.journal_id from acc.journal_lines l where l.tenant_id = t and l.entity_id = any(ents) and l.posted group by l.journal_id having sum(l.debit) <> sum(l.credit)) z;
  res := res || app.rv('unbalanced', 'books', 'IAS 1 — القيد المزدوج', 'high', n = 0, n, n || ' قيد مرحّل غير متزن', 'قيد مرحّل مدينه لا يساوي دائنه: يجب عكسه وتصحيحه فورًا', '/reports/tb');
  select count(*) into n from acc.journal_lines l join acc.journals j on j.tenant_id = l.tenant_id and j.id = l.journal_id
    where l.tenant_id = t and l.entity_id = any(ents) and ((l.posted and j.status in ('draft', 'pending', 'approved')) or (not l.posted and j.status in ('posted', 'reversed')));
  res := res || app.rv('post_flag', 'books', 'ISA 315 — سلامة البيانات', 'high', n = 0, n, n || ' سطرًا حالة ترحيله تخالف حالة قيده', 'اتساق داخلي بين القيد وسطوره', '/journals');
  select count(*) into n from acc.journal_lines l join acc.accounts a on a.tenant_id = l.tenant_id and a.id = l.account_id where l.tenant_id = t and l.entity_id = any(ents) and l.posted and a.is_group;
  res := res || app.rv('group_post', 'books', 'IAS 1 — عرض الحسابات', 'medium', n = 0, n, n || ' سطرًا مرحّلًا على حساب رئيسي (مجموعة)', 'الترحيل يكون على الحسابات الفرعية فقط', '/coa');
  select count(*) into n from acc.journals j where j.tenant_id = t and j.entity_id = any(ents) and j.status = 'posted' and j.period_id is null;
  res := res || app.rv('no_period', 'books', 'IAS 1 — الفترة المحاسبية', 'medium', n = 0, n, n || ' قيدًا مرحّلًا بلا فترة محاسبية', 'أنشئ السنة المالية والفترات للشركة', '/periods');
  select count(*) into n from (select a.id from acc.journal_lines l join acc.accounts a on a.tenant_id = l.tenant_id and a.id = l.account_id
    where l.tenant_id = t and l.posted and l.entity_id = any(ents) and l.date <= asof and a.subtype in ('receivable', 'payable', 'cash', 'bank', 'inventory', 'fixed_asset', 'vat_input', 'vat_output')
    group by a.id, a.subtype having (a.subtype in ('receivable', 'cash', 'bank', 'inventory', 'fixed_asset', 'vat_input') and sum(l.debit - l.credit) < -0.005) or (a.subtype in ('payable', 'vat_output') and sum(l.debit - l.credit) > 0.005)) z;
  res := res || app.rv('abnormal', 'books', 'IAS 1 — معقولية الأرصدة', 'medium', n = 0, n, n || ' حسابًا برصيد عكس طبيعته', 'مثل نقد/عملاء/مخزون برصيد دائن أو موردين برصيد مدين: راجع القيود', '/reports/tb');
  select count(*) into n from (select 1 from acc.invoices i where i.tenant_id = t and i.entity_id = any(ents) and i.kind = 'purchase' and i.supplier_ref <> '' and i.status <> 'void' group by i.entity_id, i.party_id, i.supplier_ref having count(*) > 1) z;
  res := res || app.rv('dup_bills', 'books', 'ISA 240 — مخاطر الاحتيال', 'medium', n = 0, n, n || ' رقم فاتورة مورد مكرر لنفس المورد', 'تكرار رقم فاتورة المورد قد يعني دفعًا مزدوجًا', '/invoices/purchase');
  select count(*) into n from acc.journals j where j.tenant_id = t and j.entity_id = any(ents) and j.status = 'posted' and j.source = 'manual' and j.created_at::date - j.date > 90 and j.created_at >= asof - 365;
  res := res || app.rv('backdated', 'books', 'ISA 240 — قيود بتاريخ قديم', 'low', n = 0, n, n || ' قيدًا يدويًا أُنشئ بتاريخ أقدم من 90 يومًا', 'راجع مبررات القيود الراجعة بتاريخ', '/journals');

  -- 2) الأرصدة الفرعية والتطابق (مؤشرات health_check مضافًا إليها المعيار)
  hc := public.health_check(p);
  for h in select * from jsonb_array_elements(hc) loop
    res := res || app.rv('hc_' || (h->>'key'), 'subledger',
      case h->>'key' when 'tb' then 'IAS 1 — ميزان المراجعة' when 'bs' then 'IAS 1 — المركز المالي' when 'ar' then 'IFRS 9 — تطابق الذمم المدينة' when 'ap' then 'IAS 37 — تطابق الذمم الدائنة'
        when 'seq' then 'ISA 500 — اكتمال المستندات' when 'stale' then 'IAS 1 — القطع' when 'inv_open' then 'IFRS 15 — اكتمال الإيراد' when 'sod' then 'COSO — فصل المهام' when 'chain' then 'ISO 27001 A.12.4 — سلامة السجلات' else 'عام' end,
      case when h->>'key' in ('tb', 'bs', 'ar', 'ap', 'chain') then 'high' when h->>'key' in ('seq', 'sod') then 'medium' else 'low' end,
      coalesce((h->>'ok')::boolean, false), case when coalesce((h->>'ok')::boolean, false) then 0 else 1 end, h->>'label' || ' — ' || coalesce(h->>'detail', ''), 'راجع التفاصيل من الرابط', h->>'link');
  end loop;
  select coalesce(sum(b.qty * b.avg_cost), 0) into x from acc.stock_bal b where b.tenant_id = t and b.entity_id = any(ents);
  select coalesce(sum(l.debit - l.credit), 0) into y from acc.journal_lines l where l.tenant_id = t and l.posted and l.entity_id = any(ents) and l.account_id in (select distinct inv_account_id from acc.items where tenant_id = t);
  if x <> 0 or y <> 0 then
    res := res || app.rv('inv_gl', 'subledger', 'IAS 2 — تقييم المخزون', 'high', abs(x - y) <= greatest(1, abs(y) * 0.001), case when abs(x - y) <= greatest(1, abs(y) * 0.001) then 0 else 1 end, 'قيمة المخزون ' || round(x, 2) || ' مقابل الأستاذ ' || round(y, 2), 'الفرق يعني حركة مخزون بلا قيد أو قيدًا يدويًا على حساب المخزون', '/inventory');
  end if;
  select count(*) into n from acc.stock_bal b where b.tenant_id = t and b.entity_id = any(ents) and b.qty < 0;
  res := res || app.rv('neg_stock', 'subledger', 'IAS 2 — كميات المخزون', 'medium', n = 0, n, n || ' صنفًا برصيد كمية سالب', 'الصرف قبل الاستلام يشوّه متوسط التكلفة', '/inventory');
  select count(*) into n from (select i.id from acc.invoices i left join acc.invoice_lines il on il.tenant_id = i.tenant_id and il.invoice_id = i.id
    where i.tenant_id = t and i.entity_id = any(ents) and i.status = 'issued' group by i.id, i.total having abs(coalesce(sum(il.net + il.tax), 0) - i.total) > 0.05) z;
  res := res || app.rv('inv_integrity', 'subledger', 'ISA 500 — سلامة المستندات', 'high', n = 0, n, n || ' فاتورة مصدرة إجماليها لا يساوي مجموع بنودها', 'خلل في الاحتساب أو تعديل خارج النظام', '/invoices/sales');
  select count(*) into n from acc.invoices i where i.tenant_id = t and i.entity_id = any(ents) and i.status = 'issued' and i.journal_id is null;
  res := res || app.rv('inv_no_je', 'subledger', 'IFRS 15 — اكتمال القيد', 'high', n = 0, n, n || ' فاتورة مصدرة بلا قيد', 'كل فاتورة مصدرة يجب أن يقابلها قيد', '/invoices/sales');

  -- 3) الامتثال الضريبي (ضريبة القيمة المضافة / ZATCA)
  select count(*) into n from (select distinct i.party_id from acc.invoices i join acc.parties pa on pa.tenant_id = i.tenant_id and pa.id = i.party_id
    where i.tenant_id = t and i.entity_id = any(ents) and i.kind = 'sales' and i.status = 'issued' and pa.vat_no = '' and i.total_base >= 1000 and pa.kind in ('customer', 'both')) z;
  res := res || app.rv('b2b_vat', 'tax', 'ZATCA — الفاتورة الضريبية (مشتري)', 'low', n = 0, n, n || ' عميلًا بفواتير 1000+ بلا رقم ضريبي', 'الفاتورة لمنشأة تحتاج رقمها الضريبي، وللأفراد تُصدر مبسّطة', '/parties');
  select count(*) into n from acc.entities e where e.tenant_id = t and e.id = any(ents) and e.vat_no = '' and exists (select 1 from acc.tax_lines tl where tl.tenant_id = t and tl.entity_id = e.id);
  res := res || app.rv('ent_vat', 'tax', 'ZATCA — تسجيل ضريبة القيمة المضافة', 'high', n = 0, n, n || ' شركة لها حركة ضريبية بلا رقم ضريبي', 'أضف الرقم الضريبي للشركة من الإعدادات ← الكيانات', '/settings');
  select count(*) into n from acc.tax_codes c where c.tenant_id = t and c.active and c.kind in ('output', 'input') and c.rate > 0 and c.account_id is null;
  res := res || app.rv('tax_acct', 'tax', 'ضريبة القيمة المضافة — حساب الرمز', 'high', n = 0, n, n || ' رمز ضريبة بنسبة بلا حساب مربوط', 'الرمز بلا حساب يفشل عند الترحيل', '/settings');
  select count(*) into n from acc.invoices i where i.tenant_id = t and i.entity_id = any(ents) and i.status <> 'void' and i.date > asof + 7;
  res := res || app.rv('future_inv', 'tax', 'ZATCA — تاريخ الفاتورة', 'low', n = 0, n, n || ' فاتورة بتاريخ مستقبلي', 'لا تُصدر فاتورة بتاريخ لم يحن', '/invoices/sales');

  -- 4) الرقابة الداخلية والصلاحيات (COSO / ISO 27001)
  res := res || app.rv('approval_on', 'control', 'COSO — الاعتماد', 'medium', coalesce((st #>> '{approval,journals,required}')::boolean, true) and coalesce((st #>> '{approval,invoices,required}')::boolean, true), 0,
    'دورة الاعتماد للقيود والفواتير ' || case when coalesce((st #>> '{approval,journals,required}')::boolean, true) and coalesce((st #>> '{approval,invoices,required}')::boolean, true) then 'مفعّلة' else 'معطّلة في الإعدادات' end, 'فعّل الاعتماد قبل الترحيل لأي شركة بأكثر من محاسب', '/settings');
  res := res || app.rv('sod_on', 'control', 'COSO — فصل المهام', 'medium', coalesce((st #>> '{approval,sod}')::boolean, true), 0,
    'فصل المهام ' || case when coalesce((st #>> '{approval,sod}')::boolean, true) then 'مفعّل' else 'معطّل' end, 'لا يعتمد المستخدم ما أعدّه بنفسه', '/settings');
  select count(*) into n from acc.members m where m.tenant_id = t and m.active and m.role = 'owner';
  res := res || app.rv('owners', 'control', 'ISO 27001 A.9 — الصلاحيات المميزة', 'medium', n between 1 and 3, n, n || ' مالك/مدير نظام نشط', 'يُنصح بمالكين اثنين على الأقل وثلاثة على الأكثر', '/users');
  res := res || app.rv('mfa', 'control', 'ISO 27001 A.9.4 — التحقق الثنائي', 'medium', coalesce((select x.require_mfa from acc.tenants x where x.id = t), false), 0,
    'التحقق الثنائي ' || case when coalesce((select x.require_mfa from acc.tenants x where x.id = t), false) then 'إلزامي' else 'غير إلزامي' end, 'ألزم التحقق الثنائي على الأقل لمدراء الحساب', '/settings');
  select count(*) into n from acc.members m where m.tenant_id = t and m.active and m.role <> 'owner' and m.entities is null and (select count(*) from acc.entities e where e.tenant_id = t and e.active) > 1;
  res := res || app.rv('users_all_ents', 'control', 'ISO 27001 A.9.1 — أقل صلاحية', 'medium', n = 0, n, n || ' مستخدمًا (غير المالك) يرى كل الشركات', 'حدّد شركات كل مستخدم', '/users');
  select count(*) into n from acc.members m where m.tenant_id = t and m.active and m.expires_at is not null and m.expires_at < now();
  res := res || app.rv('expired_users', 'control', 'ISO 27001 A.9.2 — إنهاء الوصول', 'high', n = 0, n, n || ' مستخدمًا منتهي الصلاحية ما زال نشطًا', 'عطّل أو جدّد الوصول المؤقت', '/users');
  select count(*) into n from acc.members m where m.tenant_id = t and m.active and m.created_at < now() - interval '90 days' and coalesce(m.last_login, m.created_at) < now() - interval '90 days';
  res := res || app.rv('dormant', 'control', 'ISO 27001 A.9.2 — مراجعة الحسابات', 'low', n = 0, n, n || ' مستخدمًا لم يدخل منذ 90 يومًا', 'عطّل الحسابات الخاملة', '/users');

  -- 5) الفترات والإقفال (IAS 1 / IAS 8)
  select count(*) into n from acc.entities e where e.tenant_id = t and e.id = any(ents) and e.active and not exists
    (select 1 from acc.periods pr where pr.tenant_id = t and pr.entity_id = e.id and asof between pr.start_date and pr.end_date and pr.status <> 'closed');
  res := res || app.rv('open_period', 'closing', 'IAS 1 — فترة مفتوحة للتشغيل', 'medium', n = 0, n, n || ' شركة بلا فترة مفتوحة تغطي ' || asof, 'أنشئ السنة المالية أو أعد فتح الفترة', '/periods');
  select count(*) into n from acc.fiscal_years f where f.tenant_id = t and f.entity_id = any(ents) and f.status = 'open' and f.end_date < asof - 60;
  res := res || app.rv('old_fy', 'closing', 'IAS 1 — إقفال السنة', 'medium', n = 0, n, n || ' سنة مالية انتهت منذ أكثر من 60 يومًا ولم تُقفل', 'أقفل السنة وانقل الأرباح للمبقاة', '/periods');

  -- 6) العملات الأجنبية (IAS 21)
  select count(*) into n from (select distinct i.currency from acc.invoices i where i.tenant_id = t and i.entity_id = any(ents) and i.currency <> cur_ccy and i.date >= asof - 365
    and not exists (select 1 from acc.fx_rates f where f.tenant_id = t and f.currency = i.currency and f.date between i.date - 45 and i.date)) z;
  res := res || app.rv('fx_rates', 'fx', 'IAS 21 — أسعار الصرف', 'medium', n = 0, n, n || ' عملة بفواتير بلا سعر صرف مسجّل قريب', 'سجّل أسعار الصرف دوريًا', '/settings');

  -- 7) الأصول الثابتة (IAS 16)
  select count(*) into n from acc.assets a where a.tenant_id = t and a.entity_id = any(ents) and a.status = 'active' and a.method = 'sl' and a.life_months > 0 and a.accumulated < a.cost - a.salvage
    and (date_trunc('month', asof)::date - coalesce(a.dep_through, a.acquisition_date)) > 62;
  res := res || app.rv('dep_lag', 'assets', 'IAS 16 — الإهلاك الدوري', 'medium', n = 0, n, n || ' أصلًا متأخر الإهلاك أكثر من شهرين', 'شغّل الإهلاك الشهري', '/assets');

  -- 8) خسائر الائتمان المتوقعة (IFRS 9 — الأسلوب المبسّط)
  rates := coalesce(st #> '{ecl,rates}', '{"current":0.005,"d30":0.02,"d60":0.05,"d90":0.15,"d90p":0.4}'::jsonb);
  ag := public.rpt_aging(jsonb_build_object('kind', 'ar', 'asof', asof, 'entities', to_jsonb(ents)));
  select coalesce(sum((r->>'current')::numeric) * (rates->>'current')::numeric + sum((r->>'d30')::numeric) * (rates->>'d30')::numeric + sum((r->>'d60')::numeric) * (rates->>'d60')::numeric
    + sum((r->>'d90')::numeric) * (rates->>'d90')::numeric + sum((r->>'d90p')::numeric) * (rates->>'d90p')::numeric, 0) into ecl from jsonb_array_elements(ag->'rows') r;
  select coalesce(sum(l.credit - l.debit), 0) into allw from acc.journal_lines l join acc.accounts a on a.tenant_id = l.tenant_id and a.id = l.account_id
    where l.tenant_id = t and l.posted and l.entity_id = any(ents) and l.date <= asof and a.subtype = 'allowance';
  res := res || app.rv('ecl', 'credit', 'IFRS 9 §5.5.15 — خسائر الائتمان المتوقعة', 'medium', ecl < 100 or allw >= ecl * 0.5, case when ecl < 100 or allw >= ecl * 0.5 then 0 else 1 end,
    'الخسارة المتوقعة ' || round(ecl, 2) || ' مقابل مخصص ' || round(allw, 2), 'شغّل «مخصص الديون المشكوك فيها» وراجع النسب مع الإدارة', '/review');

  -- 9) التفعيلات والإعداد
  res := res || app.rv('isolation', 'config', 'فصل بيانات الشركات', 'medium', nent <= 1 or app.iso(t), 0,
    case when nent <= 1 or app.iso(t) then 'فصل بيانات الشركات مفعّل أو غير مطلوب' else 'أكثر من شركة والدليل والأطراف مشتركة بينها' end, 'فعّل «فصل بيانات الشركات» من الإعدادات ← الكيانات لتصير كل شركة برنامجًا مستقلًا', '/settings');

  select count(*) filter (where (r->>'severity') = 'high' and not (r->>'ok')::boolean), count(*) filter (where (r->>'severity') = 'medium' and not (r->>'ok')::boolean),
    count(*) filter (where (r->>'severity') = 'low' and not (r->>'ok')::boolean), count(*) filter (where (r->>'ok')::boolean) into hi, me, lo, ps from jsonb_array_elements(res) r;
  sc := greatest(0, 100 - hi * 15 - me * 7 - lo * 2);
  return jsonb_build_object('asof', asof, 'score', sc, 'grade', case when sc >= 90 then 'A' when sc >= 75 then 'B' when sc >= 60 then 'C' else 'D' end,
    'summary', jsonb_build_object('high', hi, 'medium', me, 'low', lo, 'passed', ps, 'total', jsonb_array_length(res)), 'checks', res);
end $$;

-- مُحكَم للحسابات — مخصص خسائر الائتمان المتوقعة (IFRS 9 — الأسلوب المبسّط / مصفوفة المخصصات)
-- النسب تُعتمد من الإدارة ولا يفرضها النظام: المعاينة بنسب افتراضية إرشادية، والترحيل يتطلب نسبًا معتمدة وحساب مصروف.
-- القيد الناتج مسودة تمرّ بدورة الاعتماد المعتادة؛ لا يُرحَّل تلقائيًا.

create or replace function app.ecl_calc(t uuid, e uuid, asof date, rates jsonb) returns jsonb language plpgsql stable security definer set search_path = public, acc, app as $$
declare b jsonb; ecl numeric := 0; allw numeric; k text; amt numeric; tot numeric := 0; lines jsonb := '[]'::jsonb; ag jsonb;
begin
  ag := public.rpt_aging(jsonb_build_object('kind', 'ar', 'asof', asof, 'entity', e));
  select jsonb_build_object('current', coalesce(sum((r->>'current')::numeric), 0), 'd30', coalesce(sum((r->>'d30')::numeric), 0), 'd60', coalesce(sum((r->>'d60')::numeric), 0),
    'd90', coalesce(sum((r->>'d90')::numeric), 0), 'd90p', coalesce(sum((r->>'d90p')::numeric), 0)) into b from jsonb_array_elements(ag->'rows') r;
  foreach k in array array['current', 'd30', 'd60', 'd90', 'd90p'] loop
    amt := (b->>k)::numeric; tot := tot + amt;
    lines := lines || jsonb_build_object('bucket', k, 'amount', amt, 'rate', (rates->>k)::numeric, 'ecl', round(amt * (rates->>k)::numeric, 2));
    ecl := ecl + round(amt * (rates->>k)::numeric, 2);
  end loop;
  select coalesce(sum(l.credit - l.debit), 0) into allw from acc.journal_lines l join acc.accounts a on a.tenant_id = l.tenant_id and a.id = l.account_id
    where l.tenant_id = t and l.posted and l.entity_id = e and l.date <= asof and a.subtype = 'allowance';
  return jsonb_build_object('buckets', lines, 'receivables', tot, 'ecl', ecl, 'allowance', allw, 'delta', round(ecl - allw, 2));
end $$;

-- حفظ النسب المعتمدة وحساب المصروف (يتطلب صلاحية الإعدادات)
create or replace function public.ecl_settings_save(p jsonb) returns jsonb language plpgsql security definer set search_path = public, app, acc as $$
declare t uuid := app.need_sys('settings'); r jsonb := p->'rates'; k text; prev numeric := -1; v numeric; ex acc.accounts; xc text := nullif(trim(coalesce(p->>'expense_account', '')), '');
begin
  if jsonb_typeof(r) <> 'object' then raise exception 'النسب مطلوبة'; end if;
  foreach k in array array['current', 'd30', 'd60', 'd90', 'd90p'] loop
    if not (r ? k) or jsonb_typeof(r->k) <> 'number' then raise exception 'النسبة مطلوبة لكل فئة عمرية: %', k; end if;
    v := (r->>k)::numeric; if v < 0 or v > 1 then raise exception 'النسبة يجب أن تكون بين 0 و1 (مثال 0.05 = 5%%): %', k; end if;
    if v < prev then raise exception 'النسب يجب ألا تنخفض مع تقادم الدين'; end if; prev := v;
  end loop;
  if xc is null then raise exception 'حدد حساب مصروف الديون المشكوك فيها'; end if;
  select * into ex from acc.accounts a where a.tenant_id = t and a.code = xc and not a.is_group and a.type = 'expense' order by a.entity_id nulls first limit 1;
  if ex.id is null then raise exception 'حساب المصروف غير موجود أو ليس مصروفًا فرعيًا'; end if;
  update acc.tenants set settings = jsonb_set(settings, '{ecl}', jsonb_build_object('rates', r, 'expense_account', xc, 'confirmed', true, 'confirmed_at', now(), 'confirmed_by', auth.uid())) where id = t;
  perform app.audit('update', 'settings', 'ecl', 'اعتماد نسب خسائر الائتمان المتوقعة وحساب المصروف ' || xc);
  return jsonb_build_object('ok', true);
end $$;

-- معاينة لكل شركة: الفئات العمرية والنسب والخسارة المتوقعة مقابل رصيد المخصص
create or replace function public.ecl_preview(p jsonb default '{}') returns jsonb language plpgsql stable security definer set search_path = public, app, acc as $$
declare t uuid := app.need('reports', 'view'); ents uuid[] := app.pick_ents(p); asof date := coalesce(nullif(p->>'asof', '')::date, current_date); st jsonb; rates jsonb; conf boolean; e uuid; rows jsonb := '[]'::jsonb;
begin
  select settings #> '{ecl}' into st from acc.tenants where id = t; conf := coalesce((st->>'confirmed')::boolean, false);
  rates := coalesce(st->'rates', '{"current":0.005,"d30":0.02,"d60":0.05,"d90":0.15,"d90p":0.4}'::jsonb);
  foreach e in array ents loop
    rows := rows || (jsonb_build_object('entity', e, 'name', (select name from acc.entities where tenant_id = t and id = e)) || app.ecl_calc(t, e, asof, rates));
  end loop;
  return jsonb_build_object('asof', asof, 'confirmed', conf, 'rates', rates, 'expense_account', st->>'expense_account', 'rows', rows,
    'note', case when conf then 'النسب معتمدة من الإدارة' else 'نسب افتراضية إرشادية — اعتمد نسب شركتك قبل الترحيل (تُبنى عادة على الخبرة التاريخية للتعثر)' end);
end $$;

-- ترحيل القيد (مسودة): مصروف/مخصص بفرق المخصص المطلوب عن الرصيد الحالي، لكل شركة على حدة
create or replace function public.ecl_post(p jsonb) returns jsonb language plpgsql security definer set search_path = public, app, acc as $$
declare t uuid := app.need('journals', 'add'); e uuid := nullif(p->>'entity', '')::uuid; asof date := coalesce(nullif(p->>'asof', '')::date, current_date); st jsonb; c jsonb; allw uuid; ex uuid; d numeric; j jsonb; ref text;
begin
  if e is null or not (e = any(app.ents())) then raise exception 'حدد شركة مسموحة'; end if;
  select settings #> '{ecl}' into st from acc.tenants where id = t;
  if not coalesce((st->>'confirmed')::boolean, false) then raise exception 'اعتمد نسب الخسارة المتوقعة وحساب المصروف أولًا'; end if;
  c := app.ecl_calc(t, e, asof, st->'rates'); d := (c->>'delta')::numeric;
  if abs(d) < 0.01 then return jsonb_build_object('posted', false, 'reason', 'المخصص الحالي مطابق للخسارة المتوقعة', 'calc', c); end if;
  ref := 'ECL-' || asof;
  if exists (select 1 from acc.journals where tenant_id = t and entity_id = e and reference = ref and status <> 'reversed') then raise exception 'يوجد قيد مخصص لهذا التاريخ (%): اعكسه أولًا لإعادة الاحتساب', ref; end if;
  select id into allw from acc.accounts where tenant_id = t and subtype = 'allowance' and not is_group and (entity_id is null or entity_id = e) order by entity_id nulls last limit 1;
  select id into ex from acc.accounts where tenant_id = t and code = st->>'expense_account' and not is_group and (entity_id is null or entity_id = e) order by entity_id nulls last limit 1;
  if allw is null then raise exception 'لا يوجد حساب مخصص ديون مشكوك فيها (نوعه allowance) لهذه الشركة'; end if;
  if ex is null then raise exception 'حساب المصروف المعتمد غير متاح لهذه الشركة'; end if;
  j := public.je_save(jsonb_build_object('entity', e, 'date', asof, 'type', 'ADJ', 'reference', ref,
    'description', 'مخصص خسائر ائتمان متوقعة (IFRS 9) حتى ' || asof,
    'lines', case when d > 0 then jsonb_build_array(jsonb_build_object('account', ex, 'debit', d, 'credit', 0, 'description', 'مصروف ديون مشكوك فيها'), jsonb_build_object('account', allw, 'debit', 0, 'credit', d, 'description', 'مخصص خسائر ائتمان متوقعة'))
      else jsonb_build_array(jsonb_build_object('account', allw, 'debit', -d, 'credit', 0, 'description', 'تخفيض مخصص خسائر ائتمان'), jsonb_build_object('account', ex, 'debit', 0, 'credit', -d, 'description', 'رد مصروف ديون مشكوك فيها')) end));
  perform app.audit('create', 'ecl', coalesce(j->>'id', ''), 'قيد مخصص ECL بمبلغ ' || d || ' حتى ' || asof);
  return jsonb_build_object('posted', true, 'journal', j->>'id', 'amount', d, 'calc', c);
end $$;

-- مُحكَم للحسابات — ملف التدقيق القياسي (على نهج OECD SAF-T المبسّط) للمفتش والمراجع الخارجي
-- يُصدَّر على أقسام صغيرة (ترويسة، دليل حسابات، أطراف، رموز ضريبة، أرصدة، يومية، فواتير، سندات) مع بصمة SHA-256 لكل قسم
-- للقراءة فقط، ويُسجَّل كل تصدير في سجل التدقيق.
create or replace function public.audit_file(p jsonb) returns jsonb language plpgsql stable security definer set search_path = public, app, acc as $$
declare t uuid := app.need(null, null); ents uuid[] := app.pick_ents(p); df date := coalesce(nullif(p->>'from', '')::date, date_trunc('year', current_date)::date); dt date := coalesce(nullif(p->>'to', '')::date, current_date);
  sec text := coalesce(nullif(p->>'section', ''), 'header'); off int := greatest(coalesce(nullif(p->>'offset', '')::int, 0), 0); lim int := least(greatest(coalesce(nullif(p->>'limit', '')::int, 2000), 1), 5000);
  body jsonb; total bigint := 0; tn acc.tenants;
begin
  if not (app.can('reports', 'view') or app.can('tax', 'view') or app.sys('audit')) then raise exception 'ليست لديك صلاحية'; end if;
  if dt < df then raise exception 'نهاية الفترة قبل بدايتها'; end if;
  if dt - df > 800 then raise exception 'الفترة أطول من 800 يوم: قسّمها'; end if;
  select * into tn from acc.tenants where id = t;
  if sec = 'header' then
    body := jsonb_build_object('standard', 'SAF-T مبسّط (OECD) — ملف تدقيق مُحكَم', 'software', 'مُحكَم — نظام الحسابات (ACC)', 'generated_on', current_date,
      'company', jsonb_build_object('name', tn.name, 'name_en', tn.name_en, 'cr', tn.cr, 'vat_no', tn.vat_no, 'country', tn.country, 'currency', tn.currency),
      'period', jsonb_build_object('from', df, 'to', dt),
      'entities', (select coalesce(jsonb_agg(jsonb_build_object('code', e.code, 'name', e.name, 'vat_no', e.vat_no, 'cr', e.cr) order by e.code), '[]') from acc.entities e where e.tenant_id = t and e.id = any(ents)),
      'counts', jsonb_build_object(
        'accounts', (select count(*) from acc.accounts a where a.tenant_id = t and not a.is_group),
        'journals', (select count(*) from acc.journals j where j.tenant_id = t and j.entity_id = any(ents) and j.status in ('posted', 'reversed') and j.date between df and dt),
        'invoices', (select count(*) from acc.invoices i where i.tenant_id = t and i.entity_id = any(ents) and i.date between df and dt),
        'payments', (select count(*) from acc.payments y where y.tenant_id = t and y.entity_id = any(ents) and y.date between df and dt)));
    total := 1;
  elsif sec = 'accounts' then
    select count(*) into total from acc.accounts a where a.tenant_id = t;
    body := (select coalesce(jsonb_agg(jsonb_build_object('code', a.code, 'name', a.name, 'name_en', a.name_en, 'type', a.type, 'subtype', a.subtype, 'is_group', a.is_group,
      'parent', (select c.code from acc.accounts c where c.tenant_id = t and c.id = a.parent_id)) order by a.code), '[]') from (select * from acc.accounts a0 where a0.tenant_id = t order by a0.code offset off limit lim) a);
  elsif sec = 'parties' then
    select count(*) into total from acc.parties a where a.tenant_id = t;
    body := (select coalesce(jsonb_agg(jsonb_build_object('code', a.code, 'name', a.name, 'kind', a.kind, 'vat_no', a.vat_no, 'cr', a.cr, 'country', a.country, 'city', a.city) order by a.code), '[]')
      from (select * from acc.parties a0 where a0.tenant_id = t order by a0.code offset off limit lim) a);
  elsif sec = 'tax' then
    select count(*) into total from acc.tax_codes where tenant_id = t;
    body := (select coalesce(jsonb_agg(jsonb_build_object('code', c.code, 'name', c.name, 'rate', c.rate, 'kind', c.kind, 'account', (select a.code from acc.accounts a where a.tenant_id = t and a.id = c.account_id), 'active', c.active) order by c.code), '[]') from acc.tax_codes c where c.tenant_id = t);
  elsif sec = 'balances' then
    select count(*) into total from app.tb_rows(t, ents, df, dt, true) r where r.opening <> 0 or r.debit <> 0 or r.credit <> 0;
    body := (select coalesce(jsonb_agg(jsonb_build_object('account', a.code, 'name', a.name, 'opening', r.opening, 'debit', r.debit, 'credit', r.credit, 'closing', r.opening + r.debit - r.credit) order by a.code), '[]')
      from app.tb_rows(t, ents, df, dt, true) r join acc.accounts a on a.tenant_id = t and a.id = r.account_id where r.opening <> 0 or r.debit <> 0 or r.credit <> 0);
  elsif sec = 'journals' then
    select count(*) into total from acc.journals j where j.tenant_id = t and j.entity_id = any(ents) and j.status in ('posted', 'reversed') and j.date between df and dt;
    body := (select coalesce(jsonb_agg(jsonb_build_object('entity', e.code, 'number', j.number, 'date', j.date, 'type', j.type, 'status', j.status, 'description', j.description, 'reference', j.reference, 'source', j.source,
        'created_by', (select m.username from acc.members m where m.user_id = j.created_by), 'lines', (select coalesce(jsonb_agg(jsonb_build_object('line', l.line_no, 'account', a.code, 'debit', l.debit, 'credit', l.credit,
          'party', (select pa.code from acc.parties pa where pa.tenant_id = t and pa.id = l.party_id), 'tax_code', l.tax_code, 'tax_base', l.tax_base, 'currency', l.currency, 'fc_amount', l.fc_amount, 'description', l.description) order by l.line_no), '[]')
          from acc.journal_lines l join acc.accounts a on a.tenant_id = t and a.id = l.account_id where l.tenant_id = t and l.journal_id = j.id)) order by j.date, j.number), '[]')
      from (select * from acc.journals j0 where j0.tenant_id = t and j0.entity_id = any(ents) and j0.status in ('posted', 'reversed') and j0.date between df and dt order by j0.date, j0.number offset off limit lim) j
      join acc.entities e on e.tenant_id = t and e.id = j.entity_id);
  elsif sec = 'invoices' then
    select count(*) into total from acc.invoices i where i.tenant_id = t and i.entity_id = any(ents) and i.date between df and dt;
    body := (select coalesce(jsonb_agg(jsonb_build_object('entity', e.code, 'number', i.number, 'supplier_ref', i.supplier_ref, 'kind', i.kind, 'date', i.date, 'due_date', i.due_date, 'status', i.status,
        'party', pa.code, 'party_vat', pa.vat_no, 'currency', i.currency, 'rate', i.rate, 'subtotal', i.subtotal, 'discount', i.discount_total, 'tax', i.tax_total, 'total', i.total, 'total_base', i.total_base,
        'journal', (select j.number from acc.journals j where j.tenant_id = t and j.id = i.journal_id)) order by i.date, i.number), '[]')
      from (select * from acc.invoices i0 where i0.tenant_id = t and i0.entity_id = any(ents) and i0.date between df and dt order by i0.date, i0.number offset off limit lim) i
      join acc.entities e on e.tenant_id = t and e.id = i.entity_id join acc.parties pa on pa.tenant_id = t and pa.id = i.party_id);
  elsif sec = 'payments' then
    select count(*) into total from acc.payments y where y.tenant_id = t and y.entity_id = any(ents) and y.date between df and dt;
    body := (select coalesce(jsonb_agg(jsonb_build_object('entity', e.code, 'number', y.number, 'kind', y.kind, 'date', y.date, 'method', y.method, 'status', y.status, 'amount', y.amount, 'reference', y.reference,
        'party', (select pa.code from acc.parties pa where pa.tenant_id = t and pa.id = y.party_id), 'journal', (select j.number from acc.journals j where j.tenant_id = t and j.id = y.journal_id)) order by y.date, y.number), '[]')
      from (select * from acc.payments y0 where y0.tenant_id = t and y0.entity_id = any(ents) and y0.date between df and dt order by y0.date, y0.number offset off limit lim) y
      join acc.entities e on e.tenant_id = t and e.id = y.entity_id);
  else raise exception 'قسم غير معروف: %', sec; end if;
  if off = 0 then perform app.audit('export', 'audit_file', sec, 'ملف التدقيق — قسم ' || sec || ' ' || df || ' → ' || dt); end if;
  return jsonb_build_object('section', sec, 'from', df, 'to', dt, 'offset', off, 'limit', lim, 'total', total, 'has_more', (off + lim) < total, 'sha256', encode(sha256(convert_to(body::text, 'UTF8')), 'hex'), 'data', body);
end $$;

-- مُحكَم للحسابات — قائمة التغيرات في حقوق الملكية (IAS 1.106)
-- أربع فئات: رأس المال، الاحتياطيات، الأرباح المبقاة (تشمل ربح السنة غير المقفل)، التوزيعات والمسحوبات.
-- الأعمدة: الرصيد الافتتاحي، ربح الفترة، حركات مباشرة، تحويلات الإقفال (مجموعها صفر)، الرصيد الختامي = حقوق الملكية في المركز المالي.
create or replace function public.rpt_equity_changes(p jsonb default '{}') returns jsonb language plpgsql stable security definer set search_path = public, app, acc as $$
declare t uuid := app.need('reports', 'view'); ents uuid[] := app.pick_ents(p); dt date := coalesce(nullif(p->>'to', '')::date, current_date); df date := coalesce(nullif(p->>'from', '')::date, date_trunc('year', dt)::date);
  out jsonb; bs jsonb; tot jsonb; tc numeric;
begin
  if dt < df then raise exception 'نهاية الفترة قبل بدايتها'; end if;
  with src as (
    select case when a.type = 'equity' then case a.subtype when 'capital' then 'capital' when 'retained_earnings' then 'retained' when 'dividends' then 'distributions' when 'drawings' then 'distributions' else 'reserves' end else 'retained' end cls,
      l.date, a.type, (l.credit - l.debit) v, l.icl
    from (select l0.*, (j.type = 'CL' or exists (select 1 from acc.journals o where o.tenant_id = j.tenant_id and o.id = j.reversal_of and o.type = 'CL')) icl
          from acc.journal_lines l0 join acc.journals j on j.tenant_id = l0.tenant_id and j.id = l0.journal_id where l0.tenant_id = t and l0.posted and l0.entity_id = any(ents) and l0.date <= dt) l
      join acc.accounts a on a.tenant_id = t and a.id = l.account_id where a.type in ('equity', 'revenue', 'expense')),
  agg as (select cls, coalesce(sum(v) filter (where date < df), 0) op, coalesce(sum(v) filter (where date between df and dt and type in ('revenue', 'expense') and not icl), 0) pr,
      coalesce(sum(v) filter (where date between df and dt and type = 'equity' and not icl), 0) di, coalesce(sum(v) filter (where date between df and dt and icl), 0) cl, coalesce(sum(v), 0) cs from src group by cls)
  select coalesce(jsonb_agg(jsonb_build_object('key', c.k, 'label', c.lbl, 'opening', coalesce(a.op, 0), 'profit', coalesce(a.pr, 0), 'movements', coalesce(a.di, 0), 'closing_transfers', coalesce(a.cl, 0), 'closing', coalesce(a.cs, 0)) order by c.ord), '[]') into out
  from unnest(array['capital', 'reserves', 'retained', 'distributions'], array['رأس المال', 'الاحتياطيات', 'الأرباح المبقاة', 'التوزيعات والمسحوبات'], array[1, 2, 3, 4]) c(k, lbl, ord) left join agg a on a.cls = c.k;
  select jsonb_build_object('opening', coalesce(sum((r->>'opening')::numeric), 0), 'profit', coalesce(sum((r->>'profit')::numeric), 0), 'movements', coalesce(sum((r->>'movements')::numeric), 0),
    'closing_transfers', coalesce(sum((r->>'closing_transfers')::numeric), 0), 'closing', coalesce(sum((r->>'closing')::numeric), 0)) into tot from jsonb_array_elements(out) r;
  bs := public.rpt_balance_sheet(jsonb_build_object('asof', dt, 'entities', to_jsonb(ents)));
  return jsonb_build_object('from', df, 'to', dt, 'rows', out, 'total', tot, 'balance_sheet_equity', (bs->>'equity')::numeric,
    'reconciled', abs((tot->>'closing')::numeric - (bs->>'equity')::numeric) < 0.01 and abs((tot->>'opening')::numeric + (tot->>'profit')::numeric + (tot->>'movements')::numeric + (tot->>'closing_transfers')::numeric - (tot->>'closing')::numeric) < 0.01);
end $$;

-- مُحكَم للحسابات — الإصدار 1.8.0.0: المراجعة الشاملة، الخسائر الائتمانية IFRS 9، ملف التدقيق SAF-T، قائمة حقوق الملكية IAS 1
insert into app.schema_migrations (version, name) values ('1.7.4.0', 'الوثائق المنشورة وقبول المالك والإصدارات'), ('1.8.0.0', 'المراجعة الشاملة والمعايير الدولية: ECL وSAF-T وقائمة حقوق الملكية')
on conflict (version) do nothing;


-- صلاحيات الدوال الجديدة: للمستخدمين المسجّلين فقط (مثل بقية الدوال)
revoke execute on function public.system_review(jsonb), public.ecl_preview(jsonb), public.ecl_post(jsonb), public.ecl_settings_save(jsonb), public.audit_file(jsonb), public.rpt_equity_changes(jsonb) from public, anon;
grant execute on function public.system_review(jsonb), public.ecl_preview(jsonb), public.ecl_post(jsonb), public.ecl_settings_save(jsonb), public.audit_file(jsonb), public.rpt_equity_changes(jsonb) to authenticated;

insert into app.schema_migrations (version, name) values ('1.8.0.1', 'واجهة فقط: إصلاح عرض شرائح الخسائر الائتمانية')
on conflict (version) do nothing;
