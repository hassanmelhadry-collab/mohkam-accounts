// سيناريو «مجموعة شركات كبيرة»: يعمل على أي واجهة rpc (PGlite في الاختبار، أو Supabase الحي من المتصفح)
// ctx: { rpc(fn,p), as(username), log(...), y (السنة), close (هل يُقفل السنة في النهاية) }
export async function scenario({ rpc, as, log, y, close = false, users }) {
  const D = (m, d) => `${y}-${String(m).padStart(2, '0')}-${String(d).padStart(2, '0')}`;
  const chk = (name, ok, extra = '') => { log(`${ok ? '✓' : '✗ FAIL'} ${name} ${extra}`); if (!ok) throw new Error('فحص فشل: ' + name + ' ' + extra); };
  const near = (a, b, e = 0.01) => Math.abs(Number(a) - Number(b)) <= e;
  const attach = async (kind, id, name) => { /* المرفق الفعلي يُرفع من الواجهة؛ هنا نسجّل بيانات وصفية فقط */ };

  // ===== 1) الإعداد (المالك) =====
  as('owner');
  const prof = await rpc('my_profile'); const e1 = prof.entities[0].id;
  await rpc('entity_upsert', { id: e1, code: prof.entities[0].code, name: 'مصنع الشرق للصناعة', vat_no: '300000000000003', cr: '1010000001', active: true });
  const e2 = (await rpc('entity_upsert', { code: 'TRD', name: 'الشرق للتجارة', vat_no: '300000000000013', cr: '1010000002' })).id;
  const e3 = (await rpc('entity_upsert', { code: 'SRV', name: 'الشرق للخدمات الهندسية', vat_no: '300000000000023', cr: '1010000003' })).id;
  const ents = [e1, e2, e3];
  for (const e of [e2, e3]) { await rpc('fy_create', { entity: e, start_date: D(1, 1) }).catch(() => {}); }
  const ATT_OFF = { journal: -1, purchase: -1, sales: -1, payment: -1, receipt: -1 }, ATT_ON = { journal: 10000, purchase: 0, sales: -1, payment: 10000, receipt: 10000 };
  await rpc('settings_set', { settings: { controls: { attach: ATT_OFF } } });
  await rpc('settings_set', { settings: { approval: { journals: { required: true, threshold: 0 }, invoices: { required: true, threshold: 100000 }, payments: { required: true, threshold: 50000 }, sod: true } } });
  await rpc('admin_create_users', { users: users.map(u => ({ ...u, must_change: false })) });
  const cc = {}; for (const [c, n] of [['PRD', 'الإنتاج'], ['SAL', 'المبيعات'], ['ADM', 'الإدارة']]) cc[c] = (await rpc('dim_upsert', { kind: 'cc', code: c, name: n })).id;
  const pj = (await rpc('dim_upsert', { kind: 'project', code: 'P-101', name: 'مشروع مجمع الواحة' })).id;
  await rpc('notice_upsert', { title: 'إقفال أكتوبر', body: 'آخر موعد لتسليم المستندات 5 نوفمبر', level: 'important', pinned: true });
  const coa = await rpc('coa_list', {}); const A = (f) => coa.find(a => !a.is_group && f(a));
  const cash = A(a => a.subtype === 'cash'), bank = A(a => a.subtype === 'bank'), sales = A(a => a.system_key === 'SALES'), purch = A(a => a.system_key === 'PURCHASES');
  const equity = A(a => a.type === 'equity'), rent = A(a => a.type === 'expense' && /إيجار/.test(a.name)) || purch, salary = A(a => a.type === 'expense' && /رواتب|أجور/.test(a.name)) || purch;
  const fixed = A(a => a.type === 'asset' && /معدات|آلات|أثاث|سيارات/.test(a.name)), accum = A(a => /مجمع/.test(a.name)), dep = A(a => a.system_key === 'DEP_EXP');
  const accrued = A(a => a.type === 'liability' && a.subtype !== 'payable' && !a.system_key); const ap = A(a => a.system_key === 'AP'), ar = A(a => a.system_key === 'AR');
  log('الحسابات:', [cash, bank, sales, purch, equity, rent, salary, fixed, accum, dep, accrued, ap, ar].map(a => a?.code).join(' '));
  chk('الحسابات الأساسية موجودة', [cash, bank, sales, purch, equity, fixed, accum, dep, ap, ar].every(Boolean));
  const taxes = await rpc('tax_list', {}); const tOut = taxes.find(t => t.kind === 'output' && Number(t.rate) > 0)?.code, tIn = taxes.find(t => t.kind === 'input' && Number(t.rate) > 0)?.code;
  chk('رموز الضريبة', !!tOut && !!tIn, `${tOut}/${tIn}`);

  // ===== 2) العملاء والموردون =====
  const customers = [], suppliers = [];
  for (const [i, n] of ['شركة الواحة للمقاولات', 'مؤسسة البناء الحديث', 'مجموعة النخيل', 'شركة الأفق للتطوير', 'مصنع الجزيرة', 'مؤسسة رواد التجارة'].entries()) customers.push((await rpc('party_upsert', { name: n, kind: 'customer', terms_days: 30, credit_limit: 500000, vat_no: '3100000000' + String(i).padStart(5, '0') + '3', city: 'الرياض' })).id);
  for (const [i, n] of ['حديد الخليج', 'ألمنيوم السعودية', 'قطع الغيار الصناعية', 'الشركة الوطنية للنقل', 'مؤسسة الطاقة'].entries()) suppliers.push((await rpc('party_upsert', { name: n, kind: 'supplier', terms_days: 45 })).id);

  // ===== مساعدات: قيد/فاتورة/سند بدورة الاعتماد =====
  const postJE = async (entity, date, desc, lines, type = 'GJ', reference = '') => {
    as('acct'); const r = await rpc('je_save', { entity, type, date, description: desc, reference, lines });
    const s = await rpc('je_submit', { id: r.id }); const st = s.status || (await rpc('je_get', { id: r.id })).status;
    as('gm'); if (st !== 'approved' && st !== 'posted') await rpc('je_approve', { id: r.id });
    if (st !== 'posted') { as('chief'); await rpc('je_post', { id: r.id }); } return r.id;
  };
  const sell = async (entity, party, date, items, { pay, payDate, via = bank } = {}) => {
    as('ar'); const inv = await rpc('inv_save', { kind: 'sales', entity, party, date, lines: items.map(([d, q, p, c]) => ({ description: d, qty: q, unit_price: p, tax_code: tOut, cost_center: c })) });
    const s = await rpc('inv_submit', { id: inv.id }).catch(() => null);
    let g = await rpc('inv_get', { id: inv.id });
    if (g.status === 'pending') { as('gm'); await rpc('inv_approve', { id: inv.id }); }
    as('chief'); if ((await rpc('inv_get', { id: inv.id })).status !== 'issued') await rpc('inv_issue', { id: inv.id });
    g = await rpc('inv_get', { id: inv.id });
    if (pay) await receive(entity, party, payDate || date, pay === 'full' ? g.total : pay, [{ invoice: inv.id, amount: pay === 'full' ? g.total : pay }], via);
    return { id: inv.id, total: Number(g.total) };
  };
  const receive = async (entity, party, date, amount, allocations, via = bank) => {
    as('cashier'); const p = await rpc('pay_save', { kind: 'receipt', entity, party, date, amount, cash_account: via.code, allocations });
    const g0 = await rpc('pay_get', { id: p.id }); if (g0.status === 'draft') await rpc('pay_submit', { id: p.id }).catch(() => {});
    if ((await rpc('pay_get', { id: p.id })).status === 'pending') { as('gm'); await rpc('pay_approve', { id: p.id }); }
    as('chief'); await rpc('pay_post', { id: p.id }); return p.id;
  };
  const buy = async (entity, party, date, items, { pay, payDate, via = bank, ref } = {}) => {
    as('ap'); const inv = await rpc('inv_save', { kind: 'purchase', entity, party, date, supplier_ref: ref || 'SUP-' + date, lines: items.map(([d, q, p, c, acc]) => ({ description: d, qty: q, unit_price: p, tax_code: tIn, cost_center: c, account: (acc || purch).code })) });
    await rpc('inv_submit', { id: inv.id }).catch(() => null); let g = await rpc('inv_get', { id: inv.id });
    if (g.status === 'pending') { as('gm'); await rpc('inv_approve', { id: inv.id }); }
    as('chief'); if ((await rpc('inv_get', { id: inv.id })).status !== 'issued') await rpc('inv_issue', { id: inv.id });
    g = await rpc('inv_get', { id: inv.id });
    if (pay) { const amt = pay === 'full' ? g.total : pay; as('cashier'); const p = await rpc('pay_save', { kind: 'payment', entity, party, date: payDate || date, amount: amt, cash_account: via.code, allocations: [{ invoice: inv.id, amount: amt }] });
      await rpc('pay_submit', { id: p.id }).catch(() => {}); if ((await rpc('pay_get', { id: p.id })).status === 'pending') { as('gm'); await rpc('pay_approve', { id: p.id }); } as('chief'); await rpc('pay_post', { id: p.id }); }
    return { id: inv.id, total: Number(g.total) };
  };

  // ===== 3) الأرصدة الافتتاحية =====
  for (const e of ents) await postJE(e, D(1, 1), 'أرصدة افتتاحية', [{ account: cash.code, debit: 100000, credit: 0 }, { account: bank.code, debit: 1500000, credit: 0 }, { account: fixed.code, debit: 600000, credit: 0 }, { account: equity.code, debit: 0, credit: 2200000 }], 'OB');
  log('opening done');

  // ===== 4) مبيعات (3 كيانات × شهور) =====
  const sInv = [];
  for (let m = 1; m <= 10; m++) for (const [k, e] of ents.entries()) {
    const c = customers[(m + k) % customers.length]; const amt = 20000 + ((m * 7919 + k * 1301) % 90000);
    const full = (m + k) % 3 === 0 ? 'full' : (m + k) % 3 === 1 ? Math.round(amt * 0.575 / 2) : undefined;
    sInv.push(await sell(e, c, D(m, 5 + k), [['توريد وتركيب هياكل', 1, amt, cc.PRD], ['خدمة نقل', 1, 1500, cc.SAL]], { pay: full, payDate: D(m, 20) }));
  }
  // مبيعات كبيرة تحتاج اعتماد مدير + فاتورة مشروع
  const big = await sell(e1, customers[0], D(6, 12), [['عقد توريد مجمع الواحة', 1, 450000, cc.PRD]], { pay: 200000, payDate: D(7, 1) });
  log('sales invoices', sInv.length + 1);

  // ===== 5) مشتريات ومصروفات =====
  for (let m = 1; m <= 10; m++) for (const [k, e] of ents.entries()) {
    const s = suppliers[(m + k) % suppliers.length]; const amt = 8000 + ((m * 4231 + k * 977) % 40000);
    await buy(e, s, D(m, 8 + k), [['مواد خام', 1, amt, cc.PRD]], { pay: (m + k) % 2 === 0 ? 'full' : undefined, payDate: D(m, 25) });
  }
  const bigBuy = await buy(e1, suppliers[0], D(5, 3), [['حديد إنشائي 120 طن', 120, 3100, cc.PRD]], { pay: 100000, payDate: D(5, 20) });
  // قيود: إيجار ورواتب (كل شهر) وقيد استحقاق مع عكسه
  for (let m = 1; m <= 10; m++) { await postJE(e1, D(m, 28), 'رواتب ' + m, [{ account: salary.code, debit: 85000, credit: 0, cost_center: cc.ADM }, { account: bank.code, debit: 0, credit: 85000 }]);
    await postJE(e1, D(m, 28), 'إيجار ' + m, [{ account: rent.code, debit: 12000, credit: 0, cost_center: cc.ADM }, { account: bank.code, debit: 0, credit: 12000 }]); }
  const acc = await postJE(e1, D(9, 30), 'استحقاق كهرباء سبتمبر', [{ account: (A(a => a.type === 'expense' && /كهرباء|مرافق/.test(a.name)) || purch).code, debit: 6000, credit: 0 }, { account: (accrued || ap).code, debit: 0, credit: 6000 }], 'ADJ');
  as('chief'); const rv = await rpc('je_reverse', { id: acc, date: D(10, 1), reason: 'عكس الاستحقاق' }); log('reversal', rv.id ? 'ok' : JSON.stringify(rv));

  // ===== 6) إشعار دائن + إلغاء فاتورة =====
  as('ar'); const cn = await rpc('inv_save', { kind: 'sales_credit', entity: e1, party: customers[0], date: D(8, 10), related_id: big.id, lines: [{ description: 'مرتجع جزئي', qty: 1, unit_price: 10000, tax_code: tOut }] });
  await rpc('inv_submit', { id: cn.id }).catch(() => {}); if ((await rpc('inv_get', { id: cn.id })).status === 'pending') { as('gm'); await rpc('inv_approve', { id: cn.id }); }
  as('chief'); if ((await rpc('inv_get', { id: cn.id })).status !== 'issued') await rpc('inv_issue', { id: cn.id });
  await rpc('credit_apply', { credit_id: cn.id, invoice_id: big.id, amount: 11500 });
  const v1 = await sell(e2, customers[3], D(9, 2), [['فاتورة خاطئة', 1, 1000, cc.SAL]]); as('chief'); await rpc('inv_void', { id: v1.id, reason: 'إدخال خاطئ' });

  // ===== 7) بنك: كشف حساب + مطابقة =====
  as('cashier'); const bk = await rpc('bank_upsert', { entity: e1, name: 'البنك الأهلي — الحساب الجاري', account: bank.code });
  const glRows = (await rpc('rpt_ledger', { entity: e1, account: bank.code, from: D(1, 1), to: D(3, 31) })).rows.filter(r => r.date >= D(2, 1));
  const stmt = glRows.slice(0, 6).map(r => ({ date: r.date, amount: Number(r.debit) - Number(r.credit), description: 'حركة ' + r.number })); stmt.push({ date: D(3, 30), amount: -75, description: 'رسوم بنكية' });
  log('bank import', JSON.stringify(await rpc('bank_import', { bank: bk.id, rows: stmt }))); log('auto match', JSON.stringify(await rpc('bank_auto_match', { bank: bk.id })));
  const rec = await rpc('bank_recon_report', { bank: bk.id, asof: D(3, 31) }); log('recon diff', rec.difference);

  // ===== 8) أصول =====
  as('chief'); for (const [c, n, cost, life] of [['FA-01', 'خط إنتاج CNC', 480000, 120], ['FA-02', 'رافعة شوكية', 95000, 60], ['FA-03', 'سيارة نقل', 130000, 60]]) await rpc('asset_upsert', { entity: e1, code: c, name: n, acquisition_date: D(1, 1), cost, salvage: 0, life_months: life, asset_account: fixed.code, accum_account: accum.code, expense_account: dep.code, cost_center: cc.PRD });
  const dp = await rpc('asset_depreciate', { entity: e1, upto: D(10, 31) }); log('depreciation', dp.total);
  const fa3 = (await rpc('asset_list', { entity: e1 })).find(a => a.code === 'FA-03'); const ds = await rpc('asset_dispose', { id: fa3.id, date: D(11, 5), proceeds: 0 }).catch(e => 'dispose needs depreciation through Oct: ' + e.message); log('dispose', typeof ds === 'string' ? ds : 'ok');

  // ===== 9) موازنة =====
  as('chief'); const fy = (await rpc('fy_list', { entity: e1 })).find(f => String(f.start_date).startsWith(String(y)));
  const bg = await rpc('budget_save', { entity: e1, fy: fy.id, name: `موازنة ${y}`, lines: [{ account: sales.code, months: Array(12).fill(250000) }, { account: salary.code, months: Array(12).fill(85000) }, { account: rent.code, months: Array(12).fill(12000) }] });
  as('gm'); await rpc('budget_approve', { id: bg.id }); const bva = await rpc('budget_vs_actual', { id: bg.id, to_month: 10 }); log('budget rows', bva.rows.length);

  // ===== 10) بوابة الموظف =====
  as('owner'); const exp = (A(a => a.type === 'expense' && /سفر|انتقال|ضيافة|متنوع/.test(a.name)) || purch);
  const tTrv = await rpc('reqtype_upsert', { code: 'TRV', name: 'مطالبة سفر وانتقال', kind: 'expense', needs_attachment: true, default_account: exp.code, max_amount: 5000 });
  const tAdv = await rpc('reqtype_upsert', { code: 'ADV', name: 'سلفة موظف', kind: 'advance', default_account: (A(a => a.type === 'asset' && /سلف|موظف/.test(a.name)) || exp).code });
  const tLtr = await rpc('reqtype_upsert', { code: 'LTR', name: 'طلب خطاب تعريف', kind: 'letter', needs_amount: false });
  as('emp'); const tid = (await rpc('my_profile')).member.tenant_id;
  const r1 = await rpc('req_save', { entity: e1, type: tTrv.id, title: 'رحلة عمل الدمام', amount: 1850, date: D(10, 12) });
  const before = await err(rpc, 'req_submit', { id: r1.id }); chk('الإرسال بدون مرفق مرفوض', !!before);
  await rpc('req_attach', { id: r1.id, path: `${tid}/requests/receipt-1.pdf`, filename: 'فواتير الرحلة.pdf', size: 20000 }); await rpc('req_submit', { id: r1.id });
  const r2 = await rpc('req_save', { entity: e1, type: tLtr.id, title: 'خطاب تعريف للسفارة' }); await rpc('req_submit', { id: r2.id });
  const over = await err(rpc, 'req_save', { entity: e1, type: tTrv.id, title: 'مبلغ فوق الحد', amount: 9000 }); chk('تجاوز الحد الأقصى للطلب مرفوض', !!over);
  as('chief'); await rpc('req_decide', { id: r1.id, decision: 'approve', account: exp.code, date: D(10, 20) });
  as('cashier'); await rpc('req_pay', { id: r1.id, cash_account: cash.code, date: D(10, 25) });
  as('chief'); await rpc('req_decide', { id: r2.id, decision: 'approve' }).catch(e => log('letter approve:', e.message));
  as('emp'); const my = await rpc('req_my', {}); log('employee summary', JSON.stringify(my.summary));

  // ===== اختبار المرفقات المطلوبة (تُفعَّل الآن) =====
  as('owner'); await rpc('settings_set', { settings: { controls: { attach: ATT_ON } } });
  as('ap'); const noAtt = await rpc('inv_save', { kind: 'purchase', entity: e1, party: suppliers[1], date: D(11, 2), supplier_ref: 'X-1', lines: [{ description: 'مواد', qty: 1, unit_price: 5000, tax_code: tIn, account: purch.code }] });
  chk('فاتورة مورد بلا مرفق مرفوضة عند الإرسال', !!(await err(rpc, 'inv_submit', { id: noAtt.id })));
  const tid2 = (await rpc('my_profile')).member.tenant_id; await rpc('att_register', { owner_type: 'invoice', owner_id: noAtt.id, path: `${tid2}/invoice/${noAtt.id}-فاتورة-المورد.pdf`, filename: 'فاتورة المورد.pdf', mime: 'application/pdf', size: 1000 });
  chk('تُقبل بعد الإرفاق', !!(await rpc('inv_submit', { id: noAtt.id })).status);
  as('acct'); const je0 = await rpc('je_save', { entity: e1, type: 'GJ', date: D(11, 3), description: 'قيد كبير', lines: [{ account: rent.code, debit: 25000, credit: 0 }, { account: bank.code, debit: 0, credit: 25000 }] });
  chk('قيد يدوي كبير بلا مرفق مرفوض', !!(await err(rpc, 'je_submit', { id: je0.id })));
  const je1 = await rpc('je_save', { entity: e1, type: 'GJ', date: D(11, 3), description: 'قيد صغير', lines: [{ account: rent.code, debit: 900, credit: 0 }, { account: bank.code, debit: 0, credit: 900 }] }); chk('قيد صغير يمر بلا مرفق', !!(await rpc('je_submit', { id: je1.id })).status);
  // ===== 11) فحوصات التطابق =====
  as('gm'); const to = D(12, 31);
  const tb = await rpc('rpt_trial_balance', { from: D(1, 1), to }); chk('ميزان المراجعة متزن', near(tb.totals.debit, tb.totals.credit), `${tb.totals.debit}/${tb.totals.credit}`);
  const inc = await rpc('rpt_income', { from: D(1, 1), to }); const bs = await rpc('rpt_balance_sheet', { asof: to });
  chk('المركز المالي متزن', near(bs.assets, Number(bs.liabilities) + Number(bs.equity)), `${bs.assets} = ${bs.liabilities} + ${bs.equity}`);
  chk('صافي الدخل = الأرباح غير المقفلة', near(Number(inc.revenue) - Number(inc.expense), bs.unclosed_income), `${Number(inc.revenue) - Number(inc.expense)} vs ${bs.unclosed_income}`);
  for (const k of ['ar', 'ap']) { const ag = await rpc('rpt_aging', { kind: k, asof: to }); const tot = ag.rows.reduce((s, r) => s + Number(r.total), 0);
    const bal = Number((await rpc('rpt_trial_balance', { to })).rows.find(r => r.code === (k === 'ar' ? ar : ap).code)?.closing || 0);
    chk(`أعمار ${k === 'ar' ? 'العملاء' : 'الموردين'} = رصيد الأستاذ`, near(Math.abs(tot), Math.abs(bal)), `${tot} / ${bal}`); }
  const cf = await rpc('rpt_cashflow', { from: D(1, 1), to }); chk('التدفقات: صافي التغير = تشغيلي+استثماري+تمويلي', near(cf.net_change, Number(cf.operating) + Number(cf.investing) + Number(cf.financing)));
  chk('التدفقات تغلق على النقدية', near(Number(cf.opening_cash) + Number(cf.net_change), cf.closing_cash));
  const vat = await rpc('rpt_vat', { from: D(1, 1), to }); log('VAT out/in', vat.output_tax, vat.input_tax);
  as('auditor'); const ctl = await rpc('controls_report', {}); log('controls', ctl.items.filter(i => Number(i.count) > 0).map(i => `${i.code}:${i.count}`).join(' '));
  chk('الأستاذ العام متزن (ضابط)', ctl.items.find(i => i.code === 'tb_balanced').count == 0);
  // ===== أدوات المراجع/المفتش =====
  as('auditor'); const trs = await rpc('tax_register', { side: 'sales', from: D(1, 1), to, limit: 5000 }); const trp = await rpc('tax_register', { side: 'purchase', from: D(1, 1), to, limit: 5000 });
  const sumT = r => r.rows.filter(x => x.status !== 'void').reduce((a, x) => a + Number(x.tax) * (String(x.kind).endsWith('credit') || String(x.kind).endsWith('debit') ? -1 : 1), 0);
  chk('سجل الفواتير الضريبي يعيد صفوفًا', trs.rows.length > 0 && trp.rows.length > 0, `${trs.rows.length} مبيعات / ${trp.rows.length} مشتريات`);
  chk('ضريبة سجل المبيعات = ضريبة المخرجات في الإقرار', near(sumT(trs), Number(vat.output_tax)), `${sumT(trs)} vs ${vat.output_tax}`);
  chk('ضريبة سجل المشتريات = ضريبة المدخلات في الإقرار', near(sumT(trp), Number(vat.input_tax)), `${sumT(trp)} vs ${vat.input_tax}`);
  const gp = await rpc('seq_gaps', {}); chk('لا فجوات في تسلسل الترقيم', gp.every(g => !(g.missing || []).length), JSON.stringify(gp.filter(g => (g.missing || []).length)).slice(0, 200));
  const hc = await rpc('health_check', {}); log('health', hc.map(h => h.key + ':' + (h.ok ? 'ok' : 'FAIL')).join(' ')); chk('مؤشرات سلامة الدفاتر كلها سليمة', hc.every(h => h.ok), hc.filter(h => !h.ok).map(h => h.key + ' ' + h.detail).join('; '));
  const one = trs.rows.find(r => r.number); const gf = await rpc('global_find', { q: one.number }); chk('البحث الشامل يجد الفاتورة برقمها', gf.some(x => x.type === 'invoice' && x.id === one.id), one.number);
  as('owner');
  as('owner'); const cv = await rpc('chain_verify', {}); chk('سلسلة التدقيق والقيود سليمة', cv.ok, `${cv.audit_rows} audit / ${cv.journals} journals`);
  const dash = await rpc('dashboard', {}); log('dashboard keys', Object.keys(dash).join(','));
  // الإقفال
  if (close) { for (const e of ents) { const f = (await rpc('fy_list', { entity: e })).find(x => String(x.start_date).startsWith(String(y))); const pend = Number(f.drafts); if (pend) log('drafts in fy', pend); await rpc('fy_close', { id: f.id });
      } const bs2 = await rpc('rpt_balance_sheet', { asof: to }); chk('بعد الإقفال: لا أرباح غير مقفلة', near(bs2.unclosed_income, 0)); chk('بعد الإقفال: المركز متزن', near(bs2.assets, Number(bs2.liabilities) + Number(bs2.equity)));
    const nxt = await rpc('rpt_balance_sheet', { asof: `${y + 1}-01-01` }); chk('الأرصدة تنتقل للسنة الجديدة', near(nxt.assets, bs2.assets)); }
  return { ents, customers, suppliers };
}
async function err(rpc, fn, p) { try { await rpc(fn, p); return null; } catch (e) { return e.message; } }
