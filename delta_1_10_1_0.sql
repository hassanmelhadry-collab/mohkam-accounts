-- 1.10.0.0 → 1.10.1.0 delta (إضافي ومتكرر التشغيل): تحسين أداء قائمة التدفقات النقدية. يُتبع بـ analyze مرة واحدة.
-- مُحكَم للحسابات 1.10.1.0 — أداء: تقرير التدفقات النقدية كان تربيعي التكلفة (46 ثانية عند 4200 سطر قيد).
-- السبب: ضمّ الحسابات بالأسطر داخل حلقات متداخلة تُعيد تقييم مجموعة قيود النقد مئات المرات.
-- الحل: تحديد حسابات النقد مرة واحدة كمصفوفة، ثم قيودها كمصفوفة، ثم تجميع أسطر هذه القيود فقط. النتائج مطابقة تمامًا.
create or replace function public.rpt_cashflow(p jsonb default '{}') returns jsonb language plpgsql stable security definer set search_path = public, app, acc as $$
declare t uuid := app.need('reports','view'); ents uuid[] := app.pick_ents(p); df date := (p->>'from')::date; dt date := (p->>'to')::date; op numeric; cl numeric; rows jsonb; cash uuid[]; jids uuid[];
begin
  if df is null or dt is null then raise exception 'حدّد الفترة'; end if;
  select coalesce(array_agg(id), '{}') into cash from acc.accounts where tenant_id = t and subtype in ('cash','bank');
  select coalesce(sum(l.debit - l.credit) filter (where l.date < df), 0), coalesce(sum(l.debit - l.credit), 0) into op, cl
    from acc.journal_lines l where l.tenant_id = t and l.posted and l.entity_id = any(ents) and l.date <= dt and l.account_id = any(cash);
  select coalesce(array_agg(distinct l.journal_id), '{}') into jids
    from acc.journal_lines l where l.tenant_id = t and l.posted and l.entity_id = any(ents) and l.date between df and dt and l.account_id = any(cash);
  select coalesce(jsonb_agg(jsonb_build_object('section', s.section, 'account_id', s.account_id, 'code', s.code, 'name', s.name, 'amount', s.amt) order by s.section, s.code), '[]') into rows
  from (select case when a.cf_class in ('investing','financing') then a.cf_class else 'operating' end section, a.id account_id, a.code, a.name, -sum(l.debit - l.credit) amt
    from acc.journal_lines l join acc.accounts a on a.tenant_id = l.tenant_id and a.id = l.account_id
    where l.tenant_id = t and l.journal_id = any(jids) and l.posted and l.entity_id = any(ents) and l.date between df and dt and l.account_id <> all(cash)
    group by 1, 2, 3, 4 having sum(l.debit - l.credit) <> 0) s;
  return jsonb_build_object('opening_cash', op, 'closing_cash', cl, 'rows', rows, 'net_change', cl - op,
    'operating', (select coalesce(sum((r->>'amount')::numeric), 0) from jsonb_array_elements(rows) r where r->>'section' = 'operating'),
    'investing', (select coalesce(sum((r->>'amount')::numeric), 0) from jsonb_array_elements(rows) r where r->>'section' = 'investing'),
    'financing', (select coalesce(sum((r->>'amount')::numeric), 0) from jsonb_array_elements(rows) r where r->>'section' = 'financing'));
end $$;
insert into app.schema_migrations (version, name) values ('1.10.1.0', 'أداء: إعادة كتابة تقرير التدفقات النقدية (من تربيعي إلى خطي)')
on conflict (version) do nothing;
grant execute on function public.rpt_cashflow(jsonb) to authenticated;
revoke execute on function public.rpt_cashflow(jsonb) from anon, public;
