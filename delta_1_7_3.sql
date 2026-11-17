-- مُحكَم للحسابات 1.7.3.0: منشئ التقارير (report_custom)
-- مُحكَم 1.7.3 — منشئ التقارير: مجموعات حسابات يحددها المستخدم (برموز أو بادئات رموز) تُجمَّع على فترة،
-- إجماليًا أو شهريًا، وبتفصيل اختياري بالشركة. للشركات المسموحة للمستخدم فقط. بلا جداول جديدة.
create or replace function public.report_custom(p jsonb) returns jsonb language plpgsql stable security definer set search_path = public, app, acc as $$
declare t uuid := app.need('reports','view'); ents uuid[] := app.pick_ents(p);
  dt date := coalesce(nullif(p->>'to','')::date, current_date); df date := coalesce(nullif(p->>'from','')::date, date_trunc('year', dt)::date);
  per text := coalesce(nullif(p->>'period',''), 'total'); byent boolean := coalesce((p->>'by_entity')::boolean, false);
  g jsonb; out jsonb := '[]'::jsonb; pats text[]; rows jsonb; n int := 0; sg int; incl_cl boolean := coalesce((p->>'include_closing')::boolean, false);
begin
  if per not in ('total','month') then raise exception 'نوع الفترة غير صحيح'; end if;
  if dt < df then raise exception 'تاريخ النهاية قبل البداية'; end if;
  if per = 'month' and dt - df > 800 then raise exception 'الفترة الشهرية لا تتجاوز 26 شهرًا'; end if;
  if jsonb_typeof(p->'groups') is distinct from 'array' or jsonb_array_length(p->'groups') = 0 then raise exception 'أضف مجموعة واحدة على الأقل'; end if;
  if jsonb_array_length(p->'groups') > 20 then raise exception 'الحد الأقصى 20 مجموعة'; end if;
  for g in select * from jsonb_array_elements(p->'groups') loop
    n := n + 1;
    pats := array(select regexp_replace(x, '[^0-9A-Za-z._-]', '', 'g') || '%' from jsonb_array_elements_text(coalesce(g->'prefixes', '[]'::jsonb)) x where length(trim(x)) > 0);
    if coalesce(array_length(pats, 1), 0) = 0 then raise exception 'المجموعة % بلا رموز حسابات', n; end if;
    sg := case when g->>'sign' = 'cr' then -1 else 1 end;
    select coalesce(jsonb_agg(jsonb_build_object('period', k, 'entity_id', e, 'entity', en, 'amount', amt) order by k, en), '[]'::jsonb) into rows from (
      select case when per = 'month' then to_char(l.date, 'YYYY-MM') else 'total' end k,
             case when byent then l.entity_id end e, case when byent then (select ee.name from acc.entities ee where ee.tenant_id = t and ee.id = l.entity_id) end en,
             round(sum(l.debit - l.credit) * sg, 2) amt
      from acc.journal_lines l join acc.accounts a on a.tenant_id = l.tenant_id and a.id = l.account_id join acc.journals j on j.tenant_id = l.tenant_id and j.id = l.journal_id
      where l.tenant_id = t and l.posted and l.entity_id = any(ents) and l.date between df and dt and a.code like any (pats)
        and (incl_cl or not (j.type = 'CL' or exists (select 1 from acc.journals o where o.tenant_id = j.tenant_id and o.id = j.reversal_of and o.type = 'CL')))
      group by 1, 2, 3) z;
    out := out || jsonb_build_array(jsonb_build_object('name', coalesce(nullif(g->>'name',''), 'مجموعة ' || n), 'sign', case when sg = -1 then 'cr' else 'dr' end, 'rows', rows,
      'total', (select coalesce(sum((r->>'amount')::numeric), 0) from jsonb_array_elements(rows) r)));
  end loop;
  return jsonb_build_object('from', df, 'to', dt, 'period', per, 'by_entity', byent, 'groups', out);
end $$;
