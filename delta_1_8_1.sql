-- مُحكَم للحسابات — تحديث 1.8.1.0 (073): حزمة أدلة المراجع بالمستندات الأصلية
-- مُحكَم للحسابات — فهرس المستندات الداعمة لحزمة المراجع/المفتش (الزكاة والضريبة والمراجع الخارجي)
-- يعيد كل مرفق مرتبط بقيد/فاتورة/سند تاريخه ضمن الفترة وللشركات المختارة، مع بصمة الملف المسجّلة وقت الرفع،
-- ليُنزَّل الملف الأصلي ويُتحقق من بصمته داخل الحزمة. للقراءة فقط.
create or replace function public.audit_evidence(p jsonb default '{}') returns jsonb language plpgsql stable security definer set search_path = public, app, acc as $$
declare t uuid := app.need('attachments', 'view'); ents uuid[] := app.pick_ents(p); d_from date := coalesce(nullif(p->>'from', '')::date, date_trunc('year', current_date)::date); d_to date := coalesce(nullif(p->>'to', '')::date, current_date);
  lim int := least(greatest(coalesce(nullif(p->>'limit', '')::int, 500), 1), 1000); off int := greatest(coalesce(nullif(p->>'offset', '')::int, 0), 0); res jsonb;
begin
  if not (app.can('reports', 'view') or app.can('tax', 'view') or app.sys('audit')) then raise exception 'ليست لديك صلاحية'; end if;
  if d_to < d_from then raise exception 'نهاية الفترة قبل بدايتها'; end if;
  with ev as (
    select a.id, a.path, a.filename, a.mime, a.size, a.sha256, a.uploaded_at, a.owner_type, e.code ent, d.num, d.dt, d.amt, d.lbl
    from acc.attachments a
    join lateral (
      select j.entity_id eid, j.number num, j.date dt, j.total amt, 'قيد' lbl from acc.journals j where a.owner_type = 'journal' and j.tenant_id = t and j.id = a.owner_id and j.status in ('posted', 'reversed')
      union all select i.entity_id, i.number, i.date, i.total, case i.kind when 'sales' then 'فاتورة مبيعات' when 'purchase' then 'فاتورة مشتريات' when 'sales_credit' then 'إشعار دائن' else 'إشعار مدين' end from acc.invoices i where a.owner_type = 'invoice' and i.tenant_id = t and i.id = a.owner_id and i.status <> 'draft'
      union all select y.entity_id, y.number, y.date, y.amount, case y.kind when 'receipt' then 'سند قبض' else 'سند صرف' end from acc.payments y where a.owner_type = 'payment' and y.tenant_id = t and y.id = a.owner_id and y.status <> 'draft'
    ) d on true
    join acc.entities e on e.tenant_id = t and e.id = d.eid
    where a.tenant_id = t and d.eid = any(ents) and d.dt between d_from and d_to),
  pg as (select *, count(*) over () total from ev order by dt, num, filename offset off limit lim)
  select jsonb_build_object('from', d_from, 'to', d_to, 'offset', off, 'limit', lim, 'total', coalesce(max(total), 0), 'has_more', coalesce(max(total), 0) > off + lim,
    'rows', coalesce(jsonb_agg(jsonb_build_object('id', id, 'path', path, 'filename', filename, 'mime', mime, 'size', size, 'sha256', sha256, 'uploaded_at', uploaded_at, 'type', owner_type, 'doc_label', lbl,
      'doc_number', num, 'doc_date', dt, 'doc_amount', amt, 'entity', ent) order by dt, num, filename), '[]')) into res from pg;
  if off = 0 then perform app.audit('export', 'audit_evidence', 'evidence', 'فهرس المستندات الداعمة ' || d_from || ' → ' || d_to); end if;
  return res;
end $$;
revoke execute on function public.audit_evidence(jsonb) from public, anon;
grant execute on function public.audit_evidence(jsonb) to authenticated;

insert into app.schema_migrations (version, name) values ('1.8.1.0', 'حزمة أدلة المراجع: المستندات الأصلية مع التحقق من البصمات')
on conflict (version) do nothing;
