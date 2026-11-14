-- تحديث 1.5 (إعادة تقييم العملة للإشعارات + تجهيز ZATCA المرحلة الثانية). آمن للتكرار. تجهيز فقط بلا ربط فعلي.
-- مُحكَم للحسابات — إعادة تقييم العملة تشمل الإشعارات الدائنة والمدينة (بالعملة الأجنبية)
-- الإشعار الدائن يخفّض رصيد العملاء، والمدين يخفّض رصيد الموردين؛ فأثر فرق التقييم عليهما عكسي (إشارة −).
-- كما تُنشأ أسطر الذمم في قيد التقييم لكل طرف على حدة (الحسابات الذمّية تشترط تحديد الطرف).
create or replace function public.fx_reval(p jsonb) returns jsonb language plpgsql security definer set search_path = public, app, acc as $$
declare t uuid := app.need('reports','view'); ents uuid[] := app.pick_ents(p); asof date := coalesce(nullif(p->>'asof','')::date, current_date); rows jsonb := '[]'::jsonb; i record; nr numeric; paid numeric; bb numeric; fcb numeric; d numeric; sg int;
  tot_ar numeric := 0; tot_ap numeric := 0; j jsonb; ar uuid; ap uuid; gl uuid := nullif(p->>'gain_loss_account','')::uuid; lines jsonb := '[]'::jsonb; e uuid; pr record; net numeric;
begin
  for i in select * from acc.invoices where tenant_id = t and entity_id = any(ents) and status = 'issued' and rate <> 1 and kind in ('sales','purchase','sales_credit','purchase_debit') order by date, created_at loop
    select rate into nr from acc.fx_rates where tenant_id = t and currency = i.currency and date <= asof order by date desc limit 1; if nr is null then continue; end if;
    paid := app.inv_paid(t, i.id); bb := i.total_base - paid; if bb <= 0.005 then continue; end if; fcb := bb / i.rate;
    sg := case when i.kind in ('sales_credit','purchase_debit') then -1 else 1 end;   -- الإشعارات تخفّض رصيد الطرف
    d := round(sg * (fcb * nr - bb), 2);
    if abs(d) < 0.01 then continue; end if;
    rows := rows || jsonb_build_object('invoice', i.number, 'id', i.id, 'kind', i.kind, 'party_id', i.party_id, 'currency', i.currency, 'old_rate', i.rate, 'new_rate', nr, 'balance_fc', round(fcb,2), 'balance_base', round(bb,2), 'diff', d);
    if i.kind in ('sales','sales_credit') then tot_ar := tot_ar + d; else tot_ap := tot_ap + d; end if; e := i.entity_id;
  end loop;
  if coalesce((p->>'post')::boolean, false) and jsonb_array_length(rows) > 0 then
    if gl is null then raise exception 'حدّد حساب أرباح/خسائر فروق العملة (gain_loss_account)'; end if;
    ar := app.sysacct(t, 'AR'); ap := app.sysacct(t, 'AP');
    -- ذمم العملاء: مدين عند الزيادة. ذمم الموردين: دائن عند الزيادة (أي مدين عند النقص)
    for pr in select x->>'party_id' pid, (x->>'kind') in ('sales','sales_credit') is_ar, sum((x->>'diff')::numeric) d from jsonb_array_elements(rows) x group by 1, 2 having abs(sum((x->>'diff')::numeric)) >= 0.01 loop
      if pr.is_ar then lines := lines || jsonb_build_object('account', ar, 'party', pr.pid, 'debit', greatest(pr.d,0), 'credit', greatest(-pr.d,0), 'description', 'تقييم عملات - عملاء');
      else lines := lines || jsonb_build_object('account', ap, 'party', pr.pid, 'debit', greatest(-pr.d,0), 'credit', greatest(pr.d,0), 'description', 'تقييم عملات - موردون'); end if;
    end loop;
    net := tot_ar - tot_ap;   -- موجب = ربح فروق عملة (دائن)
    if abs(net) >= 0.01 then lines := lines || jsonb_build_object('account', gl, 'debit', greatest(-net,0), 'credit', greatest(net,0), 'description', 'فروق تقييم العملات'); end if;
    j := public.je_save(jsonb_build_object('entity', coalesce(nullif(p->>'entity','')::uuid, e), 'type', 'ADJ', 'date', asof, 'memo', 'تقييم أرصدة العملات الأجنبية بتاريخ ' || asof, 'lines', lines));
  end if;
  return jsonb_build_object('rows', rows, 'ar_diff', tot_ar, 'ap_diff', tot_ap, 'journal', j->>'id');
end $$;

-- مُحكَم للحسابات — فاتورة ZATCA المرحلة الثانية: تجهيز فقط (بلا ربط فعلي بمنصة فاتورة)
-- لكل فاتورة مبيعات/إشعار دائن صادر: UUID، عدّاد التسلسل ICV لكل كيان، سلسلة التجزئة PIH، ومستند UBL 2.1 XML جاهز.
-- ما لم يُنفَّذ (يلزم عند الربط): توقيع XAdES بشهادة CSID، الختم التشفيري، رمز QR المرحلة الثانية، التطبيع C14N 1.1، الإبلاغ/التصريح عبر API.
-- التجزئة هنا = SHA-256 (Base64) لنص الـXML المُولَّد؛ تُستبدل عند الربط بتجزئة الصيغة المُطبَّعة المطلوبة.
create table if not exists acc.zatca_docs (
  tenant_id uuid not null references acc.tenants(id) on delete cascade, invoice_id uuid not null, entity_id uuid not null, uuid uuid not null default gen_random_uuid(),
  icv bigint not null, pih text not null, hash text not null, doc_kind text not null check (doc_kind in ('invoice','credit')), subtype text not null check (subtype in ('standard','simplified')), xml text not null,
  status text not null default 'prepared' check (status in ('prepared','reported','cleared','rejected')), created_by uuid, created_at timestamptz not null default now(),
  primary key (tenant_id, invoice_id), unique (tenant_id, entity_id, icv), foreign key (tenant_id, invoice_id) references acc.invoices (tenant_id, id)
);
alter table acc.zatca_docs enable row level security;

-- تجزئة بداية السلسلة المحدّدة في مواصفات الهيئة: Base64(SHA-256hex("0"))
create or replace function app.zatca_seed() returns text language sql immutable as $$ select 'NWZlY2ViNjZmZmM4NmYzOGQ5NTI3ODZjNmQ2OTZjNzljMmRiYzIzOWRkNGU5MWI0NjcyOWQ3M2EyN2ZiNTdlOQ==' $$;
create or replace function app.xml_esc(s text) returns text language sql immutable as $$
  select replace(replace(replace(replace(replace(coalesce(s,''), '&', '&amp;'), '<', '&lt;'), '>', '&gt;'), '"', '&quot;'), '''', '&apos;') $$;
create or replace function app.xml_amt(n numeric) returns text language sql immutable as $$ select to_char(round(coalesce(n,0), 2), 'FM9999999999990.00') $$;
create or replace function app.sha256_b64(s text) returns text language sql immutable as $$ select encode(decode(encode(sha256(convert_to(s, 'UTF8')), 'hex'), 'hex'), 'base64') $$;

-- بناء XML لفاتورة صادرة (داخلي)
create or replace function app.zatca_build(t uuid, inv acc.invoices, u uuid, icv bigint, pih text, subtype text) returns text language plpgsql stable security definer set search_path = public, app, acc as $$
declare en acc.entities; pa acc.parties; credit boolean := inv.kind = 'sales_credit'; cur text := inv.currency; x text; l record; n int := 0; cat text; rate numeric; rel text; ts timestamptz := coalesce(inv.issued_at, now());
  tx_tot numeric := 0; net_tot numeric := 0; sub record; basecur text;
begin
  select * into en from acc.entities where tenant_id = t and id = inv.entity_id; select * into pa from acc.parties where tenant_id = t and id = inv.party_id;
  select currency into basecur from acc.tenants where id = t;
  if credit and inv.related_id is not null then select number into rel from acc.invoices where tenant_id = t and id = inv.related_id; end if;
  x := '<?xml version="1.0" encoding="UTF-8"?>' || E'\n' || '<Invoice xmlns="urn:oasis:names:specification:ubl:schema:xsd:Invoice-2" xmlns:cac="urn:oasis:names:specification:ubl:schema:xsd:CommonAggregateComponents-2" xmlns:cbc="urn:oasis:names:specification:ubl:schema:xsd:CommonBasicComponents-2" xmlns:ext="urn:oasis:names:specification:ubl:schema:xsd:CommonExtensionComponents-2">' || E'\n'
    || '<cbc:ProfileID>reporting:1.0</cbc:ProfileID>' || E'\n'
    || '<cbc:ID>' || app.xml_esc(inv.number) || '</cbc:ID>' || E'\n'
    || '<cbc:UUID>' || u::text || '</cbc:UUID>' || E'\n'
    || '<cbc:IssueDate>' || to_char(ts at time zone 'Asia/Riyadh', 'YYYY-MM-DD') || '</cbc:IssueDate>' || E'\n'
    || '<cbc:IssueTime>' || to_char(ts at time zone 'Asia/Riyadh', 'HH24:MI:SS') || '</cbc:IssueTime>' || E'\n'
    || '<cbc:InvoiceTypeCode name="' || case subtype when 'standard' then '01' else '02' end || '00000">' || case when credit then '381' else '388' end || '</cbc:InvoiceTypeCode>' || E'\n'
    || '<cbc:DocumentCurrencyCode>' || app.xml_esc(cur) || '</cbc:DocumentCurrencyCode>' || E'\n'
    || '<cbc:TaxCurrencyCode>' || app.xml_esc(basecur) || '</cbc:TaxCurrencyCode>' || E'\n';
  if credit then x := x || '<cac:BillingReference><cac:InvoiceDocumentReference><cbc:ID>' || app.xml_esc(coalesce(rel, '')) || '</cbc:ID></cac:InvoiceDocumentReference></cac:BillingReference>' || E'\n'; end if;
  x := x || '<cac:AdditionalDocumentReference><cbc:ID>ICV</cbc:ID><cbc:UUID>' || icv || '</cbc:UUID></cac:AdditionalDocumentReference>' || E'\n'
    || '<cac:AdditionalDocumentReference><cbc:ID>PIH</cbc:ID><cac:Attachment><cbc:EmbeddedDocumentBinaryObject mimeCode="text/plain">' || pih || '</cbc:EmbeddedDocumentBinaryObject></cac:Attachment></cac:AdditionalDocumentReference>' || E'\n'
    || '<!-- QR المرحلة الثانية والتوقيع الرقمي (XAdES) والختم التشفيري: تُضاف عند الربط الفعلي بشهادة CSID -->' || E'\n'
    || '<cac:AccountingSupplierParty><cac:Party><cac:PartyIdentification><cbc:ID schemeID="CRN">' || app.xml_esc(en.cr) || '</cbc:ID></cac:PartyIdentification>'
    || '<cac:PostalAddress><cbc:StreetName>' || app.xml_esc(en.address) || '</cbc:StreetName><cac:Country><cbc:IdentificationCode>SA</cbc:IdentificationCode></cac:Country></cac:PostalAddress>'
    || '<cac:PartyTaxScheme><cbc:CompanyID>' || app.xml_esc(en.vat_no) || '</cbc:CompanyID><cac:TaxScheme><cbc:ID>VAT</cbc:ID></cac:TaxScheme></cac:PartyTaxScheme>'
    || '<cac:PartyLegalEntity><cbc:RegistrationName>' || app.xml_esc(en.name) || '</cbc:RegistrationName></cac:PartyLegalEntity></cac:Party></cac:AccountingSupplierParty>' || E'\n'
    || '<cac:AccountingCustomerParty><cac:Party>'
    || '<cac:PostalAddress><cbc:StreetName>' || app.xml_esc(pa.address) || '</cbc:StreetName><cbc:CityName>' || app.xml_esc(pa.city) || '</cbc:CityName><cac:Country><cbc:IdentificationCode>' || app.xml_esc(coalesce(nullif(pa.country,''),'SA')) || '</cbc:IdentificationCode></cac:Country></cac:PostalAddress>'
    || case when pa.vat_no <> '' then '<cac:PartyTaxScheme><cbc:CompanyID>' || app.xml_esc(pa.vat_no) || '</cbc:CompanyID><cac:TaxScheme><cbc:ID>VAT</cbc:ID></cac:TaxScheme></cac:PartyTaxScheme>' else '' end
    || '<cac:PartyLegalEntity><cbc:RegistrationName>' || app.xml_esc(pa.name) || '</cbc:RegistrationName></cac:PartyLegalEntity></cac:Party></cac:AccountingCustomerParty>' || E'\n';
  -- إجماليات الضريبة بحسب الفئة
  x := x || '<cac:TaxTotal><cbc:TaxAmount currencyID="' || cur || '">' || app.xml_amt(inv.tax_total) || '</cbc:TaxAmount>';
  for sub in select coalesce(c.kind,'oos') k, coalesce(c.rate,0) r, sum(l2.net) base, sum(l2.tax) tx from acc.invoice_lines l2 left join acc.tax_codes c on c.tenant_id = l2.tenant_id and c.code = l2.tax_code where l2.tenant_id = t and l2.invoice_id = inv.id group by 1, 2 order by 1, 2 loop
    cat := case sub.k when 'output' then 'S' when 'zero_out' then 'Z' when 'exempt' then 'E' else 'O' end;
    x := x || '<cac:TaxSubtotal><cbc:TaxableAmount currencyID="' || cur || '">' || app.xml_amt(sub.base) || '</cbc:TaxableAmount><cbc:TaxAmount currencyID="' || cur || '">' || app.xml_amt(sub.tx) || '</cbc:TaxAmount>'
      || '<cac:TaxCategory><cbc:ID>' || cat || '</cbc:ID><cbc:Percent>' || app.xml_amt(sub.r) || '</cbc:Percent><cac:TaxScheme><cbc:ID>VAT</cbc:ID></cac:TaxScheme></cac:TaxCategory></cac:TaxSubtotal>';
  end loop;
  x := x || '</cac:TaxTotal>' || E'\n';
  if cur <> basecur then x := x || '<cac:TaxTotal><cbc:TaxAmount currencyID="' || basecur || '">' || app.xml_amt(round(inv.tax_total * inv.rate, 2)) || '</cbc:TaxAmount></cac:TaxTotal>' || E'\n'; end if;
  x := x || '<cac:LegalMonetaryTotal><cbc:LineExtensionAmount currencyID="' || cur || '">' || app.xml_amt(inv.subtotal) || '</cbc:LineExtensionAmount><cbc:TaxExclusiveAmount currencyID="' || cur || '">' || app.xml_amt(inv.subtotal) || '</cbc:TaxExclusiveAmount>'
    || '<cbc:TaxInclusiveAmount currencyID="' || cur || '">' || app.xml_amt(inv.total) || '</cbc:TaxInclusiveAmount><cbc:AllowanceTotalAmount currencyID="' || cur || '">' || app.xml_amt(inv.discount_total) || '</cbc:AllowanceTotalAmount>'
    || '<cbc:PayableAmount currencyID="' || cur || '">' || app.xml_amt(inv.total) || '</cbc:PayableAmount></cac:LegalMonetaryTotal>' || E'\n';
  for l in select l2.*, c.kind ckind, coalesce(c.rate,0) crate from acc.invoice_lines l2 left join acc.tax_codes c on c.tenant_id = l2.tenant_id and c.code = l2.tax_code where l2.tenant_id = t and l2.invoice_id = inv.id order by l2.line_no loop
    cat := case l.ckind when 'output' then 'S' when 'zero_out' then 'Z' when 'exempt' then 'E' else 'O' end;
    x := x || '<cac:InvoiceLine><cbc:ID>' || l.line_no || '</cbc:ID><cbc:InvoicedQuantity unitCode="PCE">' || trim(to_char(l.qty, 'FM9999999990.0000')) || '</cbc:InvoicedQuantity><cbc:LineExtensionAmount currencyID="' || cur || '">' || app.xml_amt(l.net) || '</cbc:LineExtensionAmount>'
      || '<cac:TaxTotal><cbc:TaxAmount currencyID="' || cur || '">' || app.xml_amt(l.tax) || '</cbc:TaxAmount><cbc:RoundingAmount currencyID="' || cur || '">' || app.xml_amt(l.net + l.tax) || '</cbc:RoundingAmount></cac:TaxTotal>'
      || '<cac:Item><cbc:Name>' || app.xml_esc(coalesce(nullif(l.description,''), 'بند ' || l.line_no)) || '</cbc:Name><cac:ClassifiedTaxCategory><cbc:ID>' || cat || '</cbc:ID><cbc:Percent>' || app.xml_amt(l.crate) || '</cbc:Percent><cac:TaxScheme><cbc:ID>VAT</cbc:ID></cac:TaxScheme></cac:ClassifiedTaxCategory></cac:Item>'
      || '<cac:Price><cbc:PriceAmount currencyID="' || cur || '">' || trim(to_char(l.unit_price, 'FM9999999990.0000')) || '</cbc:PriceAmount></cac:Price></cac:InvoiceLine>' || E'\n';
  end loop;
  return x || '</Invoice>' || E'\n';
end $$;

-- تجهيز كل الفواتير الصادرة غير المجهّزة للكيان بترتيب الإصدار (يحافظ على سلسلة ICV/PIH)
create or replace function public.zatca_prepare(p jsonb default '{}') returns jsonb language plpgsql security definer set search_path = public, app, acc as $$
declare t uuid := app.need('sales','post'); ents uuid[] := app.pick_ents(p); e uuid; inv acc.invoices; last_icv bigint; last_hash text; u uuid; st text; x text; h text; n int := 0; pa acc.parties; one uuid := nullif(p->>'invoice','')::uuid; res jsonb := '[]'::jsonb;
begin
  foreach e in array ents loop
    perform pg_advisory_xact_lock(hashtextextended(t::text || e::text, 21));
    for inv in select i.* from acc.invoices i where i.tenant_id = t and i.entity_id = e and i.kind in ('sales','sales_credit') and i.status in ('issued','void') and i.issued_at is not null
        and not exists (select 1 from acc.zatca_docs z where z.tenant_id = t and z.invoice_id = i.id) and (one is null or i.id = one) order by i.issued_at, i.number loop
      if inv.status = 'void' then continue; end if;
      if one is not null and exists (select 1 from acc.invoices i2 where i2.tenant_id = t and i2.entity_id = e and i2.kind in ('sales','sales_credit') and i2.status = 'issued' and i2.issued_at < inv.issued_at
          and not exists (select 1 from acc.zatca_docs z where z.tenant_id = t and z.invoice_id = i2.id)) then raise exception 'جهّز الفواتير الأقدم أولًا للحفاظ على تسلسل ICV وسلسلة التجزئة'; end if;
      select icv, hash into last_icv, last_hash from acc.zatca_docs where tenant_id = t and entity_id = e order by icv desc limit 1;
      select * into pa from acc.parties where tenant_id = t and id = inv.party_id; st := case when pa.vat_no <> '' then 'standard' else 'simplified' end; u := gen_random_uuid();
      x := app.zatca_build(t, inv, u, coalesce(last_icv, 0) + 1, coalesce(last_hash, app.zatca_seed()), st); h := app.sha256_b64(x);
      insert into acc.zatca_docs (tenant_id, invoice_id, entity_id, uuid, icv, pih, hash, doc_kind, subtype, xml, created_by) values (t, inv.id, e, u, coalesce(last_icv, 0) + 1, coalesce(last_hash, app.zatca_seed()), h, case when inv.kind = 'sales_credit' then 'credit' else 'invoice' end, st, x, auth.uid());
      n := n + 1; res := res || jsonb_build_object('invoice', inv.number, 'icv', coalesce(last_icv, 0) + 1, 'uuid', u);
    end loop;
  end loop;
  if n > 0 then perform app.audit('prepare','zatca','batch','تجهيز ' || n || ' مستند ZATCA'); end if;
  return jsonb_build_object('prepared', n, 'docs', res);
end $$;

create or replace function public.zatca_list(p jsonb default '{}') returns jsonb language plpgsql stable security definer set search_path = public, app, acc as $$
declare t uuid := app.need('sales','view'); ents uuid[] := app.pick_ents(p);
begin
  return jsonb_build_object('rows', coalesce((select jsonb_agg(jsonb_build_object('invoice_id', z.invoice_id, 'number', i.number, 'kind', z.doc_kind, 'subtype', z.subtype, 'uuid', z.uuid, 'icv', z.icv, 'hash', z.hash, 'status', z.status, 'date', i.date, 'total', i.total) order by z.icv desc)
      from acc.zatca_docs z join acc.invoices i on i.tenant_id = z.tenant_id and i.id = z.invoice_id where z.tenant_id = t and z.entity_id = any(ents)), '[]'::jsonb),
    'pending', (select count(*) from acc.invoices i where i.tenant_id = t and i.entity_id = any(ents) and i.kind in ('sales','sales_credit') and i.status = 'issued' and not exists (select 1 from acc.zatca_docs z where z.tenant_id = t and z.invoice_id = i.id)));
end $$;
create or replace function public.zatca_get(p jsonb) returns jsonb language plpgsql stable security definer set search_path = public, app, acc as $$
declare t uuid := app.need('sales','view'); z acc.zatca_docs;
begin select * into z from acc.zatca_docs where tenant_id = t and invoice_id = (p->>'invoice')::uuid; if z.invoice_id is null then raise exception 'لم يُجهَّز مستند ZATCA لهذه الفاتورة بعد'; end if; perform app.entity_ok(t, z.entity_id);
  return jsonb_build_object('uuid', z.uuid, 'icv', z.icv, 'pih', z.pih, 'hash', z.hash, 'status', z.status, 'xml', z.xml); end $$;

-- التحقق من سلامة السلسلة: تجزئة كل مستند تطابق نصّه، وPIH يطابق تجزئة السابق، وICV متسلسل بلا فجوات
create or replace function public.zatca_verify(p jsonb default '{}') returns jsonb language plpgsql stable security definer set search_path = public, app, acc as $$
declare t uuid := app.need('sales','view'); ents uuid[] := app.pick_ents(p); e uuid; z record; prev text; expect bigint; bad jsonb := '[]'::jsonb; n int := 0;
begin
  foreach e in array ents loop prev := app.zatca_seed(); expect := 1;
    for z in select * from acc.zatca_docs where tenant_id = t and entity_id = e order by icv loop n := n + 1;
      if z.icv <> expect then bad := bad || jsonb_build_object('icv', z.icv, 'problem', 'فجوة في التسلسل'); end if;
      if z.pih <> prev then bad := bad || jsonb_build_object('icv', z.icv, 'problem', 'PIH لا يطابق تجزئة السابق'); end if;
      if z.hash <> app.sha256_b64(z.xml) then bad := bad || jsonb_build_object('icv', z.icv, 'problem', 'تجزئة المستند لا تطابق نصّه (تلاعب)'); end if;
      prev := z.hash; expect := z.icv + 1;
    end loop;
  end loop;
  return jsonb_build_object('checked', n, 'ok', jsonb_array_length(bad) = 0, 'problems', bad);
end $$;

-- منع تعديل/حذف المستند بعد تجهيزه (سلسلة غير قابلة للتغيير)؛ الحالة وحدها قابلة للتحديث عند الربط لاحقًا
create or replace function app.zatca_guard() returns trigger language plpgsql as $$
begin
  if tg_op = 'DELETE' then if current_setting('app.demo_wipe', true) = '1' or not exists (select 1 from acc.tenants where id = old.tenant_id) then return old; end if; raise exception 'مستندات ZATCA المجهّزة لا تُحذف'; end if;
  if new.xml is distinct from old.xml or new.hash is distinct from old.hash or new.pih is distinct from old.pih or new.icv is distinct from old.icv or new.uuid is distinct from old.uuid then raise exception 'مستندات ZATCA المجهّزة لا تُعدَّل'; end if;
  return new;
end $$;
drop trigger if exists zatca_guard on acc.zatca_docs;
create trigger zatca_guard before update or delete on acc.zatca_docs for each row execute function app.zatca_guard();

