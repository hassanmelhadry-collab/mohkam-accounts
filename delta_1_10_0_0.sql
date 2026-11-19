-- مُحكَم للحسابات 1.10.0.0 — الإيجارات (IFRS 16) والاضمحلال (IAS 36).
-- الإيجارات: عقد بدفعات شهرية ثابتة في نهاية الشهر وسعر خصم سنوي؛ القيد الابتدائي (أصل حق الاستخدام / التزام الإيجار بالقيمة الحالية)، جدول إطفاء، وترحيل شهري (فائدة + سداد + إهلاك بالقسط الثابت).
-- الاضمحلال: مقارنة القيمة الدفترية من الدفتر بالقيمة القابلة للاسترداد التي يدخلها المستخدم، وقيد خسارة الاضمحلال عند الزيادة. لا يحسب القيمة القابلة للاسترداد (حكم إدارة).
-- نطاق مبسّط: لا تعديلات عقود ولا دفعات متغيرة ولا إعفاء الإيجارات قصيرة الأجل/منخفضة القيمة (يُقرَّر خارج النظام).
create table if not exists acc.leases (
  tenant_id uuid not null references acc.tenants(id) on delete cascade, id uuid not null default gen_random_uuid(), entity_id uuid not null, name text not null, start_date date not null, months int not null check (months between 1 and 360),
  payment numeric(18,2) not null check (payment > 0), rate_annual numeric(7,4) not null check (rate_annual >= 0 and rate_annual <= 100), pv numeric(18,2) not null,
  rou_account_id uuid not null, liability_account_id uuid not null, interest_account_id uuid not null, dep_account_id uuid not null, accum_dep_account_id uuid not null,
  init_journal_id uuid, status text not null default 'active', created_by uuid, created_at timestamptz not null default now(), primary key (tenant_id, id),
  foreign key (tenant_id, entity_id) references acc.entities (tenant_id, id));
create table if not exists acc.lease_schedule (
  tenant_id uuid not null, lease_id uuid not null, n int not null, due_date date not null, opening numeric(18,2) not null, interest numeric(18,2) not null, payment numeric(18,2) not null, closing numeric(18,2) not null, dep numeric(18,2) not null,
  journal_id uuid, primary key (tenant_id, lease_id, n), foreign key (tenant_id, lease_id) references acc.leases (tenant_id, id) on delete cascade);
create table if not exists acc.impairments (
  tenant_id uuid not null references acc.tenants(id) on delete cascade, id uuid not null default gen_random_uuid(), entity_id uuid not null, date date not null, asset_account_id uuid not null, loss_account_id uuid not null, allowance_account_id uuid not null,
  carrying numeric(18,2) not null, recoverable numeric(18,2) not null check (recoverable >= 0), loss numeric(18,2) not null, basis text not null default '', journal_id uuid, created_by uuid, created_at timestamptz not null default now(),
  primary key (tenant_id, id), foreign key (tenant_id, entity_id) references acc.entities (tenant_id, id));
alter table acc.leases enable row level security; alter table acc.lease_schedule enable row level security; alter table acc.impairments enable row level security;
with ins as (
  insert into app.feature_cat (key, name, grp, core, since, sort) values ('leases', 'الإيجارات (IFRS 16) والاضمحلال (IAS 36)', 'المالية', false, 1, 42)
  on conflict (key) do nothing returning key)
update acc.tenants set features_off = array_append(features_off, 'leases') where exists (select 1 from ins) and not ('leases' = any(features_off));

create or replace function app.lease_acct(t uuid, a uuid, ty text) returns void language plpgsql stable security definer set search_path = public, acc as $$
begin
  if not exists (select 1 from acc.accounts where tenant_id = t and id = a and not is_group and type = ty) then raise exception 'حساب غير صالح (يلزم حساب من نوع %)', ty; end if;
end $$;

create or replace function public.lease_create(p jsonb) returns jsonb language plpgsql security definer set search_path = public, app, acc as $$
declare t uuid := app.need('journals', 'post'); e uuid := (p->>'entity')::uuid; lid uuid := gen_random_uuid(); jid uuid := gen_random_uuid(); n int := (p->>'months')::int; pm numeric := round((p->>'payment')::numeric, 2); ra numeric := (p->>'rate_annual')::numeric; r numeric; pv numeric;
  d date := (p->>'start_date')::date; rou uuid := (p->>'rou_account')::uuid; li uuid := (p->>'liability_account')::uuid; ia uuid := (p->>'interest_account')::uuid; da uuid := (p->>'dep_account')::uuid; ad uuid := (p->>'accum_dep_account')::uuid;
  i int; op numeric; it numeric; cl numeric; dep numeric; dd date; j acc.journals; ds text;
begin
  if not app.feat_on('leases') then raise exception 'الميزة غير مفعّلة لشركتك'; end if;
  if e is null or not (e = any(app.ents())) then raise exception 'كيان غير مسموح'; end if;
  if nullif(trim(p->>'name'),'') is null then raise exception 'اسم العقد مطلوب'; end if;
  if d is null or n is null or n < 1 or n > 360 then raise exception 'تاريخ البدء ومدة بين 1 و360 شهرًا مطلوبان'; end if;
  if pm is null or pm <= 0 then raise exception 'الدفعة الشهرية يجب أن تكون موجبة'; end if;
  if ra is null or ra < 0 or ra > 100 then raise exception 'سعر الخصم بين 0 و100'; end if;
  perform app.lease_acct(t, rou, 'asset'); perform app.lease_acct(t, ad, 'asset'); perform app.lease_acct(t, li, 'liability'); perform app.lease_acct(t, ia, 'expense'); perform app.lease_acct(t, da, 'expense');
  r := ra / 1200; pv := case when r = 0 then pm * n else pm * (1 - power(1 + r, -n)) / r end; pv := round(pv, 2);
  insert into acc.leases (tenant_id, id, entity_id, name, start_date, months, payment, rate_annual, pv, rou_account_id, liability_account_id, interest_account_id, dep_account_id, accum_dep_account_id, created_by)
  values (t, lid, e, trim(p->>'name'), d, n, pm, ra, pv, rou, li, ia, da, ad, auth.uid());
  op := pv; dep := round(pv / n, 2);
  for i in 1..n loop
    it := round(op * r, 2); cl := op + it - pm; if i = n then dep := pv - dep * (n - 1); end if;
    if i = n and cl <> 0 then it := it - cl; cl := 0; end if;
    dd := (d + (i || ' month')::interval)::date - 1;
    insert into acc.lease_schedule (tenant_id, lease_id, n, due_date, opening, interest, payment, closing, dep) values (t, lid, i, dd, op, it, pm, cl, case when i = n then pv - round(pv / n, 2) * (n - 1) else round(pv / n, 2) end);
    op := cl;
  end loop;
  ds := 'إيجار IFRS 16 — ' || trim(p->>'name') || ' — الاعتراف الأولي';
  insert into acc.journals (tenant_id, id, entity_id, type, date, description, status, source, source_id, created_by) values (t, jid, e, 'GJ', d, ds, 'draft', 'lease', lid, auth.uid());
  perform app.put_lines(t, jid, e, d, jsonb_build_array(jsonb_build_object('account', rou, 'debit', pv, 'description', ds), jsonb_build_object('account', li, 'credit', pv, 'description', ds)));
  j := app.post_journal(jid); update acc.leases set init_journal_id = j.id where tenant_id = t and id = lid;
  perform app.audit('create', 'lease', lid::text, ds || ' — ' || pv); return jsonb_build_object('id', lid, 'pv', pv, 'journal', j.id);
end $$;

create or replace function public.lease_list(p jsonb default '{}') returns jsonb language plpgsql stable security definer set search_path = public, app, acc as $$
declare t uuid := app.need('journals', 'view');
begin
  if not app.feat_on('leases') then raise exception 'الميزة غير مفعّلة لشركتك'; end if;
  return coalesce((select jsonb_agg(to_jsonb(l) - 'tenant_id' || jsonb_build_object('posted', (select count(*) from acc.lease_schedule s where s.tenant_id = l.tenant_id and s.lease_id = l.id and s.journal_id is not null),
      'liability_now', coalesce((select (case when count(*) filter (where s.journal_id is not null) = 0 then l.pv else (select s2.closing from acc.lease_schedule s2 where s2.tenant_id = l.tenant_id and s2.lease_id = l.id and s2.journal_id is not null order by s2.n desc limit 1) end) from acc.lease_schedule s where s.tenant_id = l.tenant_id and s.lease_id = l.id), l.pv)) order by l.start_date desc)
    from acc.leases l where l.tenant_id = t and l.entity_id = any(app.ents())), '[]'::jsonb);
end $$;

create or replace function public.lease_get(p jsonb) returns jsonb language plpgsql stable security definer set search_path = public, app, acc as $$
declare t uuid := app.need('journals', 'view'); l acc.leases;
begin
  if not app.feat_on('leases') then raise exception 'الميزة غير مفعّلة لشركتك'; end if;
  select * into l from acc.leases where tenant_id = t and id = (p->>'id')::uuid and entity_id = any(app.ents()); if l.id is null then raise exception 'العقد غير موجود'; end if;
  return jsonb_build_object('lease', to_jsonb(l) - 'tenant_id', 'schedule', (select coalesce(jsonb_agg(to_jsonb(s) - 'tenant_id' order by s.n), '[]'::jsonb) from acc.lease_schedule s where s.tenant_id = t and s.lease_id = l.id));
end $$;

-- ترحيل الأقساط المستحقة حتى تاريخ: لكل قسط قيد: مدين فائدة + مدين التزام (السداد - الفائدة) / دائن بنك ، ومدين إهلاك / دائن مجمع إهلاك
create or replace function public.lease_post(p jsonb) returns jsonb language plpgsql security definer set search_path = public, app, acc as $$
declare t uuid := app.need('journals', 'post'); l acc.leases; upto date := coalesce(nullif(p->>'upto','')::date, current_date); ba uuid := (p->>'bank_account')::uuid; s acc.lease_schedule; cnt int := 0; tot numeric := 0; jid uuid; j acc.journals; ds text;
begin
  if not app.feat_on('leases') then raise exception 'الميزة غير مفعّلة لشركتك'; end if;
  select * into l from acc.leases where tenant_id = t and id = (p->>'id')::uuid and entity_id = any(app.ents()); if l.id is null then raise exception 'العقد غير موجود'; end if;
  perform app.lease_acct(t, ba, 'asset');
  for s in select * from acc.lease_schedule where tenant_id = t and lease_id = l.id and journal_id is null and due_date <= upto order by n loop
    jid := gen_random_uuid(); ds := 'إيجار ' || l.name || ' — القسط ' || s.n || '/' || l.months;
    insert into acc.journals (tenant_id, id, entity_id, type, date, description, status, source, source_id, created_by) values (t, jid, l.entity_id, 'GJ', s.due_date, ds, 'draft', 'lease', l.id, auth.uid());
    perform app.put_lines(t, jid, l.entity_id, s.due_date, jsonb_build_array(
      jsonb_build_object('account', l.interest_account_id, 'debit', s.interest, 'description', ds), jsonb_build_object('account', l.liability_account_id, 'debit', s.payment - s.interest, 'description', ds),
      jsonb_build_object('account', ba, 'credit', s.payment, 'description', ds), jsonb_build_object('account', l.dep_account_id, 'debit', s.dep, 'description', ds), jsonb_build_object('account', l.accum_dep_account_id, 'credit', s.dep, 'description', ds)));
    j := app.post_journal(jid); update acc.lease_schedule set journal_id = j.id where tenant_id = t and lease_id = l.id and n = s.n; cnt := cnt + 1; tot := tot + s.payment;
  end loop;
  if cnt = 0 then raise exception 'لا أقساط مستحقة غير مرحّلة حتى هذا التاريخ'; end if;
  perform app.audit('post', 'lease', l.id::text, l.name || ' — ' || cnt || ' قسط'); return jsonb_build_object('posted', cnt, 'paid', tot);
end $$;

-- الاضمحلال: القيمة الدفترية من رصيد حساب الأصل (مدين - دائن) لكيان واحد حتى التاريخ
create or replace function public.impair_record(p jsonb) returns jsonb language plpgsql security definer set search_path = public, app, acc as $$
declare t uuid := app.need('journals', 'post'); e uuid := (p->>'entity')::uuid; d date := coalesce(nullif(p->>'date','')::date, current_date); aa uuid := (p->>'asset_account')::uuid; la uuid := (p->>'loss_account')::uuid; wa uuid := (p->>'allowance_account')::uuid;
  rec numeric := round((p->>'recoverable')::numeric, 2); car numeric; loss numeric; id uuid := gen_random_uuid(); jid uuid := gen_random_uuid(); j acc.journals; ds text;
begin
  if not app.feat_on('leases') then raise exception 'الميزة غير مفعّلة لشركتك'; end if;
  if e is null or not (e = any(app.ents())) then raise exception 'كيان غير مسموح'; end if;
  if rec is null or rec < 0 then raise exception 'القيمة القابلة للاسترداد غير صالحة'; end if;
  if nullif(trim(p->>'basis'),'') is null then raise exception 'اكتب أساس تقدير القيمة القابلة للاسترداد'; end if;
  perform app.lease_acct(t, aa, 'asset'); perform app.lease_acct(t, wa, 'asset'); perform app.lease_acct(t, la, 'expense');
  if aa = wa then raise exception 'حساب مجمع الاضمحلال يجب أن يختلف عن حساب الأصل'; end if;
  select coalesce(sum(l.debit - l.credit), 0) into car from acc.journal_lines l where l.tenant_id = t and l.posted and l.entity_id = e and l.date <= d and l.account_id in (aa, wa);
  loss := round(car - rec, 2); if loss <= 0 then raise exception 'لا اضمحلال: القيمة الدفترية % لا تتجاوز القابلة للاسترداد %', car, rec; end if;
  ds := 'خسارة اضمحلال IAS 36 — ' || trim(p->>'basis');
  insert into acc.journals (tenant_id, id, entity_id, type, date, description, status, source, source_id, created_by) values (t, jid, e, 'GJ', d, ds, 'draft', 'impairment', id, auth.uid());
  perform app.put_lines(t, jid, e, d, jsonb_build_array(jsonb_build_object('account', la, 'debit', loss, 'description', ds), jsonb_build_object('account', wa, 'credit', loss, 'description', ds)));
  j := app.post_journal(jid);
  insert into acc.impairments (tenant_id, id, entity_id, date, asset_account_id, loss_account_id, allowance_account_id, carrying, recoverable, loss, basis, journal_id, created_by) values (t, id, e, d, aa, la, wa, car, rec, loss, trim(p->>'basis'), j.id, auth.uid());
  perform app.audit('create', 'impairment', id::text, ds || ' — ' || loss); return jsonb_build_object('id', id, 'carrying', car, 'loss', loss, 'journal', j.id);
end $$;

create or replace function public.impair_list(p jsonb default '{}') returns jsonb language plpgsql stable security definer set search_path = public, app, acc as $$
declare t uuid := app.need('journals', 'view');
begin
  if not app.feat_on('leases') then raise exception 'الميزة غير مفعّلة لشركتك'; end if;
  return coalesce((select jsonb_agg(to_jsonb(i) - 'tenant_id' || jsonb_build_object('asset', (select name from acc.accounts a where a.tenant_id = i.tenant_id and a.id = i.asset_account_id)) order by i.date desc) from acc.impairments i where i.tenant_id = t and i.entity_id = any(app.ents())), '[]'::jsonb);
end $$;
insert into app.schema_migrations (version, name) values ('1.10.0.0', 'الإيجارات IFRS 16 (التزام وأصل حق استخدام وجدول وترحيل) والاضمحلال IAS 36 (قيد خسارة)')
on conflict (version) do nothing;
grant execute on function public.lease_create(jsonb), public.lease_list(jsonb), public.lease_get(jsonb), public.lease_post(jsonb), public.impair_record(jsonb), public.impair_list(jsonb) to authenticated;
revoke execute on function public.lease_create(jsonb), public.lease_list(jsonb), public.lease_get(jsonb), public.lease_post(jsonb), public.impair_record(jsonb), public.impair_list(jsonb) from anon, public;
