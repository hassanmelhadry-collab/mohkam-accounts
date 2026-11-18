-- مُحكَم للحسابات — دلتا 1.9.0.0 (من 1.8.1.0): مكتبة المعايير + سدّ ثغرة حذف التخزين + التجميد والاحتفاظ + محادثة الطلبات + كشف الموظف
-- مُحكَم للحسابات — مكتبة المعايير المحاسبية والنظامية (IFRS / SOCPA / ZATCA / ISA …)
-- المالك يرفع نسخًا مرخّصة من المعايير (نصًا مقسّمًا إلى مقاطع بأرقام صفحاتها)، ويبحث فيها المساعد والمستخدمون،
-- وكل جواب يُعرض مع سنده: الجهة، رقم المعيار، الصفحة، واسم الملف المرفوع.
-- «خريطة المعايير» المرافقة ملخصات مرجعية موجزة بصياغتنا للاسترشاد فقط، وليست نصوص المعايير الرسمية ولا تحمل أرقام فقرات.
create table if not exists acc.kb_docs (
  tenant_id uuid not null references acc.tenants(id) on delete cascade, id uuid not null default gen_random_uuid(),
  body text not null default 'other', code text not null default '', title text not null, lang text not null default 'ar' check (lang in ('ar','en','mixed')),
  version text not null default '', kind text not null default 'standard' check (kind in ('standard','regulation','guidance','policy','other')), source_note text not null default '',
  sha256 text not null default '', pages int not null default 0, chunks int not null default 0, active boolean not null default true,
  uploaded_by uuid, uploaded_at timestamptz not null default now(), primary key (tenant_id, id)
);
create unique index if not exists kb_docs_sha on acc.kb_docs (tenant_id, sha256) where sha256 <> '';
create table if not exists acc.kb_chunks (
  tenant_id uuid not null, doc_id uuid not null, seq int not null, page int not null default 0, section text not null default '', content text not null, tsv tsvector not null,
  primary key (tenant_id, doc_id, seq), foreign key (tenant_id, doc_id) references acc.kb_docs (tenant_id, id) on delete cascade
);
create index if not exists kb_chunks_tsv on acc.kb_chunks using gin (tsv);
alter table acc.kb_docs enable row level security; alter table acc.kb_chunks enable row level security;

create table if not exists app.kb_map (
  id serial primary key, body text not null, code text not null, title_ar text not null, title_en text not null, topic text not null, summary text not null, keywords text not null default ''
);
alter table app.kb_map enable row level security;

create or replace function app.kb_norm(x text) returns text language sql immutable as
$$ select trim(regexp_replace(regexp_replace(translate(lower(coalesce(x, '')), 'أإآىةًٌٍَُِّْـ', 'ااايه'), '[^[:alnum:]\u0600-\u06FF]+', ' ', 'g'), '(^| )(وال|بال|كال|فال|لل|ال)(?=[\u0621-\u064A]{3})', '\1', 'g')) $$;

create or replace function app.kb_query(q text) returns tsquery language plpgsql immutable as $$
declare w text[]; s text;
begin
  select array_agg(distinct x) into w from unnest(string_to_array(app.kb_norm(q), ' ')) x where length(x) >= 2 and x not in ('ما','هل','في','من','على','عن','الى','او','ثم','هو','هي','كيف','متى','the','of','and','is','to','in','for','a','an','how','what','when','are');
  if w is null then return null; end if;
  s := array_to_string(array(select quote_literal(x) from unnest(w) x), ' | ');
  return to_tsquery('simple', s);
end $$;

create or replace function public.kb_ingest(p jsonb) returns jsonb language plpgsql security definer set search_path = public, app, acc as $$
declare t uuid := app.need_sys('settings'); d jsonb := coalesce(p->'doc', '{}'); did uuid := nullif(p->>'doc_id', '')::uuid; c jsonb; n int := 0; mx int; sh text := coalesce(d->>'sha256', ''); txt text;
begin
  if jsonb_typeof(p->'chunks') <> 'array' or jsonb_array_length(p->'chunks') > 200 then raise exception 'أرسل حتى 200 مقطع في الدفعة'; end if;
  if did is null then
    if nullif(trim(coalesce(d->>'title', '')), '') is null then raise exception 'اسم الوثيقة مطلوب'; end if;
    if sh <> '' and exists (select 1 from acc.kb_docs where tenant_id = t and sha256 = sh) then return jsonb_build_object('duplicate', true, 'doc_id', (select id from acc.kb_docs where tenant_id = t and sha256 = sh)); end if;
    insert into acc.kb_docs (tenant_id, body, code, title, lang, version, kind, source_note, sha256, pages, uploaded_by)
    values (t, coalesce(nullif(trim(d->>'body'), ''), 'other'), trim(coalesce(d->>'code', '')), trim(d->>'title'), coalesce(nullif(d->>'lang', ''), 'ar'), coalesce(d->>'version', ''), coalesce(nullif(d->>'kind', ''), 'standard'), coalesce(d->>'source_note', ''), sh, coalesce(nullif(d->>'pages', '')::int, 0), auth.uid())
    returning id into did;
    perform app.audit('create', 'kb_doc', did::text, 'رفع وثيقة مرجعية: ' || trim(d->>'title'));
  else
    if not exists (select 1 from acc.kb_docs where tenant_id = t and id = did) then raise exception 'الوثيقة غير موجودة'; end if;
  end if;
  select coalesce(max(seq), -1) + 1 into mx from acc.kb_chunks where tenant_id = t and doc_id = did;
  for c in select * from jsonb_array_elements(p->'chunks') loop
    txt := left(coalesce(c->>'text', ''), 4000); continue when length(trim(txt)) < 3;
    insert into acc.kb_chunks (tenant_id, doc_id, seq, page, section, content, tsv) values (t, did, mx + n, coalesce(nullif(c->>'page', '')::int, 0), left(coalesce(c->>'section', ''), 200), txt, to_tsvector('simple', app.kb_norm(txt)));
    n := n + 1;
  end loop;
  update acc.kb_docs set chunks = (select count(*) from acc.kb_chunks where tenant_id = t and doc_id = did) where tenant_id = t and id = did;
  return jsonb_build_object('doc_id', did, 'added', n);
end $$;

create or replace function public.kb_list(p jsonb default '{}') returns jsonb language plpgsql stable security definer set search_path = public, app, acc as $$
declare t uuid := app.need(null, null);
begin
  return jsonb_build_object('docs', coalesce((select jsonb_agg(jsonb_build_object('id', id, 'body', body, 'code', code, 'title', title, 'lang', lang, 'version', version, 'kind', kind, 'pages', pages, 'chunks', chunks, 'active', active, 'uploaded_at', uploaded_at,
      'uploaded_by', (select name from acc.members m where m.user_id = d.uploaded_by)) order by body, code, title) from acc.kb_docs d where tenant_id = t), '[]'),
    'map_count', (select count(*) from app.kb_map));
end $$;

create or replace function public.kb_doc_set(p jsonb) returns jsonb language plpgsql security definer set search_path = public, app, acc as $$
declare t uuid := app.need_sys('settings'); did uuid := (p->>'id')::uuid; d acc.kb_docs;
begin
  select * into d from acc.kb_docs where tenant_id = t and id = did; if not found then raise exception 'الوثيقة غير موجودة'; end if;
  if (p->>'delete')::boolean is true then delete from acc.kb_docs where tenant_id = t and id = did; perform app.audit('delete', 'kb_doc', did::text, 'حذف وثيقة مرجعية: ' || d.title); return jsonb_build_object('deleted', true); end if;
  update acc.kb_docs set active = coalesce((p->>'active')::boolean, active), title = coalesce(nullif(trim(p->>'title'), ''), title), version = coalesce(p->>'version', version), code = coalesce(p->>'code', code) where tenant_id = t and id = did;
  perform app.audit('update', 'kb_doc', did::text, 'تعديل وثيقة مرجعية: ' || d.title); return jsonb_build_object('ok', true);
end $$;

-- بحث: نصوص مرفوعة (بصفحاتها) أولًا ثم الخريطة المرجعية. كل نتيجة تحمل سندها.
create or replace function public.kb_search(p jsonb) returns jsonb language plpgsql stable security definer set search_path = public, app, acc as $$
declare t uuid := app.need(null, null); q text := trim(coalesce(p->>'q', '')); tq tsquery; lim int := least(greatest(coalesce(nullif(p->>'limit', '')::int, 6), 1), 20); bd text := nullif(p->>'body', ''); docs jsonb; maps jsonb; nq text := app.kb_norm(q);
begin
  if length(q) < 2 then raise exception 'اكتب سؤالًا أو كلمة بحث'; end if;
  tq := app.kb_query(q);
  if tq is null then return jsonb_build_object('q', q, 'docs', '[]'::jsonb, 'map', '[]'::jsonb, 'has_official', false); end if;
  select coalesce(jsonb_agg(jsonb_build_object('doc_id', x.did, 'body', x.body, 'code', x.code, 'title', x.title, 'version', x.version, 'page', x.page, 'section', x.section, 'text', left(x.content, 900), 'rank', round(x.r::numeric, 4)) order by x.r desc), '[]') into docs
  from (select c.doc_id did, d.body, d.code, d.title, d.version, c.page, c.section, c.content, ts_rank(c.tsv, tq) + case when d.code <> '' and nq like '%' || app.kb_norm(d.code) || '%' then 0.5 else 0 end r
        from acc.kb_chunks c join acc.kb_docs d on d.tenant_id = c.tenant_id and d.id = c.doc_id where c.tenant_id = t and d.active and (bd is null or d.body = bd) and c.tsv @@ tq order by r desc limit lim) x;
  select coalesce(jsonb_agg(jsonb_build_object('body', m.body, 'code', m.code, 'title', m.title_ar, 'title_en', m.title_en, 'topic', m.topic, 'summary', m.summary) order by m.r desc), '[]') into maps
  from (select k.*, ts_rank(to_tsvector('simple', app.kb_norm(k.code || ' ' || k.title_ar || ' ' || k.title_en || ' ' || k.topic || ' ' || k.summary || ' ' || k.keywords)), tq) + case when nq like '%' || app.kb_norm(k.code) || '%' then 0.6 else 0 end r from app.kb_map k
        where (bd is null or k.body = bd) and (to_tsvector('simple', app.kb_norm(k.code || ' ' || k.title_ar || ' ' || k.title_en || ' ' || k.topic || ' ' || k.summary || ' ' || k.keywords)) @@ tq or nq like '%' || app.kb_norm(k.code) || '%') order by r desc limit 4) m;
  return jsonb_build_object('q', q, 'docs', docs, 'map', maps, 'has_official', jsonb_array_length(docs) > 0,
    'note', 'النتائج المرفوعة نصوص رسمية بصفحاتها؛ الخريطة المرجعية ملخصات موجزة للاسترشاد وليست النص الرسمي. ارجع للمعيار الرسمي قبل أي قرار محاسبي أو نظامي.');
end $$;

-- خريطة المعايير: تُعاد كتابتها عند كل تشغيل للدلتا (صياغتنا الموجزة، ليست نصوصًا رسمية)
delete from app.kb_map;
insert into app.kb_map (body, code, title_ar, title_en, topic, summary, keywords) values
($k$IAS$k$,$k$IAS 1$k$,$k$عرض القوائم المالية$k$,$k$Presentation of Financial Statements$k$,$k$مجموعة القوائم الكاملة$k$,$k$يحدد مكوّنات القوائم المالية (المركز المالي، الدخل الشامل، التغيرات في حقوق الملكية، التدفقات النقدية، الإيضاحات)، وأسس العرض: الاستمرارية، الاستحقاق، الثبات، الأهمية النسبية، عدم المقاصة، وأرقام المقارنة. يتطلب تصنيف الأصول والالتزامات إلى متداول وغير متداول ما لم يكن العرض حسب السيولة أنسب.$k$,$k$قائمة المركز المالي الدخل الشامل حقوق الملكية استمرارية استحقاق متداول غير متداول مقارنة$k$),
($k$IAS$k$,$k$IAS 2$k$,$k$المخزون$k$,$k$Inventories$k$,$k$قياس المخزون$k$,$k$يقيس المخزون بالأقل من التكلفة وصافي القيمة القابلة للتحقق. تشمل التكلفة الشراء والتحويل وما أُنفق لإيصاله لموقعه وحالته. تُستخدم طريقة الوارد أولًا صادر أولًا أو المتوسط المرجح، ولا يُسمح بالوارد أخيرًا صادر أخيرًا. تُخفَّض القيمة عند التقادم أو انخفاض سعر البيع ويُعكس التخفيض إذا زال سببه.$k$,$k$مخزون تكلفة صافي القيمة القابلة للتحقق متوسط مرجح fifo تقادم بضاعة$k$),
($k$IAS$k$,$k$IAS 7$k$,$k$قائمة التدفقات النقدية$k$,$k$Statement of Cash Flows$k$,$k$التدفقات النقدية$k$,$k$تُعرض التدفقات في ثلاثة أنشطة: تشغيلية واستثمارية وتمويلية. يجوز عرض التشغيلية بالطريقة المباشرة أو غير المباشرة. تشمل النقدية المعادلات النقدية قصيرة الأجل عالية السيولة. تُفصح المنشأة عن الأنشطة غير النقدية المهمة.$k$,$k$تدفقات نقدية تشغيلية استثمارية تمويلية طريقة مباشرة غير مباشرة نقد$k$),
($k$IAS$k$,$k$IAS 8$k$,$k$السياسات المحاسبية والتقديرات والأخطاء$k$,$k$Accounting Policies, Changes in Accounting Estimates and Errors$k$,$k$تغيير سياسة وتقدير وتصحيح خطأ$k$,$k$تغيير السياسة المحاسبية يُطبَّق بأثر رجعي ما لم يكن غير عملي، وتغيير التقدير يُطبَّق مستقبليًا، وأخطاء الفترات السابقة الجوهرية تُصحَّح بإعادة عرض أرقام المقارنة مع إفصاح مناسب.$k$,$k$تغيير سياسة محاسبية تقدير خطأ سنوات سابقة اعادة عرض اثر رجعي$k$),
($k$IAS$k$,$k$IAS 10$k$,$k$الأحداث بعد فترة التقرير$k$,$k$Events after the Reporting Period$k$,$k$أحداث لاحقة$k$,$k$الأحداث المعدِّلة تقدّم دليلًا على ظروف قائمة في تاريخ التقرير فتُعدَّل القوائم لها، وغير المعدِّلة تحدث بعده فيُفصح عنها إن كانت جوهرية. توزيعات الأرباح المعلنة بعد تاريخ التقرير لا تُعتبر التزامًا في ذلك التاريخ.$k$,$k$احداث لاحقة تاريخ التقرير معدلة غير معدلة توزيعات$k$),
($k$IAS$k$,$k$IAS 12$k$,$k$ضرائب الدخل$k$,$k$Income Taxes$k$,$k$ضريبة جارية ومؤجلة$k$,$k$تُثبَّت الضريبة الجارية على الربح الخاضع للضريبة، وتُحتسب الضريبة المؤجلة على الفروق المؤقتة بين القيمة الدفترية والأساس الضريبي، مع اختبار قابلية استرداد الأصول الضريبية المؤجلة. يُقاس الأثر بالمعدلات المقررة أو المعتمدة فعليًا.$k$,$k$ضريبة دخل مؤجلة فروق مؤقتة اصل ضريبي مؤجل معدل ضريبة$k$),
($k$IAS$k$,$k$IAS 16$k$,$k$العقارات والآلات والمعدات$k$,$k$Property, Plant and Equipment$k$,$k$أصول ثابتة$k$,$k$يُثبَّت الأصل بالتكلفة وتشمل سعر الشراء والتكاليف المباشرة لتجهيزه. يُختار بعدها نموذج التكلفة أو إعادة التقييم لكل فئة. يُستهلك كل جزء مهم على عمره الإنتاجي بطريقة تعكس نمط الاستفادة، وتُراجَع القيمة التخريدية والعمر والطريقة دوريًا. عند الاستبعاد يُثبَّت الربح أو الخسارة في قائمة الدخل.$k$,$k$اهلاك اصول ثابتة عمر انتاجي قيمة تخريدية اعادة تقييم استبعاد معدات$k$),
($k$IAS$k$,$k$IAS 19$k$,$k$منافع الموظفين$k$,$k$Employee Benefits$k$,$k$مكافأة نهاية الخدمة والإجازات$k$,$k$تُثبَّت المنافع قصيرة الأجل عند تقديم الخدمة. المنافع المحددة بعد انتهاء الخدمة (كمكافأة نهاية الخدمة) تُقاس اكتواريًا بطريقة وحدة الائتمان المقدَّرة، وتُعرض إعادة القياس في الدخل الشامل الآخر.$k$,$k$مكافأة نهاية الخدمة منافع موظفين اجازات التزام اكتواري رواتب$k$),
($k$IAS$k$,$k$IAS 21$k$,$k$آثار التغيرات في أسعار الصرف$k$,$k$The Effects of Changes in Foreign Exchange Rates$k$,$k$العملات الأجنبية$k$,$k$تُحدَّد العملة الوظيفية للمنشأة. تُسجَّل المعاملات الأجنبية بسعر الصرف في تاريخ المعاملة، وتُحوَّل البنود النقدية بسعر الإقفال، وتُثبَّت فروق الصرف في الربح أو الخسارة. عند تحويل القوائم لعملة العرض تُحوَّل الأصول والالتزامات بسعر الإقفال والدخل والمصروفات بالمتوسط أو بسعر المعاملة.$k$,$k$عملة اجنبية فروق صرف عملة وظيفية سعر الاقفال تحويل$k$),
($k$IAS$k$,$k$IAS 23$k$,$k$تكاليف الاقتراض$k$,$k$Borrowing Costs$k$,$k$رسملة الفوائد$k$,$k$تُرسمل تكاليف الاقتراض المتعلقة مباشرة باقتناء أو إنشاء أصل مؤهل يحتاج وقتًا طويلًا ليصبح جاهزًا للاستخدام، وتوقف الرسملة عند اكتمال الأنشطة. وما سوى ذلك يُحمَّل مصروفًا.$k$,$k$تكاليف اقتراض فوائد رسملة اصل مؤهل قروض$k$),
($k$IAS$k$,$k$IAS 24$k$,$k$إفصاحات الأطراف ذات العلاقة$k$,$k$Related Party Disclosures$k$,$k$أطراف ذات علاقة$k$,$k$يتطلب الإفصاح عن العلاقات والمعاملات والأرصدة مع الأطراف ذات العلاقة، وتعويضات كبار الإدارة، بحيث يفهم القارئ أثرها على المركز المالي والأداء.$k$,$k$اطراف ذات علاقة كبار الادارة معاملات مع الشركاء$k$),
($k$IAS$k$,$k$IAS 27 / 28$k$,$k$القوائم المنفصلة والاستثمار في الشركات الزميلة$k$,$k$Separate Financial Statements / Investments in Associates and Joint Ventures$k$,$k$استثمارات$k$,$k$القوائم المنفصلة تعرض الاستثمارات بالتكلفة أو وفق IFRS 9 أو بحقوق الملكية. الاستثمار في شركة زميلة (نفوذ مؤثر عادة بين 20% و50%) أو مشروع مشترك يُعالج بطريقة حقوق الملكية في القوائم الموحدة.$k$,$k$شركة زميلة مشروع مشترك حقوق الملكية نفوذ مؤثر استثمار$k$),
($k$IAS$k$,$k$IAS 32 / IFRS 7$k$,$k$الأدوات المالية: العرض والإفصاح$k$,$k$Financial Instruments: Presentation / Disclosures$k$,$k$تصنيف الدين وحقوق الملكية$k$,$k$يحدد IAS 32 تصنيف الأداة التزامًا أو حقوق ملكية بحسب الالتزام التعاقدي بتسليم نقد، وشروط المقاصة. ويتطلب IFRS 7 إفصاحات عن المخاطر الائتمانية والسيولة والسوق وأهمية الأدوات للمركز المالي.$k$,$k$ادوات مالية التزام مالي حقوق ملكية مقاصة مخاطر ائتمان سيولة افصاح$k$),
($k$IAS$k$,$k$IAS 33$k$,$k$ربحية السهم$k$,$k$Earnings per Share$k$,$k$ربحية السهم$k$,$k$تُعرض ربحية السهم الأساسية والمخفَّضة للمنشآت المدرجة أو التي تعرض قوائمها لغرض الإدراج، بقسمة الربح العائد للمساهمين على المتوسط المرجح للأسهم.$k$,$k$ربحية السهم الاساسية المخفضة متوسط مرجح للاسهم$k$),
($k$IAS$k$,$k$IAS 34$k$,$k$التقارير المالية الأولية$k$,$k$Interim Financial Reporting$k$,$k$قوائم أولية$k$,$k$يحدد الحد الأدنى لمحتوى التقرير المالي المرحلي والمبادئ التي تُطبَّق في الاعتراف والقياس خلال الفترة الأولية بنفس سياسات القوائم السنوية.$k$,$k$تقارير اولية ربع سنوية نصف سنوية مرحلية$k$),
($k$IAS$k$,$k$IAS 36$k$,$k$اضمحلال قيمة الأصول$k$,$k$Impairment of Assets$k$,$k$اختبار الاضمحلال$k$,$k$يُجري اختبار الاضمحلال عند وجود مؤشر عليه، ويُجرى سنويًا للشهرة والأصول غير الملموسة غير محددة العمر. تُثبَّت الخسارة إذا زادت القيمة الدفترية عن القيمة القابلة للاسترداد (الأعلى من القيمة العادلة ناقصًا تكلفة البيع وقيمة الاستخدام). لا تُعكس خسارة الشهرة.$k$,$k$اضمحلال الاصول القيمة القابلة للاسترداد وحدة مولدة للنقد شهرة انخفاض القيمة$k$),
($k$IAS$k$,$k$IAS 37$k$,$k$المخصصات والالتزامات والأصول المحتملة$k$,$k$Provisions, Contingent Liabilities and Contingent Assets$k$,$k$مخصصات$k$,$k$يُثبَّت المخصص عند وجود التزام حالي نتيجة حدث سابق مع احتمال تدفق خارج للموارد وإمكانية تقدير موثوق. الالتزام المحتمل يُفصح عنه ولا يُثبَّت، والأصل المحتمل لا يُثبَّت إلا إذا أصبح تحققه مؤكدًا فعليًا.$k$,$k$مخصص التزام محتمل قضايا ضمانات اصل محتمل مخصصات$k$),
($k$IAS$k$,$k$IAS 38$k$,$k$الأصول غير الملموسة$k$,$k$Intangible Assets$k$,$k$اصول غير ملموسة$k$,$k$تُثبَّت إذا كانت قابلة للتحديد ومسيطرًا عليها ويُتوقع منها منافع مستقبلية ويمكن قياس تكلفتها. مصروفات البحث تُحمَّل مصروفًا، وتُرسمل مرحلة التطوير عند استيفاء شروط محددة. تُطفأ ذات العمر المحدد.$k$,$k$اصول غير ملموسة برمجيات تطوير بحث اطفاء علامة تجارية$k$),
($k$IAS$k$,$k$IAS 40$k$,$k$العقارات الاستثمارية$k$,$k$Investment Property$k$,$k$عقارات استثمارية$k$,$k$العقار المحتفظ به لتحقيق إيجار أو ارتفاع قيمة يُقاس بعد الاعتراف إما بنموذج القيمة العادلة أو بنموذج التكلفة، ويُطبَّق الخيار على كل العقارات الاستثمارية.$k$,$k$عقار استثماري قيمة عادلة ايجار عقارات$k$),
($k$IAS$k$,$k$IAS 41$k$,$k$الزراعة$k$,$k$Agriculture$k$,$k$نشاط زراعي$k$,$k$تُقاس الأصول الحيوية والمنتجات الزراعية عند الحصاد بالقيمة العادلة ناقصًا تكاليف البيع، وتُثبَّت التغيرات في الربح أو الخسارة، مع معالجة خاصة للنباتات المنتجة وفق IAS 16.$k$,$k$زراعة اصول حيوية نخيل مزرعة محصول قيمة عادلة$k$),
($k$IFRS$k$,$k$IFRS 1$k$,$k$التطبيق الأول للمعايير الدولية$k$,$k$First-time Adoption of IFRS$k$,$k$التحول للمعايير$k$,$k$تعرض المنشأة قوائمها الأولى وفق المعايير الدولية بتطبيق المعايير النافذة بأثر رجعي مع استثناءات وإعفاءات محددة، وتفصح عن تسويات الانتقال من الإطار السابق.$k$,$k$التحول الى المعايير الدولية التطبيق الاول تسويات الانتقال$k$),
($k$IFRS$k$,$k$IFRS 3$k$,$k$تجميع الأعمال$k$,$k$Business Combinations$k$,$k$الاستحواذ$k$,$k$تُطبَّق طريقة الاستحواذ: تحديد المستحوذ، وقياس الأصول المقتناة والالتزامات المتحملة بالقيمة العادلة في تاريخ الاستحواذ، وإثبات الشهرة أو مكسب الشراء بأسعار تفضيلية. تكاليف الاستحواذ تُحمَّل مصروفًا.$k$,$k$استحواذ دمج شركات شهرة تجميع اعمال القيمة العادلة$k$),
($k$IFRS$k$,$k$IFRS 5$k$,$k$الأصول المحتفظ بها للبيع والعمليات المتوقفة$k$,$k$Non-current Assets Held for Sale and Discontinued Operations$k$,$k$اصول للبيع$k$,$k$يُصنَّف الأصل (أو مجموعة الاستبعاد) محتفظًا به للبيع عند استرداد قيمته الدفترية أساسًا من البيع وكون البيع محتملًا بدرجة عالية، ويُقاس بالأقل من القيمة الدفترية والقيمة العادلة ناقصًا تكاليف البيع، ويتوقف إهلاكه.$k$,$k$اصول محتفظ بها للبيع عمليات متوقفة تصفية بيع مصنع$k$),
($k$IFRS$k$,$k$IFRS 8$k$,$k$القطاعات التشغيلية$k$,$k$Operating Segments$k$,$k$قطاعات$k$,$k$تُفصح المنشآت المدرجة عن القطاعات التشغيلية بحسب ما يراجعه صانع القرار التشغيلي الرئيس، مع مقاييس الربح والأصول والتسويات مع القوائم.$k$,$k$قطاعات تشغيلية تقرير القطاعات صانع القرار$k$),
($k$IFRS$k$,$k$IFRS 9$k$,$k$الأدوات المالية$k$,$k$Financial Instruments$k$,$k$تصنيف وقياس وخسائر ائتمان متوقعة$k$,$k$يصنف الأصول المالية بحسب نموذج الأعمال وخصائص التدفقات إلى التكلفة المطفأة أو القيمة العادلة من خلال الدخل الشامل الآخر أو الربح والخسارة. ويعتمد نموذج الخسائر الائتمانية المتوقعة للاضمحلال: الأسلوب المبسّط للذمم التجارية يقيس المخصص على مدى عمر الأداة غالبًا بمصفوفة مخصصات مبنية على الخبرة التاريخية والتوقعات. ويتناول محاسبة التحوط.$k$,$k$ذمم مدينة خسائر ائتمان متوقعة ecl مخصص ديون مشكوك فيها الاضمحلال الاسلوب المبسط مصفوفة مخصصات ادوات مالية تحوط$k$),
($k$IFRS$k$,$k$IFRS 10 / 11 / 12$k$,$k$القوائم الموحدة والترتيبات المشتركة والإفصاح عن الحصص$k$,$k$Consolidated Financial Statements / Joint Arrangements / Disclosure of Interests$k$,$k$التوحيد$k$,$k$تُوحَّد القوائم عند السيطرة (سلطة وتعرض لعوائد متغيرة وقدرة على التأثير فيها). تُحذف الأرصدة والمعاملات بين شركات المجموعة. الترتيبات المشتركة تُصنَّف عمليات مشتركة أو مشاريع مشتركة. ويُفصح عن الحصص في المنشآت الأخرى.$k$,$k$توحيد القوائم سيطرة حقوق الاقلية حذف المعاملات البينية مجموعة شركات عمليات مشتركة$k$),
($k$IFRS$k$,$k$IFRS 13$k$,$k$قياس القيمة العادلة$k$,$k$Fair Value Measurement$k$,$k$القيمة العادلة$k$,$k$القيمة العادلة سعر الخروج في معاملة منظمة بين متعاملين في السوق في تاريخ القياس، وتُصنَّف مدخلات التقييم في ثلاثة مستويات حسب إمكانية رصدها، مع إفصاحات بحسب المستوى.$k$,$k$قيمة عادلة مستويات مدخلات التقييم سعر الخروج$k$),
($k$IFRS$k$,$k$IFRS 15$k$,$k$الإيراد من العقود مع العملاء$k$,$k$Revenue from Contracts with Customers$k$,$k$اعتراف بالايراد$k$,$k$نموذج من خمس خطوات: تحديد العقد، تحديد التزامات الأداء، تحديد سعر المعاملة، توزيعه على التزامات الأداء، ثم الاعتراف بالإيراد عند (أو كلما) استوفت المنشأة التزام الأداء بنقل السيطرة. تُعرض أصول العقد والتزاماته والدفعات المقدمة وفق ذلك.$k$,$k$ايراد عقود العملاء التزام الاداء سعر المعاملة نقل السيطرة ايراد مؤجل دفعات مقدمة اعتراف مشاريع تحت التنفيذ$k$),
($k$IFRS$k$,$k$IFRS 16$k$,$k$عقود الإيجار$k$,$k$Leases$k$,$k$اجارات$k$,$k$يثبّت المستأجر أصل حق استخدام والتزام إيجار بالقيمة الحالية للدفعات لمعظم العقود، مع إعفاء اختياري للعقود قصيرة الأجل (حتى 12 شهرًا) ومنخفضة القيمة. يُهلك الأصل ويُحمَّل الفائدة على الالتزام. المؤجر يستمر في التصنيف تشغيليًا أو تمويليًا.$k$,$k$ايجار عقد ايجار حق استخدام التزام ايجار مستاجر مؤجر ايجار تمويلي$k$),
($k$IFRS$k$,$k$IFRS 17$k$,$k$عقود التأمين$k$,$k$Insurance Contracts$k$,$k$تأمين$k$,$k$يضع نموذج قياس شامل لعقود التأمين وإعادة التأمين يعتمد على التدفقات المستقبلية المخصومة وهامش الخدمة التعاقدية. يعني منشآت التأمين.$k$,$k$عقود التامين هامش الخدمة التعاقدية$k$),
($k$IFRS$k$,$k$IFRS for SMEs$k$,$k$المعيار الدولي للمنشآت الصغيرة والمتوسطة$k$,$k$IFRS for Small and Medium-sized Entities$k$,$k$منشآت غير مدرجة$k$,$k$إطار مبسط للمنشآت غير ذات المساءلة العامة. تحدد الجهات المحلية، ومنها SOCPA في المملكة، من يطبقه ومتى. تحقق من آخر قرارات الهيئة قبل الاعتماد.$k$,$k$منشات صغيرة ومتوسطة معيار مبسط شركات غير مدرجة$k$),
($k$ISA$k$,$k$ISA 200 / 315 / 330$k$,$k$أهداف المراجع وتقييم المخاطر والاستجابة لها$k$,$k$Overall Objectives / Identifying and Assessing Risks / Responses$k$,$k$منهج المراجعة$k$,$k$يعمل المراجع بتشكك مهني ويحصل على تأكيد معقول بخلو القوائم من التحريف الجوهري. يقيّم مخاطر التحريف الجوهري بفهم المنشأة وبيئة الرقابة الداخلية، ثم يصمم إجراءات مراجعة استجابة لها.$k$,$k$مراجعة مخاطر جوهرية تقييم المخاطر الرقابة الداخلية اجراءات المراجعة تاكيد معقول$k$),
($k$ISA$k$,$k$ISA 240 / 500 / 700$k$,$k$الغش وأدلة المراجعة وتكوين الرأي$k$,$k$The Auditor’s Responsibilities Relating to Fraud / Audit Evidence / Forming an Opinion$k$,$k$ادلة واحتيال$k$,$k$يتطلب شك مهني وتقييم مخاطر الغش ومنها تجاوز الإدارة للرقابة (كالقيود اليدوية غير العادية). أدلة المراجعة يجب أن تكون كافية وملائمة، وتؤسس لرأي المراجع ويصدر تقريره وفق ذلك.$k$,$k$غش احتيال قيود يدوية ادلة المراجعة كفاية ملاءمة رأي المراجع تقرير$k$),
($k$ISA$k$,$k$ISA 570 / 580$k$,$k$الاستمرارية والإقرارات المكتوبة$k$,$k$Going Concern / Written Representations$k$,$k$استمرارية$k$,$k$يقيّم المراجع ملاءمة افتراض الاستمرارية وكفاية الإفصاح عند وجود شك جوهري. ويحصل على إقرارات مكتوبة من الإدارة بمسؤولياتها عن القوائم.$k$,$k$استمرارية شك جوهري اقرارات الادارة$k$),
($k$COSO$k$,$k$COSO ICIF$k$,$k$إطار الرقابة الداخلية المتكامل$k$,$k$Internal Control – Integrated Framework$k$,$k$رقابة داخلية$k$,$k$خمسة مكوّنات: بيئة الرقابة، تقييم المخاطر، أنشطة الرقابة، المعلومات والاتصال، المراقبة، وسبعة عشر مبدأً. من أنشطة الرقابة النمطية فصل المهام والاعتمادات والمطابقات والرقابة على النظم.$k$,$k$رقابة داخلية فصل المهام اعتمادات مطابقات بيئة الرقابة تقييم المخاطر$k$),
($k$ISO$k$,$k$ISO/IEC 27001$k$,$k$نظام إدارة أمن المعلومات$k$,$k$Information Security Management Systems$k$,$k$امن المعلومات$k$,$k$يضع متطلبات نظام إدارة أمن المعلومات القائم على المخاطر، وملحقه يضم ضوابط منها التحكم بالوصول وأقل الصلاحيات والتشفير وسجلات الأحداث وإدارة الحوادث والاستمرارية.$k$,$k$امن المعلومات صلاحيات سجلات تدقيق تشفير نسخ احتياطي حوادث ثغرات$k$),
($k$ZATCA$k$,$k$VAT$k$,$k$ضريبة القيمة المضافة في المملكة$k$,$k$VAT in KSA$k$,$k$ضريبة القيمة المضافة$k$,$k$النظام الضريبي لهيئة الزكاة والضريبة والجمارك يفرض الضريبة على التوريدات ويحدد التسجيل والفواتير الضريبية والإقرارات الدورية والخصم الضريبي للمدخلات وشروطه والتعامل مع الإشعارات الدائنة والمدينة. راجع اللائحة التنفيذية والنسب والاستثناءات السارية قبل التطبيق.$k$,$k$ضريبة القيمة المضافة فاتورة ضريبية اقرار ضريبي خصم مدخلات اشعار دائن توريد نسبة 15 تسجيل ضريبي$k$),
($k$ZATCA$k$,$k$E-Invoicing$k$,$k$الفوترة الإلكترونية (فاتورة)$k$,$k$E-Invoicing (FATOORA)$k$,$k$فاتورة الكترونية$k$,$k$تتطلب الفوترة الإلكترونية إصدار الفواتير بصيغة منظّمة (XML) مع رمز QR وختم تشفير، وعلى مرحلتين: الإصدار والحفظ، ثم الربط والتكامل مع منصة الهيئة وفق موجات تحددها الهيئة. تحقق من موجة المنشأة ومواصفاتها الحالية.$k$,$k$فاتورة الكترونية فوترة xml qr ربط وتكامل مرحلة الاصدار ختم تشفير zatca$k$),
($k$ZATCA$k$,$k$Zakat$k$,$k$الزكاة وضريبة الدخل$k$,$k$Zakat and Income Tax$k$,$k$وعاء الزكاة$k$,$k$تخضع المنشآت المملوكة لسعوديين وخليجيين للزكاة على الوعاء الزكوي بحسب لائحة الجباية، وغير السعودية لضريبة الدخل، والمختلطة لكل بحسب حصتها. تقديم الإقرار والقوائم المراجعة والمستندات الداعمة مطلوب. اعتمد آخر لائحة وتعليمات الهيئة.$k$,$k$زكاة وعاء زكوي ضريبة دخل اقرار زكوي مراجع قانوني حسم$k$),
($k$ZATCA$k$,$k$WHT$k$,$k$ضريبة الاستقطاع$k$,$k$Withholding Tax$k$,$k$استقطاع$k$,$k$تُستقطع ضريبة على بعض المدفوعات لغير المقيمين وفق نسب تختلف بحسب نوع الدفعة، وتُسدَّد للهيئة خلال المدة النظامية مع تقديم نموذج الاستقطاع. راجع الجدول الحالي للنسب.$k$,$k$استقطاع ضريبة مدفوعات لغير مقيم خدمات فوائد ايجار نسب الاستقطاع$k$),
($k$SOCPA$k$,$k$SOCPA$k$,$k$الهيئة السعودية للمراجعين والمحاسبين$k$,$k$Saudi Organization for Chartered and Professional Accountants$k$,$k$المعايير المحلية$k$,$k$تعتمد الهيئة المعايير الدولية للتقرير المالي في المملكة وتصدر معها متطلبات وتفسيرات محلية، ومعايير المراجعة، وتنظم مزاولة المهنة. من يطبق المعايير الكاملة ومن يطبق معيار المنشآت الصغيرة والمتوسطة تحدده قراراتها واللوائح. اطلب النص الرسمي المحدّث من موقع الهيئة.$k$,$k$هيئة المراجعين والمحاسبين السعودية معايير سعودية socpa تبني المعايير الدولية$k$),
($k$SOCPA$k$,$k$Zakat accounting$k$,$k$المعالجة المحاسبية للزكاة$k$,$k$Accounting for Zakat$k$,$k$زكاة في القوائم$k$,$k$تتناول الجهة التنظيمية السعودية المعالجة المحاسبية للزكاة وضريبة الدخل في القوائم المالية بإرشاد خاص، والتوجه العام اختلاف معالجة الزكاة عن ضريبة الدخل في IAS 12. تأكد من آخر إصدار للمعالجة قبل التطبيق.$k$,$k$زكاة مصروف زكاة المعالجة المحاسبية للزكاة وعاء قوائم$k$),
($k$KSA$k$,$k$Companies Law$k$,$k$نظام الشركات$k$,$k$Saudi Companies Law$k$,$k$نظام الشركات$k$,$k$ينظم تأسيس الشركات وأنواعها وحوكمتها وعقود التأسيس وتوزيع الأرباح والاحتياطيات وحسابات الشركة والمراجعين. احرص على تطبيق متطلبات الاحتياطي النظامي ونسب التوزيع الواردة في النظام والعقد.$k$,$k$نظام الشركات احتياطي نظامي توزيع ارباح عقد تاسيس ذات مسؤولية محدودة جمعية الشركاء$k$),
($k$KSA$k$,$k$Labor Law$k$,$k$نظام العمل ومكافأة نهاية الخدمة$k$,$k$Labor Law – End of Service$k$,$k$نهاية الخدمة$k$,$k$يحدد نظام العمل حقوق العاملين ومنها مكافأة نهاية الخدمة والإجازات، وتُقاس محاسبيًا التزاماتها بحسب IAS 19. راجع مواد النظام الحالية لحساب المكافأة بحسب سبب الإنهاء ومدة الخدمة.$k$,$k$نظام العمل مكافأة نهاية الخدمة اجازات استقالة انهاء عقد$k$);

-- ===== ربط بوابة الذكاء الاصطناعي: دوال المعايير والمراجعة تُعرض للنماذج الخارجية وقواعد الاستشهاد =====
do $$ begin
  if to_regprocedure('app.ai_catalog(jsonb)') is null then alter function public.ai_catalog(jsonb) set schema app; end if;
end $$;
create or replace function public.ai_catalog(p jsonb default '{}') returns jsonb language plpgsql stable security definer set search_path = public, app as $$
declare r jsonb := app.ai_catalog(p);
begin
  r := jsonb_set(r, '{functions}', coalesce(r->'functions', '[]'::jsonb) || jsonb_build_array(
    jsonb_build_object('fn', 'kb_search', 'purpose', 'بحث في مكتبة المعايير المرفوعة (IFRS/SOCPA/ZATCA…) مع سند كل نتيجة: الجهة والمعيار والصفحة', 'params', '{q, body?, limit?}'),
    jsonb_build_object('fn', 'kb_list', 'purpose', 'الوثائق المرجعية المرفوعة وإصداراتها', 'params', '{}'),
    jsonb_build_object('fn', 'system_review', 'purpose', 'درجة سلامة النظام وفحوصه مقابل المعايير', 'params', '{asof?, entity?}'),
    jsonb_build_object('fn', 'rpt_equity_changes', 'purpose', 'قائمة التغيرات في حقوق الملكية (IAS 1)', 'params', '{from,to}'),
    jsonb_build_object('fn', 'ecl_preview', 'purpose', 'معاينة الخسائر الائتمانية المتوقعة (IFRS 9)', 'params', '{asof?}')));
  r := jsonb_set(r, '{rules}', coalesce(r->'rules', '[]'::jsonb) || jsonb_build_array(
    'لأي سؤال محاسبي أو نظامي استدعِ kb_search أولًا وأجب من النص المرجعي المرفوع فقط، واذكر السند: الجهة والرمز والإصدار والصفحة.',
    'إن لم تجد نصًا رسميًا فصرّح بذلك ولا تختلق رقم فقرة؛ ما في «map» ملخص للاسترشاد وليس نصًا رسميًا.',
    'ميّز بين ما تقوله المكتبة وما هو اجتهادك، ونبّه إلى مراجعة المحاسب القانوني أو مستشار الزكاة قبل القرار.'));
  return r;
end $$;

revoke execute on function public.kb_ingest(jsonb), public.kb_list(jsonb), public.kb_doc_set(jsonb), public.kb_search(jsonb), public.ai_catalog(jsonb) from public, anon;
grant execute on function public.kb_ingest(jsonb), public.kb_list(jsonb), public.kb_doc_set(jsonb), public.kb_search(jsonb), public.ai_catalog(jsonb) to authenticated;

insert into app.schema_migrations (version, name) values ('1.9.0.0', 'مكتبة المعايير والمراجع: رفع وبحث بالسند وربط المساعد وبوابة الذكاء')
on conflict (version) do nothing;
-- مُحكَم للحسابات 075 — سدّ ثغرة حذف ملفات التخزين + التجميد القانوني وسياسة الاحتفاظ + محادثة الطلبات + كشف الموظف الشخصي

-- ===== 1) ثغرة: سياسة حذف التخزين كانت تسمح لأي مستخدم في الشركة بحذف أي ملف بمسار مباشر، متجاوزةً قفل المستندات =====
-- الإصلاح: لا يُحذف من التخزين إلا ملف غير مسجَّل في جدول المرفقات (أي بعد حذف سجله بالدالة المحمية أو ملف لم يكتمل تسجيله)
create or replace function public.att_registered(p text) returns boolean language sql stable security definer set search_path = public, acc as $$ select exists (select 1 from acc.attachments where path = p) $$;
revoke execute on function public.att_registered(text) from public, anon; grant execute on function public.att_registered(text) to authenticated;
do $$ begin
  if exists (select 1 from information_schema.schemata where schema_name = 'storage') then
    drop policy if exists acc_files_delete on storage.objects;
    create policy acc_files_delete on storage.objects for delete to authenticated using (bucket_id = 'acc-files' and (storage.foldername(name))[1] = public.tenant_folder() and not public.att_registered(name));
  end if;
end $$;

-- ===== 2) التجميد القانوني =====
alter table acc.attachments add column if not exists hold boolean not null default false, add column if not exists hold_reason text not null default '', add column if not exists hold_by uuid, add column if not exists hold_at timestamptz;

create or replace function public.att_hold(p jsonb) returns jsonb language plpgsql security definer set search_path = public, app, acc as $$
declare t uuid := app.need_sys('settings'); h boolean := coalesce((p->>'hold')::boolean, true); rs text := trim(coalesce(p->>'reason', '')); n int;
begin
  if h and length(rs) < 3 then raise exception 'اذكر سبب التجميد (قضية، فحص، تحقيق…)'; end if;
  update acc.attachments set hold = h, hold_reason = case when h then rs else '' end, hold_by = case when h then auth.uid() end, hold_at = case when h then now() end
   where tenant_id = t and ((p->>'id') is not null and id = (p->>'id')::uuid or (p->>'id') is null and owner_type = p->>'owner_type' and owner_id = (p->>'owner_id')::uuid);
  get diagnostics n = row_count; if n = 0 then raise exception 'لا مرفقات مطابقة'; end if;
  perform app.audit(case when h then 'hold' else 'unhold' end, 'attachment', coalesce(p->>'id', p->>'owner_id'), (case when h then 'تجميد قانوني: ' else 'رفع التجميد القانوني: ' end) || coalesce(nullif(rs, ''), '—') || ' (' || n || ' مرفق)');
  return jsonb_build_object('ok', true, 'count', n);
end $$;

create or replace function public.att_delete(p jsonb) returns jsonb language plpgsql security definer set search_path = public, app, acc as $$
declare t uuid := app.need('attachments','delete'); a acc.attachments; locked boolean := false;
begin
  select * into a from acc.attachments where tenant_id = t and id = (p->>'id')::uuid;
  if a.id is null then raise exception 'المرفق غير موجود'; end if;
  if a.hold then raise exception 'المرفق تحت تجميد قانوني (%): لا يُحذف حتى يرفع المدير التجميد', a.hold_reason; end if;
  if a.owner_type = 'journal' then locked := exists (select 1 from acc.journals where tenant_id = t and id = a.owner_id and status in ('posted','reversed','approved')); end if;
  if a.owner_type in ('invoice','payment') then locked := true; end if;
  if locked then raise exception 'المرفق مرتبط بقيد/مستند معتمد أو مرحّل — لا يُحذف (للحفظ والتدقيق)'; end if;
  delete from acc.attachments where tenant_id = t and id = a.id;
  perform app.audit('detach', a.owner_type, a.owner_id::text, 'حذف مرفق ' || a.filename);
  return jsonb_build_object('ok', true, 'path', a.path);
end $$;

create or replace function public.req_detach(p jsonb) returns jsonb language plpgsql security definer set search_path = public, app, acc as $$
declare t uuid := app.need(null, null); a acc.attachments; r acc.requests;
begin
  select * into a from acc.attachments where tenant_id = t and id = (p->>'id')::uuid and owner_type = 'request'; if a.id is null then raise exception 'المرفق غير موجود'; end if;
  if a.hold then raise exception 'المرفق تحت تجميد قانوني'; end if;
  select * into r from acc.requests where tenant_id = t and id = a.owner_id; if r.user_id <> auth.uid() or r.status <> 'draft' then raise exception 'لا يُحذف المرفق بعد رفع الطلب'; end if;
  delete from acc.attachments where tenant_id = t and id = a.id; return jsonb_build_object('ok', true, 'path', a.path);
end $$;

-- فهرس المرفقات يُظهر حالة التجميد
create or replace function public.att_all(p jsonb default '{}') returns jsonb language plpgsql stable security definer set search_path = public, app, acc as $$
declare t uuid := app.need('attachments','view'); ents uuid[] := app.ents(); lim int := least(coalesce(nullif(p->>'limit','')::int, 50), 200); off int := coalesce(nullif(p->>'offset','')::int, 0);
  ty text := nullif(p->>'owner_type',''); q text := nullif(trim(coalesce(p->>'q','')), '');
begin
  return (select jsonb_build_object('total', count(*) over (), 'rows', coalesce(jsonb_agg(x.o order by x.at desc), '[]'::jsonb)) from (
    select a.uploaded_at at, jsonb_build_object('id', a.id, 'filename', a.filename, 'mime', a.mime, 'size', a.size, 'path', a.path, 'uploaded_at', a.uploaded_at, 'by', (select name from acc.members where user_id = a.uploaded_by),
      'owner_type', a.owner_type, 'owner_id', a.owner_id, 'note', a.note, 'hold', a.hold, 'hold_reason', a.hold_reason,
      'owner_label', case a.owner_type
        when 'journal' then (select 'قيد ' || coalesce(j.number, 'مسودة') || ' — ' || left(j.description, 40) from acc.journals j where j.tenant_id = t and j.id = a.owner_id)
        when 'invoice' then (select case i.kind when 'sales' then 'فاتورة مبيعات ' when 'purchase' then 'فاتورة مشتريات ' when 'sales_credit' then 'إشعار دائن ' else 'إشعار مدين ' end || coalesce(i.number, 'مسودة') from acc.invoices i where i.tenant_id = t and i.id = a.owner_id)
        when 'payment' then (select case y.kind when 'receipt' then 'سند قبض ' else 'سند صرف ' end || coalesce(y.number, 'مسودة') from acc.payments y where y.tenant_id = t and y.id = a.owner_id)
        when 'asset' then (select 'أصل ' || s.name from acc.assets s where s.tenant_id = t and s.id = a.owner_id)
        when 'party' then (select 'ملف ' || pa.name from acc.parties pa where pa.tenant_id = t and pa.id = a.owner_id)
        when 'request' then (select 'طلب ' || coalesce(r.number, '') || ' ' || r.title from acc.requests r where r.tenant_id = t and r.id = a.owner_id)
        else a.owner_type end) o
    from acc.attachments a where a.tenant_id = t and (a.entity_id is null or a.entity_id = any(ents)) and (ty is null or a.owner_type = ty)
      and (a.owner_type <> 'request' or app.can('requests','view') or exists (select 1 from acc.requests r where r.tenant_id = t and r.id = a.owner_id and r.user_id = auth.uid()))
      and (q is null or a.filename ilike '%' || q || '%' or a.note ilike '%' || q || '%')
    order by a.uploaded_at desc limit lim offset off) x);
end $$;

-- ===== 3) سياسة الاحتفاظ (إعلامية: لا حذف آلي أبدًا) =====
create or replace function public.retention_save(p jsonb) returns jsonb language plpgsql security definer set search_path = public, app, acc as $$
declare t uuid := app.need_sys('settings'); y int := (p->>'years')::int;
begin
  if y is null or y < 5 or y > 30 then raise exception 'مدة الاحتفاظ بين 5 و30 سنة'; end if;
  update acc.tenants set settings = jsonb_set(coalesce(settings, '{}'), '{retention}', jsonb_build_object('years', y, 'note', left(coalesce(p->>'note', ''), 300), 'confirmed', true, 'confirmed_at', now(), 'confirmed_by', auth.uid())) where id = t;
  perform app.audit('update', 'settings', 'retention', 'سياسة الاحتفاظ بالمستندات: ' || y || ' سنة'); return jsonb_build_object('ok', true, 'years', y);
end $$;

create or replace function public.retention_report(p jsonb default '{}') returns jsonb language plpgsql stable security definer set search_path = public, app, acc as $$
declare t uuid := app.need('controls', 'view'); st jsonb; y int; cutoff date; ents uuid[] := app.pick_ents(p);
begin
  select settings->'retention' into st from acc.tenants where id = t; y := coalesce((st->>'years')::int, 10); cutoff := (current_date - (y || ' years')::interval)::date;
  return jsonb_build_object('years', y, 'confirmed', coalesce((st->>'confirmed')::boolean, false), 'note', coalesce(st->>'note', ''), 'cutoff', cutoff,
    'journals_total', (select count(*) from acc.journals where tenant_id = t and entity_id = any(ents) and status in ('posted','reversed')),
    'journals_past', (select count(*) from acc.journals where tenant_id = t and entity_id = any(ents) and status in ('posted','reversed') and date < cutoff),
    'invoices_past', (select count(*) from acc.invoices where tenant_id = t and entity_id = any(ents) and status <> 'draft' and date < cutoff),
    'payments_past', (select count(*) from acc.payments where tenant_id = t and entity_id = any(ents) and status <> 'draft' and date < cutoff),
    'attachments_total', (select count(*) from acc.attachments where tenant_id = t and (entity_id is null or entity_id = any(ents))),
    'attachments_held', (select count(*) from acc.attachments where tenant_id = t and hold and (entity_id is null or entity_id = any(ents))),
    'held', coalesce((select jsonb_agg(jsonb_build_object('id', a.id, 'filename', a.filename, 'type', a.owner_type, 'reason', a.hold_reason, 'at', a.hold_at) order by a.hold_at desc) from (select * from acc.attachments where tenant_id = t and hold limit 100) a), '[]'),
    'note_policy', 'السياسة إعلامية: النظام لا يحذف مستندات آليًا. تحقق من مدة الاحتفاظ النظامية المطبّقة على منشأتك (الأنظمة التجارية والضريبية) مع مستشارك.');
end $$;

-- ===== 4) محادثة الطلبات (موظف ↔ المالية) =====
create table if not exists acc.req_comments (
  tenant_id uuid not null references acc.tenants(id) on delete cascade, id uuid not null default gen_random_uuid(), request_id uuid not null, user_id uuid not null, body text not null check (length(body) between 1 and 2000), created_at timestamptz not null default now(),
  primary key (tenant_id, id), foreign key (tenant_id, request_id) references acc.requests (tenant_id, id) on delete cascade
);
create index if not exists req_comments_req on acc.req_comments (tenant_id, request_id, created_at);
alter table acc.req_comments enable row level security;

create or replace function app.req_access(t uuid, rid uuid) returns acc.requests language plpgsql stable security definer set search_path = public, app, acc as $$
declare r acc.requests; fin boolean := app.can('requests', 'view');
begin
  select * into r from acc.requests where tenant_id = t and id = rid; if r.id is null then raise exception 'الطلب غير موجود'; end if;
  if not (r.user_id = auth.uid() or (fin and r.entity_id = any(app.ents()))) then raise exception 'الطلب غير موجود'; end if;
  return r;
end $$;

create or replace function public.req_comments(p jsonb) returns jsonb language plpgsql stable security definer set search_path = public, app, acc as $$
declare t uuid := app.need(null, null); r acc.requests := app.req_access(t, (p->>'id')::uuid);
begin
  return coalesce((select jsonb_agg(jsonb_build_object('id', c.id, 'at', c.created_at, 'body', c.body, 'by', coalesce((select m.name from acc.members m where m.user_id = c.user_id), '—'), 'mine', c.user_id = auth.uid(), 'owner', c.user_id = r.user_id) order by c.created_at)
    from acc.req_comments c where c.tenant_id = t and c.request_id = r.id), '[]');
end $$;

create or replace function public.req_comment_add(p jsonb) returns jsonb language plpgsql security definer set search_path = public, app, acc as $$
declare t uuid := app.need(null, null); r acc.requests := app.req_access(t, (p->>'id')::uuid); b text := trim(coalesce(p->>'body', '')); id uuid;
begin
  if length(b) < 1 then raise exception 'اكتب رسالتك'; end if; if length(b) > 2000 then raise exception 'الرسالة أطول من 2000 حرف'; end if;
  if r.status = 'cancelled' then raise exception 'الطلب ملغى'; end if;
  insert into acc.req_comments (tenant_id, request_id, user_id, body) values (t, r.id, auth.uid(), b) returning acc.req_comments.id into id;
  perform app.audit('comment', 'request', r.id::text, 'رسالة على الطلب ' || coalesce(r.number, ''));
  return jsonb_build_object('id', id);
end $$;

-- ===== 5) كشفي: ما لي وما عليّ (للموظف) =====
create or replace function public.my_statement(p jsonb default '{}') returns jsonb language plpgsql stable security definer set search_path = public, app, acc as $$
declare t uuid := app.need('portal', 'view'); pid uuid; d_from date := coalesce(nullif(p->>'from', '')::date, date_trunc('year', current_date)::date); d_to date := coalesce(nullif(p->>'to', '')::date, current_date);
  opening numeric := 0; lines jsonb; pname text;
begin
  select party_id into pid from acc.employee_links where tenant_id = t and user_id = auth.uid();
  if pid is not null then
    select name into pname from acc.parties where tenant_id = t and id = pid;
    select coalesce(sum(debit - credit), 0) into opening from acc.journal_lines where tenant_id = t and party_id = pid and posted and date < d_from;
    select coalesce(jsonb_agg(jsonb_build_object('date', x.date, 'journal', x.number, 'description', x.description, 'debit', x.debit, 'credit', x.credit, 'balance', opening + x.run) order by x.date, x.number, x.line_no), '[]') into lines
    from (select l.date, j.number, l.line_no, l.description, l.debit, l.credit, sum(l.debit - l.credit) over (order by l.date, j.number, l.line_no) run
          from acc.journal_lines l join acc.journals j on j.tenant_id = l.tenant_id and j.id = l.journal_id where l.tenant_id = t and l.party_id = pid and l.posted and l.date between d_from and d_to) x;
  end if;
  return jsonb_build_object('from', d_from, 'to', d_to, 'linked', pid is not null, 'party', pname, 'opening', opening, 'lines', coalesce(lines, '[]'),
    'closing', case when pid is null then 0 else opening + coalesce((select sum(debit - credit) from acc.journal_lines where tenant_id = t and party_id = pid and posted and date between d_from and d_to), 0) end,
    'requests', (select coalesce(jsonb_object_agg(status, jsonb_build_object('count', n, 'amount', amt)), '{}') from (select status, count(*) n, coalesce(sum(amount), 0) amt from acc.requests where tenant_id = t and user_id = auth.uid() and coalesce(date, created_at::date) between d_from and d_to group by status) s),
    'note', 'الرصيد الموجب: لك على الشركة بحسب تعريف حسابك؛ راجع المالية لأي فرق.');
end $$;

revoke execute on function public.att_hold(jsonb), public.retention_save(jsonb), public.retention_report(jsonb), public.req_comments(jsonb), public.req_comment_add(jsonb), public.my_statement(jsonb) from public, anon;
grant execute on function public.att_hold(jsonb), public.retention_save(jsonb), public.retention_report(jsonb), public.req_comments(jsonb), public.req_comment_add(jsonb), public.my_statement(jsonb) to authenticated;

insert into app.schema_migrations (version, name) values ('1.9.0.0', 'مكتبة المعايير + سدّ ثغرة حذف التخزين + التجميد القانوني والاحتفاظ + محادثة الطلبات + كشف الموظف')
on conflict (version) do nothing;
