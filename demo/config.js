// إعداد الاتصال بـ Supabase + النسخة التجريبية (الدخول السريع بالأدوار). احذف ACC_DEMO في نسخة الإنتاج.
window.ACC_CLOUD = {
  url: 'https://mltyzkaxfdkbqcfxbrkv.supabase.co',
  key: 'sb_publishable_7VlBCqOaVLHgmyD4qh2TVw_K0YyZGoJ',
};
window.ACC_DEMO = {
  code: 'group5', password: 'Group#Demo2026x',
  users: [
    { u: 'owner', label: 'المالك', hint: 'كل الصلاحيات' },
    { u: 'gm', label: 'المدير العام', hint: 'اعتماد وتقارير' },
    { u: 'cfo', label: 'المدير المالي', hint: 'الاعتماد المالي والتحليل' },
    { u: 'chief', label: 'رئيس الحسابات', hint: 'مراجعة وترحيل' },
    { u: 'acct', label: 'محاسب', hint: 'إدخال القيود' },
    { u: 'ar', label: 'محاسب العملاء', hint: 'المبيعات والتحصيل' },
    { u: 'ap', label: 'محاسب الموردين', hint: 'المشتريات والسداد' },
    { u: 'cashier', label: 'أمين الصندوق والبنوك', hint: 'السندات والبنوك' },
    { u: 'auditor', label: 'المراجع الداخلي', hint: 'اطلاع وتدقيق' },
    { u: 'employee', label: 'موظف', hint: 'بوابة الموظف' },
    { u: 'viewer', label: 'قراءة فقط', hint: 'بدون تعديل' },
  ],
};
