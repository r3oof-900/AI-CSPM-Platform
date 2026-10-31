# معمل الاختبار المعياري الموحد (Unified Cross-Layer Vulnerable Benchmark Lab)
## إثبات فجوات أدوات CSPM في تحليل مسار الهجوم (Kubernetes Pod → IRSA → IAM → KMS)

---

### 1. نظرة عامة والهدف الأكاديمي (Research Motivation)
يقوم هذا المعمل المعياري على بناء سيناريو حقيقي متصل يربط بين ثلاث طبقات سحابية:
1. **طبقة الحاويات (Kubernetes Workload Tier):** تطبيق دفع مالي `payment-processing-pod` يعمل بحساب خدمة `payment-service-sa`.
2. **طبقة تفويض الهوية السحابية (AWS IAM & IRSA Tier):** دور سحابي حقيقي `eks-payment-kms-role` يتم تفويضه عبر مزود الهوية المفتوح (EKS OIDC Provider) ويحمل سياسة بصلاحية مفرطة `kms:Decrypt` على مورد عام (`Resource: "*"`).
3. **طبقة المفاتيح والبيانات الحساسة (AWS KMS & S3 Tier):** مفتاح تشفير مدار من العميل (CMK) باسم `alias/payment-vault-cmk` يشفر خزينة بيانات مالية في S3.

---

### 2. مسار الهجوم المستهدف (Target Attack Vector)
```
[ Kubernetes Pod: payment-processing-pod ]
                     │
                     ▼  (serviceAccountName)
[ ServiceAccount: payment-service-sa ]
                     │
                     ▼  (eks.amazonaws.com/role-arn via OIDC Federation)
[ AWS IAM Role: eks-payment-kms-role ]
                     │
                     ▼  (Overprivileged Policy: kms:Decrypt on "*")
[ AWS KMS Key: alias/payment-vault-cmk ] ──► [ Decrypt Financial Data Vault ]
```

---

### 3. المقارنة المنهجية للفجوات بين الأدوات السبعة وحل مشروعنا

| الأداة المختبرة | ما تراه الأداة وتكشفه | الفجوة العملية المثبتة (Research Gap) | حل مشروعنا المقترح (AI-CSPM) |
| :--- | :--- | :--- | :--- |
| **Checkov** | يفحص كود K8s وتيرافورم، ويكشف مخالفات معزولة في كل ملف. | يُخرج مصفوفتين مستقلتين (`kubernetes` و `terraform`) ولا يربط الـ ServiceAccount بالدور ومفتاح KMS. | يوحد مخرجات IaC مع بيانات السحابة في رسم بياني واحد. |
| **Trivy** | يكتشف ثغرات الحاويات والأخطاء التكوينية (Misconfigurations). | يفحص كل ملف بشكل منعزل دون إدراك لسلسلة الهجوم العابرة للطبقات. | يبني مسار الهجوم التكاملي التلقائي. |
| **Kubescape** | يقرأ الـ Annotation الخاص بـ IRSA على ServiceAccount. | لا يتصل بـ AWS IAM APIs لتقييم ما إذا كان الدور يملك صلاحيات خطيرة على KMS. | يتتبع الـ Role السحابي ويحلل صلاحياته الفعلية. |
| **kube-bench** | يفحص إعدادات العقد وخوادم التحكم وفق معايير CIS. | محصور تماماً داخل العنقود، أعمى عن هويات IAM ومفاتيح التشفير. | يربط نتائج CIS بهويات الحاويات ومسارات الوصول السحابية. |
| **AWS IAM Access Analyzer** | يفحص سياسة `kms:Decrypt` على `*`. | يعيد `findings: []` لأن السياسة صحيحة صياغياً ونحوياً، رغم أنها كارثية سياقياً. | يقيّم الخطورة وفق المورد والسياق التشغيلي ومسار الوصول. |
| **Prowler v5** | يفحص إعدادات IAM وKMS في AWS. | لا يربط دور IAM بالـ Pod داخل كوبرنيتس في مسار خطر واحد مخصص. | يربط المسار كاملاً من الـ Pod إلى المفتاح ويرتب الأولوية. |
| **Cloud Custodian** | يكتشف الدور والمفتاح عبر قواعد YAML مسبقة. | يتطلب سياستين منفصلتين، وإجراءاته ميكانيكية مسبقة (مثل حذف الدور وتعطيل التطبيق). | يولد سياسة Least-Privilege ذكية دون تعطيل الخدمة. |
| **ScoutSuite** | يعرض تقرير أمان لخدمات AWS. | يعزل خدمات IAM وKMS في صفحات مستقلة ولا يوفر تتبعاً تفاعلياً لهوية كوبرنيتس. | لوحة تحكم تفاعلية توضح سلسلة الهجوم عبر الموارد. |
