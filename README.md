# سويتش واي فاي - تحكم عن بعد (Cloudflare Workers)

بيعمل: تشغيل/إطفاء، مؤقت، جدولة بمواعيد، أكتر من سويتش، إشعارات على الموبايل، وسجل نشاط في الإعدادات.
الشكل بيتغير تلقائي مع وضع الموبايل (غامق/فاتح).
بتدخل بكود واحد، وبيجيب كل الأجهزة المربوطة بحساب Smart Life تلقائي.

> للتشغيل من Android Studio + GitHub شوف ملف **SETUP-GITHUB.md**

## الإعداد (مرة واحدة)

1. **Tuya**: اعمل Cloud Project على iot.tuya.com واربط حساب Smart Life (Devices > Link App Account).
   من Project Overview خد Access ID و Access Secret.
   (لو الأجهزة مش بتظهر، تأكد إن الـ API اسمه "Smart Home Scene Linkage" / "Authorization Token Management" / "Device Status Notification" / "IoT Core" متضافين للمشروع.)
2. افتح الفولدر في Terminal ونفذ:
   ```
   npm install
   npx wrangler login
   npx wrangler kv namespace create KV
   ```
   الأمر الأخير هيطلعلك `id` — الصقه في `wrangler.toml` مكان `حط_ID_بتاع_KV_هنا`.
3. في `wrangler.toml` اظبط `TUYA_ENDPOINT` حسب منطقة مشروعك (اوروبا الافتراضي).
4. الأسرار (كل أمر هيسألك تكتب القيمة):
   ```
   npx wrangler secret put TUYA_ACCESS_ID
   npx wrangler secret put TUYA_ACCESS_KEY
   npx wrangler secret put ACCESS_CODE      <- الكود اللي هتدخل بيه انت والناس
   npx wrangler secret put SESSION_SECRET   <- أي نص عشوائي طويل
   ```
5. **الإشعارات** (مرة واحدة):
   ```
   npm run vapid
   ```
   هيطبع سطر JSON. انسخه وبعدين:
   ```
   npx wrangler secret put VAPID_PRIVATE_JWK   <- الصق السطر ده
   ```
   وغيّر `VAPID_SUBJECT` في `wrangler.toml` لإيميلك.
6. `npm run deploy` وهيديك رابط `...workers.dev`. افتحه من الموبايل واعمل Add to Home Screen، وبعدين من الإعدادات داخل التطبيق دوس "فعّل الإشعارات" (على كل جهاز لوحده).

## ملاحظات
- الجداول والمؤقتات بتتنفذ في ثانيتها بالظبط، من السيرفر (Durable Object بيصحى في الميعاد)، فمش محتاجة الموبايل يكون مفتوح. أي تأخير بسيط هيبقى بس وقت رد Tuya (حوالي ثانية أو أقل). الـ Cron كل دقيقة بقى شبكة أمان وفحص النت بس.
- الـ Durable Object متاح في الخطة المجانية (بنستخدم نسخة SQLite)، ومفيش حاجة تعملها غير `npm run deploy`.
- التوقيت بتوقيت القاهرة (بيتعامل مع التوقيت الصيفي لوحده).
- الكود يتقفل 15 دقيقة بعد 5 محاولات غلط من نفس الشبكة.
- لو عايز تحدد أجهزة معينة بس: فك التعليق عن `TUYA_DEVICE_IDS` في `wrangler.toml`.
- أي تعديل في الكود: `npm run deploy` تاني.
- الإشعارات بتوصل: لما جدول أو مؤقت يتنفذ (أو يفشل)، ولما سويتش يفصل من النت (بعد قراءتين ورا بعض، يعني حوالي 10 دقايق) ولما يرجع.
- فحص النت بيتم كل 5 دقايق علشان مايستهلكش حصة Tuya API. لو حصة مشروعك قليلة، شوفها من صفحة المشروع في Tuya.
- على الآيفون الإشعارات بتشتغل بس لو أضفت التطبيق للشاشة الرئيسية (iOS 16.4 أو أحدث).
