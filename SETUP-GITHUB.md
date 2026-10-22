# التشغيل عن طريق Android Studio + GitHub + Cloudflare

الفكرة: ترفع المشروع على GitHub، وCloudflare يقرأه من هناك **أول مرة بس**.
بعد كده أي تعديل تعمله، تكتب `npm run deploy` في Terminal بتاع Android Studio فيتحدّث على Cloudflare مباشرة.

## المتطلبات
- Node.js (نسخة 18 أو أحدث) و Git منزّلين على الجهاز
- حساب GitHub وحساب Cloudflare
- Android Studio: افتح الفولدر من File > Open (الـ Terminal بتلاقيه تحت في الشاشة)

## 1) جهّز المشروع (مرة واحدة)

في Terminal جوه Android Studio:

```
npm install
npm run login
npm run kv:create
```

الأمر الأخير هيطبع `id`. الصقه في `wrangler.toml` مكان `حط_ID_بتاع_KV_هنا`.
وغيّر كمان `VAPID_SUBJECT` لإيميلك، و`TUYA_ENDPOINT` لو منطقة مشروع Tuya مش أوروبا.

> الـ id ده مش سر، عادي يتحط في الريبو. بس خلّي الريبو **Private**.

## 2) ارفع على GitHub

اعمل ريبو جديد Private على github.com (فاضي، من غير README)، وبعدين:

```
git init
git add .
git commit -m "first commit"
git branch -M main
git remote add origin https://github.com/USERNAME/switch-control.git
git push -u origin main
```

(أو من Android Studio: Git > Create Git Repository، وبعدين Git > GitHub > Share Project on GitHub.)

## 3) اربط Cloudflare بالريبو (أول مرة)

1. Cloudflare Dashboard > Workers & Pages > Create > **Import a repository**
2. اختار حساب GitHub والريبو
3. اسم الـ Worker لازم يكون `switch-control` (نفس `name` في `wrangler.toml`)
4. Build command: سيبه فاضي. Deploy command: `npx wrangler deploy`
5. دوس Deploy

## 4) الأسرار (مرة واحدة، من Terminal)

```
npm run secrets
npm run vapid
npm run secret:vapid
```

- `npm run secrets` هيسألك على: TUYA_ACCESS_ID, TUYA_ACCESS_KEY, ACCESS_CODE, SESSION_SECRET
- `npm run vapid` يطلع سطر JSON، انسخه والصقه لما `npm run secret:vapid` يسألك

الأسرار بتفضل محفوظة على Cloudflare ومش بتتمسح مع أي Deploy جديد.

## 5) التحديث بعد كده

عدّل الكود في Android Studio وبعدين:

```
npm run deploy
```

ده بيرفع الملفات على Cloudflare مباشرة من جهازك.
ولو عايز الكود يفضل متزامن على GitHub كمان:

```
git add .
git commit -m "وصف التعديل"
git push
```

### مهم: تجنب التحديث المزدوج
بعد ما تربط الريبو في الخطوة 3، Cloudflare هيعمل Deploy تلقائي مع كل `git push`.
اختار واحدة من الاتنين:

- **تحديث بالأمر بس** (زي ما طلبت): من Cloudflare > الـ Worker > Settings > Builds > **Branch control**، وقف الـ "Automatic deployments" (Disable non-production / production branch builds حسب الواجهة). كده الـ push بيحفظ على GitHub بس، و`npm run deploy` هو اللي بيحدّث.
- **تحديث تلقائي**: سيب الإعدادات زي ما هي، و`git push` لوحده كفاية.

## أوامر مفيدة
| الأمر | بيعمل إيه |
|---|---|
| `npm run deploy` | يحدّث الـ Worker على Cloudflare |
| `npm run dev` | تجربة محلية (محتاج `.dev.vars`، انسخه من `.dev.vars.example`) |
| `npm run logs` | يعرض اللوج المباشر من Cloudflare، مفيد لو في error |
