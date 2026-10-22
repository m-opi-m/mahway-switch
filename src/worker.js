import INDEX_HTML from "./index.html";

const enc = new TextEncoder();
const SESSION_DAYS = 30;
const TZ = "Africa/Cairo";

/* ---------------- أدوات عامة ---------------- */
const hex = (buf) => [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, "0")).join("");
const sha256Hex = async (s) => hex(await crypto.subtle.digest("SHA-256", enc.encode(s)));
async function hmacRaw(key, msg) {
  const k = await crypto.subtle.importKey("raw", enc.encode(key), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  return crypto.subtle.sign("HMAC", k, enc.encode(msg));
}
function b64url(buf) {
  let s = "";
  for (const b of new Uint8Array(buf)) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
function ctEqual(a, b) {
  if (a.length !== b.length) return false;
  let r = 0;
  for (let i = 0; i < a.length; i++) r |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return r === 0;
}
const json = (data, status = 200, headers = {}) =>
  new Response(JSON.stringify(data), {
    status,
    headers: { "content-type": "application/json; charset=utf-8", "cache-control": "no-store", ...headers },
  });
const kget = async (env, key, def) => JSON.parse((await env.KV.get(key)) || "null") ?? def;
const kput = (env, key, val) => env.KV.put(key, JSON.stringify(val));

function cairoNow(ts = Date.now()) {
  const parts = new Intl.DateTimeFormat("en-GB", {
    timeZone: TZ, hour: "2-digit", minute: "2-digit", weekday: "short", hourCycle: "h23",
  }).formatToParts(ts);
  const get = (t) => parts.find((p) => p.type === t).value;
  const days = { Sun: 0, Mon: 1, Tue: 2, Wed: 3, Thu: 4, Fri: 5, Sat: 6 };
  return { hm: `${get("hour")}:${get("minute")}`, day: days[get("weekday")] };
}

/* ---------------- الدخول بالكود ---------------- */
async function makeSession(env) {
  const payload = b64url(enc.encode(JSON.stringify({ exp: Date.now() + SESSION_DAYS * 864e5 })));
  return `${payload}.${b64url(await hmacRaw(env.SESSION_SECRET, payload))}`;
}
async function validSession(env, request) {
  const m = /(?:^|;\s*)s=([^;]+)/.exec(request.headers.get("cookie") || "");
  if (!m) return false;
  const [payload, sig] = m[1].split(".");
  if (!payload || !sig) return false;
  if (!ctEqual(sig, b64url(await hmacRaw(env.SESSION_SECRET, payload)))) return false;
  try {
    return JSON.parse(atob(payload.replace(/-/g, "+").replace(/_/g, "/"))).exp > Date.now();
  } catch {
    return false;
  }
}
async function login(request, env) {
  const key = `fail:${request.headers.get("cf-connecting-ip") || "x"}`;
  const rec = await kget(env, key, null);
  if (rec && rec.n >= 5 && Date.now() - rec.t < 15 * 60000) {
    return json({ error: "محاولات كتير، جرّب بعد شوية" }, 429);
  }
  const { code = "" } = await request.json().catch(() => ({}));
  const a = await sha256Hex("c:" + String(code));
  const b = await sha256Hex("c:" + env.ACCESS_CODE);
  if (!ctEqual(a, b)) {
    await env.KV.put(key, JSON.stringify({ n: (rec?.n || 0) + 1, t: Date.now() }), { expirationTtl: 900 });
    return json({ error: "الكود غلط" }, 401);
  }
  await env.KV.delete(key);
  const cookie = `s=${await makeSession(env)}; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=${SESSION_DAYS * 86400}`;
  return json({ ok: true }, 200, { "set-cookie": cookie });
}

/* ---------------- Tuya Cloud ---------------- */
let tokenCache = { token: "", exp: 0 };

async function tuyaRequest(env, method, path, body, withToken = true) {
  const t = Date.now().toString();
  const bodyStr = body ? JSON.stringify(body) : "";
  const token = withToken ? await getToken(env) : "";
  const stringToSign = [method, await sha256Hex(bodyStr), "", path].join("\n");
  const sign = (hex(await hmacRaw(env.TUYA_ACCESS_KEY, env.TUYA_ACCESS_ID + token + t + stringToSign))).toUpperCase();
  const headers = { client_id: env.TUYA_ACCESS_ID, sign, t, sign_method: "HMAC-SHA256" };
  if (token) headers.access_token = token;
  if (body) headers["Content-Type"] = "application/json";
  const res = await fetch(env.TUYA_ENDPOINT + path, { method, headers, body: body ? bodyStr : undefined });
  return res.json();
}
async function getToken(env) {
  if (tokenCache.token && Date.now() < tokenCache.exp - 60000) return tokenCache.token;
  // الكاش في KV علشان كل تشغيل للـ cron مايطلبش توكن جديد (بيوفر استهلاك الـ API)
  const saved = await kget(env, "tuya_token", null);
  if (saved && Date.now() < saved.exp - 60000) {
    tokenCache = saved;
    return saved.token;
  }
  const r = await tuyaRequest(env, "GET", "/v1.0/token?grant_type=1", null, false);
  if (!r.success) throw new Error(`Tuya token: ${r.msg || r.code}`);
  tokenCache = { token: r.result.access_token, exp: Date.now() + r.result.expire_time * 1000 };
  await kput(env, "tuya_token", tokenCache);
  return tokenCache.token;
}
const tuyaErr = (r) => new Error(`Tuya: ${r.msg || r.code}`);

async function listDevices(env) {
  if (env.TUYA_DEVICE_IDS) {
    const ids = env.TUYA_DEVICE_IDS.split(",").map((s) => s.trim()).filter(Boolean);
    return Promise.all(ids.map(async (id) => {
      const r = await tuyaRequest(env, "GET", `/v1.0/devices/${id}`);
      if (!r.success) throw tuyaErr(r);
      return { id, name: r.result.name, online: r.result.online };
    }));
  }
  const out = [];
  let last = "";
  for (let i = 0; i < 5; i++) {
    const q = last ? `?last_row_key=${encodeURIComponent(last)}` : "";
    const r = await tuyaRequest(env, "GET", `/v1.0/iot-01/associated-users/devices${q}`);
    if (!r.success) throw tuyaErr(r);
    out.push(...(r.result.devices || []));
    if (!r.result.has_more) break;
    last = r.result.last_row_key;
  }
  return out.map((d) => ({ id: d.id, name: d.name, online: d.online }));
}

async function listChannels(env) {
  const devices = await listDevices(env);
  const lists = await Promise.all(devices.map(async (d) => {
    const r = await tuyaRequest(env, "GET", `/v1.0/devices/${d.id}/status`);
    if (!r.success) return [];
    const sw = (r.result || []).filter((x) => /^switch(_\d+)?$/.test(x.code));
    return sw.map((x) => ({
      key: `${d.id}:${x.code}`,
      name: sw.length > 1 ? `${d.name} (${x.code.replace("switch_", "")})` : d.name,
      online: !!d.online,
      on: !!x.value,
    }));
  }));
  return lists.flat();
}

const okKey = (k) => typeof k === "string" && /^[A-Za-z0-9_-]+:switch(_\d+)?$/.test(k);

async function setSwitch(env, key, on) {
  const [id, code] = key.split(":");
  const r = await tuyaRequest(env, "POST", `/v1.0/devices/${id}/commands`, { commands: [{ code, value: !!on }] });
  if (!r.success) throw tuyaErr(r);
}

/* ---------------- الإشعارات (Web Push) ---------------- */
const b64uToBytes = (s) => {
  s = s.replace(/-/g, "+").replace(/_/g, "/");
  return Uint8Array.from(atob(s + "=".repeat((4 - (s.length % 4)) % 4)), (c) => c.charCodeAt(0));
};
const concat = (...arrs) => {
  const out = new Uint8Array(arrs.reduce((n, a) => n + a.length, 0));
  let o = 0;
  for (const a of arrs) { out.set(a, o); o += a.length; }
  return out;
};
let vapidCache = null;
async function getVapid(env) {
  if (!env.VAPID_PRIVATE_JWK) return null;
  if (vapidCache) return vapidCache;
  const jwk = JSON.parse(env.VAPID_PRIVATE_JWK);
  delete jwk.key_ops; delete jwk.ext;
  const key = await crypto.subtle.importKey("jwk", jwk, { name: "ECDSA", namedCurve: "P-256" }, false, ["sign"]);
  const pub = concat(new Uint8Array([4]), b64uToBytes(jwk.x), b64uToBytes(jwk.y));
  return (vapidCache = { key, pubB64: b64url(pub) });
}
async function vapidHeader(env, endpoint, v) {
  const hdr = b64url(enc.encode(JSON.stringify({ typ: "JWT", alg: "ES256" })));
  const pl = b64url(enc.encode(JSON.stringify({
    aud: new URL(endpoint).origin,
    exp: Math.floor(Date.now() / 1000) + 12 * 3600,
    sub: env.VAPID_SUBJECT || "mailto:admin@example.com",
  })));
  const sig = await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, v.key, enc.encode(`${hdr}.${pl}`));
  return `vapid t=${hdr}.${pl}.${b64url(sig)}, k=${v.pubB64}`;
}
async function hkdf(salt, ikm, info, len) {
  const k = await crypto.subtle.importKey("raw", ikm, "HKDF", false, ["deriveBits"]);
  return new Uint8Array(await crypto.subtle.deriveBits({ name: "HKDF", hash: "SHA-256", salt, info }, k, len * 8));
}
// تشفير الرسالة حسب RFC 8291 (aes128gcm)
async function encryptPayload(sub, payload) {
  const ua = b64uToBytes(sub.keys.p256dh);
  const auth = b64uToBytes(sub.keys.auth);
  const eph = await crypto.subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, true, ["deriveBits"]);
  const asPub = new Uint8Array(await crypto.subtle.exportKey("raw", eph.publicKey));
  const uaKey = await crypto.subtle.importKey("raw", ua, { name: "ECDH", namedCurve: "P-256" }, false, []);
  const secret = new Uint8Array(await crypto.subtle.deriveBits({ name: "ECDH", public: uaKey }, eph.privateKey, 256));
  const prk = await hkdf(auth, secret, concat(enc.encode("WebPush: info\0"), ua, asPub), 32);
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const cek = await hkdf(salt, prk, enc.encode("Content-Encoding: aes128gcm\0"), 16);
  const nonce = await hkdf(salt, prk, enc.encode("Content-Encoding: nonce\0"), 12);
  const aes = await crypto.subtle.importKey("raw", cek, "AES-GCM", false, ["encrypt"]);
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv: nonce }, aes, concat(payload, new Uint8Array([2]))));
  return concat(salt, new Uint8Array([0, 0, 0x10, 0, 65]), asPub, ct);
}
async function sendPush(env, payload) {
  const v = await getVapid(env);
  if (!v) return;
  const subs = await kget(env, "subs", []);
  if (!subs.length) return;
  const body = enc.encode(JSON.stringify(payload));
  const dead = new Set();
  await Promise.all(subs.map(async (s) => {
    try {
      const res = await fetch(s.endpoint, {
        method: "POST",
        headers: {
          Authorization: await vapidHeader(env, s.endpoint, v),
          "Content-Encoding": "aes128gcm", "Content-Type": "application/octet-stream", TTL: "3600", Urgency: "high",
        },
        body: await encryptPayload(s, body),
      });
      if (res.status === 404 || res.status === 410) dead.add(s.endpoint);
    } catch { /* تجاهل */ }
  }));
  if (dead.size) await kput(env, "subs", (await kget(env, "subs", [])).filter((s) => !dead.has(s.endpoint)));
}

/* ---------------- مراقبة النت بتاع الأجهزة ---------------- */
async function checkOnline(env) {
  const devices = await listDevices(env);
  const st = await kget(env, "online", {});
  const out = [];
  for (const d of devices) {
    const prev = st[d.id] || { off: 0, notified: false };
    if (d.online) {
      if (prev.notified) out.push({ title: "رجع للنت", body: `${d.name} رجع متصل`, tag: "online-" + d.id });
      st[d.id] = { off: 0, notified: false };
    } else {
      const off = prev.off + 1;
      let notified = prev.notified;
      if (off >= 2 && !notified) {
        out.push({ title: "فصل من النت", body: `${d.name} مش متصل`, tag: "online-" + d.id });
        notified = true;
      }
      st[d.id] = { off, notified };
    }
  }
  await kput(env, "online", st);
  return out;
}

/* ---------------- السجل ---------------- */
async function logHistory(env, entries) {
  const h = await kget(env, "history", []);
  h.unshift(...entries);
  await kput(env, "history", h.slice(0, 100));
}

/* ---------------- التنفيذ في ميعاده بالظبط (Durable Object) ---------------- */
// الـ Cron أقل حاجة فيه دقيقة، فالتنفيذ بيتم بـ alarm بيصحى في الثانية المطلوبة.
async function runDue(env) {
  const real = Date.now();
  const now = real % 60000 > 59000 ? real + 1000 : real; // لو الـ alarm صحي بدري جدًا بجزء من الثانية
  const { hm, day } = cairoNow(now);
  const stamp = Math.floor(now / 60000);
  const logs = [];
  const run = async (item, src) => {
    const base = { t: Date.now(), name: item.name || item.key, on: item.on, src };
    try {
      await setSwitch(env, item.key, item.on);
      logs.push({ ...base, ok: true });
    } catch (e) {
      logs.push({ ...base, ok: false, err: String(e.message || e).slice(0, 120) });
    }
  };

  const schedules = await kget(env, "schedules", []);
  const dueS = schedules.filter((s) => s.enabled && s.time === hm && s.days.includes(day) && s.last !== stamp);
  dueS.forEach((s) => (s.last = stamp));
  const timers = await kget(env, "timers", []);
  const dueT = timers.filter((t) => t.at <= now + 50);

  if (dueS.length) await kput(env, "schedules", schedules);
  if (dueT.length) await kput(env, "timers", timers.filter((t) => t.at > now + 50));
  await Promise.all([...dueS.map((s) => run(s, "schedule")), ...dueT.map((t) => run(t, "timer"))]);
  if (!logs.length) return;
  await logHistory(env, logs);

  const notes = logs.map((l) => ({
    title: l.ok ? "اتنفذ" : "فشل التنفيذ",
    body: l.ok
      ? `${l.name}: ${l.on ? "اتشغّل" : "اتطفى"} (${l.src === "timer" ? "مؤقت" : "جدول"})`
      : `مقدرتش ${l.on ? "اشغّل" : "اطفي"} ${l.name}`,
    tag: "run-" + l.t,
  }));
  await Promise.all(notes.map((n) => sendPush(env, n)));
}

// أقرب وقت لازم الـ alarm يصحى فيه: أقرب مؤقت، أو بداية الدقيقة الجاية لو في جدول مفعّل
async function nextAlarmAt(env, now) {
  const schedules = await kget(env, "schedules", []);
  const timers = await kget(env, "timers", []);
  let at = Infinity;
  for (const t of timers) at = Math.min(at, t.at);
  if (schedules.some((s) => s.enabled)) at = Math.min(at, (Math.floor(now / 60000) + 1) * 60000);
  return at;
}
const armScheduler = (env) => env.SCHED.get(env.SCHED.idFromName("main")).fetch("https://scheduler/arm", { method: "POST" });

export class Scheduler {
  constructor(ctx, env) {
    this.ctx = ctx;
    this.env = env;
  }
  async arm() {
    const at = await nextAlarmAt(this.env, Date.now());
    if (at === Infinity) await this.ctx.storage.deleteAlarm();
    else await this.ctx.storage.setAlarm(Math.max(at, Date.now() + 10));
  }
  async fetch() {
    await this.arm();
    return new Response("ok");
  }
  async alarm() {
    try {
      await runDue(this.env);
    } finally {
      await this.arm();
    }
  }
}

// الـ Cron (كل دقيقة) بقى شبكة أمان: بيتأكد إن الـ alarm متظبط، وبيفحص النت كل 5 دقايق
async function cronTick(env) {
  await armScheduler(env).catch(() => {});
  if (Math.floor(Date.now() / 60000) % 5 === 0) {
    try {
      const notes = await checkOnline(env);
      await Promise.all(notes.map((n) => sendPush(env, n)));
    } catch { /* تجاهل */ }
  }
}

/* ---------------- الـ API ---------------- */
const saveList = async (env, key, val) => {
  await kput(env, key, val);
  await armScheduler(env);
};

async function api(p, m, request, env) {
  const body = m === "POST" ? await request.json().catch(() => ({})) : {};
  const name = String(body.name || "").slice(0, 60);

  if (p === "/api/logout" && m === "POST") {
    return json({ ok: true }, 200, { "set-cookie": "s=; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=0" });
  }

  if (p === "/api/overview" && m === "GET") {
    let channels = [], error = null;
    try { channels = await listChannels(env); } catch (e) { error = String(e.message || e); }
    const schedules = await kget(env, "schedules", []);
    const timers = (await kget(env, "timers", [])).filter((t) => t.at > Date.now());
    return json({ channels, schedules, timers, error });
  }

  if (p === "/api/set" && m === "POST") {
    if (!okKey(body.key)) return json({ error: "جهاز غير صالح" }, 400);
    const on = !!body.on;
    try {
      await setSwitch(env, body.key, on);
      await logHistory(env, [{ t: Date.now(), name: name || body.key, on, src: "manual", ok: true }]);
      return json({ on });
    } catch (e) {
      await logHistory(env, [{ t: Date.now(), name: name || body.key, on, src: "manual", ok: false, err: String(e.message).slice(0, 120) }]);
      return json({ error: String(e.message || e) }, 502);
    }
  }

  if (p === "/api/schedules" && m === "POST") {
    const days = Array.isArray(body.days) ? [...new Set(body.days.map(Number))].filter((d) => d >= 0 && d <= 6) : [];
    if (!okKey(body.key) || !/^([01]\d|2[0-3]):[0-5]\d$/.test(body.time || "") || !days.length) {
      return json({ error: "بيانات الجدول ناقصة" }, 400);
    }
    const list = await kget(env, "schedules", []);
    if (list.length >= 50) return json({ error: "وصلت للحد الأقصى للجداول" }, 400);
    list.push({ id: crypto.randomUUID(), key: body.key, name, time: body.time, days, on: !!body.on, enabled: true });
    await saveList(env, "schedules", list);
    return json({ ok: true });
  }
  let mm = /^\/api\/schedules\/([\w-]+)(\/toggle)?$/.exec(p);
  if (mm) {
    const list = await kget(env, "schedules", []);
    if (m === "DELETE") {
      await saveList(env, "schedules", list.filter((s) => s.id !== mm[1]));
      return json({ ok: true });
    }
    if (m === "POST" && mm[2]) {
      const s = list.find((x) => x.id === mm[1]);
      if (s) s.enabled = !s.enabled;
      await saveList(env, "schedules", list);
      return json({ ok: true });
    }
  }

  if (p === "/api/timers" && m === "POST") {
    const minutes = Math.round(Number(body.minutes));
    if (!okKey(body.key) || !(minutes >= 1 && minutes <= 1440)) return json({ error: "المدة لازم تكون من 1 لـ 1440 دقيقة" }, 400);
    const list = (await kget(env, "timers", [])).filter((t) => t.key !== body.key);
    list.push({ id: crypto.randomUUID(), key: body.key, name, on: !!body.on, at: Date.now() + minutes * 60000 });
    await saveList(env, "timers", list);
    return json({ ok: true });
  }
  mm = /^\/api\/timers\/([\w-]+)$/.exec(p);
  if (mm && m === "DELETE") {
    await saveList(env, "timers", (await kget(env, "timers", [])).filter((t) => t.id !== mm[1]));
    return json({ ok: true });
  }

  if (p === "/api/push/key" && m === "GET") {
    const v = await getVapid(env);
    return v ? json({ key: v.pubB64 }) : json({ error: "الإشعارات مش مفعّلة على السيرفر (VAPID_PRIVATE_JWK ناقص)" }, 501);
  }
  if (p === "/api/push/subscribe" && m === "POST") {
    const sub = body.subscription;
    if (!sub?.endpoint || !sub?.keys?.p256dh || !sub?.keys?.auth || !/^https:\/\//.test(sub.endpoint)) {
      return json({ error: "اشتراك غير صالح" }, 400);
    }
    const subs = (await kget(env, "subs", [])).filter((x) => x.endpoint !== sub.endpoint);
    subs.push({ endpoint: sub.endpoint, keys: { p256dh: sub.keys.p256dh, auth: sub.keys.auth } });
    await kput(env, "subs", subs.slice(-20));
    return json({ ok: true });
  }
  if (p === "/api/push/unsubscribe" && m === "POST") {
    await kput(env, "subs", (await kget(env, "subs", [])).filter((x) => x.endpoint !== body.endpoint));
    return json({ ok: true });
  }
  if (p === "/api/push/test" && m === "POST") {
    await sendPush(env, { title: "تجربة", body: "الإشعارات شغالة", tag: "test" });
    return json({ ok: true });
  }

  if (p === "/api/history" && m === "GET") return json(await kget(env, "history", []));
  if (p === "/api/history" && m === "DELETE") {
    await kput(env, "history", []);
    return json({ ok: true });
  }

  return json({ error: "not found" }, 404);
}

/* ---------------- الصفحة والـ PWA ---------------- */
const CSP = "default-src 'self'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src https://fonts.gstatic.com; script-src 'self' 'unsafe-inline'; worker-src 'self'; img-src 'self' data:; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'";
const MANIFEST = {
  name: "سويتش", short_name: "سويتش", start_url: "/", display: "standalone", lang: "ar", dir: "rtl",
  background_color: "#14181d", theme_color: "#14181d",
  icons: [
    { src: "/icon-192.png", sizes: "192x192", type: "image/png", purpose: "any" },
    { src: "/icon-512.png", sizes: "512x512", type: "image/png", purpose: "any" },
    { src: "/icon-512.png", sizes: "512x512", type: "image/png", purpose: "maskable" },
    { src: "/icon.svg", sizes: "any", type: "image/svg+xml", purpose: "any" },
  ],
};
const SW = `self.addEventListener("install", () => self.skipWaiting());
self.addEventListener("activate", (e) => e.waitUntil(self.clients.claim()));
self.addEventListener("push", (e) => {
  let d = {};
  try { d = e.data.json(); } catch (err) {}
  e.waitUntil(self.registration.showNotification(d.title || "سويتش", {
    body: d.body || "", tag: d.tag, dir: "rtl", lang: "ar", icon: "/icon-192.png", badge: "/icon-192.png",
  }));
});
self.addEventListener("notificationclick", (e) => {
  e.notification.close();
  e.waitUntil(self.clients.matchAll({ type: "window", includeUncontrolled: true }).then((list) => {
    for (const c of list) if ("focus" in c) return c.focus();
    return self.clients.openWindow("/");
  }));
});`;
const pngResponse = (b64) => new Response(Uint8Array.from(atob(b64), (c) => c.charCodeAt(0)), { headers: { "content-type": "image/png", "cache-control": "public, max-age=86400" } });
const ICON_192 = "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";
const ICON_512 = "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QAAAAAACAAAAEAAAAIAAAAAABAAAACAAAAAAAQAAAAgAAABAAAAAAAIAAAAQAAAAgAAAAAAEAAAAIAAAAAABAAAACAAAAEAAAAAAAgAAABAAAACAAAAAAAQAAAAgAAAAEAAAAIAAAAAABAAAACAAAAAAAQAAAAgAAABAAAAAAAIAAAAQAAAAgAAAAAAEAAAAIAAAAAABAAAACAAAAEAAAAAAAgAAABAAAACAAAAAAAQAAAAgAAAAAAEAAAAIAAAAQAAAACAA8AgAABAAAACAAAAAAAQAAAAgAAAAAAEAAAAIAAAAQAAAAAACAAAAEAAAAIAAAAAABAAAACAAAAAAAQAAAAgAAABAAAAAAAIAAAAQAAAAgAAAAAAEAAAAIAAAAAABAAAACAAAAEAAAAAgAAAAAAEAAAAIAAAAQAAAAAACAAAAEAAAAIAAAAAABAAAACAAAAAAAQAAAAgAAABAAAAAAAIAAAAQAAAAgAAAAAAEAAAAIAAAAAABAAAACAAAAEAAAAAAAgAAABAAAACAAAAAQAAAAAACAAAAEAAAAIAAAAAABAAAACAAAAAAAQAAAAgAAABAAAAAAAIAAAAQAAAAgAAAAAAEAAAAIAAAAAABAAAACAAAAEAAAAAAAgAAABAAAACAAAAAAAQAAAAgAAAAAAEAAAAIAAAABAAAACAAAAAAAQAAAAgAAABAAAAAAAIAAAAQAAAAgAAAAAAEAAAAIAAAAAABAAAACAAAAEAAAAAAAgAAABAAAACAAAAAAAQAAAAgAAAAAAEAAAAIAAAAQAAAAAACAAAAEAAAAAgAAABAAAAAAAIAAAAQAAAAMAH9f2IWsGLPDGdPAAAAAElFTkSuQmCC";
const ICON = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 512 512"><rect width="512" height="512" fill="#14181d"/><g fill="none" stroke="#ffc247" stroke-width="30" stroke-linecap="round"><path d="M256 130v120"/><path d="M175 175a118 118 0 1 0 162 0"/></g></svg>`;

export default {
  async fetch(request, env) {
    const { pathname: p } = new URL(request.url);
    const m = request.method;
    try {
      if (p === "/" && m === "GET") {
        return new Response(INDEX_HTML, {
          headers: {
            "content-type": "text/html; charset=utf-8", "cache-control": "no-store",
            "content-security-policy": CSP, "x-content-type-options": "nosniff", "referrer-policy": "no-referrer",
          },
        });
      }
      if (p === "/manifest.webmanifest") return new Response(JSON.stringify(MANIFEST), { headers: { "content-type": "application/manifest+json" } });
      if (p === "/sw.js") return new Response(SW, { headers: { "content-type": "text/javascript; charset=utf-8", "cache-control": "no-cache" } });
      if (p === "/icon-192.png") return pngResponse(ICON_192);
      if (p === "/icon-512.png") return pngResponse(ICON_512);
      if (p === "/icon.svg") return new Response(ICON, { headers: { "content-type": "image/svg+xml", "cache-control": "public, max-age=86400" } });
      if (p === "/api/login" && m === "POST") return await login(request, env);
      if (p.startsWith("/api/")) {
        if (!(await validSession(env, request))) return json({ error: "unauthorized" }, 401);
        return await api(p, m, request, env);
      }
      return new Response("Not found", { status: 404 });
    } catch (e) {
      return json({ error: String(e.message || e) }, 502);
    }
  },
  async scheduled(event, env, ctx) {
    ctx.waitUntil(cronTick(env));
  },
};
