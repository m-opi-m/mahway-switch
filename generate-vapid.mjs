// بيطلع مفتاح VAPID للإشعارات. شغله مرة واحدة: node generate-vapid.mjs
import { webcrypto as c } from "node:crypto";
const kp = await c.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
const jwk = await c.subtle.exportKey("jwk", kp.privateKey);
delete jwk.key_ops; delete jwk.ext;
console.log("\nانسخ السطر ده كله (اللي بيبدأ بـ { وبينتهي بـ }) والصقه لما wrangler يسألك عن VAPID_PRIVATE_JWK:\n");
console.log(JSON.stringify(jwk));
console.log("");
