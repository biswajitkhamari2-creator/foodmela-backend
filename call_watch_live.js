const admin = require("firebase-admin");
const fs = require("fs");
const sa = JSON.parse(fs.readFileSync("D:/sdk/food-mela-notification-firebase-adminsdk-fbsvc-fd5ccffa58.json", "utf8"));
if (!admin.apps.length) admin.initializeApp({ credential: admin.credential.cert(sa) });
const db = admin.firestore();
const seen = new Map(); // docId -> {status, callId, stage, riderId, hasRiderToken, hasCustToken}
async function poll() {
  try {
    const snap = await db.collection("orders").orderBy("updatedAt", "desc").limit(15).get();
    const now = new Date().toISOString().slice(11, 19);
    snap.docs.forEach(d => {
      const o = d.data() || {};
      const ac = o.activeCall || null;
      const key = d.id;
      const cur = {
        status: ac ? ac.status : "-",
        callId: ac ? (ac.callId || "?") : "-",
        receiverId: ac ? (ac.receiverId || "?") : "-",
        stage: o.stage, riderId: o.riderId || "-", rpid: o.riderPartnerId || "-",
        rt: o.riderFcmToken ? "YES" : "no", ct: o.customerFcmToken ? "YES" : "no"
      };
      const prev = seen.get(key);
      if (!prev) { seen.set(key, cur); return; }
      const changes = [];
      for (const k of Object.keys(cur)) if (String(prev[k]) !== String(cur[k])) changes.push(`${k}: ${prev[k]} -> ${cur[k]}`);
      if (changes.length) {
        console.log(`[${now}] ${key} | ${changes.join(" | ")}`);
        seen.set(key, cur);
      }
    });
  } catch (e) { console.log("poll err:", e.message); }
}
(async () => {
  console.log("watching orders (15 most recent by updatedAt)...");
  await poll();
  // baseline snapshot
  const snap = await db.collection("orders").orderBy("updatedAt", "desc").limit(5).get();
  snap.docs.forEach(d => {
    const o = d.data() || {};
    console.log(`BASE ${d.id} stage=${o.stage} riderId=${o.riderId||"-"} rpid=${o.riderPartnerId||"-"} riderTok=${o.riderFcmToken?"YES":"no"} custTok=${o.customerFcmToken?"YES":"no"} activeCall=${o.activeCall?JSON.stringify({s:o.activeCall.status,c:o.activeCall.callId,r:o.activeCall.receiverId}):"none"}`);
  });
  setInterval(poll, 4000);
})();
