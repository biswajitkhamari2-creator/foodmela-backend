const admin = require("firebase-admin");
const fs = require("fs");
const sa = JSON.parse(fs.readFileSync("D:/sdk/food-mela-notification-firebase-adminsdk-fbsvc-fd5ccffa58.json", "utf8"));
if (!admin.apps.length) admin.initializeApp({ credential: admin.credential.cert(sa) });
const db = admin.firestore();
(async () => {
  const snap = await db.collection("orders").orderBy("updatedAt", "desc").limit(3).get();
  snap.docs.forEach(d => {
    const o = d.data() || {};
    console.log(`${d.id} stage=${o.stage} riderId=${o.riderId||"-"} rpid=${o.riderPartnerId||"-"} riderTok=${o.riderFcmToken?"YES("+String(o.riderFcmToken).slice(0,12)+"...)":"NO"} custTok=${o.customerFcmToken?"YES":"NO"}`);
    if (o.activeCall) console.log(`  activeCall=${JSON.stringify({s:o.activeCall.status,c:o.activeCall.callId,r:o.activeCall.receiverId,caller:o.activeCall.callerId,at:new Date(o.activeCall.createdAt).toISOString().slice(11,19)})}`);
    else console.log("  activeCall=none");
  });
  process.exit(0);
})();
