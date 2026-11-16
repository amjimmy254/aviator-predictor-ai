require("dotenv").config();
const express = require("express");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const Database = require("better-sqlite3");
const path = require("path");
const crypto = require("crypto");

const app = express();
const db = new Database(process.env.DB_PATH || "aviator.sqlite");
db.pragma("journal_mode = WAL");
db.exec(`
CREATE TABLE IF NOT EXISTS customers (
 id INTEGER PRIMARY KEY AUTOINCREMENT, phone TEXT UNIQUE, created_at TEXT DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS payments (
 id INTEGER PRIMARY KEY AUTOINCREMENT, checkout_request_id TEXT UNIQUE,
 merchant_request_id TEXT, phone TEXT NOT NULL, amount INTEGER NOT NULL,
 package_code TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'pending',
 mpesa_receipt TEXT, created_at TEXT DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS entitlements (
 id INTEGER PRIMARY KEY AUTOINCREMENT, phone TEXT NOT NULL,
 package_code TEXT NOT NULL, analyses_total INTEGER NOT NULL,
 analyses_used INTEGER NOT NULL DEFAULT 0, expires_at TEXT,
 created_at TEXT DEFAULT CURRENT_TIMESTAMP
);
`);
const PACKAGES = {
 starter: { name: "Starter", amount: 100, analyses: 5 },
 pro: { name: "Pro", amount: 500, analyses: 15 },
 premium: { name: "Premium", amount: 1000, analyses: 30 }
};

app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.json({ limit: "100kb" }));
app.use(express.static(path.join(__dirname, "public")));
app.use("/api/", rateLimit({ windowMs: 60_000, limit: 30, standardHeaders: true, legacyHeaders: false }));

function normalizePhone(input) {
  let p = String(input || "").replace(/[^\d+]/g, "");
  if (p.startsWith("+")) p = p.slice(1);
  if (p.startsWith("0")) p = "254" + p.slice(1);
  if (p.startsWith("7") || p.startsWith("1")) p = "254" + p;
  if (!/^254[17]\d{8}$/.test(p)) throw new Error("Enter a valid Kenyan M-Pesa number.");
  return p;
}
function auth(req, res, next) {
  const token = (req.headers.authorization || "").replace(/^Bearer\s+/i, "");
  try { req.user = jwt.verify(token, process.env.JWT_SECRET); next(); }
  catch { res.status(401).json({ error: "Authentication required." }); }
}
function adminOnly(req, res, next) {
  if (req.user?.role !== "admin") return res.status(403).json({ error: "Admin access only." });
  next();
}
async function darajaToken() {
  const host = process.env.MPESA_ENV === "production"
    ? "https://api.safaricom.co.ke" : "https://sandbox.safaricom.co.ke";
  const credentials = Buffer.from(`${process.env.MPESA_CONSUMER_KEY}:${process.env.MPESA_CONSUMER_SECRET}`).toString("base64");
  const response = await fetch(`${host}/oauth/v1/generate?grant_type=client_credentials`, {
    headers: { Authorization: `Basic ${credentials}` }
  });
  const data = await response.json();
  if (!response.ok || !data.access_token) throw new Error("Could not authenticate with Daraja.");
  return { token: data.access_token, host };
}
function mpesaPassword(shortcode, passkey, timestamp) {
  return Buffer.from(`${shortcode}${passkey}${timestamp}`).toString("base64");
}

app.get("/api/packages", (_req, res) => res.json(PACKAGES));

app.post("/api/payments/stk", async (req, res) => {
  try {
    const phone = normalizePhone(req.body.phone);
    const pkg = PACKAGES[req.body.packageCode];
    if (!pkg) return res.status(400).json({ error: "Choose a valid package." });
    const required = ["MPESA_CONSUMER_KEY","MPESA_CONSUMER_SECRET","MPESA_SHORTCODE","MPESA_PASSKEY","MPESA_CALLBACK_URL"];
    if (required.some(k => !process.env[k])) return res.status(503).json({ error: "M-Pesa is not configured yet. Contact the site administrator." });

    const { token, host } = await darajaToken();
    const timestamp = new Date().toISOString().replace(/[-T:.Z]/g, "").slice(0,14);
    const shortcode = process.env.MPESA_SHORTCODE;
    const body = {
      BusinessShortCode: shortcode,
      Password: mpesaPassword(shortcode, process.env.MPESA_PASSKEY, timestamp),
      Timestamp: timestamp,
      TransactionType: process.env.MPESA_TRANSACTION_TYPE || "CustomerPayBillOnline",
      Amount: pkg.amount,
      PartyA: phone,
      PartyB: shortcode,
      PhoneNumber: phone,
      CallBackURL: process.env.MPESA_CALLBACK_URL,
      AccountReference: process.env.MPESA_ACCOUNT_REFERENCE || "AviatorAI",
      TransactionDesc: process.env.MPESA_TRANSACTION_DESC || "Package purchase"
    };
    const response = await fetch(`${host}/mpesa/stkpush/v1/processrequest`, {
      method: "POST", headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
      body: JSON.stringify(body)
    });
    const data = await response.json();
    if (!response.ok || data.ResponseCode !== "0") return res.status(502).json({ error: data.errorMessage || data.ResponseDescription || "M-Pesa request failed." });
    db.prepare(`INSERT OR IGNORE INTO payments
      (checkout_request_id, merchant_request_id, phone, amount, package_code, status)
      VALUES (?, ?, ?, ?, ?, 'pending')`).run(data.CheckoutRequestID, data.MerchantRequestID, phone, pkg.amount, req.body.packageCode);
    db.prepare("INSERT OR IGNORE INTO customers(phone) VALUES (?)").run(phone);
    res.json({ ok: true, message: "STK Push sent. Enter your M-Pesa PIN on your phone to complete payment." });
  } catch (e) { res.status(400).json({ error: e.message || "Could not start payment." }); }
});

// Safaricom sends the payment result here. Only successful callbacks grant package access.
app.post("/api/mpesa/callback", (req, res) => {
  try {
    const result = req.body?.Body?.stkCallback;
    if (!result) return res.json({ ResultCode: 0, ResultDesc: "Accepted" });
    const payment = db.prepare("SELECT * FROM payments WHERE checkout_request_id = ?").get(result.CheckoutRequestID);
    if (!payment) return res.json({ ResultCode: 0, ResultDesc: "Accepted" });
    if (result.ResultCode === 0) {
      const items = result.CallbackMetadata?.Item || [];
      const receipt = items.find(x => x.Name === "MpesaReceiptNumber")?.Value;
      const paidAmount = Number(items.find(x => x.Name === "Amount")?.Value);
      const paidPhone = String(items.find(x => x.Name === "PhoneNumber")?.Value || "");
      if (paidAmount === payment.amount && paidPhone === payment.phone) {
        const update = db.prepare("UPDATE payments SET status='paid', mpesa_receipt=? WHERE id=? AND status='pending'");
        const info = update.run(receipt || null, payment.id);
        if (info.changes) {
          const pkg = PACKAGES[payment.package_code];
          db.prepare(`INSERT INTO entitlements(phone, package_code, analyses_total)
            VALUES (?, ?, ?)`).run(payment.phone, payment.package_code, pkg.analyses);
        }
      } else {
        db.prepare("UPDATE payments SET status='review' WHERE id=?").run(payment.id);
      }
    } else {
      db.prepare("UPDATE payments SET status='failed' WHERE id=? AND status='pending'").run(payment.id);
    }
    res.json({ ResultCode: 0, ResultDesc: "Accepted" });
  } catch { res.json({ ResultCode: 0, ResultDesc: "Accepted" }); }
});

app.post("/api/admin/login", async (req, res) => {
  const email = String(req.body.email || "").toLowerCase();
  const password = String(req.body.password || "");
  const hash = process.env.ADMIN_PASSWORD_HASH || "";
  if (!process.env.JWT_SECRET || !hash || email !== String(process.env.ADMIN_EMAIL || "").toLowerCase() ||
      !(await bcrypt.compare(password, hash))) return res.status(401).json({ error: "Invalid administrator credentials." });
  const token = jwt.sign({ role: "admin", email }, process.env.JWT_SECRET, { expiresIn: "2h" });
  res.json({ token, expiresIn: 7200 });
});
app.get("/api/admin/overview", auth, adminOnly, (_req, res) => {
  const totals = db.prepare(`SELECT
    COUNT(*) AS transactions,
    COALESCE(SUM(CASE WHEN status='paid' THEN amount ELSE 0 END),0) AS grossCollected,
    SUM(CASE WHEN status='pending' THEN 1 ELSE 0 END) AS pendingPayments
    FROM payments`).get();
  const recent = db.prepare(`SELECT phone, amount, package_code, status, mpesa_receipt, created_at
    FROM payments ORDER BY id DESC LIMIT 50`).all();
  res.json({ totals, recent });
});
app.get("/api/account/:phone", (req, res) => {
  try {
    const phone = normalizePhone(req.params.phone);
    const packages = db.prepare(`SELECT package_code, analyses_total, analyses_used, expires_at, created_at
      FROM entitlements WHERE phone=? ORDER BY id DESC`).all(phone);
    res.json({ packages });
  } catch (e) { res.status(400).json({ error: e.message }); }
});

// Analysis endpoint uses only supplied historical observations. It never claims to know the next ride.
app.post("/api/analyze", (req, res) => {
  const values = Array.isArray(req.body.multipliers) ? req.body.multipliers.slice(-500) : [];
  const nums = values.map(Number).filter(n => Number.isFinite(n) && n >= 1 && n <= 100000);
  if (nums.length < 5) return res.status(400).json({ error: "Enter at least five valid historical multipliers." });
  const sorted = [...nums].sort((a,b)=>a-b);
  const mean = nums.reduce((a,b)=>a+b,0)/nums.length;
  const median = sorted.length % 2 ? sorted[(sorted.length-1)/2] : (sorted[sorted.length/2-1]+sorted[sorted.length/2])/2;
  const bands = [
    { label: "Below 2x", count: nums.filter(x=>x<2).length },
    { label: "2x–under 5x", count: nums.filter(x=>x>=2 && x<5).length },
    { label: "5x–under 10x", count: nums.filter(x=>x>=5 && x<10).length },
    { label: "10x and above", count: nums.filter(x=>x>=10).length }
  ].map(x=>({...x, percent: +(x.count/nums.length*100).toFixed(1)}));
  res.json({ sampleSize: nums.length, mean: +mean.toFixed(2), median: +median.toFixed(2),
    min: sorted[0], max: sorted[sorted.length-1], bands,
    note: "Descriptive statistics of the entered history only. Past outcomes do not predict or change the probability of future independent rounds." });
});

app.get("/health", (_req,res)=>res.json({ok:true}));
app.get("*", (_req,res)=>res.sendFile(path.join(__dirname,"public","index.html")));
const port = Number(process.env.PORT || 3000);
app.listen(port, ()=>console.log(`Aviator Predictor AI running on port ${port}`));
