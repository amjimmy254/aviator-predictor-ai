
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
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  phone TEXT UNIQUE,
  created_at TEXT DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS payments (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  checkout_request_id TEXT UNIQUE,
  merchant_request_id TEXT,
  phone TEXT NOT NULL,
  amount INTEGER NOT NULL,
  package_code TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'pending',
  mpesa_receipt TEXT,
  created_at TEXT DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS entitlements (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  phone TEXT NOT NULL,
  package_code TEXT NOT NULL,
  analyses_total INTEGER NOT NULL,
  analyses_used INTEGER NOT NULL DEFAULT 0,
  expires_at TEXT,
  created_at TEXT DEFAULT CURRENT_TIMESTAMP
);
`);

// Safely add Cyzora columns to existing databases.
const columns = db.prepare("PRAGMA table_info(payments)").all();
const columnNames = columns.map(column => column.name);

if (!columnNames.includes("provider")) {
  db.exec("ALTER TABLE payments ADD COLUMN provider TEXT NOT NULL DEFAULT 'mpesa'");
}
if (!columnNames.includes("cyzora_charge_id")) {
  db.exec("ALTER TABLE payments ADD COLUMN cyzora_charge_id TEXT");
}
if (!columnNames.includes("cyzora_reference")) {
  db.exec("ALTER TABLE payments ADD COLUMN cyzora_reference TEXT");
}

db.exec(`
CREATE INDEX IF NOT EXISTS idx_payments_cyzora_reference
ON payments(cyzora_reference);
`);

const PACKAGES = {
  starter: { name: "Starter", amount: 100, analyses: 5 },
  pro: { name: "Pro", amount: 500, analyses: 15 },
  premium: { name: "Premium", amount: 1000, analyses: 30 }
};

app.use(helmet({ contentSecurityPolicy: false }));

app.use("/api/", rateLimit({
  windowMs: 60_000,
  limit: 30,
  standardHeaders: true,
  legacyHeaders: false
}));

// Verify Cyzora's signature against the RAW body before JSON parsing.
app.post(
  "/api/cyzora/webhook",
  express.raw({ type: "application/json", limit: "100kb" }),
  (req, res) => {
    try {
      const secret = process.env.CYZORA_WEBHOOK_SECRET;
      if (!secret) {
        return res.status(503).json({ error: "Webhook secret is not configured." });
      }

      const signature = String(req.get("X-Cyzora-Signature") || "");

      if (!/^[a-f0-9]{64}$/i.test(signature)) {
        return res.status(401).json({ error: "Invalid webhook signature." });
      }

      const expected = crypto
        .createHmac("sha256", secret)
        .update(req.body)
        .digest();

      const received = Buffer.from(signature, "hex");

      if (
        received.length !== expected.length ||
        !crypto.timingSafeEqual(received, expected)
      ) {
        return res.status(401).json({ error: "Invalid webhook signature." });
      }

      const event = JSON.parse(req.body.toString("utf8"));

      if (event.event === "webhook.test") {
        return res.status(200).json({ received: true });
      }

      if (event.event === "charge.succeeded") {
        const payment = db.prepare(`
          SELECT * FROM payments
          WHERE provider = 'cyzora'
          AND (cyzora_charge_id = ? OR cyzora_reference = ?)
        `).get(event.charge_id || "", event.reference || "");

        if (!payment) {
          // Acknowledge unrelated events; do not activate an unknown order.
          return res.status(200).json({ received: true, matched: false });
        }

        const paidAmount = Number(event.amount);
        const expectedAmount = payment.amount * 100;

        if (
          event.currency !== "KES" ||
          paidAmount !== expectedAmount ||
          event.status !== "succeeded"
        ) {
          db.prepare(`
            UPDATE payments SET status = 'review'
            WHERE id = ? AND status = 'pending'
          `).run(payment.id);

          return res.status(200).json({ received: true, review: true });
        }

        // Idempotent: duplicate webhooks cannot grant the package twice.
        const update = db.prepare(`
          UPDATE payments
          SET status = 'paid', mpesa_receipt = ?
          WHERE id = ? AND status = 'pending'
        `);

        const result = update.run(event.mpesa_receipt || null, payment.id);

        if (result.changes === 1) {
          const pkg = PACKAGES[payment.package_code];

          if (pkg) {
            db.prepare(`
              INSERT INTO entitlements
              (phone, package_code, analyses_total)
              VALUES (?, ?, ?)
            `).run(payment.phone, payment.package_code, pkg.analyses);
          }
        }
      }

      if (
        event.event === "charge.failed" ||
        event.event === "charge.expired"
      ) {
        db.prepare(`
          UPDATE payments SET status = 'failed'
          WHERE provider = 'cyzora'
          AND status = 'pending'
          AND (cyzora_charge_id = ? OR cyzora_reference = ?)
        `).run(event.charge_id || "", event.reference || "");
      }

      // Cyzora considers any 2xx response a successful delivery.
      return res.status(200).json({ received: true });

    } catch (error) {
      console.error("Cyzora webhook error:", error.message);
      return res.status(400).json({ error: "Invalid webhook payload." });
    }
  }
);

// Normal JSON parsing happens after the raw-body webhook route.
app.use(express.json({ limit: "100kb" }));
app.use(express.static(path.join(__dirname, "public")));

function normalizePhone(input) {
  let phone = String(input || "").replace(/[^\d+]/g, "");

  if (phone.startsWith("+")) phone = phone.slice(1);
  if (phone.startsWith("0")) phone = "254" + phone.slice(1);
  if (phone.startsWith("7") || phone.startsWith("1")) {
    phone = "254" + phone;
  }

  if (!/^254[17]\d{8}$/.test(phone)) {
    throw new Error("Enter a valid Kenyan M-Pesa number.");
  }

  return phone;
}

function auth(req, res, next) {
  const token = (req.headers.authorization || "")
    .replace(/^Bearer\s+/i, "");

  try {
    req.user = jwt.verify(token, process.env.JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ error: "Authentication required." });
  }
}

function adminOnly(req, res, next) {
  if (req.user?.role !== "admin") {
    return res.status(403).json({ error: "Admin access only." });
  }
  next();
}

app.get("/api/packages", (_req, res) => {
  res.json(PACKAGES);
});

// Cyzora M-Pesa STK Push.
app.post("/api/payments/stk", async (req, res) => {
  try {
    const phone = normalizePhone(req.body.phone);
    const packageCode = String(req.body.packageCode || "");
    const pkg = PACKAGES[packageCode];

    if (!pkg) {
      return res.status(400).json({ error: "Choose a valid package." });
    }

    const secretKey = process.env.CYZORA_SECRET_KEY;

    if (!secretKey) {
      return res.status(503).json({
        error: "Cyzora is not configured. Contact the site administrator."
      });
    }

    const orderReference =
      "GW-" + Date.now() + "-" + crypto.randomBytes(4).toString("hex");

    // Cyzora amounts are cents: KSh 500 = 50000.
    const response = await fetch(
      "https://api.cyzora.co.ke/api/v1/charges",
      {
        method: "POST",
        headers: {
          "X-API-Key": secretKey,
          "Idempotency-Key": orderReference,
          "Content-Type": "application/json"
        },
        body: JSON.stringify({
          amount: pkg.amount * 100,
          phone,
          network: "mpesa",
          account_ref: orderReference,
          metadata: {
            order_reference: orderReference,
            package_code: packageCode
          }
        })
      }
    );

    const data = await response.json();

    if (!response.ok || !data.id || !data.reference) {
      console.error("Cyzora charge error:", data);

      return res.status(response.status === 429 ? 429 : 502).json({
        error: data.error || "Cyzora could not start the M-Pesa payment."
      });
    }

    // Save the pending order before granting any package access.
    db.prepare(`
      INSERT INTO payments (
        checkout_request_id,
        merchant_request_id,
        phone,
        amount,
        package_code,
        status,
        provider,
        cyzora_charge_id,
        cyzora_reference
      )
      VALUES (?, ?, ?, ?, ?, 'pending', 'cyzora', ?, ?)
    `).run(
      data.id,
      data.reference,
      phone,
      pkg.amount,
      packageCode,
      data.id,
      data.reference
    );

    db.prepare(`
      INSERT OR IGNORE INTO customers(phone) VALUES (?)
    `).run(phone);

    res.json({
      ok: true,
      reference: data.reference,
      message:
        "M-Pesa prompt requested. Enter your PIN. Your package activates after Cyzora confirms payment."
    });

  } catch (error) {
    console.error("Payment initiation error:", error.message);
    res.status(400).json({
      error: error.message || "Could not start payment."
    });
  }
});

// Check payment status using the reference returned by the server.
app.get("/api/payments/status/:reference", (req, res) => {
  const payment = db.prepare(`
    SELECT cyzora_reference AS reference,
           amount,
           package_code,
           status,
           created_at
    FROM payments
    WHERE cyzora_reference = ?
      AND provider = 'cyzora'
  `).get(req.params.reference);

  if (!payment) {
    return res.status(404).json({ error: "Payment not found." });
  }

  res.json({
    reference: payment.reference,
    amount: payment.amount,
    currency: "KES",
    packageCode: payment.package_code,
    status: payment.status
  });
});

// Keep the old Safaricom callback for any older pending transactions.
app.post("/api/mpesa/callback", (req, res) => {
  try {
    const result = req.body?.Body?.stkCallback;

    if (!result) {
      return res.json({ ResultCode: 0, ResultDesc: "Accepted" });
    }

    const payment = db.prepare(`
      SELECT * FROM payments WHERE checkout_request_id = ?
    `).get(result.CheckoutRequestID);

    if (!payment || payment.provider === "cyzora") {
      return res.json({ ResultCode: 0, ResultDesc: "Accepted" });
    }

    if (result.ResultCode === 0) {
      const items = result.CallbackMetadata?.Item || [];
      const receipt = items.find(x => x.Name === "MpesaReceiptNumber")?.Value;
      const paidAmount = Number(items.find(x => x.Name === "Amount")?.Value);
      const paidPhone = String(
        items.find(x => x.Name === "PhoneNumber")?.Value || ""
      );

      if (paidAmount === payment.amount && paidPhone === payment.phone) {
        const update = db.prepare(`
          UPDATE payments SET status = 'paid', mpesa_receipt = ?
          WHERE id = ? AND status = 'pending'
        `);

        const info = update.run(receipt || null, payment.id);

        if (info.changes) {
          const pkg = PACKAGES[payment.package_code];

          if (pkg) {
            db.prepare(`
              INSERT INTO entitlements
              (phone, package_code, analyses_total)
              VALUES (?, ?, ?)
            `).run(payment.phone, payment.package_code, pkg.analyses);
          }
        }
      } else {
        db.prepare(`
          UPDATE payments SET status = 'review' WHERE id = ?
        `).run(payment.id);
      }
    } else {
      db.prepare(`
        UPDATE payments SET status = 'failed'
        WHERE id = ? AND status = 'pending'
      `).run(payment.id);
    }

    res.json({ ResultCode: 0, ResultDesc: "Accepted" });
  } catch (error) {
    console.error("Old M-Pesa callback error:", error.message);
    res.json({ ResultCode: 0, ResultDesc: "Accepted" });
  }
});

app.post("/api/admin/login", async (req, res) => {
  const email = String(req.body.email || "").toLowerCase();
  const password = String(req.body.password || "");
  const hash = process.env.ADMIN_PASSWORD_HASH || "";

  if (
    !process.env.JWT_SECRET ||
    !hash ||
    email !== String(process.env.ADMIN_EMAIL || "").toLowerCase() ||
    !(await bcrypt.compare(password, hash))
  ) {
    return res.status(401).json({
      error: "Invalid administrator credentials."
    });
  }

  const token = jwt.sign(
    { role: "admin", email },
    process.env.JWT_SECRET,
    { expiresIn: "2h" }
  );

  res.json({ token, expiresIn: 7200 });
});

app.get("/api/admin/overview", auth, adminOnly, (_req, res) => {
  const totals = db.prepare(`
    SELECT
      COUNT(*) AS transactions,
      COALESCE(
        SUM(CASE WHEN status = 'paid' THEN amount ELSE 0 END), 0
      ) AS grossCollected,
      SUM(CASE WHEN status = 'pending' THEN 1 ELSE 0 END)
        AS pendingPayments
    FROM payments
  `).get();

  const recent = db.prepare(`
    SELECT phone, amount, package_code, status,
           mpesa_receipt, created_at
    FROM payments
    ORDER BY id DESC
    LIMIT 50
  `).all();

  res.json({ totals, recent });
});

app.get("/api/account/:phone", (req, res) => {
  try {
    const phone = normalizePhone(req.params.phone);

    const packages = db.prepare(`
      SELECT package_code, analyses_total, analyses_used,
             expires_at, created_at
      FROM entitlements
      WHERE phone = ?
      ORDER BY id DESC
    `).all(phone);

    res.json({ packages });
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

// Descriptive statistics only; past outcomes do not predict future rounds.
app.post("/api/analyze", (req, res) => {
  const values = Array.isArray(req.body.multipliers)
    ? req.body.multipliers.slice(-500)
    : [];

  const nums = values
    .map(Number)
    .filter(n => Number.isFinite(n) && n >= 1 && n <= 100000);

  if (nums.length < 5) {
    return res.status(400).json({
      error: "Enter at least five valid historical multipliers."
    });
  }

  const sorted = [...nums].sort((a, b) => a - b);
  const mean = nums.reduce((a, b) => a + b, 0) / nums.length;

  const median = sorted.length % 2
    ? sorted[(sorted.length - 1) / 2]
    : (
        sorted[sorted.length / 2 - 1] +
        sorted[sorted.length / 2]
      ) / 2;

  const bands = [
    { label: "Below 2x", count: nums.filter(x => x < 2).length },
    {
      label: "2x–under 5x",
      count: nums.filter(x => x >= 2 && x < 5).length
    },
    {
      label: "5x–under 10x",
      count: nums.filter(x => x >= 5 && x < 10).length
    },
    {
      label: "10x and above",
      count: nums.filter(x => x >= 10).length
    }
  ].map(x => ({
    ...x,
    percent: +(x.count / nums.length * 100).toFixed(1)
  }));

  res.json({
    sampleSize: nums.length,
    mean: +mean.toFixed(2),
    median: +median.toFixed(2),
    min: sorted[0],
    max: sorted[sorted.length - 1],
    bands,
    note:
      "Descriptive statistics of the entered history only. Past outcomes do not predict future independent rounds."
  });
});

app.get("/health", (_req, res) => res.json({ ok: true }));

app.get("*", (_req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

const port = Number(process.env.PORT || 3000);

app.listen(port, () => {
  console.log(`GoalWise AI running on port ${port}`);
});
