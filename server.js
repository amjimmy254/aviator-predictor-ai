
// CYZORA WEBHOOK WITH DIAGNOSTIC LOGGING
app.post(
  "/api/cyzora/webhook",
  express.raw({ type: "*/*", limit: "100kb" }),
  (req, res) => {
    console.log("CYZORA WEBHOOK RECEIVED");
    console.log("Content-Type:", req.get("Content-Type"));
    console.log(
      "Signature header present:",
      !!req.get("X-Cyzora-Signature")
    );
    console.log(
      "Webhook secret configured:",
      !!process.env.CYZORA_WEBHOOK_SECRET
    );
    console.log(
      "Raw body received:",
      Buffer.isBuffer(req.body)
    );

    try {
      const secret = process.env.CYZORA_WEBHOOK_SECRET;

      if (!secret) {
        console.error("WEBHOOK ERROR: Missing CYZORA_WEBHOOK_SECRET");
        return res.status(503).json({
          error: "Webhook secret is not configured."
        });
      }

      if (!Buffer.isBuffer(req.body)) {
        console.error("WEBHOOK ERROR: Raw body is missing");
        return res.status(400).json({
          error: "Raw request body is missing."
        });
      }

      const signature = String(
        req.get("X-Cyzora-Signature") || ""
      );

      if (!/^[a-f0-9]{64}$/i.test(signature)) {
        console.error("WEBHOOK ERROR: Invalid signature format");
        return res.status(401).json({
          error: "Invalid webhook signature format."
        });
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
        console.error("WEBHOOK ERROR: Signature verification failed");
        return res.status(401).json({
          error: "Webhook signature verification failed."
        });
      }

      const event = JSON.parse(req.body.toString("utf8"));

      console.log("CYZORA EVENT:", event.event);

      if (event.event === "webhook.test") {
        console.log("CYZORA TEST WEBHOOK VERIFIED");
        return res.status(200).json({
          received: true
        });
      }

      const payment = db.prepare(`
        SELECT * FROM payments
        WHERE provider = 'cyzora'
        AND (
          cyzora_charge_id = ?
          OR cyzora_reference = ?
          OR merchant_request_id = ?
        )
        LIMIT 1
      `).get(
        event.charge_id || "",
        event.reference || "",
        event.account_ref || ""
      );

      if (event.event === "charge.succeeded") {
        if (!payment) {
          console.log("Webhook received but payment not matched.");

          return res.status(200).json({
            received: true,
            matched: false
          });
        }

        const paidAmount = Number(event.amount);
        const expectedAmount = payment.amount * 100;

        if (
          event.currency !== "KES" ||
          paidAmount !== expectedAmount ||
          event.status !== "succeeded"
        ) {
          console.error("PAYMENT REVIEW: Amount or currency mismatch");

          db.prepare(`
            UPDATE payments
            SET status = 'review'
            WHERE id = ? AND status = 'pending'
          `).run(payment.id);

          return res.status(200).json({
            received: true,
            review: true
          });
        }

        const result = db.prepare(`
          UPDATE payments
          SET status = 'paid', mpesa_receipt = ?
          WHERE id = ? AND status = 'pending'
        `).run(
          event.mpesa_receipt || null,
          payment.id
        );

        if (result.changes === 1) {
          const pkg = PACKAGES[payment.package_code];

          if (pkg) {
            db.prepare(`
              INSERT INTO entitlements
              (phone, package_code, analyses_total)
              VALUES (?, ?, ?)
            `).run(
              payment.phone,
              payment.package_code,
              pkg.analyses
            );

            console.log("PACKAGE ACTIVATED:", payment.package_code);
          }
        }
      }

      if (
        event.event === "charge.failed" ||
        event.event === "charge.expired"
      ) {
        if (payment) {
          db.prepare(`
            UPDATE payments
            SET status = 'failed'
            WHERE id = ? AND status = 'pending'
          `).run(payment.id);
        }
      }

      return res.status(200).json({
        received: true
      });

    } catch (error) {
      console.error("CYZORA WEBHOOK ERROR:", error.message);

      return res.status(400).json({
        error: "Invalid webhook payload."
      });
    }
  }
);
