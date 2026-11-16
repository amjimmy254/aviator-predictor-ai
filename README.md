# Aviator Predictor AI

A responsive website starter with:
- KSh 100 / 500 / 1,000 one-time packages (5 / 15 / 30 analysis sessions)
- Safaricom Daraja STK Push integration scaffold
- Callback-based payment confirmation before package activation
- Historical multiplier statistics and probability-band summaries
- Owner-only admin login and transaction overview
- Database-backed customer entitlements
- Telegram integration configuration placeholder

## Important limitations
This product analyses historical data supplied by a user. It does not predict or guarantee future Aviator outcomes. Past rounds do not establish the next multiplier. Do not market random estimates as reliable predictions.

## Run locally
1. Install Node.js 20 or later.
2. Copy `.env.example` to `.env`.
3. Configure a long random `JWT_SECRET`.
4. Create an administrator password hash:
   `node -e "require('bcryptjs').hash('YOUR_LONG_PASSWORD', 12).then(console.log)"`
   Put the resulting hash in `ADMIN_PASSWORD_HASH`.
5. Install and start:
   `npm install`
   `npm start`
6. Open `http://localhost:3000`.

## M-Pesa setup
1. Register/use a Safaricom Daraja developer account and create an app.
2. Start with Daraja sandbox credentials and a supported test shortcode/passkey.
3. Deploy the server to a public HTTPS host. A static-only host such as a basic Netlify site cannot run this Express/SQLite backend by itself.
4. Set `BASE_URL` and `MPESA_CALLBACK_URL` to the public HTTPS address ending in `/api/mpesa/callback`.
5. Add production credentials only after Safaricom approval and end-to-end testing.
6. Confirm the merchant shortcode/account is owned or authorised by you. Customer payments settle to that merchant account; the website database is not a bank wallet.

The callback endpoint must be publicly reachable over HTTPS. For production, add a Daraja callback validation strategy supported by Safaricom, operational monitoring, database backups, reconciliation against the M-Pesa statement, and idempotency/replay tests before accepting live payments. Never expose Daraja credentials in browser code.

## Owner-controlled withdrawals
This starter deliberately does not provide a public withdrawal endpoint or customer cash-out function. Merchant funds remain under the control of the registered merchant account holder and are withdrawn through the authorised Safaricom/bank channel. Keep merchant account access and payout credentials private.

## Telegram
Create a bot with Telegram's BotFather, then configure `TELEGRAM_BOT_TOKEN` on the server. Telegram bot commands, secure account linking, and package entitlement checks still need to be implemented and tested before public launch. Do not paste your bot token into the website or a public repository.

## Before launch
- Replace the demo brand copy and publish your support/contact details and terms/privacy/refund policies.
- Add CSRF protection for browser-authenticated state-changing routes, stronger admin MFA, audit logs, HTTPS, backups and monitoring.
- Add phone OTP/account verification and secure account linking.
- Add a customer package/session decrement endpoint with authentication and abuse prevention.
- Complete Daraja sandbox tests and live approval.
- Test callbacks for duplicates, amount/phone mismatch, failed payment and delayed delivery.
- Obtain appropriate legal/compliance advice for the markets where the service will be offered.


## Render deployment blueprint
This project includes `render.yaml`. It provisions a Node web service with a 1 GB persistent disk mounted at `/var/data` and stores SQLite at `/var/data/aviator.sqlite`. Render persistent disks are a paid feature and disable zero-downtime deploys; confirm current pricing in Render before deploying. Keep M-Pesa in sandbox until payment callbacks and security controls have been independently tested. This blueprint is a deployment starting point, not a production-readiness certification.
