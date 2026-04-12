# Checkout + KeyAuth Delivery Setup

## 1) Configure `.env`
1. Copy `.env.example` to `.env`.
2. Stripe setup:
   - Set `STRIPE_SECRET_KEY`
   - Set `STRIPE_PRICE_STARTER`, `STRIPE_PRICE_PRO`, `STRIPE_PRICE_LIFETIME` (must be `price_...`, not `prod_...`)
   - Set `PUBLIC_BASE_URL` to your live/local URL (default local: `http://127.0.0.1:5700`)
3. KeyAuth setup:
   - Set `KEYAUTH_SELLER_KEY`
   - Set `KEYAUTH_SUB_STARTER`, `KEYAUTH_SUB_PRO`, `KEYAUTH_SUB_LIFETIME` to your KeyAuth subscription names
   - Optional: set `KEYAUTH_SELLER_URL=https://keyauth.win/api/seller/` to force one seller host
   - Optional: set `KEYAUTH_KEYS_PRO=1` and `KEYAUTH_KEYS_LIFETIME=1` if KeyAuth bulk generation is blocked
   - Set backend device-slot policy with `DEVICE_SLOTS_STARTER`, `DEVICE_SLOTS_PRO`, `DEVICE_SLOTS_LIFETIME` (for example `1/3/2`)
   - Optional: tune durations with `KEYAUTH_DAYS_*`
   - Optional: customize key mask with `KEYAUTH_MASK`
4. Loader token setup:
   - Set `LAUNCH_TOKEN_SECRET` (long random value)
   - Optional: set `LAUNCH_TOKEN_TTL_SECONDS` (default 120)
   - Optional: set `LOADER_CLIENT_SECRET` and send it in header `x-loader-secret` from your loader
5. Customer portal setup:
   - Optional: set `STRIPE_PORTAL_RETURN_URL` (default fallback is `PUBLIC_BASE_URL/#pricing`)
   - Users can self-manage/cancel through `POST /api/create-portal-session` (site now includes this form)

If KeyAuth seller key is not set, the server still fulfills with internal fallback keys.

## 2) Run the site
```powershell
cd "C:\Users\jettk\OneDrive\Documents\New folder\website topfun.gg"
node server.js
```

Open: `http://127.0.0.1:5700`

## 3) Enable Stripe webhook forwarding
Run Stripe CLI in another terminal:
```powershell
& "C:\Users\jettk\AppData\Local\Microsoft\WinGet\Packages\Stripe.StripeCli_Microsoft.Winget.Source_8wekyb3d8bbwe\stripe.exe" listen --forward-to http://127.0.0.1:5700/api/stripe-webhook
```
Copy the printed `whsec_...` into `.env` as `STRIPE_WEBHOOK_SECRET`, then restart `node server.js`.
Webhook processing is now strict: if the secret is missing/invalid, `/api/stripe-webhook` returns error and does not process events.

## 4) Live automated behavior
1. Buyer pays via Stripe Checkout.
2. Webhook `checkout.session.completed` triggers fulfillment.
3. Server auto-creates license:
   - Uses KeyAuth seller API (`type=add`) if configured
   - Stores order + license in `data/orders.json`
   - Writes artifacts in `data/deliveries/` and `data/outbox/`
4. Success page polls order status and now has fallback finalize by session id if webhook is delayed.
5. If subscription is later canceled (`customer.subscription.deleted`), server revokes the KeyAuth key automatically (`type=del`) and marks order revoked.
6. Non-payment/cancel coverage:
   - `invoice.payment_failed` -> auto revoke key
   - `customer.subscription.deleted` -> auto revoke key
   - `customer.subscription.updated` with `cancel_at_period_end=true` -> auto revoke by default (`REVOKE_ON_CANCEL_AT_PERIOD_END=true`)

## 5) Useful local test routes
Simulate fulfillment:
```powershell
Invoke-RestMethod -Method Post -Uri http://127.0.0.1:5700/api/dev/fulfill-session -ContentType 'application/json' -Body '{"username":"dev","email":"dev@example.com","plan":"Pro - $25/month"}'
```

Simulate subscription-linked fulfillment:
```powershell
Invoke-RestMethod -Method Post -Uri http://127.0.0.1:5700/api/dev/fulfill-session -ContentType 'application/json' -Body '{"username":"dev","email":"dev@example.com","plan":"Pro - $25/month","stripeSubscriptionId":"sub_test_123"}'
```

Simulate cancellation revoke:
```powershell
Invoke-RestMethod -Method Post -Uri http://127.0.0.1:5700/api/dev/revoke-subscription -ContentType 'application/json' -Body '{"subscription_id":"sub_test_123"}'
```

Check order status:
```powershell
Invoke-RestMethod -Uri "http://127.0.0.1:5700/api/order-status?session_id=cs_test_xxx"
```
`order-status` now returns `slotLimit` and `hwidBindings` in the `order` payload.

Force finalize from Stripe session id:
```powershell
Invoke-RestMethod -Method Post -Uri http://127.0.0.1:5700/api/finalize-session -ContentType 'application/json' -Body '{"session_id":"cs_test_xxx"}'
```
`finalize-session` now also returns `slotLimit` and `hwidBindings`.

Issue loader launch token (after successful order):
```powershell
Invoke-RestMethod -Method Post -Uri http://127.0.0.1:5700/api/loader-token -Headers @{ "x-loader-secret" = "YOUR_LOADER_SECRET_IF_SET" } -ContentType 'application/json' -Body '{"session_id":"cs_test_xxx","license_key":"TOPFUN-XXXXX","hwid":"PC-123"}'
```

Verify loader token:
```powershell
Invoke-RestMethod -Method Post -Uri http://127.0.0.1:5700/api/loader-verify -Headers @{ "x-loader-secret" = "YOUR_LOADER_SECRET_IF_SET" } -ContentType 'application/json' -Body '{"token":"PASTE_TOKEN_HERE"}'
```

Create billing portal session (cancel/manage subscription):
```powershell
Invoke-RestMethod -Method Post -Uri http://127.0.0.1:5700/api/create-portal-session -ContentType 'application/json' -Body '{"email":"buyer@example.com"}'
```

## 6) Production hardening
- Disable `ENABLE_DEV_FULFILL` in production.
- Use HTTPS and a public webhook endpoint.
- Rotate leaked API keys immediately.
- Add real email sender for outbox delivery.
- Add auth on any admin/dev routes.
- Keep `STRIPE_WEBHOOK_SECRET`, `LAUNCH_TOKEN_SECRET`, and `LOADER_CLIENT_SECRET` in server-only env.


