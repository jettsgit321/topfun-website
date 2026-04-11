# topfun.gg website

Landing + checkout website with:

- Static frontend (`index.html`, `styles.css`, `app.js`)
- Node backend (`server.js`) for:
  - Stripe Checkout + webhooks
  - Stripe Customer Portal sessions
  - KeyAuth license delivery/revoke
  - Loader token issue/verify APIs

## Local run

```powershell
node server.js
```

Open `http://127.0.0.1:5700`
