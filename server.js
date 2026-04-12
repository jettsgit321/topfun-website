const http = require("http");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

loadLocalEnv(path.join(__dirname, ".env"));

const HOST = process.env.HOST || "127.0.0.1";
const PORT = Number(process.env.PORT || 5500);
const ROOT = __dirname;
const PUBLIC_BASE_URL = process.env.PUBLIC_BASE_URL || `http://${HOST}:${PORT}`;
const DISCORD_INVITE_URL = process.env.DISCORD_INVITE_URL || "https://discord.gg/NmSn7dqPC8";
const WEBHOOK_TOLERANCE_SECONDS = 300;
const LAUNCH_TOKEN_TTL_SECONDS = Math.max(
  30,
  Number(process.env.LAUNCH_TOKEN_TTL_SECONDS || 120)
);
const LAUNCH_TOKEN_ISSUER = "topfun.gg";

const RATE_LIMIT_RULES = {
  checkout: { windowMs: 5 * 60_000, max: 20, cooldownMs: 10 * 60_000 },
  portal: { windowMs: 5 * 60_000, max: 30, cooldownMs: 10 * 60_000 },
  finalize: { windowMs: 10 * 60_000, max: 20, cooldownMs: 15 * 60_000 },
  orderStatus: { windowMs: 2 * 60_000, max: 120, cooldownMs: 5 * 60_000 },
  loaderToken: { windowMs: 2 * 60_000, max: 45, cooldownMs: 15 * 60_000 },
  loaderVerify: { windowMs: 2 * 60_000, max: 120, cooldownMs: 10 * 60_000 },
};
const RATE_LIMIT_STATE = new Map();

const DATA_DIR = path.join(ROOT, "data");
const ORDERS_PATH = path.join(DATA_DIR, "orders.json");
const DELIVERY_DIR = path.join(DATA_DIR, "deliveries");
const OUTBOX_DIR = path.join(DATA_DIR, "outbox");

const MIME_TYPES = {
  ".html": "text/html; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".js": "application/javascript; charset=utf-8",
  ".json": "application/json; charset=utf-8",
  ".png": "image/png",
  ".jpg": "image/jpeg",
  ".jpeg": "image/jpeg",
  ".svg": "image/svg+xml",
  ".ico": "image/x-icon",
};

const PLAN_TO_ENV_KEY = {
  "Starter - $6/week": "STRIPE_PRICE_STARTER",
  "Pro - $25/month": "STRIPE_PRICE_PRO",
  "Lifetime - $85 once": "STRIPE_PRICE_LIFETIME",
};

const KEYAUTH_PLAN_CONFIG = {
  "Starter - $6/week": {
    subEnv: "KEYAUTH_SUB_STARTER",
    daysEnv: "KEYAUTH_DAYS_STARTER",
    defaultSub: "starter",
    defaultDays: 7,
  },
  "Pro - $25/month": {
    subEnv: "KEYAUTH_SUB_PRO",
    daysEnv: "KEYAUTH_DAYS_PRO",
    countEnv: "KEYAUTH_KEYS_PRO",
    defaultSub: "pro",
    defaultDays: 30,
    defaultCount: 3,
  },
  "Lifetime - $85 once": {
    subEnv: "KEYAUTH_SUB_LIFETIME",
    daysEnv: "KEYAUTH_DAYS_LIFETIME",
    defaultSub: "lifetime",
    defaultDays: 36500,
  },
};

function loadLocalEnv(filePath) {
  if (!fs.existsSync(filePath)) {
    return;
  }

  const raw = fs.readFileSync(filePath, "utf8");
  const lines = raw.split(/\r?\n/);

  for (const line of lines) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith("#")) {
      continue;
    }

    const equalsIndex = trimmed.indexOf("=");
    if (equalsIndex <= 0) {
      continue;
    }

    const key = trimmed.slice(0, equalsIndex).trim();
    let value = trimmed.slice(equalsIndex + 1).trim();

    if (
      (value.startsWith('"') && value.endsWith('"')) ||
      (value.startsWith("'") && value.endsWith("'"))
    ) {
      value = value.slice(1, -1);
    }

    if (!process.env[key]) {
      process.env[key] = value;
    }
  }
}

function base64UrlEncode(inputBuffer) {
  return Buffer.from(inputBuffer)
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");
}

function base64UrlDecode(input) {
  const normalized = String(input || "")
    .replace(/-/g, "+")
    .replace(/_/g, "/");
  const padding = normalized.length % 4 === 0 ? "" : "=".repeat(4 - (normalized.length % 4));
  return Buffer.from(`${normalized}${padding}`, "base64");
}

function getLaunchTokenSecret() {
  return String(process.env.LAUNCH_TOKEN_SECRET || "").trim();
}

function createLaunchToken(payload) {
  const secret = getLaunchTokenSecret();
  if (!secret) {
    throw new Error("LAUNCH_TOKEN_SECRET is not configured.");
  }

  const header = {
    alg: "HS256",
    typ: "JWT",
  };

  const now = Math.floor(Date.now() / 1000);
  const body = {
    iss: LAUNCH_TOKEN_ISSUER,
    iat: now,
    exp: now + LAUNCH_TOKEN_TTL_SECONDS,
    ...payload,
  };

  const headerB64 = base64UrlEncode(Buffer.from(JSON.stringify(header), "utf8"));
  const payloadB64 = base64UrlEncode(Buffer.from(JSON.stringify(body), "utf8"));
  const signingInput = `${headerB64}.${payloadB64}`;
  const signature = base64UrlEncode(
    crypto.createHmac("sha256", secret).update(signingInput, "utf8").digest()
  );

  return `${signingInput}.${signature}`;
}

function verifyLaunchToken(token) {
  const secret = getLaunchTokenSecret();
  if (!secret) {
    throw new Error("LAUNCH_TOKEN_SECRET is not configured.");
  }

  const parts = String(token || "").split(".");
  if (parts.length !== 3) {
    throw new Error("Invalid token format.");
  }

  const [headerB64, payloadB64, signature] = parts;
  const signingInput = `${headerB64}.${payloadB64}`;
  const expected = base64UrlEncode(
    crypto.createHmac("sha256", secret).update(signingInput, "utf8").digest()
  );

  const sigA = Buffer.from(signature, "utf8");
  const sigB = Buffer.from(expected, "utf8");
  if (sigA.length !== sigB.length || !crypto.timingSafeEqual(sigA, sigB)) {
    throw new Error("Invalid token signature.");
  }

  const payloadRaw = base64UrlDecode(payloadB64).toString("utf8");
  const payload = JSON.parse(payloadRaw);
  const now = Math.floor(Date.now() / 1000);
  if (!payload.exp || Number(payload.exp) < now) {
    throw new Error("Token expired.");
  }
  if (payload.iss !== LAUNCH_TOKEN_ISSUER) {
    throw new Error("Token issuer mismatch.");
  }

  return payload;
}

function getClientIp(req) {
  const forwarded = String(req.headers["x-forwarded-for"] || "").split(",")[0].trim();
  if (forwarded) {
    return forwarded;
  }
  return (
    req.socket?.remoteAddress ||
    req.connection?.remoteAddress ||
    "unknown"
  );
}

function enforceRateLimit(req, res, key, rule) {
  const now = Date.now();
  const ip = getClientIp(req);
  const entryKey = `${key}:${ip}`;
  let state = RATE_LIMIT_STATE.get(entryKey);

  if (!state) {
    state = {
      count: 0,
      resetAt: now + rule.windowMs,
      blockedUntil: 0,
      strikes: 0,
    };
  }

  if (state.blockedUntil > now) {
    const retryAfter = Math.max(1, Math.ceil((state.blockedUntil - now) / 1000));
    res.writeHead(429, {
      "Content-Type": MIME_TYPES[".json"],
      "Retry-After": String(retryAfter),
    });
    res.end(
      JSON.stringify({
        ok: false,
        error: "Too many requests. Try again later.",
      })
    );
    RATE_LIMIT_STATE.set(entryKey, state);
    return false;
  }

  if (now >= state.resetAt) {
    state.count = 0;
    state.resetAt = now + rule.windowMs;
  }

  state.count += 1;
  if (state.count > rule.max) {
    state.strikes += 1;
    state.blockedUntil = now + rule.cooldownMs;
    RATE_LIMIT_STATE.set(entryKey, state);
    const retryAfter = Math.max(1, Math.ceil(rule.cooldownMs / 1000));
    res.writeHead(429, {
      "Content-Type": MIME_TYPES[".json"],
      "Retry-After": String(retryAfter),
    });
    res.end(
      JSON.stringify({
        ok: false,
        error: "Rate limit exceeded. Cooldown applied.",
      })
    );
    return false;
  }

  RATE_LIMIT_STATE.set(entryKey, state);
  return true;
}

function requireLoaderClientSecret(req) {
  const expected = String(process.env.LOADER_CLIENT_SECRET || "").trim();
  if (!expected) {
    return true;
  }

  const provided = String(req.headers["x-loader-secret"] || "").trim();
  if (!provided) {
    return false;
  }

  const a = Buffer.from(provided, "utf8");
  const b = Buffer.from(expected, "utf8");
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

function ensureDataStore() {
  fs.mkdirSync(DATA_DIR, { recursive: true });
  fs.mkdirSync(DELIVERY_DIR, { recursive: true });
  fs.mkdirSync(OUTBOX_DIR, { recursive: true });

  if (!fs.existsSync(ORDERS_PATH)) {
    fs.writeFileSync(ORDERS_PATH, "[]\n", "utf8");
  }
}

function readOrders() {
  ensureDataStore();
  try {
    const raw = fs.readFileSync(ORDERS_PATH, "utf8");
    const parsed = JSON.parse(raw || "[]");
    return Array.isArray(parsed) ? parsed : [];
  } catch {
    return [];
  }
}

function writeOrders(orders) {
  ensureDataStore();
  fs.writeFileSync(ORDERS_PATH, `${JSON.stringify(orders, null, 2)}\n`, "utf8");
}

function randomToken(bytes = 18) {
  return crypto.randomBytes(bytes).toString("hex");
}

function generateLicenseKey() {
  const prefix = (process.env.LICENSE_PREFIX || "TOPFUN").toUpperCase().replace(/[^A-Z0-9]/g, "");
  const chunk = () => crypto.randomBytes(3).toString("hex").toUpperCase();
  return `${prefix}-${chunk()}-${chunk()}-${chunk()}`;
}

function createDeliveryUrl(token, publicBaseUrl) {
  return `${publicBaseUrl.replace(/\/$/, "")}/delivery/${token}`;
}

function writeDeliveryArtifacts(order, publicBaseUrl) {
  ensureDataStore();

  const deliveryUrl = createDeliveryUrl(order.deliveryToken, publicBaseUrl);
  const allKeys = Array.isArray(order.licenseKeys) && order.licenseKeys.length > 0
    ? order.licenseKeys
    : [order.licenseKey].filter(Boolean);
  const keysBlock = allKeys.map((key, index) => `License Key ${index + 1}: ${key}`).join("\n");
  const deliveryText = [
    "TopFun.gg Delivery",
    "",
    `Order ID: ${order.orderId}`,
    `Session ID: ${order.sessionId}`,
    `Plan: ${order.plan}`,
    `Username: ${order.username}`,
    `Email: ${order.email}`,
    keysBlock,
    `Delivery Link: ${deliveryUrl}`,
    `Support Discord: ${DISCORD_INVITE_URL}`,
    "",
    "Instructions:",
    "1. Open your loader.",
    "2. Login with your account.",
    "3. Enter your license key.",
    "4. Join Discord if you need setup help.",
  ].join("\n");

  fs.writeFileSync(path.join(DELIVERY_DIR, `${order.sessionId}.txt`), `${deliveryText}\n`, "utf8");

  const outboxPayload = {
    to: order.email,
    subject: `TopFun.gg access for ${order.plan}`,
    sentAt: new Date().toISOString(),
    body: {
      username: order.username,
      plan: order.plan,
      licenseKey: order.licenseKey,
      licenseKeys: allKeys,
      deliveryUrl,
      supportDiscord: DISCORD_INVITE_URL,
    },
  };

  fs.writeFileSync(
    path.join(OUTBOX_DIR, `${order.sessionId}.json`),
    `${JSON.stringify(outboxPayload, null, 2)}\n`,
    "utf8"
  );

  return deliveryUrl;
}

function htmlEscape(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

function sendDeliveryPage(res, order, publicBaseUrl) {
  const deliveryUrl = createDeliveryUrl(order.deliveryToken, publicBaseUrl);
  const allKeys = Array.isArray(order.licenseKeys) && order.licenseKeys.length > 0
    ? order.licenseKeys
    : [order.licenseKey].filter(Boolean);
  const keyRows = allKeys
    .map(
      (key, index) =>
        `<div class="row"><span class="label">License Key ${index + 1}:</span><span class="value key">${htmlEscape(
          key
        )}</span></div>`
    )
    .join("");

  const html = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>TopFun.gg | Delivery</title>
  <style>
    body { margin: 0; font-family: "Segoe UI", system-ui, sans-serif; background: #080808; color: #f5f5f5; }
    .wrap { min-height: 100vh; display: grid; place-items: center; padding: 1rem; }
    .card { width: min(680px, 100%); border: 1px solid #2c2c2c; border-radius: 14px; padding: 1.2rem; background: #121212; }
    h1 { margin: 0; }
    p { color: #b6b6b6; }
    .row { display: grid; grid-template-columns: 140px 1fr; gap: 0.55rem; margin-bottom: 0.42rem; }
    .label { color: #9f9f9f; }
    .value { word-break: break-word; }
    .key { font-size: 1.02rem; font-weight: 800; color: #fff; }
    .btns { margin-top: 1rem; display: flex; gap: 0.6rem; flex-wrap: wrap; }
    a.btn { text-decoration: none; color: #fff; background: #9f1021; padding: 0.7rem 0.95rem; border-radius: 10px; font-weight: 700; }
    a.btn.alt { background: #1f1f1f; border: 1px solid #333; }
  </style>
</head>
<body>
  <main class="wrap">
    <section class="card">
      <h1>Access Delivered</h1>
      <p>Your order is fulfilled. Use the license key below to activate your plan.</p>
      <div class="row"><span class="label">Order ID:</span><span class="value">${htmlEscape(order.orderId)}</span></div>
      <div class="row"><span class="label">Plan:</span><span class="value">${htmlEscape(order.plan)}</span></div>
      <div class="row"><span class="label">Username:</span><span class="value">${htmlEscape(order.username)}</span></div>
      <div class="row"><span class="label">Email:</span><span class="value">${htmlEscape(order.email)}</span></div>
      ${keyRows}
      <div class="row"><span class="label">Delivery Link:</span><span class="value">${htmlEscape(deliveryUrl)}</span></div>
      <div class="btns">
        <a class="btn" href="${htmlEscape(DISCORD_INVITE_URL)}" target="_blank" rel="noopener noreferrer">Join Support Discord</a>
        <a class="btn alt" href="/">Back to site</a>
      </div>
    </section>
  </main>
</body>
</html>`;

  res.writeHead(200, { "Content-Type": "text/html; charset=utf-8" });
  res.end(html);
}

function sendJson(res, statusCode, payload) {
  res.writeHead(statusCode, { "Content-Type": MIME_TYPES[".json"] });
  res.end(JSON.stringify(payload));
}

function sendFile(res, absolutePath) {
  fs.readFile(absolutePath, (error, data) => {
    if (error) {
      res.writeHead(404, { "Content-Type": "text/plain; charset=utf-8" });
      res.end("Not found");
      return;
    }

    const extension = path.extname(absolutePath).toLowerCase();
    const mimeType = MIME_TYPES[extension] || "application/octet-stream";
    res.writeHead(200, { "Content-Type": mimeType });
    res.end(data);
  });
}

function parseBody(req) {
  return new Promise((resolve, reject) => {
    let body = "";

    req.on("data", (chunk) => {
      body += chunk;
      if (body.length > 1_000_000) {
        reject(new Error("Body too large"));
        req.destroy();
      }
    });

    req.on("end", () => {
      try {
        resolve(JSON.parse(body || "{}"));
      } catch {
        reject(new Error("Invalid JSON"));
      }
    });

    req.on("error", reject);
  });
}

function parseRawBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let total = 0;

    req.on("data", (chunk) => {
      chunks.push(chunk);
      total += chunk.length;
      if (total > 1_000_000) {
        reject(new Error("Body too large"));
        req.destroy();
      }
    });

    req.on("end", () => {
      resolve(Buffer.concat(chunks));
    });

    req.on("error", reject);
  });
}

function buildOrigin(req) {
  const hostHeader = req.headers.host || `${HOST}:${PORT}`;
  return `http://${hostHeader}`;
}

function buildPublicBaseUrl(req) {
  if (process.env.PUBLIC_BASE_URL) {
    return process.env.PUBLIC_BASE_URL;
  }
  return buildOrigin(req);
}

function hasStripeConfigForPlan(plan) {
  const envKey = PLAN_TO_ENV_KEY[plan];
  return Boolean(process.env.STRIPE_SECRET_KEY && envKey && process.env[envKey]);
}

function getWebhookSecret() {
  return String(process.env.STRIPE_WEBHOOK_SECRET || "").trim();
}

function isWebhookSecretConfigured() {
  const secret = getWebhookSecret();
  return Boolean(secret && secret.startsWith("whsec_") && secret.length > 10);
}

function getKeyAuthPlanConfig(plan) {
  const config = KEYAUTH_PLAN_CONFIG[plan] || null;
  if (!config) {
    return null;
  }

  const subscriptionName = String(process.env[config.subEnv] || config.defaultSub).trim();
  const daysRaw = Number(process.env[config.daysEnv] || config.defaultDays);
  const durationDays = Number.isFinite(daysRaw) && daysRaw > 0 ? Math.floor(daysRaw) : config.defaultDays;
  const proCountRaw = Number(process.env.KEYAUTH_KEYS_PRO || 3);
  const lifetimeCountRaw = Number(process.env.KEYAUTH_KEYS_LIFETIME || 2);
  const proKeyCount =
    Number.isFinite(proCountRaw) && proCountRaw > 0 ? Math.floor(proCountRaw) : 3;
  const lifetimeKeyCount =
    Number.isFinite(lifetimeCountRaw) && lifetimeCountRaw > 0 ? Math.floor(lifetimeCountRaw) : 2;

  let keyCount = 1;
  if (plan === "Pro - $25/month") {
    keyCount = proKeyCount;
  } else if (plan === "Lifetime - $85 once") {
    keyCount = lifetimeKeyCount;
  }

  return {
    subscriptionName,
    durationDays,
    keyCount,
  };
}

function hasKeyAuthConfigForPlan(plan) {
  const sellerKey = String(process.env.KEYAUTH_SELLER_KEY || "").trim();
  const planConfig = getKeyAuthPlanConfig(plan);
  return Boolean(sellerKey && planConfig && planConfig.subscriptionName);
}

async function keyAuthSellerRequest(params) {
  const sellerKey = String(process.env.KEYAUTH_SELLER_KEY || "").trim();
  if (!sellerKey) {
    throw new Error("KEYAUTH_SELLER_KEY is not configured.");
  }

  const query = new URLSearchParams({
    sellerkey: sellerKey,
    format: "JSON",
  });

  for (const [key, value] of Object.entries(params)) {
    if (value === undefined || value === null) {
      continue;
    }
    query.set(key, String(value));
  }

  const endpoint = `https://keyauth.win/api/seller/?${query.toString()}`;
  let lastError = null;

  for (let attempt = 1; attempt <= 3; attempt += 1) {
    try {
      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), 15_000);
      let response = null;
      try {
        response = await fetch(endpoint, {
          method: "GET",
          headers: {
            Accept: "application/json",
            "Accept-Encoding": "identity",
            "User-Agent": "topfun.gg/1.0 (+https://www.topfun.gg)",
            Connection: "close",
          },
          signal: controller.signal,
        });
      } finally {
        clearTimeout(timeout);
      }

      const rawText = await response.text();
      let data = null;
      try {
        data = rawText ? JSON.parse(rawText) : null;
      } catch {
        data = null;
      }

      if (!response.ok) {
        const preview = rawText ? rawText.slice(0, 220) : "empty response";
        throw new Error(`KeyAuth HTTP ${response.status}: ${preview}`);
      }
      if (!data || data.success === false) {
        const message = data?.message || (rawText ? rawText.slice(0, 220) : "KeyAuth seller API request failed.");
        throw new Error(message);
      }

      return data;
    } catch (error) {
      const message = String(error?.message || error || "unknown");
      lastError = new Error(`KeyAuth attempt ${attempt}/3 failed: ${message}`);
      const retryable =
        message.includes("terminated")
        || message.includes("fetch failed")
        || message.includes("aborted")
        || message.includes("socket");
      if (!retryable || attempt === 3) {
        break;
      }
      await new Promise((resolve) => setTimeout(resolve, 350 * attempt));
    }
  }

  throw lastError || new Error("KeyAuth seller API request failed.");
}

async function provisionKeyAuthLicenseForOrder({ plan, username, sessionId }) {
  const planConfig = getKeyAuthPlanConfig(plan);
  if (!planConfig) {
    throw new Error(`No KeyAuth plan mapping found for plan: ${plan}`);
  }

  const mask = String(process.env.KEYAUTH_MASK || "TOPFUN-*****");
  const note = `stripe_session=${sessionId}; user=${username}; plan=${plan}`;

  const data = await keyAuthSellerRequest({
    type: "add",
    expiry: planConfig.durationDays,
    mask,
    level: planConfig.subscriptionName,
    amount: planConfig.keyCount,
    note,
  });

  const keys = Array.isArray(data?.keys)
    ? data.keys.map((key) => String(key || "").trim()).filter(Boolean)
    : [];

  const singleKey = String(data?.key || "").trim();
  if (singleKey) {
    keys.push(singleKey);
  }

  const uniqueKeys = Array.from(new Set(keys));
  if (uniqueKeys.length === 0) {
    throw new Error("KeyAuth did not return a license key.");
  }

  return {
    key: uniqueKeys[0],
    keys: uniqueKeys,
    subscriptionName: planConfig.subscriptionName,
    durationDays: planConfig.durationDays,
    keyCount: planConfig.keyCount,
  };
}

async function revokeKeyAuthLicense(key) {
  const cleanKey = String(key || "").trim();
  if (!cleanKey) {
    throw new Error("Missing KeyAuth license key for revoke.");
  }

  await keyAuthSellerRequest({
    type: "del",
    key: cleanKey,
    usertoo: "false",
  });
}

async function stripeGetJson(apiPath, secretKey) {
  const response = await fetch(`https://api.stripe.com${apiPath}`, {
    method: "GET",
    headers: {
      Authorization: `Bearer ${secretKey}`,
    },
  });

  const json = await response.json();
  if (!response.ok) {
    const message = json?.error?.message || "Stripe request failed.";
    throw new Error(message);
  }

  return json;
}

async function stripePostForm(apiPath, payload, secretKey) {
  const response = await fetch(`https://api.stripe.com${apiPath}`, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${secretKey}`,
      "Content-Type": "application/x-www-form-urlencoded",
    },
    body: payload.toString(),
  });

  const json = await response.json();
  if (!response.ok) {
    const message = json?.error?.message || "Stripe request failed.";
    throw new Error(message);
  }

  return json;
}

function normalizeEmail(email) {
  return String(email || "").trim().toLowerCase();
}

function getPortalReturnUrl(req) {
  const configured = String(process.env.STRIPE_PORTAL_RETURN_URL || "").trim();
  if (configured) {
    return configured;
  }
  return `${buildPublicBaseUrl(req).replace(/\/$/, "")}/#pricing`;
}

async function findStripeCustomerIdForPortal({ orders, sessionId, email, secretKey }) {
  const cleanSessionId = String(sessionId || "").trim();
  const cleanEmail = normalizeEmail(email);

  if (cleanSessionId) {
    const orderBySession = orders.find((entry) => String(entry.sessionId || "") === cleanSessionId);
    if (orderBySession?.stripeCustomerId) {
      return String(orderBySession.stripeCustomerId);
    }
  }

  if (cleanEmail) {
    const orderCandidates = orders
      .filter((entry) => normalizeEmail(entry.email) === cleanEmail && entry.stripeCustomerId)
      .sort((a, b) => String(b.createdAt || "").localeCompare(String(a.createdAt || "")));
    if (orderCandidates.length > 0) {
      return String(orderCandidates[0].stripeCustomerId);
    }
  }

  if (cleanSessionId) {
    const stripeSession = await stripeGetJson(
      `/v1/checkout/sessions/${encodeURIComponent(cleanSessionId)}`,
      secretKey
    );
    if (stripeSession?.customer) {
      return String(stripeSession.customer);
    }
  }

  if (cleanEmail) {
    const customerLookup = await stripeGetJson(
      `/v1/customers?email=${encodeURIComponent(cleanEmail)}&limit=1`,
      secretKey
    );
    const first = Array.isArray(customerLookup?.data) ? customerLookup.data[0] : null;
    if (first?.id) {
      return String(first.id);
    }
  }

  return "";
}

async function createStripePortalSession({ customerId, returnUrl, secretKey }) {
  const payload = new URLSearchParams();
  payload.set("customer", customerId);
  payload.set("return_url", returnUrl);

  const portalResult = await stripePostForm("/v1/billing_portal/sessions", payload, secretKey);
  if (!portalResult?.url) {
    throw new Error("Stripe customer portal session could not be created.");
  }
  return portalResult;
}

async function createStripeCheckoutSession({ username, email, plan, origin }) {
  const secretKey = process.env.STRIPE_SECRET_KEY;
  const priceEnvKey = PLAN_TO_ENV_KEY[plan];
  const priceId = process.env[priceEnvKey];

  if (!secretKey || !priceEnvKey || !priceId) {
    throw new Error("Stripe is not configured for the selected plan.");
  }

  const priceResult = await stripeGetJson(`/v1/prices/${encodeURIComponent(priceId)}`, secretKey);
  const checkoutMode = priceResult.recurring ? "subscription" : "payment";

  const payload = new URLSearchParams();
  payload.set("mode", checkoutMode);
  payload.set("success_url", `${origin}/checkout-success.html?session_id={CHECKOUT_SESSION_ID}`);
  payload.set("cancel_url", `${origin}/checkout-cancel.html`);
  payload.set("line_items[0][price]", priceId);
  payload.set("line_items[0][quantity]", "1");
  payload.set("customer_email", email);
  payload.set("client_reference_id", username);
  payload.set("metadata[username]", username);
  payload.set("metadata[plan]", plan);

  const response = await fetch("https://api.stripe.com/v1/checkout/sessions", {
    method: "POST",
    headers: {
      Authorization: `Bearer ${secretKey}`,
      "Content-Type": "application/x-www-form-urlencoded",
    },
    body: payload.toString(),
  });

  const stripeResult = await response.json();
  if (!response.ok || !stripeResult.url) {
    const message = stripeResult?.error?.message || "Stripe checkout session could not be created.";
    throw new Error(message);
  }

  return {
    mode: "stripe",
    checkoutUrl: stripeResult.url,
    sessionId: stripeResult.id,
  };
}

function createMockCheckoutLink({ username, email, plan, origin }) {
  const token = randomToken(6);
  const checkoutUrl = new URL("/checkout-test.html", origin);
  checkoutUrl.searchParams.set("token", token);
  checkoutUrl.searchParams.set("user", username);
  checkoutUrl.searchParams.set("plan", plan);
  checkoutUrl.searchParams.set("email", email);

  return {
    mode: "mock",
    checkoutUrl: checkoutUrl.toString(),
  };
}

function secureHexEquals(a, b) {
  const one = Buffer.from(a, "hex");
  const two = Buffer.from(b, "hex");
  if (one.length !== two.length) {
    return false;
  }
  return crypto.timingSafeEqual(one, two);
}

function verifyStripeSignature(rawBody, signatureHeader, webhookSecret) {
  if (!signatureHeader || !webhookSecret) {
    return false;
  }

  const parts = signatureHeader.split(",").map((part) => part.trim());
  const timestampPart = parts.find((part) => part.startsWith("t="));
  const v1Part = parts.find((part) => part.startsWith("v1="));

  if (!timestampPart || !v1Part) {
    return false;
  }

  const timestamp = Number(timestampPart.slice(2));
  const signature = v1Part.slice(3);
  if (!Number.isFinite(timestamp) || !/^[a-f0-9]+$/i.test(signature)) {
    return false;
  }

  const ageSeconds = Math.abs(Math.floor(Date.now() / 1000) - timestamp);
  if (ageSeconds > WEBHOOK_TOLERANCE_SECONDS) {
    return false;
  }

  const signedPayload = `${timestamp}.${rawBody.toString("utf8")}`;
  const expected = crypto
    .createHmac("sha256", webhookSecret)
    .update(signedPayload, "utf8")
    .digest("hex");

  return secureHexEquals(expected, signature);
}

async function fulfillCheckoutSession(session, publicBaseUrl) {
  const sessionId = String(session.id || "").trim();
  if (!sessionId) {
    throw new Error("Missing Stripe session id for fulfillment.");
  }

  const orders = readOrders();
  const existing = orders.find((order) => order.sessionId === sessionId);
  if (existing) {
    return existing;
  }

  const username =
    String(session?.metadata?.username || "").trim() ||
    String(session.client_reference_id || "").trim() ||
    "unknown";

  const email =
    String(session.customer_email || "").trim() ||
    String(session?.customer_details?.email || "").trim() ||
    "unknown@example.com";

  const plan = String(session?.metadata?.plan || "").trim() || "Unknown plan";

  const amountTotal = Number.isFinite(session.amount_total) ? session.amount_total : null;
  const currency = session.currency ? String(session.currency).toUpperCase() : null;
  const deliveryToken = randomToken(24);
  const orderId = `ORD-${sessionId.toUpperCase()}`;
  const stripeSubscriptionId = session.subscription ? String(session.subscription) : null;
  const stripeCustomerId = session.customer ? String(session.customer) : null;

  let issuedLicenseKey = generateLicenseKey();
  let issuedLicenseKeys = [issuedLicenseKey];
  let licenseSource = "internal";
  let keyAuthSubscription = null;
  let keyAuthDurationDays = null;

  if (hasKeyAuthConfigForPlan(plan)) {
    const provisioned = await provisionKeyAuthLicenseForOrder({
      plan,
      username,
      sessionId,
    });
    issuedLicenseKey = provisioned.key;
    issuedLicenseKeys = Array.isArray(provisioned.keys) && provisioned.keys.length > 0
      ? provisioned.keys
      : [provisioned.key];
    licenseSource = "keyauth";
    keyAuthSubscription = provisioned.subscriptionName;
    keyAuthDurationDays = provisioned.durationDays;
  }

  const order = {
    orderId,
    sessionId,
    stripeSubscriptionId,
    stripeCustomerId,
    username,
    email,
    plan,
    amountTotal,
    currency,
    paymentStatus: String(session.payment_status || "paid"),
    status: "delivered",
    licenseKey: issuedLicenseKey,
    licenseKeys: issuedLicenseKeys,
    licenseSource,
    keyAuthSubscription,
    keyAuthDurationDays,
    keyAuthRevoked: false,
    revokedAt: null,
    hwidBindings: [],
    deliveryToken,
    discordInvite: DISCORD_INVITE_URL,
    createdAt: new Date().toISOString(),
  };

  orders.push(order);
  writeOrders(orders);

  const deliveryUrl = writeDeliveryArtifacts(order, publicBaseUrl);
  return {
    ...order,
    deliveryUrl,
  };
}

async function finalizeSessionById(sessionId, publicBaseUrl) {
  const cleanSessionId = String(sessionId || "").trim();
  if (!cleanSessionId) {
    throw new Error("Missing session_id");
  }

  const orders = readOrders();
  const existing = orders.find((order) => order.sessionId === cleanSessionId);
  if (existing) {
    return {
      from: "existing",
      order: existing,
    };
  }

  const secretKey = process.env.STRIPE_SECRET_KEY;
  if (!secretKey) {
    throw new Error("Stripe key missing on server.");
  }

  const stripeSession = await stripeGetJson(
    `/v1/checkout/sessions/${encodeURIComponent(cleanSessionId)}`,
    secretKey
  );

  const paymentStatus = String(stripeSession.payment_status || "").toLowerCase();
  if (!(paymentStatus === "paid" || paymentStatus === "no_payment_required")) {
    throw new Error(`Session is not paid yet (payment_status=${paymentStatus || "unknown"}).`);
  }

  const fulfilled = await fulfillCheckoutSession(stripeSession, publicBaseUrl);
  return {
    from: "stripe",
    order: fulfilled,
  };
}

async function revokeOrdersForSubscription(subscriptionId, reason = "subscription_revoked") {
  const cleanSubscriptionId = String(subscriptionId || "").trim();
  if (!cleanSubscriptionId) {
    return {
      matched: 0,
      revoked: 0,
      failures: [],
    };
  }

  const orders = readOrders();
  const matched = orders.filter((order) => String(order.stripeSubscriptionId || "") === cleanSubscriptionId);
  const failures = [];
  let revokedCount = 0;

  for (const order of matched) {
    if (order.keyAuthRevoked) {
      continue;
    }

    try {
      if (order.licenseSource === "keyauth") {
        const keys = Array.isArray(order.licenseKeys) && order.licenseKeys.length > 0
          ? order.licenseKeys
          : [order.licenseKey].filter(Boolean);
        for (const key of keys) {
          await revokeKeyAuthLicense(key);
        }
      }

      order.keyAuthRevoked = true;
      order.revokedAt = new Date().toISOString();
      order.status = "revoked";
      order.revokedReason = reason;
      revokedCount += 1;
    } catch (error) {
      failures.push({
        sessionId: order.sessionId,
        message: error.message || "Failed to revoke KeyAuth key.",
      });
    }
  }

  if (matched.length > 0) {
    writeOrders(orders);
  }

  return {
    matched: matched.length,
    revoked: revokedCount,
    failures,
  };
}

function upsertHwidBinding(order, hwid) {
  const normalizedHwid = String(hwid || "").trim();
  if (!normalizedHwid) {
    throw new Error("Missing HWID.");
  }

  const keys = Array.isArray(order.licenseKeys) && order.licenseKeys.length > 0
    ? order.licenseKeys
    : [order.licenseKey].filter(Boolean);
  const slotLimit = Math.max(1, keys.length);

  if (!Array.isArray(order.hwidBindings)) {
    order.hwidBindings = [];
  }

  const now = new Date().toISOString();
  const existing = order.hwidBindings.find((entry) => entry.hwid === normalizedHwid);
  if (existing) {
    existing.lastSeenAt = now;
    return {
      slotLimit,
      slotUsed: order.hwidBindings.length,
      accepted: true,
      isNew: false,
    };
  }

  if (order.hwidBindings.length >= slotLimit) {
    return {
      slotLimit,
      slotUsed: order.hwidBindings.length,
      accepted: false,
      isNew: true,
    };
  }

  order.hwidBindings.push({
    hwid: normalizedHwid,
    firstSeenAt: now,
    lastSeenAt: now,
  });

  return {
    slotLimit,
    slotUsed: order.hwidBindings.length,
    accepted: true,
    isNew: true,
  };
}

function getOrderLicenseKeys(order) {
  const keys = Array.isArray(order?.licenseKeys) ? order.licenseKeys : [];
  const normalized = keys.map((key) => String(key || "").trim()).filter(Boolean);
  if (normalized.length > 0) {
    return normalized;
  }
  const single = String(order?.licenseKey || "").trim();
  return single ? [single] : [];
}

function getOrderSlotLimit(order) {
  return Math.max(1, getOrderLicenseKeys(order).length);
}

function buildOrderPayload(order, publicBaseUrl) {
  return {
    orderId: order.orderId,
    sessionId: order.sessionId,
    username: order.username,
    email: order.email,
    plan: order.plan,
    status: order.status,
    paymentStatus: order.paymentStatus,
    licenseKey: order.licenseKey,
    licenseKeys: getOrderLicenseKeys(order),
    slotLimit: getOrderSlotLimit(order),
    hwidBindings: Array.isArray(order.hwidBindings) ? order.hwidBindings : [],
    licenseSource: order.licenseSource || null,
    keyAuthRevoked: Boolean(order.keyAuthRevoked),
    revokedAt: order.revokedAt || null,
    revokedReason: order.revokedReason || null,
    deliveryUrl: order.deliveryToken ? createDeliveryUrl(order.deliveryToken, publicBaseUrl) : null,
    createdAt: order.createdAt,
  };
}

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, buildOrigin(req));

  if (req.method === "POST" && url.pathname === "/api/create-checkout") {
    if (!enforceRateLimit(req, res, "create-checkout", RATE_LIMIT_RULES.checkout)) {
      return;
    }

    try {
      const body = await parseBody(req);
      const username = String(body.username || "").trim();
      const email = String(body.email || "").trim();
      const plan = String(body.plan || "").trim();

      if (!username || !email || !plan) {
        sendJson(res, 400, { ok: false, error: "Missing required fields." });
        return;
      }

      const origin = buildOrigin(req);
      const result = hasStripeConfigForPlan(plan)
        ? await createStripeCheckoutSession({ username, email, plan, origin })
        : createMockCheckoutLink({ username, email, plan, origin });

      sendJson(res, 200, {
        ok: true,
        mode: result.mode,
        checkoutUrl: result.checkoutUrl,
        sessionId: result.sessionId || null,
      });
      return;
    } catch (error) {
      sendJson(res, 400, {
        ok: false,
        error: error.message || "Could not create checkout link.",
      });
      return;
    }
  }

  if (req.method === "POST" && url.pathname === "/api/create-portal-session") {
    if (!enforceRateLimit(req, res, "create-portal-session", RATE_LIMIT_RULES.portal)) {
      return;
    }

    try {
      const secretKey = String(process.env.STRIPE_SECRET_KEY || "").trim();
      if (!secretKey) {
        sendJson(res, 503, { ok: false, error: "Stripe is not configured on the server." });
        return;
      }

      const body = await parseBody(req);
      const email = String(body.email || "").trim();
      const sessionId = String(body.session_id || body.sessionId || "").trim();
      if (!email && !sessionId) {
        sendJson(res, 400, { ok: false, error: "Provide email or session_id." });
        return;
      }

      const orders = readOrders();
      const customerId = await findStripeCustomerIdForPortal({
        orders,
        sessionId,
        email,
        secretKey,
      });

      if (!customerId) {
        sendJson(res, 404, {
          ok: false,
          error: "No Stripe customer found for that email/session.",
        });
        return;
      }

      const portalSession = await createStripePortalSession({
        customerId,
        returnUrl: getPortalReturnUrl(req),
        secretKey,
      });

      sendJson(res, 200, {
        ok: true,
        portalUrl: portalSession.url,
        customerId,
      });
      return;
    } catch (error) {
      sendJson(res, 400, {
        ok: false,
        error: error.message || "Could not create portal session.",
      });
      return;
    }
  }

  if (req.method === "POST" && url.pathname === "/api/stripe-webhook") {
    try {
      if (!isWebhookSecretConfigured()) {
        sendJson(res, 503, {
          ok: false,
          error: "Stripe webhook secret is not configured on the server.",
        });
        return;
      }

      const rawBody = await parseRawBody(req);
      const webhookSecret = getWebhookSecret();
      const signature = String(req.headers["stripe-signature"] || "");

      const valid = verifyStripeSignature(rawBody, signature, webhookSecret);
      if (!valid) {
        sendJson(res, 400, { ok: false, error: "Invalid webhook signature." });
        return;
      }

      const event = JSON.parse(rawBody.toString("utf8") || "{}");
      let fulfilled = false;
      let deliveryUrl = null;
      let revoked = false;
      let revokeSummary = null;
      let revokeTrigger = null;

      if (event.type === "checkout.session.completed" && event?.data?.object) {
        const order = await fulfillCheckoutSession(event.data.object, buildPublicBaseUrl(req));
        fulfilled = true;
        deliveryUrl = createDeliveryUrl(order.deliveryToken, buildPublicBaseUrl(req));
      }

      if (event.type === "customer.subscription.deleted" && event?.data?.object?.id) {
        revokeSummary = await revokeOrdersForSubscription(
          event.data.object.id,
          "subscription_deleted"
        );
        revoked = (revokeSummary?.revoked || 0) > 0;
        revokeTrigger = "customer.subscription.deleted";
      }

      if (event.type === "invoice.payment_failed" && event?.data?.object?.subscription) {
        revokeSummary = await revokeOrdersForSubscription(
          event.data.object.subscription,
          "payment_failed"
        );
        revoked = (revokeSummary?.revoked || 0) > 0;
        revokeTrigger = "invoice.payment_failed";
      }

      if (event.type === "customer.subscription.updated" && event?.data?.object?.id) {
        const sub = event.data.object;
        const status = String(sub.status || "").toLowerCase();
        const cancelAtPeriodEnd = Boolean(sub.cancel_at_period_end);
        const revokeOnCancelAtPeriodEnd = String(
          process.env.REVOKE_ON_CANCEL_AT_PERIOD_END || "true"
        ).toLowerCase() !== "false";

        const shouldRevoke =
          status === "canceled" ||
          status === "unpaid" ||
          status === "incomplete_expired" ||
          (cancelAtPeriodEnd && revokeOnCancelAtPeriodEnd);

        if (shouldRevoke) {
          const reason = cancelAtPeriodEnd ? "cancel_at_period_end" : `subscription_status_${status}`;
          revokeSummary = await revokeOrdersForSubscription(sub.id, reason);
          revoked = (revokeSummary?.revoked || 0) > 0;
          revokeTrigger = "customer.subscription.updated";
        }
      }

      sendJson(res, 200, {
        ok: true,
        received: true,
        type: event.type || null,
        fulfilled,
        deliveryUrl,
        revoked,
        revokeSummary,
        revokeTrigger,
      });
      return;
    } catch (error) {
      sendJson(res, 400, {
        ok: false,
        error: error.message || "Webhook handling failed.",
      });
      return;
    }
  }

  if (req.method === "GET" && url.pathname === "/api/order-status") {
    if (!enforceRateLimit(req, res, "order-status", RATE_LIMIT_RULES.orderStatus)) {
      return;
    }

    const sessionId = String(url.searchParams.get("session_id") || "").trim();
    if (!sessionId) {
      sendJson(res, 400, { ok: false, error: "Missing session_id" });
      return;
    }

    const orders = readOrders();
    const found = orders.find((order) => order.sessionId === sessionId);

    if (!found) {
      sendJson(res, 200, { ok: true, found: false });
      return;
    }

    sendJson(res, 200, {
      ok: true,
      found: true,
      order: buildOrderPayload(found, buildPublicBaseUrl(req)),
    });
    return;
  }

  if (req.method === "POST" && url.pathname === "/api/finalize-session") {
    if (!enforceRateLimit(req, res, "finalize-session", RATE_LIMIT_RULES.finalize)) {
      return;
    }

    try {
      const body = await parseBody(req);
      const sessionId = String(body.session_id || body.sessionId || "").trim();
      if (!sessionId) {
        sendJson(res, 400, { ok: false, error: "Missing session_id" });
        return;
      }

      const finalized = await finalizeSessionById(sessionId, buildPublicBaseUrl(req));
      sendJson(res, 200, {
        ok: true,
        finalized: true,
        source: finalized.from,
        order: buildOrderPayload(finalized.order, buildPublicBaseUrl(req)),
      });
      return;
    } catch (error) {
      sendJson(res, 400, {
        ok: false,
        error: error.message || "Could not finalize session.",
      });
      return;
    }
  }

  if (req.method === "POST" && url.pathname === "/api/loader-token") {
    if (!enforceRateLimit(req, res, "loader-token", RATE_LIMIT_RULES.loaderToken)) {
      return;
    }

    if (!requireLoaderClientSecret(req)) {
      sendJson(res, 401, { ok: false, error: "Unauthorized loader client." });
      return;
    }

    try {
      const body = await parseBody(req);
      const sessionId = String(body.session_id || body.sessionId || "").trim();
      const licenseKey = String(body.license_key || body.licenseKey || "").trim();
      const hwid = String(body.hwid || "").trim();

      if (!sessionId || !licenseKey || !hwid) {
        sendJson(res, 400, {
          ok: false,
          error: "Missing required fields: session_id, license_key, hwid.",
        });
        return;
      }

      const orders = readOrders();
      const order = orders.find((entry) => entry.sessionId === sessionId);
      if (!order) {
        sendJson(res, 404, { ok: false, error: "Order not found for session_id." });
        return;
      }

      if (order.keyAuthRevoked || String(order.status || "").toLowerCase() === "revoked") {
        sendJson(res, 403, { ok: false, error: "License is revoked." });
        return;
      }

      const paymentStatus = String(order.paymentStatus || "").toLowerCase();
      if (!(paymentStatus === "paid" || paymentStatus === "no_payment_required")) {
        sendJson(res, 403, { ok: false, error: "Order payment is not valid." });
        return;
      }

      const keys = getOrderLicenseKeys(order);
      if (!keys.includes(licenseKey)) {
        sendJson(res, 403, { ok: false, error: "License key is not valid for this order." });
        return;
      }

      const binding = upsertHwidBinding(order, hwid);
      if (!binding.accepted) {
        sendJson(res, 403, {
          ok: false,
          error: `HWID slot limit reached (${binding.slotUsed}/${binding.slotLimit}).`,
          slotLimit: binding.slotLimit,
          slotUsed: binding.slotUsed,
        });
        return;
      }

      writeOrders(orders);

      const token = createLaunchToken({
        sid: order.sessionId,
        oid: order.orderId,
        lkey: licenseKey,
        hwid,
        plan: order.plan,
      });

      sendJson(res, 200, {
        ok: true,
        token,
        tokenType: "bearer",
        expiresIn: LAUNCH_TOKEN_TTL_SECONDS,
        slotLimit: binding.slotLimit,
        slotUsed: binding.slotUsed,
        isNewDevice: binding.isNew,
      });
      return;
    } catch (error) {
      const message = error.message || "Could not issue loader token.";
      const statusCode = message.includes("LAUNCH_TOKEN_SECRET") ? 500 : 400;
      sendJson(res, statusCode, {
        ok: false,
        error: message,
      });
      return;
    }
  }

  if (req.method === "POST" && url.pathname === "/api/loader-verify") {
    if (!enforceRateLimit(req, res, "loader-verify", RATE_LIMIT_RULES.loaderVerify)) {
      return;
    }

    if (!requireLoaderClientSecret(req)) {
      sendJson(res, 401, { ok: false, error: "Unauthorized loader client." });
      return;
    }

    try {
      const body = await parseBody(req);
      const token = String(body.token || "").trim();
      if (!token) {
        sendJson(res, 400, { ok: false, error: "Missing token." });
        return;
      }

      const payload = verifyLaunchToken(token);
      const orders = readOrders();
      const order = orders.find((entry) => entry.sessionId === String(payload.sid || "").trim());
      if (!order) {
        throw new Error("Order not found for token.");
      }
      if (order.keyAuthRevoked || String(order.status || "").toLowerCase() === "revoked") {
        throw new Error("License revoked.");
      }

      const keys = getOrderLicenseKeys(order);
      const tokenLicense = String(payload.lkey || "").trim();
      if (!tokenLicense || !keys.includes(tokenLicense)) {
        throw new Error("License key no longer valid.");
      }

      const tokenHwid = String(payload.hwid || "").trim();
      if (tokenHwid) {
        const hasHwid = Array.isArray(order.hwidBindings)
          && order.hwidBindings.some((binding) => binding?.hwid === tokenHwid);
        if (!hasHwid) {
          throw new Error("HWID is not authorized for this license.");
        }
      }

      sendJson(res, 200, {
        ok: true,
        valid: true,
        token: {
          sessionId: order.sessionId,
          orderId: order.orderId,
          plan: order.plan,
          licenseKey: tokenLicense,
          hwid: tokenHwid || null,
          issuedAt: payload.iat || null,
          expiresAt: payload.exp || null,
        },
      });
      return;
    } catch (error) {
      sendJson(res, 401, {
        ok: false,
        valid: false,
        error: error.message || "Invalid loader token.",
      });
      return;
    }
  }

  if (req.method === "POST" && url.pathname === "/api/dev/fulfill-session") {
    if (process.env.ENABLE_DEV_FULFILL === "false") {
      sendJson(res, 403, { ok: false, error: "Dev fulfill route disabled." });
      return;
    }

    try {
      const body = await parseBody(req);
      const username = String(body.username || "devuser");
      const email = String(body.email || "dev@example.com");
      const plan = String(body.plan || "Pro - $25/month");
      const sessionId = String(body.sessionId || `cs_test_${randomToken(8)}`);
      const amountTotal = Number(body.amountTotal || 4900);
      const currency = String(body.currency || "usd");
      const subscriptionId = body.stripeSubscriptionId
        ? String(body.stripeSubscriptionId)
        : null;

      const session = {
        id: sessionId,
        client_reference_id: username,
        customer_email: email,
        metadata: {
          username,
          plan,
        },
        payment_status: "paid",
        amount_total: Number.isFinite(amountTotal) ? amountTotal : null,
        currency,
        subscription: subscriptionId,
      };

      const order = await fulfillCheckoutSession(session, buildPublicBaseUrl(req));
      sendJson(res, 200, {
        ok: true,
        delivered: true,
        orderId: order.orderId,
        licenseKey: order.licenseKey,
        deliveryUrl: createDeliveryUrl(order.deliveryToken, buildPublicBaseUrl(req)),
      });
      return;
    } catch (error) {
      sendJson(res, 400, {
        ok: false,
        error: error.message || "Dev fulfill failed.",
      });
      return;
    }
  }

  if (req.method === "POST" && url.pathname === "/api/dev/revoke-subscription") {
    if (process.env.ENABLE_DEV_FULFILL === "false") {
      sendJson(res, 403, { ok: false, error: "Dev revoke route disabled." });
      return;
    }

    try {
      const body = await parseBody(req);
      const subscriptionId = String(body.subscription_id || body.subscriptionId || "").trim();
      if (!subscriptionId) {
        sendJson(res, 400, { ok: false, error: "Missing subscription_id" });
        return;
      }

      const summary = await revokeOrdersForSubscription(subscriptionId);
      sendJson(res, 200, {
        ok: true,
        revoked: true,
        subscriptionId,
        summary,
      });
      return;
    } catch (error) {
      sendJson(res, 400, {
        ok: false,
        error: error.message || "Dev revoke failed.",
      });
      return;
    }
  }

  if (req.method === "GET" && url.pathname.startsWith("/delivery/")) {
    const token = String(url.pathname.slice("/delivery/".length) || "").trim();
    if (!token) {
      res.writeHead(404, { "Content-Type": "text/plain; charset=utf-8" });
      res.end("Not found");
      return;
    }

    const orders = readOrders();
    const order = orders.find((item) => item.deliveryToken === token);
    if (!order) {
      res.writeHead(404, { "Content-Type": "text/plain; charset=utf-8" });
      res.end("Delivery not found");
      return;
    }

    sendDeliveryPage(res, order, buildPublicBaseUrl(req));
    return;
  }

  if (req.method !== "GET" && req.method !== "HEAD") {
    res.writeHead(405, { "Content-Type": "text/plain; charset=utf-8" });
    res.end("Method not allowed");
    return;
  }

  const requestPath = url.pathname === "/" ? "/index.html" : url.pathname;
  const safePath = path.normalize(requestPath).replace(/^([.][.][/\\])+/, "");
  const filePath = path.resolve(ROOT, `.${safePath}`);

  if (!filePath.startsWith(ROOT)) {
    res.writeHead(403, { "Content-Type": "text/plain; charset=utf-8" });
    res.end("Forbidden");
    return;
  }

  sendFile(res, filePath);
});

server.listen(PORT, HOST, () => {
  ensureDataStore();
  const stripeReady = Boolean(process.env.STRIPE_SECRET_KEY);
  const mode = stripeReady ? "stripe+delivery" : "mock+delivery";
  console.log(`TopFun server running at http://${HOST}:${PORT} (${mode})`);
});
