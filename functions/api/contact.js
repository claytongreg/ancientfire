// Cloudflare Pages Function — POST /api/contact
// Sends contact-form submissions to info@ancientfire.ca via Resend.
//
// Required environment variables (set in Cloudflare Pages dashboard):
//   RESEND_API_KEY         — your Resend API key
//   TURNSTILE_SECRET_KEY   — Cloudflare Turnstile secret (not the site key)
//
// Spam protection layers:
//   1. Cloudflare Turnstile (bot/human verification)
//   2. Method + content-type guard
//   3. Honeypot field ("website" — must be empty)
//   4. Submission timing (must be >= 3s after the form rendered)
//   5. Field length + basic email shape validation
//   6. Lightweight per-IP rate limit (5 req / 10 min) via Cache API

const TO_ADDRESS = "info@ancientfire.ca";
const FROM_ADDRESS = "Ancient Fire <info@ancientfire.ca>";
const MIN_FILL_MS = 3000;
const MAX_NAME = 120;
const MAX_EMAIL = 200;
const MAX_PHONE = 40;
const MAX_MESSAGE = 5000;
const RATE_LIMIT = 5;          // submissions
const RATE_WINDOW_S = 600;     // per 10 minutes

const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

function json(status, body) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json; charset=utf-8" },
  });
}

function escapeHtml(s = "") {
  return s
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

async function rateLimited(request) {
  const ip =
    request.headers.get("cf-connecting-ip") ||
    request.headers.get("x-forwarded-for") ||
    "unknown";
  const key = `https://rate-limit.local/contact/${encodeURIComponent(ip)}`;
  const cache = caches.default;
  const cached = await cache.match(key);
  let count = 0;
  if (cached) {
    count = parseInt(await cached.text(), 10) || 0;
  }
  if (count >= RATE_LIMIT) return true;
  const next = new Response(String(count + 1), {
    headers: { "cache-control": `max-age=${RATE_WINDOW_S}` },
  });
  await cache.put(key, next);
  return false;
}

export async function onRequestPost({ request, env }) {
  // Method + content-type guard
  const ctype = request.headers.get("content-type") || "";
  if (!ctype.includes("application/json")) {
    return json(415, { ok: false, error: "Unsupported content type." });
  }

  if (await rateLimited(request)) {
    return json(429, { ok: false, error: "Too many submissions. Please try again later." });
  }

  let body;
  try {
    body = await request.json();
  } catch {
    return json(400, { ok: false, error: "Invalid JSON." });
  }

  const name = (body.name || "").toString().trim();
  const email = (body.email || "").toString().trim();
  const phone = (body.phone || "").toString().trim();
  const message = (body.message || "").toString().trim();
  const website = (body.website || "").toString();   // honeypot
  const turnstileToken = (body.turnstileToken || "").toString();
  const startedAt = Number(body.startedAt) || 0;

  // Honeypot
  if (website.length > 0) {
    return json(200, { ok: true });   // silently accept to confuse bots
  }

  // Timing
  if (!startedAt || Date.now() - startedAt < MIN_FILL_MS) {
    return json(400, { ok: false, error: "Submission was too fast. Please try again." });
  }

  // Validation
  if (!name || name.length > MAX_NAME) {
    return json(400, { ok: false, error: "Please provide your name." });
  }
  if (!email || email.length > MAX_EMAIL || !EMAIL_RE.test(email)) {
    return json(400, { ok: false, error: "Please provide a valid email." });
  }
  if (phone.length > MAX_PHONE) {
    return json(400, { ok: false, error: "Phone number is too long." });
  }
  if (!message || message.length > MAX_MESSAGE) {
    return json(400, { ok: false, error: "Please include a message." });
  }

  // Turnstile verification
  if (!env.TURNSTILE_SECRET_KEY) {
    return json(500, { ok: false, error: "Verification service is not configured." });
  }
  if (!turnstileToken) {
    return json(400, { ok: false, error: "Please complete the verification." });
  }
  const clientIp =
    request.headers.get("cf-connecting-ip") ||
    request.headers.get("x-forwarded-for") ||
    "";
  const verifyRes = await fetch(
    "https://challenges.cloudflare.com/turnstile/v0/siteverify",
    {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        secret: env.TURNSTILE_SECRET_KEY,
        response: turnstileToken,
        remoteip: clientIp,
      }),
    }
  );
  const verify = await verifyRes.json().catch(() => ({}));
  if (!verify.success) {
    return json(400, { ok: false, error: "Verification failed. Please try again." });
  }

  if (!env.RESEND_API_KEY) {
    return json(500, { ok: false, error: "Email service is not configured." });
  }

  const subject = `New contact form message from ${name}`;
  const text =
    `Name: ${name}\n` +
    `Email: ${email}\n` +
    `Phone: ${phone || "(not provided)"}\n\n` +
    `Message:\n${message}\n`;

  const html =
    `<div style="font-family:Inter,Arial,sans-serif;font-size:14px;line-height:1.5;color:#222;">` +
    `<p><strong>Name:</strong> ${escapeHtml(name)}</p>` +
    `<p><strong>Email:</strong> ${escapeHtml(email)}</p>` +
    `<p><strong>Phone:</strong> ${escapeHtml(phone) || "(not provided)"}</p>` +
    `<p><strong>Message:</strong></p>` +
    `<p style="white-space:pre-wrap;">${escapeHtml(message)}</p>` +
    `</div>`;

  const resendRes = await fetch("https://api.resend.com/emails", {
    method: "POST",
    headers: {
      "authorization": `Bearer ${env.RESEND_API_KEY}`,
      "content-type": "application/json",
    },
    body: JSON.stringify({
      from: FROM_ADDRESS,
      to: [TO_ADDRESS],
      reply_to: email,
      subject,
      text,
      html,
    }),
  });

  if (!resendRes.ok) {
    const detail = await resendRes.text().catch(() => "");
    console.error("Resend error", resendRes.status, detail);
    return json(502, { ok: false, error: "Could not send message right now. Please try again later." });
  }

  return json(200, { ok: true });
}

export function onRequest({ request }) {
  // Anything other than POST
  return json(405, { ok: false, error: "Method not allowed." });
}
