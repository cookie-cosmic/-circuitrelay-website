/**
 * CircuitRelay - Secure Cloudflare Worker
 * ---------------------------------------
 * This Worker acts as a secure private API between the website and GitHub.
 * The GitHub token is stored ONLY as a Cloudflare secret (env var), never
 * in client-side code. It reads/writes the site-data.json file in the repo.
 *
 * Security features:
 *  - GitHub token accessed only via env var (never exposed to clients)
 *  - Optional ADMIN_KEY secret required for write operations
 *  - CORS restricted to allowed origins
 *  - Rate limiting to prevent abuse
 */

// ---------- Configuration (via Cloudflare secret / vars) ----------
// Env vars to set in Cloudflare Worker:
//   GITHUB_TOKEN  (secret) - the personal access token
//   ADMIN_KEY     (secret) - any long random string you choose; the site
//                            sends this to authorize writes. Keep it secret.
//   ALLOWED_ORIGIN (var)   - e.g. "https://yourdomain.com" or "*" for dev
//   GITHUB_OWNER  (var)    - "cookie-cosmic"
//   GITHUB_REPO   (var)    - "-circuitrelay-website"
//   GITHUB_BRANCH (var)    - "main"
//   DATA_FILE     (var)    - "site-data.json"

const OWNER = envOrDefault("GITHUB_OWNER", "cookie-cosmic");
const REPO = envOrDefault("GITHUB_REPO", "-circuitrelay-website");
const BRANCH = envOrDefault("GITHUB_BRANCH", "main");
const FILE = envOrDefault("DATA_FILE", "site-data.json");

const API = `https://api.github.com/repos/${OWNER}/${REPO}/contents/${FILE}`;
const RAW = `https://raw.githubusercontent.com/${OWNER}/${REPO}/${BRANCH}/${FILE}`;

// Simple in-memory rate limiter: max N requests per IP per minute
const RATE_LIMIT = 60;
const rateMap = new Map();

function envOrDefault(name, fallback) {
  try {
    return (typeof name !== "undefined" && globalThis && globalThis[name] !== undefined) ? globalThis[name] : fallback;
  } catch {
    return fallback;
  }
}

function corsHeaders() {
  const origin = typeof ALLOWED_ORIGIN === "undefined" ? "*" : ALLOWED_ORIGIN;
  return {
    "Access-Control-Allow-Origin": origin,
    "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, x-admin-key",
    "Access-Control-Max-Age": "86400",
  };
}

function json(data, status = 200, headers = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "Content-Type": "application/json", ...corsHeaders(), ...headers },
  });
}

function rateLimit(ip) {
  const now = Date.now();
  const windowMs = 60 * 1000;
  const entry = rateMap.get(ip) || { count: 0, start: now };
  if (now - entry.start > windowMs) {
    entry.count = 0;
    entry.start = now;
  }
  entry.count += 1;
  rateMap.set(ip, entry);
  return entry.count <= RATE_LIMIT;
}

async function getFileSha() {
  const res = await fetch(API, {
    headers: {
      Authorization: `token ${GITHUB_TOKEN}`,
      Accept: "application/vnd.github.v3+json",
    },
  });
  if (!res.ok) return null;
  const data = await res.json();
  return data.sha || null;
}

async function handleGet() {
  // Public read - no token needed from GitHub raw
  const res = await fetch(RAW, { cache: "no-store" });
  if (!res.ok) {
    return json({ ok: false, error: "Could not read site data" }, 404);
  }
  const text = await res.text();
  return new Response(text, {
    status: 200,
    headers: { "Content-Type": "application/json", ...corsHeaders(), "Cache-Control": "no-store" },
  });
}

async function handlePost(request) {
  // Write - requires ADMIN_KEY
  const adminKey = request.headers.get("x-admin-key") || "";
  if (typeof ADMIN_KEY === "undefined" || adminKey !== ADMIN_KEY) {
    return json({ ok: false, error: "Unauthorized" }, 401);
  }

  let body;
  try {
    body = await request.json();
  } catch {
    return json({ ok: false, error: "Invalid JSON" }, 400);
  }

  if (!body || typeof body.data === "undefined") {
    return json({ ok: false, error: "Missing data" }, 400);
  }

  const payload = JSON.stringify(body.data, null, 2);
  const content = btoa(unescape(encodeURIComponent(payload)));

  const sha = await getFileSha();
  const updateBody = {
    message: "Update site data via Cloudflare Worker",
    content,
    branch: BRANCH,
  };
  if (sha) updateBody.sha = sha;

  const res = await fetch(API, {
    method: "PUT",
    headers: {
      Authorization: `token ${GITHUB_TOKEN}`,
      Accept: "application/vnd.github.v3+json",
      "Content-Type": "application/json",
    },
    body: JSON.stringify(updateBody),
  });

  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    return json({ ok: false, error: err.message || "Failed to save" }, 500);
  }
  return json({ ok: true });
}

export default {
  async fetch(request, env) {
    // Provide env vars to the configuration helpers
    Object.assign(globalThis, env);

    const url = new URL(request.url);
    const ip = request.headers.get("CF-Connecting-IP") || "unknown";

    if (!rateLimit(ip)) {
      return json({ ok: false, error: "Rate limit exceeded" }, 429);
    }

    if (request.method === "OPTIONS") {
      return new Response(null, { status: 204, headers: corsHeaders() });
    }

    if (request.method === "GET") {
      return handleGet();
    }

    if (request.method === "POST") {
      return handlePost(request);
    }

    return json({ ok: false, error: "Method not allowed" }, 405);
  },
};
