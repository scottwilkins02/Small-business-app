// /api/gdrive-callback
//
// Google redirects the browser here after the user signs in (a normal
// full-page navigation — not a popup, so none of the Safari popup issues
// from the previous approach apply). This function:
//   1. exchanges the one-time authorization code for an access token AND a
//      refresh token (this exchange requires the Client Secret, which is
//      why this step has to happen server-side — the secret must never
//      reach the browser),
//   2. stores the refresh token server-side in Upstash Redis, keyed by a
//      random session id (the refresh token itself never goes to the
//      browser),
//   3. sets that session id as an httpOnly cookie (so client-side JS can
//      never read it either — the browser just carries it automatically on
//      requests to our own /api endpoints),
//   4. redirects back to the app with a plain status flag in the URL.
//
// Required environment variables (set in Vercel Project Settings → Environment Variables):
//   GOOGLE_CLIENT_ID       — same value as GDRIVE_CLIENT_ID in the app's inline script
//   GOOGLE_CLIENT_SECRET   — from Google Cloud Console → Credentials → your OAuth Client
//   KV_REST_API_URL        — from the Upstash Redis integration (Vercel → Storage/Marketplace)
//   KV_REST_API_TOKEN      — same, the integration sets both automatically once added

const REFRESH_TOKEN_TTL_SECONDS = 60 * 60 * 24 * 180; // 180 days — comfortably inside Google's own 6-month (≈183 day) inactivity revocation, refreshed below on every real use so an actively-used connection never actually hits this.

module.exports = async (req, res) => {
  const appOrigin = "https://" + req.headers.host;
  const url = new URL(req.url, appOrigin);
  const code = url.searchParams.get("code");
  const oauthError = url.searchParams.get("error");

  function backToApp(status, extra) {
    const params = new URLSearchParams({ gdrive: status, ...(extra || {}) });
    res.writeHead(302, { Location: appOrigin + "/?" + params.toString() });
    res.end();
  }

  if (oauthError) return backToApp("error", { reason: oauthError });
  if (!code) return backToApp("error", { reason: "missing_code" });

  try {
    const tokenResp = await fetch("https://oauth2.googleapis.com/token", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        code,
        client_id: process.env.GOOGLE_CLIENT_ID,
        client_secret: process.env.GOOGLE_CLIENT_SECRET,
        redirect_uri: appOrigin + "/api/gdrive-callback",
        grant_type: "authorization_code",
      }),
    });
    const tokenData = await tokenResp.json();

    if (!tokenResp.ok) return backToApp("error", { reason: tokenData.error || "token_exchange_failed" });
    if (!tokenData.refresh_token) {
      // Google only issues a refresh_token on first-ever consent for this
      // account+app, unless prompt=consent is forced on every request
      // (which gdriveConnect() in the app does — see its comment). Seeing
      // this branch hit in practice would mean that's been removed.
      return backToApp("error", { reason: "no_refresh_token" });
    }

    // Best-effort — a missing email just means the Settings panel shows a
    // blank account label; not worth failing the whole connect over.
    let email = "";
    try {
      const who = await fetch("https://www.googleapis.com/oauth2/v2/userinfo", {
        headers: { Authorization: "Bearer " + tokenData.access_token },
      });
      if (who.ok) email = ((await who.json()) || {}).email || "";
    } catch (_) {}

    const sessionId = cryptoRandomId();
    const kvUrl = process.env.KV_REST_API_URL;
    const kvToken = process.env.KV_REST_API_TOKEN;
    const record = JSON.stringify({ refresh_token: tokenData.refresh_token, email });

    // SETEX <key> <seconds> <value> — Upstash's REST API takes the value as
    // the POST body (not a path segment) specifically so JSON/binary values
    // with arbitrary characters don't need path-safe encoding. See
    // gdriveKvSet() in gdrive-token.js for the exact same pattern, reused
    // there for refreshing this TTL on every real use.
    const setResp = await fetch(kvUrl + "/setex/gdrive_session:" + sessionId + "/" + REFRESH_TOKEN_TTL_SECONDS, {
      method: "POST",
      headers: { Authorization: "Bearer " + kvToken },
      body: record,
    });
    if (!setResp.ok) return backToApp("error", { reason: "storage_failed" });

    res.setHeader(
      "Set-Cookie",
      `gdrive_session=${sessionId}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=${REFRESH_TOKEN_TTL_SECONDS}`
    );
    backToApp("connected", { email });
  } catch (err) {
    backToApp("error", { reason: "server_error" });
  }
};

function cryptoRandomId() {
  // Node's global crypto (available in Vercel's Node.js runtime) — no
  // 'crypto' import needed, and avoids adding a dependency/package.json to
  // what has otherwise been a dependency-free, single-file deploy.
  return globalThis.crypto && globalThis.crypto.randomUUID
    ? globalThis.crypto.randomUUID()
    : require("crypto").randomBytes(24).toString("hex");
}
