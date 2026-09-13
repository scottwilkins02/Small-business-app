// /api/gdrive-token
//
// Called by the app's own JS (gdriveEnsureAccessToken()) whenever it needs
// a usable Google Drive access token — on boot, before a sync, and
// proactively before the current one expires. The browser only ever sends
// its httpOnly session cookie; this function looks up the matching refresh
// token server-side, in Upstash Redis, and uses IT to mint a fresh short-
// lived access token from Google. The refresh token itself is never
// included in the response — only the short-lived access token is, which
// is exactly what used to come back from the (now-removed) Google Identity
// Services popup, so the rest of the app's Drive-upload/download code
// didn't need to change at all.
//
// Same required environment variables as gdrive-callback.js.

const REFRESH_TOKEN_TTL_SECONDS = 60 * 60 * 24 * 180;

module.exports = async (req, res) => {
  const sessionId = readCookie(req.headers.cookie, "gdrive_session");
  if (!sessionId) return json(res, 401, { error: "not_connected" });

  const kvUrl = process.env.KV_REST_API_URL;
  const kvToken = process.env.KV_REST_API_TOKEN;

  try {
    const getResp = await fetch(kvUrl + "/get/gdrive_session:" + sessionId, {
      headers: { Authorization: "Bearer " + kvToken },
    });
    const getData = await getResp.json();
    if (!getResp.ok || !getData.result) return json(res, 401, { error: "session_expired" });

    const record = JSON.parse(getData.result); // { refresh_token, email }

    const tokenResp = await fetch("https://oauth2.googleapis.com/token", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        refresh_token: record.refresh_token,
        client_id: process.env.GOOGLE_CLIENT_ID,
        client_secret: process.env.GOOGLE_CLIENT_SECRET,
        grant_type: "refresh_token",
      }),
    });
    const tokenData = await tokenResp.json();

    if (!tokenResp.ok) {
      // invalid_grant here means Google itself revoked this refresh token
      // (user removed access in their Google Account, 6 months unused,
      // password change, etc.) — not something retrying fixes. Clean up
      // our side too, so the app shows a clean "reconnect" state rather
      // than repeating this failure forever.
      await fetch(kvUrl + "/del/gdrive_session:" + sessionId, { headers: { Authorization: "Bearer " + kvToken } }).catch(() => {});
      res.setHeader("Set-Cookie", "gdrive_session=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0");
      return json(res, 401, { error: tokenData.error || "refresh_failed" });
    }

    // Sliding expiry: every real use pushes the stored refresh token's TTL
    // back out to the full 180 days, so an actively-used connection never
    // actually approaches that limit — it only matters for a connection
    // that goes genuinely unused, which is the case it's meant to catch.
    fetch(kvUrl + "/setex/gdrive_session:" + sessionId + "/" + REFRESH_TOKEN_TTL_SECONDS, {
      method: "POST",
      headers: { Authorization: "Bearer " + kvToken },
      body: JSON.stringify(record),
    }).catch(() => {}); // best-effort, deliberately not awaited — a missed TTL refresh this one time isn't worth delaying the response over.

    json(res, 200, {
      access_token: tokenData.access_token,
      expires_in: tokenData.expires_in,
      email: record.email || "",
    });
  } catch (err) {
    json(res, 500, { error: "server_error" });
  }
};

function readCookie(cookieHeader, name) {
  if (!cookieHeader) return null;
  const parts = cookieHeader.split(";");
  for (let i = 0; i < parts.length; i++) {
    const p = parts[i].trim();
    if (p.indexOf(name + "=") === 0) return decodeURIComponent(p.slice(name.length + 1));
  }
  return null;
}

function json(res, status, obj) {
  res.statusCode = status;
  res.setHeader("Content-Type", "application/json");
  res.end(JSON.stringify(obj));
}
