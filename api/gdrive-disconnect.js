// /api/gdrive-disconnect
//
// Called when the user taps "Disconnect" in Settings. Revokes the refresh
// token with Google directly (so it stops working immediately, not just
// locally) and deletes the server-side record, then clears the session
// cookie. If the person only ever revokes access from *within this app*,
// this is what makes that actually take effect at Google's end too — not
// just locally.

module.exports = async (req, res) => {
  const sessionId = readCookie(req.headers.cookie, "gdrive_session");
  const kvUrl = process.env.KV_REST_API_URL;
  const kvToken = process.env.KV_REST_API_TOKEN;

  if (sessionId && kvUrl && kvToken) {
    try {
      const getResp = await fetch(kvUrl + "/get/gdrive_session:" + sessionId, {
        headers: { Authorization: "Bearer " + kvToken },
      });
      const getData = await getResp.json();
      if (getData && getData.result) {
        const record = JSON.parse(getData.result);
        if (record.refresh_token) {
          // Best-effort: revoke with Google. If this fails (network blip,
          // token already invalid, etc.) we still proceed to delete our own
          // record below — a stale, already-useless token sitting unrevoked
          // at Google's end is a far smaller concern than leaving OUR
          // record around after the user explicitly asked to disconnect.
          await fetch("https://oauth2.googleapis.com/revoke?token=" + encodeURIComponent(record.refresh_token), {
            method: "POST",
          }).catch(() => {});
        }
      }
      await fetch(kvUrl + "/del/gdrive_session:" + sessionId, { headers: { Authorization: "Bearer " + kvToken } }).catch(() => {});
    } catch (_) {
      // Fall through — clearing the cookie below still leaves the app in a
      // correct "disconnected" state locally even if Google-side cleanup
      // partly failed.
    }
  }

  res.setHeader("Set-Cookie", "gdrive_session=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0");
  res.statusCode = 200;
  res.setHeader("Content-Type", "application/json");
  res.end(JSON.stringify({ ok: true }));
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
