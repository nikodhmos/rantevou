// Vercel function: προωθεί ειδοποιήσεις στο ntfy.sh για τον Cloudflare Worker
// (το ntfy.sh δεν δέχεται συνδέσεις από Cloudflare Workers).
// Env var στο Vercel: RELAY_KEY (ίδιο με το secret RELAY_KEY του Worker).
module.exports = async (req, res) => {
  if (req.method !== "POST") return res.status(405).json({ ok: false, error: "POST only" });
  const key = process.env.RELAY_KEY;
  if (!key || req.headers["x-relay-key"] !== key) return res.status(403).json({ ok: false, error: "forbidden" });
  const b = (typeof req.body === "string" ? JSON.parse(req.body || "{}") : req.body) || {};
  if (typeof b.topic !== "string" || !/^[A-Za-z0-9_-]{1,64}$/.test(b.topic)) return res.status(400).json({ ok: false, error: "bad topic" });
  const payload = {
    topic: b.topic,
    title: String(b.title || "").slice(0, 200),
    message: String(b.message || "").slice(0, 2000),
    tags: Array.isArray(b.tags) ? b.tags.slice(0, 5).map(String) : [],
    priority: 5,
  };
  try {
    const r = await fetch("https://ntfy.sh/", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(payload) });
    if (r.ok) return res.status(200).json({ ok: true });
    return res.status(502).json({ ok: false, error: `ntfy ${r.status}: ${(await r.text()).slice(0, 120)}` });
  } catch (e) {
    return res.status(502).json({ ok: false, error: "ntfy: " + String(e).slice(0, 120) });
  }
};
