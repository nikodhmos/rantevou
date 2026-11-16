// v3.1
// Ραντεβού / Ρετσίνες: ενδιάμεσος server για τις ειδοποιήσεις ntfy.
// Κρατάει κρυφά τα topics και ελέγχει ό,τι στέλνεται.
//
// Secrets (Settings → Variables and Secrets, τύπος "Secret"):
//   NTFY_TOPIC  το topic σου για το απλό link του ραντεβού
//   KEY         τυχαίο μυστικό για να κλειδώνονται τα topics των προσωπικών links
// Binding (Settings → Bindings → KV namespace):
//   LINKS       KV "rantevou-links": τα κοντά links (π.χ. ?nikos-k7p)

const ORIGINS = ["https://nikodhmos.github.io"];

const RANTEVOU = { food: "🍝 ΦΑΓΗΤΟ", drink: "🍸 ΠΟΤΟ" };
const DRINKS = {
  krasi:    { label: "🍷 Κρασί",    places: ["bit", "rotonda"] },
  mpyra:    { label: "🍺 Μπύρα",    places: ["lefkos", "magkazi"] },
  volta:    { label: "🚶 Βόλτα",    places: ["paralia", "ompreles", "kastra", "aristotelous"] },
  retsines: { label: "🍾 Ρετσίνες", places: ["bit", "rotonda"] },
};
const PLACES = {
  bit: "Bit", rotonda: "Ροτόντα", lefkos: "Λευκός", magkazi: "Μαγαζί",
  paralia: "Παραλία", ompreles: "Ομπρέλες", kastra: "Κάστρα", aristotelous: "Αριστοτέλους",
};

/* ---------- όριο αποστολών (ανά IP) ---------- */
const hits = new Map();
function limited(ip, bucket, max, windowMs) {
  const k = bucket + ":" + ip, now = Date.now();
  const arr = (hits.get(k) || []).filter(t => now - t < windowMs);
  if (arr.length >= max) { hits.set(k, arr); return true; }
  arr.push(now); hits.set(k, arr);
  if (hits.size > 5000) hits.clear();
  return false;
}

/* ---------- κλείδωμα topic → token ---------- */
const b64u = buf => btoa(String.fromCharCode(...new Uint8Array(buf))).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
const unb64u = s => {
  const b = s.replace(/-/g, "+").replace(/_/g, "/");
  return Uint8Array.from(atob(b + "===".slice((b.length + 3) % 4)), c => c.charCodeAt(0));
};
async function aesKey(secret) {
  const raw = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(secret));
  return crypto.subtle.importKey("raw", raw, "AES-GCM", false, ["encrypt", "decrypt"]);
}
async function seal(env, topic) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, await aesKey(env.KEY), new TextEncoder().encode(topic));
  const out = new Uint8Array(12 + ct.byteLength); out.set(iv); out.set(new Uint8Array(ct), 12);
  return b64u(out);
}
async function unseal(env, token) {
  try {
    if (typeof token !== "string" || token.length > 200) return null;
    const all = unb64u(token);
    const pt = await crypto.subtle.decrypt({ name: "AES-GCM", iv: all.slice(0, 12) }, await aesKey(env.KEY), all.slice(12));
    const t = new TextDecoder().decode(pt);
    return /^[A-Za-z0-9_-]{16,64}$/.test(t) ? t : null;
  } catch (e) { return null; }
}
/* ---------- κοντά links (KV) ---------- */
const GR = { α:"a", β:"v", γ:"g", δ:"d", ε:"e", ζ:"z", η:"i", θ:"th", ι:"i", κ:"k", λ:"l", μ:"m", ν:"n", ξ:"x",
  ο:"o", π:"p", ρ:"r", σ:"s", ς:"s", τ:"t", υ:"y", φ:"f", χ:"ch", ψ:"ps", ω:"o" };
const slug = name => (name.normalize("NFD").replace(/[\u0300-\u036f]/g, "").toLowerCase()
  .split("").map(c => GR[c] ?? c).join("").replace(/[^a-z0-9]+/g, "").slice(0, 12)) || "link";
const rnd = n => { const a = "abcdefghjkmnpqrstuvwxyz23456789";
  return [...crypto.getRandomValues(new Uint8Array(n))].map(b => a[b % a.length]).join(""); };
const CODE_RE = /^[a-z0-9]{1,12}-[a-z0-9]{3}$/;
async function getLink(env, code) {
  if (!env.LINKS || typeof code !== "string" || !CODE_RE.test(code)) return null;
  try { return JSON.parse(await env.LINKS.get(code) || "null"); } catch (e) { return null; }
}

const newTopic = () => "n-" + b64u(crypto.getRandomValues(new Uint8Array(18)));

/* ---------- έλεγχος δεδομένων ---------- */
const clean = (v, max) => typeof v === "string"
  ? v.replace(/[\u0000-\u001f\u007f]/g, " ").replace(/\s+/g, " ").trim().slice(0, max) : "";
function athensToday() {
  return new Intl.DateTimeFormat("en-CA", { timeZone: "Europe/Athens" }).format(new Date()); // YYYY-MM-DD
}
function niceDate(v) {
  const [Y, M, D] = v.split("-").map(Number);
  return new Date(Date.UTC(Y, M - 1, D, 12)).toLocaleDateString("el-GR", { weekday: "long", day: "numeric", month: "long", timeZone: "UTC" });
}
function checkWhen(date, time) {
  if (!/^\d{4}-\d{2}-\d{2}$/.test(date) || !/^([01]\d|2[0-3]):[0-5]\d$/.test(time)) return "Λάθος μέρα ή ώρα";
  const today = athensToday();
  if (date < today) return "Στο παρελθόν δεν πάμε";
  const max = new Date(Date.parse(today) + 90 * 864e5).toISOString().slice(0, 10);
  if (date > max) return "Πολύ μακριά";
  if (isNaN(Date.parse(date))) return "Λάθος μέρα";
  return null;
}

// Επιστρέφει null αν πήγε καλά, αλλιώς το λάθος του ntfy.
// Προαιρετικό secret NTFY_TOKEN (tk_...) από δωρεάν λογαριασμό ntfy.sh, αν το ntfy κόβει τα αιτήματα.
let ntfyEnv = {};
async function ntfy(topic, title, message, tags) {
  const headers = { "Content-Type": "application/json" };
  if (ntfyEnv.NTFY_TOKEN) headers.Authorization = "Bearer " + ntfyEnv.NTFY_TOKEN;
  try {
    const r = await fetch("https://ntfy.sh/", {
      method: "POST", headers,
      body: JSON.stringify({ topic, title, message, tags, priority: 5 }),
    });
    if (r.ok) return null;
    return `ntfy ${r.status}: ${(await r.text()).slice(0, 120)}`;
  } catch (e) { return "ntfy: " + String(e).slice(0, 120); }
}

/* ---------- server ---------- */
export default {
  async fetch(req, env) {
    ntfyEnv = env;
    const origin = req.headers.get("Origin") || "";
    const cors = {
      "Access-Control-Allow-Origin": ORIGINS.includes(origin) ? origin : ORIGINS[0],
      "Access-Control-Allow-Methods": "POST, OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type",
      "Vary": "Origin",
    };
    const json = (o, status = 200) => new Response(JSON.stringify(o), { status, headers: { ...cors, "Content-Type": "application/json" } });
    if (req.method === "OPTIONS") return new Response(null, { headers: cors });
    if (req.method !== "POST") return json({ ok: false, error: "POST only" }, 405);
    if (!ORIGINS.includes(origin)) return json({ ok: false, error: "forbidden" }, 403);
    if (!env.KEY || !env.NTFY_TOPIC) return json({ ok: false, error: "server not configured" }, 500);

    const ip = req.headers.get("CF-Connecting-IP") || "?";
    const path = new URL(req.url).pathname;
    let body;
    try { body = await req.json(); } catch (e) { return json({ ok: false, error: "bad json" }, 400); }
    if (!body || typeof body !== "object") return json({ ok: false, error: "bad json" }, 400);

    // Νέο προσωπικό link
    if (path === "/new") {
      if (limited(ip, "new", 6, 36e5)) return json({ ok: false, error: "Πολλά links, δοκίμασε σε λίγο" }, 429);
      // κοντό link (KV)
      if (env.LINKS && body.mode) {
        const f = clean(body.f, 30), mode = body.mode, site = body.site;
        if (!f) return json({ ok: false, error: "Γράψε όνομα" }, 400);
        if (!["rantevou", "retsines"].includes(site)) return json({ ok: false, error: "bad site" }, 400);
        const rec = { site, f, mode };
        if (mode === "ntfy") rec.topic = newTopic();
        else if (mode === "email") {
          rec.e = clean(body.e, 100);
          if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(rec.e)) return json({ ok: false, error: "Λάθος email" }, 400);
        } else if (mode === "sms" || mode === "wa") {
          rec.p = clean(body.p, 15);
          if (!/^\d{10,15}$/.test(rec.p)) return json({ ok: false, error: "Λάθος κινητό" }, 400);
        } else return json({ ok: false, error: "bad mode" }, 400);
        let code;
        for (let i = 0; i < 6; i++) { const c = slug(f) + "-" + rnd(3); if (!(await env.LINKS.get(c))) { code = c; break; } }
        if (!code) return json({ ok: false, error: "δοκίμασε ξανά" }, 500);
        await env.LINKS.put(code, JSON.stringify(rec));
        return json({ ok: true, code, topic: rec.topic });
      }
      // παλιός τρόπος (κλειδωμένο token)
      const topic = newTopic();
      return json({ ok: true, topic, token: await seal(env, topic) });
    }

    // Τι είναι ένα κοντό link (χωρίς το topic)
    if (path === "/resolve") {
      if (limited(ip, "resolve", 60, 6e5)) return json({ ok: false, error: "slow down" }, 429);
      const rec = await getLink(env, body.c);
      if (!rec) return json({ ok: false, error: "not found" }, 404);
      return json({ ok: true, site: rec.site, f: rec.f, mode: rec.mode, e: rec.e, p: rec.p });
    }

    // Δοκιμή για τον δημιουργό του link
    if (path === "/test") {
      if (limited(ip, "test", 5, 6e5)) return json({ ok: false, error: "Πολλές δοκιμές" }, 429);
      const rec = body.c ? await getLink(env, body.c) : null;
      const topic = rec ? rec.topic : await unseal(env, body.r);
      if (!topic) return json({ ok: false, error: "bad link" }, 400);
      const err = await ntfy(topic, "🔔 Δοκιμή", "Αν το βλέπεις, δουλεύει! Εδώ θα σου έρχονται οι απαντήσεις.", ["bell"]);
      return err ? json({ ok: false, error: err }, 502) : json({ ok: true });
    }

    // Απάντηση σε πρόσκληση
    if (path === "/send") {
      if (limited(ip, "send", 3, 6e5)) return json({ ok: false, error: "Έχεις στείλει ήδη, περίμενε λίγο" }, 429);
      let topic;
      if (body.c) {
        const rec = await getLink(env, body.c);
        topic = rec && rec.mode === "ntfy" && rec.site === body.kind ? rec.topic : null;
      } else topic = body.r ? await unseal(env, body.r) : env.NTFY_TOPIC;
      if (!topic) return json({ ok: false, error: "bad link" }, 400);

      const name = clean(body.name, 40), msg = clean(body.msg, 300);
      const date = clean(body.date, 10), time = clean(body.time, 5);
      const tries = Math.max(0, Math.min(999, parseInt(body.noCount, 10) || 0));
      if (!name) return json({ ok: false, error: "Γράψε όνομα" }, 400);
      const bad = checkWhen(date, time);
      if (bad) return json({ ok: false, error: bad }, 400);

      let title, lines;
      if (body.kind === "rantevou") {
        const choice = RANTEVOU[body.choice];
        if (!choice) return json({ ok: false, error: "Λάθος επιλογή" }, 400);
        title = `💕 ${name} → ${choice} · ${niceDate(date)} ${time}`;
        lines = [`Όνομα: ${name}`, `Επιλογή: ${choice}`];
      } else if (body.kind === "retsines") {
        const dr = DRINKS[body.drink];
        if (!dr || !dr.places.includes(body.place)) return json({ ok: false, error: "Λάθος επιλογή" }, 400);
        title = `${dr.label.split(" ")[0]} ${name} → ${dr.label.split(" ")[1]} · ${PLACES[body.place]}, ${niceDate(date)} ${time}`;
        lines = [`Όνομα: ${name}`, `Τι: ${dr.label}`, `Μέρος: ${PLACES[body.place]}`];
      } else {
        return json({ ok: false, error: "bad kind" }, 400);
      }
      lines.push(`Μέρα: ${niceDate(date)}`, `Ώρα: ${time}`);
      if (msg) lines.push(`Μήνυμα: ${msg}`);
      lines.push(`Προσπάθειες να πατήσει το ΟΧΙ: ${tries}`);

      const err = await ntfy(topic, title, lines.join("\n"), [body.kind === "rantevou" ? "heart" : "wine_glass"]);
      return err ? json({ ok: false, error: err }, 502) : json({ ok: true });
    }

    return json({ ok: false, error: "not found" }, 404);
  },
};
