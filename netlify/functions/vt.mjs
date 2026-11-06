const VT_URL = "https://www.virustotal.com/ui/search";
const ANTI_ABUSE_MIDDLE = "ZG9udCBiZSBldmls"; // btoa("dont be evil")

function generateAntiAbuseHeader() {
  const rand = Math.floor(1e10 + Math.random() * 9e10);
  const ts = (Date.now() / 1000).toFixed(3);
  return btoa(`${rand}-${ANTI_ABUSE_MIDDLE}-${ts}`);
}

function getScore(m) {
  if (typeof m !== "number" || !Number.isInteger(m)) return "N/A";
  if (m <= 7) return 0;
  if (m <= 19) return 3;
  if (m <= 49) return 2;
  return 1;
}

function buildHeaders() {
  return {
    "Accept-Ianguage": "en-US,en;q=0.9,es;q=0.8",
    "sec-ch-ua-platform": '"Windows"',
    "Referer": "https://www.virustotal.com/",
    "sec-ch-ua": '"Google Chrome";v="155", "Chromium";v="155", "Not(A:Brand";v="24"',
    "X-VT-Anti-Abuse-Header": generateAntiAbuseHeader(),
    "sec-ch-ua-mobile": "?0",
    "X-Tool": "vt-ui-main",
    "x-app-version": "v1x674x0",
    "User-Agent":
      "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/155.0.0.0 Safari/537.36",
    "accept": "application/json",
    "Content-Type": "application/json",
  };
}

async function queryVT(hash) {
  const url =
    `${VT_URL}?limit=2` +
    `&relationships%5Bcomment%5D=author%2Citem` +
    `&query=${encodeURIComponent(hash)}`;

  try {
    const resp = await fetch(url, { headers: buildHeaders() });
    if (!resp.ok) {
      return { malicious: null, total: null, error: `HTTP ${resp.status}` };
    }
    const data = await resp.json();
    const stats = data?.data?.[0]?.attributes?.last_analysis_stats;
    if (!stats) return { malicious: null, total: null, error: "no stats" };

    const malicious = stats.malicious ?? 0;
    const total =
      (stats.malicious ?? 0) +
      (stats.suspicious ?? 0) +
      (stats.harmless ?? 0) +
      (stats.undetected ?? 0);
    return { malicious, total };
  } catch (e) {
    return { malicious: null, total: null, error: String(e) };
  }
}

function parseCsvLine(line) {
  const parts = line.split(",");
  if (parts.length < 2) return null;
  const uuid = (parts[0] || "").replace(/\r/g, "").trim();
  const hash = (parts[1] || "").replace(/\r/g, "").trim();
  if (!uuid || !hash || hash.toLowerCase() === "hash") return null;
  return { uuid, hash };
}

export default async (request, context) => {
  const url = new URL(request.url);

  // ── GET /?hash=... → singolo lookup JSON
  if (request.method === "GET" && url.searchParams.has("hash")) {
    const hash = (url.searchParams.get("hash") || "").trim();
    if (!hash) {
      return new Response(JSON.stringify({ error: "empty hash" }), {
        status: 400,
        headers: { "content-type": "application/json; charset=utf-8" },
      });
    }
    const r = await queryVT(hash);
    return new Response(
      JSON.stringify({
        hash,
        malicious: r.malicious,
        total: r.total,
        score: getScore(r.malicious),
        ...(r.error ? { error: r.error } : {}),
      }),
      {
        headers: { "content-type": "application/json; charset=utf-8" },
      }
    );
  }

  // ── POST / (body = CSV uuid,hash) → risposta CSV
  if (request.method === "POST") {
    const body = await request.text();
    const rows = [];
    for (const rawLine of body.split(/\r?\n/)) {
      const parsed = parseCsvLine(rawLine);
      if (!parsed) continue;
      const r = await queryVT(parsed.hash);
      const score = getScore(r.malicious);
      rows.push(`${parsed.uuid},${parsed.hash},${score}`);
    }
    const csv = "uuid,hash,score\n" + rows.join("\n") + (rows.length ? "\n" : "");
    return new Response(csv, {
      headers: { "content-type": "text/csv; charset=utf-8" },
    });
  }

  return new Response(
    "VT Netlify Worker\n\n" +
      "GET  /?hash=<sha256> → JSON {malicious, total, score}\n" +
      "POST /               → body CSV uuid,hash → CSV uuid,hash,score\n",
    { headers: { "content-type": "text/plain; charset=utf-8" } }
  );
};

export const config = {
  path: "/*",
};
