// VeriPress: shared by the app (/) and the public record page (/v/<id>, which embeds the report).
// ---------------------------------------------------------------- state, helpers, API
const $ = (s, r = document) => r.querySelector(s);
const esc = (x) => String(x ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const short = (h, n = 6) => (h ? (h.length > 2 * n + 2 ? `${h.slice(0, n)}…${h.slice(-n)}` : h) : "—");
const when = (t) => (t ? new Date(t * 1000).toLocaleString("en-GB", { day: "numeric", month: "short", year: "numeric", hour: "2-digit", minute: "2-digit", second: "2-digit" }) : "—");
const hms = (t) => new Date(t * 1000).toLocaleTimeString("en-GB");
const safeUrl = (u) => { try { const x = new URL(u, location.href); return ["https:", "http:"].includes(x.protocol) ? x.href : "#"; } catch { return "#"; } };
const S = {
  tab: "verify", theme: localStorage.vpTheme || (matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light"),
  health: null, pk: null, local: ["localhost", "127.0.0.1", "[::1]"].includes(location.hostname), specimens: [],
  // examine
  vfile: null, img: null, tx: "", busy: false, err: "", report: null, retries: 0,
  // certify
  sfile: null, simg: null, mode: "device", lk: null, ver: "new", sbusy: "", serr: "", sres: null, svalid: null,
  bfiles: [], bbusy: false, bres: null, berr: "",
  // viewer (tiles, drift, Merkle tree) and redaction
  view: null, off: {}, level: 0, hover: null, hnode: null, pin: null, M: null,
  red: false, boxes: [], drag: null, rbusy: false, rerr: "", rdl: null,
};
async function api(url, opts) {
  const r = await fetch(url, opts), b = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(typeof b.detail === "string" ? b.detail : `HTTP ${r.status}`);
  return b;
}
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// Examine: the watermark (or perceptual hash, or a given record id) finds the record, the server
// checks signature, ledger and tiles. A provisional verdict (anchor not validated yet) is re-run.
async function runVerify(file, { tx = S.tx, again = false } = {}) {
  if (!again) { S.vfile = file; S.img = URL.createObjectURL(file); S.retries = 0; S.report = null; S.rdl = null; }
  S.tab = "verify"; S.busy = true; S.err = ""; S.red = false; render();
  const fd = new FormData(); fd.append("image", S.vfile); fd.append("heatmap", "0"); if (tx) fd.append("entry_id", tx.trim());
  try { S.report = await api("/api/verify", { method: "POST", body: fd }); } catch (e) { S.err = e.message; }
  S.busy = false; render();
  if (S.report?.pending && S.retries < 8) { S.retries++; const f = S.vfile; setTimeout(() => S.vfile === f && runVerify(f, { tx, again: true }), 4000); }
}
async function loadSpecimen(name) {
  const b = await fetch(`/api/demo/${encodeURIComponent(name)}`).then((r) => (r.ok ? r.blob() : null));
  if (b) { S.tx = ""; runVerify(new File([b], name, { type: b.type })); }
}
// Picking a file: in Certify it is only selected (shown in the drop zone); in Examine it is checked.
function takeFile(f) {
  if (!f) return;
  if (S.tab === "sign") { S.sfile = f; S.simg = URL.createObjectURL(f); S.sres = null; S.serr = ""; findOriginal(f); }
  else { S.tx = ""; runVerify(f); }
}
$("#file").addEventListener("change", (e) => { const f = e.target.files[0]; e.target.value = ""; takeFile(f); });
const pick = () => $("#file").click();
document.addEventListener("dragover", (e) => { const d = e.target.closest?.("[data-pick]"); if (d) { e.preventDefault(); d.classList.add("over"); } });
document.addEventListener("dragleave", (e) => e.target.closest?.("[data-pick]")?.classList.remove("over"));
document.addEventListener("drop", (e) => { const d = e.target.closest?.("[data-pick]"); if (!d) return; e.preventDefault(); d.classList.remove("over"); takeFile(e.dataTransfer.files[0]); });
// HEIC on Chrome, camera RAW: the browser cannot draw it; the server develops a JPEG preview.
async function previewFallback(img, which) {
  if (img.dataset.fb || !(which === "sign" ? S.sfile : S.vfile)) return; img.dataset.fb = 1;
  const fd = new FormData(); fd.append("image", which === "sign" ? S.sfile : S.vfile);
  const r = await fetch("/api/preview", { method: "POST", body: fd }).catch(() => null);
  if (!r?.ok) return;
  const u = URL.createObjectURL(await r.blob());
  if (which === "sign") S.simg = u; else S.img = u;
  img.src = u; img.addEventListener("load", () => drawViewer(), { once: true });
}

// Version chain, found automatically: the watermark (or perceptual hash) of the chosen file leads
// to the certified photo it derives from; the user only says how it relates to it.
async function findOriginal(f) {
  S.lk = "busy"; S.ver = "new"; render();
  const fd = new FormData(); fd.append("image", f);
  const res = await api("/api/lookup", { method: "POST", body: fd }).catch(() => ({ candidates: [] }));
  if (S.sfile !== f) return;
  S.lk = res.candidates[0] || null; S.ver = S.lk ? "edit" : "new"; render();
}
const parentTx = () => (S.lk && S.lk !== "busy" && S.ver !== "new" ? S.lk.tx_hash : "");
function originalHtml() {
  if (!S.sfile) return "";
  if (S.lk === "busy") return `<div class="orig"><span class="spin"></span> Looking for a certified original (invisible watermark, perceptual hash)…</div>`;
  if (!S.lk) return `<div class="orig none">No certified original found: it will be certified as a new photo.</div>`;
  const c = S.lk, by = c.anonymous ? "an anonymous accredited device" : c.op === "ai_generate" ? "an AI generator" : `device <span class="mono">${esc(short(c.signer))}</span>`;
  const opt = (k, title, hint) => `<label class="opt"><input type="radio" name="ver" value="${k}" ${S.ver === k ? "checked" : ""}><span><b>${title}</b><small>${hint}</small></span></label>`;
  return `<div class="orig"><img src="${esc(safeUrl(c.image_url))}" alt=""><div><div class="kicker">Derived from a certified photo</div>
    <p>Certified ${esc(when(c.timestamp))} by ${by}, found by its ${c.found_by === "watermark" ? "invisible watermark" : "perceptual fingerprint"}.</p>
    ${opt("edit", "A new version of it", "An edit or a crop: its history will lead back to this photo.")}
    ${opt("develop", "The JPEG developed from that RAW", "Same device: it inherits the RAW's provenance.")}
    ${opt("new", "An independent photo", "Do not link them.")}</div></div>`;
}

// Certify. Fast anchoring: the server answers at submission, the page polls until validated.
async function runSign() {
  if (!S.sfile) return;
  S.serr = ""; S.sres = null; S.svalid = null;
  try {
    if (S.mode === "passkey") {
      S.sbusy = "Preparing the manifest…"; render();
      const fd = new FormData(); fd.append("image", S.sfile); if (parentTx()) fd.append("parent", parentTx());
      const prep = await api("/api/sign/passkey/prepare", { method: "POST", body: fd });
      S.sbusy = "Touch ID…"; render();
      const cred = await navigator.credentials.get({ publicKey: {
        challenge: hexBytes(prep.challenge), // = the manifest digest
        allowCredentials: [{ type: "public-key", id: b64u.dec(S.pk.credential_id) }], userVerification: "required", timeout: 60000 } });
      const assertion = { credential_id: b64u.enc(cred.rawId), authenticator_data: b64u.enc(cred.response.authenticatorData),
        client_data_json: b64u.enc(cred.response.clientDataJSON), signature: b64u.enc(cred.response.signature), public_key: S.pk.public_key };
      S.sbusy = "Recording on the XRP Ledger…"; render();
      S.sres = await api("/api/sign/passkey/complete", { method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ prep_id: prep.prep_id, assertion, wait: 0 }) });
    } else {
      const fd = new FormData();
      fd.append("image", S.sfile); fd.append("signer", S.mode === "ai" ? "ai" : "device"); fd.append("wait", "0");
      if (S.mode === "anonymous") fd.append("anonymous", "1");
      if (parentTx()) fd.append("parent", parentTx());
      if (parentTx() && S.ver === "develop") fd.append("op", "develop");
      S.sbusy = S.mode === "anonymous" ? "Proving in zero knowledge, then recording on XRPL…" : "Signing every tile, then recording on XRPL…"; render();
      S.sres = await api("/api/sign", { method: "POST", body: fd });
    }
  } catch (e) { S.serr = e.message; }
  S.sbusy = ""; render();
  if (S.sres?.pending) watchValidation(S.sres.tx_hash);
}
async function watchValidation(tx) {
  for (let i = 0; i < 40; i++) {
    await sleep(1500);
    const a = await fetch(`/api/anchor/${encodeURIComponent(tx)}`).then((r) => (r.ok ? r.json() : null)).catch(() => null);
    if (S.sres?.tx_hash !== tx) return;
    if (a?.validated) { S.svalid = a.timestamp || Date.now() / 1000; return render(); }
  }
  S.svalid = -1; render();
}
async function runBatch() {
  if (!S.bfiles.length) return;
  S.bbusy = true; S.berr = ""; S.bres = null; render();
  const fd = new FormData();
  for (const f of S.bfiles) fd.append("images", f);
  fd.append("signer", S.mode === "ai" ? "ai" : "device"); fd.append("wait", "0");
  if (S.mode === "anonymous") fd.append("anonymous", "1");
  try { S.bres = await api("/api/sign/batch", { method: "POST", body: fd }); } catch (e) { S.berr = e.message; }
  S.bbusy = false; render();
}
async function examineUrl(url, name) {
  const b = await fetch(url).then((r) => (r.ok ? r.blob() : null)).catch(() => null);
  if (b) { S.tx = ""; runVerify(new File([b], name, { type: "image/png" })); scrollTo({ top: 0, behavior: "smooth" }); }
}

// Passkey (WebAuthn P-256, Touch ID): registration from this laptop only, then attested by the registry.
const b64u = {
  enc: (buf) => btoa(String.fromCharCode(...new Uint8Array(buf))).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, ""),
  dec: (s) => Uint8Array.from(atob(s.replace(/-/g, "+").replace(/_/g, "/") + "===".slice((s.length + 3) % 4)), (c) => c.charCodeAt(0)),
};
const hexBytes = (h) => Uint8Array.from(h.match(/../g), (x) => parseInt(x, 16));
const passkeyCapable = !!(window.PublicKeyCredential && window.isSecureContext);
async function refreshPasskey() { S.pk = await fetch("/api/passkey").then((r) => r.json()).catch(() => null); if (S.tab === "sign") render(); }
async function setupPasskey() {
  S.serr = "";
  try {
    const cred = await navigator.credentials.create({ publicKey: {
      challenge: crypto.getRandomValues(new Uint8Array(32)), rp: { name: "VeriPress" },
      user: { id: crypto.getRandomValues(new Uint8Array(16)), name: "veripress-device", displayName: "VeriPress capture device" },
      pubKeyCredParams: [{ type: "public-key", alg: -7 }],
      authenticatorSelection: { authenticatorAttachment: "platform", userVerification: "required", residentKey: "discouraged" },
      attestation: "none", timeout: 60000 } });
    const spki = cred.response.getPublicKey && cred.response.getPublicKey();
    if (!spki) throw new Error("this browser cannot export the passkey public key");
    await api("/api/passkey/register", { method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ credential_id: b64u.enc(cred.rawId), public_key: b64u.enc(spki) }) });
  } catch (e) { S.serr = "Passkey setup: " + e.message; }
  refreshPasskey(); render();
}

// Readiness: which ledger, and whether the watermark models are loaded (check before demoing).
async function pollHealth() {
  try {
    const h = await fetch("/api/health").then((r) => r.json());
    const wm = !h.watermark ? "watermark off" : { ready: "watermark ready", loading: "loading watermark…", failed: "watermark failed" }[h.watermark_ready] || "watermark";
    S.health = { onchain: h.ledger === "XrplLedger", text: `${h.ledger === "XrplLedger" ? "XRPL Testnet" : "offline ledger"} · ${wm}`,
      warn: h.ledger !== "XrplLedger" || (h.watermark && h.watermark_ready !== "ready") };
    const p = $("#pill"); if (p) p.outerHTML = pill();
    if (h.watermark && h.watermark_ready === "loading") setTimeout(pollHealth, 3000);
  } catch { setTimeout(pollHealth, 5000); }
}
const pill = () => `<span class="pill ${S.health?.warn ? "warn" : ""}" id="pill">${S.health ? esc(S.health.text) : "…"}</span>`;



// One reading of the report, shared by all variants: verdict + the chain of evidence.
function verdictOf(r) {
  const t = r.tiles?.counts || {};
  return {
    real: { word: "Authentic", line: t.redacted ? `Taken by an accredited device. ${t.redacted} tiles were redacted on purpose; everything else is untouched.` : t.robust ? "Taken by an accredited device. Recompressed when shared, content unchanged." : "Taken by an accredited device. Not a pixel changed since." },
    edited: t.changed || (r.history || []).length < 2
      ? { word: "Edited", line: `${t.changed} of ${(t.exact || 0) + (t.robust || 0) + (t.changed || 0) + (t.redacted || 0)} areas were changed after it was signed.` }
      : { word: "Edited", line: "A declared edit of a certified photo: signed as a new version, its history leads back to the original." },
    ai: { word: "AI-generated", line: "Declared at creation by an accredited AI generator." },
    unknown: { word: "Unverified", line: r.reason },
  }[r.verdict] || { word: r.verdict, line: r.reason };
}
function checks(r) {
  const c = [], t = r.tiles?.counts || {}, total = (t.exact || 0) + (t.robust || 0) + (t.changed || 0) + (t.redacted || 0);
  const who = r.anonymous ? "An accredited device (identity hidden)" : r.credential === "AI_GENERATOR" ? "Accredited AI generator" : r.credential === "CAPTURE_DEVICE" ? "Accredited capture device" : "No accredited signer";
  c.push({ k: "source", title: "Who signed it", prim: r.anonymous ? "Groth16 ZK" : r.passkey ? "P-256 passkey" : "Ed25519", st: r.signature_ok && r.credential ? (r.credential_revoked_at ? "warn" : "ok") : "fail",
    value: who + (r.passkey ? " · Touch ID passkey" : ""),
    plain: r.anonymous ? "A zero-knowledge proof shows one of the accredited devices signed it, without revealing which." : "Its key holds a credential issued on the XRP Ledger by the registry." + (r.credential_revoked_at ? ` Revoked since ${when(r.credential_revoked_at)}, after this photo.` : ""),
    raw: { signer: r.anchor?.signer, credential: r.credential, signature_ok: r.signature_ok, passkey: r.passkey, anonymous: r.anonymous, revoked_at: r.credential_revoked_at } });
  if (r.post_quantum) c.push({ k: "pq", title: "Quantum-safe signature", prim: r.post_quantum.alg, st: r.post_quantum.signature_ok ? "ok" : "fail",
    value: `Ed25519 + ${r.post_quantum.alg}`, plain: "A second signature, ML-DSA-87 (FIPS 204), that a quantum computer cannot forge.", raw: r.post_quantum });
  if (r.time_window) c.push({ k: "time", title: "When it was signed", prim: "XRPL ledger hash", st: r.time_window.t0_ok ? "ok" : "warn",
    value: `${hms(r.time_window.not_before)} → ${hms(r.time_window.not_after)}`, plain: `Not before ledger #${r.time_window.ledger_index} (its hash is inside the signature), not after the anchor: a ${r.time_window.not_after - r.time_window.not_before} s window.`, raw: r.time_window });
  if (r.anchor) c.push({ k: "anchor", title: "Public record", prim: "XRPL Testnet", st: "ok",
    value: `${when(r.anchor.timestamp)} · tx ${short(r.anchor.tx_hash)}`, plain: "The fingerprint sits in an XRP Ledger transaction nobody can edit or delete.", link: r.anchor.explorer_url, raw: r.anchor });
  for (const m of r.meta_claims || []) c.push({ k: "meta", title: m.kind === "day" ? "Day it was taken" : "Where it was taken", prim: "Groth16 ZK", st: m.proof_ok ? "ok" : "fail",
    value: m.label, plain: "Proven from the camera's metadata; the exact time and GPS stay private.", raw: m });
  if (r.tiles) c.push({ k: "pixels", title: "Pixels", prim: "Merkle / SHA-256", st: t.changed ? "fail" : "ok",
    value: t.changed ? `${t.changed} of ${total} tiles changed` : `${total - (t.redacted || 0)} tiles ${t.robust ? "match after recompression" : "identical"}${t.redacted ? `, ${t.redacted} redacted` : ""}`,
    plain: t.changed ? "These tiles no longer match the fingerprint signed at capture; they are marked on the photo." : "Every tile still matches what the device signed, even after recompression.", raw: { grid: r.tiles.grid, counts: t, cid: r.disclosure_cid } });
  c.push({ k: "found", title: "How the record was found", prim: r.found_by || "—", st: "info",
    value: { watermark: "Invisible watermark in the pixels", phash: "Perceptual fingerprint search", entry_id: "Transaction id given" }[r.found_by] || "Not found",
    plain: "No metadata needed: it survives WhatsApp, screenshots and re-encoding.", raw: { found_by: r.found_by, entry_id: r.entry_id } });
  c.push({ k: "c2pa", title: "C2PA manifest", prim: "C2PA", st: "info", value: r.c2pa ? (r.c2pa.matches_anchor ? "Present, points to this record" : "Present, points elsewhere") : "Stripped when shared",
    plain: "Information only: messaging apps strip it, VeriPress does not need it.", raw: r.c2pa });
  if (r.verdict === "unknown") c.unshift({ k: "why", title: "Why it is unverified", prim: "", st: "fail", value: r.reason, plain: "", raw: { reason: r.reason } });
  return c;
}

// ---------------------------------------------------------------- viewer: photo / tiles / drift / Merkle tree
// Tile colours, same meaning everywhere (exact / recompressed / changed / redacted).
const TCOL = { exact: [47, 158, 102], robust: [217, 162, 27], changed: [226, 69, 43], redacted: [74, 78, 88] };
const TLABEL = { exact: "exact", robust: "recompressed", changed: "changed", redacted: "redacted" };
const RANK = { exact: 0, redacted: 1, robust: 2, changed: 3 };
const TOL = 4.5; // features.TOLERANCE

// Merkle levels over tile statuses, as merkle.py: row-major leaves, pairs (i, i^1), odd last node
// promoted. Node j at level k covers leaves [j*2^k, (j+1)*2^k): a run of tiles in reading order.
function merkle(r) {
  const st = r.tiles.statuses, levels = [st.slice()];
  while (levels.at(-1).length > 1) {
    const p = levels.at(-1), n = [];
    for (let i = 0; i < p.length; i += 2) n.push(i + 1 < p.length && RANK[p[i + 1]] > RANK[p[i]] ? p[i + 1] : p[i]);
    levels.push(n);
  }
  return { st, n: st.length, cols: r.tiles.grid.cols, rows: r.tiles.grid.rows, d: r.tiles.distances || [], levels };
}
const proofLen = (M, i) => M.levels.slice(0, -1).filter((l, k) => ((i >> k) ^ 1) < l.length).length;

function viewerHtml(r) {
  const img = `<img id="vimg" src="${S.img}" alt="Examined photo" onerror="previewFallback(this,'verify')">`;
  if (!r.tiles?.statuses) return `<div class="stagebox"><div class="ovl" id="stage">${img}</div></div>`;
  const t = r.tiles.counts, L = S.M.levels.length - 1;
  const ctl = S.red
    ? `<span>Drag boxes over what must be hidden (faces, plates). The hidden tiles stay authenticated.</span>`
    : {
      photo: `<button class="chipk" data-drift aria-pressed="${!!S.drift}">${S.drift ? "◉" : "○"} Show drift</button>${S.drift ? `<span>0</span><span class="ramp"></span><span>tolerance ${TOL} → changed</span><span class="sans">How far each tile drifted from what the camera signed.</span>` : `<span>The photo as submitted. Hover it to inspect any tile.</span>`}`,
      tiles: Object.keys(TLABEL).map((s) => `<button class="chipk" data-off="${s}" aria-pressed="${!S.off[s]}"><i style="background:rgb(${TCOL[s]})"></i>${TLABEL[s]} <b>${t[s] || 0}</b></button>`).join(""),
      merkle: `<input type="range" min="0" max="${L}" value="${S.level}" data-level aria-label="Merkle level"><span id="lvlTxt"></span><button class="ghost" data-fold>▶ Fold to the root</button>`,
    }[S.view];
  const canProve = r.anchor && r.verdict !== "unknown";
  const side = S.red
    ? `<div class="redbox"><b>Redaction</b><p>Creates a new record linked to this one: the boxes become black tiles whose hashes are kept, so the rest of the photo still verifies.</p>
        <p><button class="primary" data-redapply ${S.boxes.length && !S.rbusy ? "" : "disabled"}>${S.rbusy ? "Redacting…" : `Redact ${S.boxes.length || ""} area${S.boxes.length === 1 ? "" : "s"}`}</button>
        <button class="ghost" data-redclear>Clear</button> <button class="ghost" data-redcancel>Cancel</button></p>${S.rerr ? `<p class="err">${esc(S.rerr)}</p>` : ""}</div>`
    : `<p>${canProve ? `<button class="primary" data-rp="open">▶ Replay the proof in this browser</button>` : ""}
        ${r.entry_id && r.verdict !== "unknown" && !S.public ? `<button class="ghost" data-redstart>✎ Redact areas</button>` : ""}
        ${S.rdl ? `<a class="ghost" href="${esc(safeUrl(S.rdl))}" download>↓ Redacted image</a>` : ""}<br>
        ${canProve ? `<span class="note" style="margin:0">Click a tile on the photo first to choose it.</span>` : ""}</p>`;
  return `<div class="vfig"><div class="vleft"><div class="vtools"><div class="seg">${["photo", "tiles", "merkle"].map((m) => `<button data-view="${m}" aria-pressed="${S.view === m}" ${S.red ? "disabled" : ""}>${{ photo: "Photo", tiles: "Tiles", merkle: "Merkle tree" }[m]}</button>`).join("")}</div>
      <span class="mono" style="color:var(--muted)">${r.tiles.grid.cols}×${r.tiles.grid.rows} tiles · ${r.tiles.grid.tile}px</span></div>
    <div class="stagebox"><div class="ovl" id="stage">${img}<canvas id="vcv"></canvas>${S.red ? `<canvas id="rcv" class="rcv"></canvas>` : ""}</div></div>
    <div class="ctl">${ctl}</div></div>
    <div class="vright"><div class="kicker tk"><span>Merkle tree · ${S.M.n} leaves → 1 root</span><span>↑ root, anchored on XRPL</span></div>
    <svg class="mtree" id="mtree" preserveAspectRatio="none" role="img" aria-label="Merkle tree of the tiles"></svg><div class="kicker tk"><span>↓ leaves: one per tile, in reading order</span></div>
    <div class="vinfo" id="vinfo"></div>${side}</div></div>`;
}

function buildTreeSvg() { S.rects = treeInto($("#mtree")); }
function treeInto(svg) {
  if (!svg || !S.M) return null;
  const { levels, n } = S.M, L = levels.length, W = 1000; let out = "";
  levels.forEach((lvl, k) => lvl.forEach((s, j) => {
    const lo = j << k, hi = Math.min((j + 1) << k, n);
    out += `<rect data-k="${k}" data-j="${j}" x="${(lo / n) * W}" y="${L - 1 - k}" width="${((hi - lo) / n) * W}" height="1" fill="rgb(${TCOL[s]})" stroke="var(--paper)" stroke-width=".6" vector-effect="non-scaling-stroke"/>`;
  }));
  svg.setAttribute("viewBox", `0 0 ${W} ${L}`); svg.innerHTML = out;
  return levels.map((lvl, k) => lvl.map((_, j) => svg.querySelector(`rect[data-k="${k}"][data-j="${j}"]`)));
}

function drawViewer() {
  const cv = $("#vcv"), img = $("#vimg"), M = S.M; if (!cv || !img || !M) return;
  const dpr = devicePixelRatio || 1, W = img.clientWidth * dpr, H = img.clientHeight * dpr;
  if (!W) return;
  if (cv.width !== W || cv.height !== H) { cv.width = W; cv.height = H; }
  const x = cv.getContext("2d"), tw = W / M.cols, th = H / M.rows;
  const box = (i) => [(i % M.cols) * tw, Math.floor(i / M.cols) * th, tw, th];
  const rgba = (s, a) => `rgba(${TCOL[s]},${a})`;
  x.clearRect(0, 0, W, H);
  if (S.red) { drawBoxes(); return; }
  if (S.view === "tiles") {
    for (let i = 0; i < M.n; i++) { const s = M.st[i]; if (S.off[s]) continue; x.fillStyle = rgba(s, s === "redacted" ? .92 : s === "changed" ? .62 : .34); x.fillRect(...box(i)); }
    x.strokeStyle = "rgba(255,255,255,.14)"; x.lineWidth = 1;
    for (let c = 1; c < M.cols; c++) { x.beginPath(); x.moveTo(c * tw, 0); x.lineTo(c * tw, H); x.stroke(); }
    for (let r = 1; r < M.rows; r++) { x.beginPath(); x.moveTo(0, r * th); x.lineTo(W, r * th); x.stroke(); }
  } else if (S.view === "photo" && S.drift) {
    for (let i = 0; i < M.n; i++) {
      const d = M.d[i] ?? 0, s = M.st[i];
      if (s === "redacted") x.fillStyle = "rgba(0,0,0,.92)";
      else if (d > TOL || s === "changed") x.fillStyle = "rgba(226,69,43,.7)";
      else { const t = d / TOL; x.fillStyle = `rgba(217,162,27,${(0.05 + 0.6 * t * t).toFixed(3)})`; }
      x.fillRect(...box(i));
    }
  } else if (S.view === "merkle") {
    const k = S.level, lvl = M.levels[k], node = (i) => i >> k;
    for (let i = 0; i < M.n; i++) { x.fillStyle = rgba(lvl[node(i)], lvl[node(i)] === "changed" ? .5 : .22); x.fillRect(...box(i)); }
    // node borders: an edge is drawn where the neighbour tile belongs to another node
    x.strokeStyle = "rgba(255,255,255,.85)"; x.lineWidth = Math.max(1, 1.4 * dpr); x.beginPath();
    for (let i = 0; i < M.n; i++) {
      const [bx, by] = box(i), c = i % M.cols;
      if (c === M.cols - 1 || node(i + 1) !== node(i)) { x.moveTo(bx + tw, by); x.lineTo(bx + tw, by + th); }
      if (i + M.cols >= M.n || node(i + M.cols) !== node(i)) { x.moveTo(bx, by + th); x.lineTo(bx + tw, by + th); }
      if (c === 0) { x.moveTo(bx, by); x.lineTo(bx, by + th); }
      if (i < M.cols) { x.moveTo(bx, by); x.lineTo(bx + tw, by); }
    }
    x.stroke();
  }
  // highlight: hovered tree node (its run of tiles) or hovered tile (+ its node at the current level)
  const mark = (lo, hi, fill) => { x.fillStyle = fill; x.strokeStyle = "#fff"; x.lineWidth = 2 * dpr; for (let i = lo; i < hi; i++) { const b = box(i); x.fillRect(...b); x.strokeRect(b[0] + 1, b[1] + 1, b[2] - 2, b[3] - 2); } };
  if (S.hnode) { const { k, j } = S.hnode; mark(j << k, Math.min((j + 1) << k, M.n), "rgba(255,255,255,.28)"); }
  else if (S.hover != null) {
    if (S.view === "merkle" && S.level) { const j = S.hover >> S.level; mark(j << S.level, Math.min((j + 1) << S.level, M.n), "rgba(255,255,255,.18)"); }
    mark(S.hover, S.hover + 1, "rgba(255,255,255,.2)");
  }
  if (S.pin != null && S.pin !== S.hover) { const b = box(S.pin); x.strokeStyle = "#f0c674"; x.lineWidth = 3 * dpr; x.strokeRect(b[0] + 1, b[1] + 1, b[2] - 2, b[3] - 2); }
  // tree: path from the hovered leaf to the root, siblings dashed (= the inclusion proof)
  S.rects?.flat().forEach((r) => r.classList.remove("path", "sib"));
  if (S.hnode) S.rects[S.hnode.k][S.hnode.j].classList.add("path");
  else if (S.hover != null) for (let k = 0, j = S.hover; k < M.levels.length; k++, j >>= 1) {
    S.rects[k][j].classList.add("path"); if ((j ^ 1) < M.levels[k].length) S.rects[k][j ^ 1].classList.add("sib");
  }
  const info = $("#vinfo"), L = M.levels.length - 1;
  if ($("#lvlTxt")) $("#lvlTxt").textContent = S.level === 0 ? `level 0 · ${M.n} leaves, one per tile` : S.level === L ? `level ${L} · the root: one hash for the whole photo, anchored on XRPL` : `level ${S.level} · ${M.levels[S.level].length} nodes, each hashing ${1 << S.level} tiles`;
  if (S.hnode) {
    const { k, j } = S.hnode, lo = j << k, hi = Math.min((j + 1) << k, M.n);
    info.textContent = k === L ? `Root · commits to all ${M.n} tiles · this single hash is what sits on the XRP Ledger` : `Level ${k} node #${j} · hashes tiles ${lo}–${hi - 1} · worst status inside: ${TLABEL[M.levels[k][j]]}`;
  } else if (S.hover != null) {
    const i = S.hover, d = M.d[i];
    info.textContent = `Tile #${i} · row ${Math.floor(i / M.cols)}, col ${i % M.cols} · ${TLABEL[M.st[i]]}${d != null ? ` · drift ${d.toFixed(2)} / ${TOL}` : ""}\nInclusion proof: ${proofLen(M, i)} sibling hashes from this tile up to the anchored root.`;
  } else info.textContent = S.pin != null ? `Tile #${S.pin} chosen for the proof replay.` : "Hover the photo to inspect a tile and its proof, or the tree to see which tiles a hash covers.";
}

// Redaction: boxes drawn in displayed coordinates, sent in image pixels.
function drawBoxes() {
  const cv = $("#rcv"), img = $("#vimg"); if (!cv || !img) return;
  const dpr = devicePixelRatio || 1;
  if (cv.width !== img.clientWidth * dpr) { cv.width = img.clientWidth * dpr; cv.height = img.clientHeight * dpr; }
  const x = cv.getContext("2d"); x.clearRect(0, 0, cv.width, cv.height);
  x.fillStyle = "rgba(0,0,0,.85)"; x.strokeStyle = "#fff"; x.lineWidth = 2 * dpr;
  for (const b of S.drag ? [...S.boxes, S.drag] : S.boxes) { x.fillRect(b[0], b[1], b[2] - b[0], b[3] - b[1]); x.strokeRect(b[0], b[1], b[2] - b[0], b[3] - b[1]); }
}
function bindRedact() {
  const cv = $("#rcv"); if (!cv) return;
  const pt = (e) => { const r = cv.getBoundingClientRect(); return [(e.clientX - r.left) * cv.width / r.width, (e.clientY - r.top) * cv.height / r.height]; };
  cv.addEventListener("pointerdown", (e) => { cv.setPointerCapture(e.pointerId); const p = pt(e); S.drag = [...p, ...p]; });
  cv.addEventListener("pointermove", (e) => { if (!S.drag) return; const p = pt(e); S.drag[2] = p[0]; S.drag[3] = p[1]; drawBoxes(); });
  cv.addEventListener("pointerup", () => {
    if (!S.drag) return;
    const [a, b, c, d] = S.drag, n = [Math.min(a, c), Math.min(b, d), Math.max(a, c), Math.max(b, d)]; S.drag = null;
    if (n[2] - n[0] > 4 && n[3] - n[1] > 4) S.boxes.push(n);
    render();
  });
}
async function applyRedaction() {
  const img = $("#vimg"), cv = $("#rcv"), sx = img.naturalWidth / cv.width, sy = img.naturalHeight / cv.height;
  const px = S.boxes.map((b) => [Math.floor(b[0] * sx), Math.floor(b[1] * sy), Math.ceil(b[2] * sx), Math.ceil(b[3] * sy)]);
  const fd = new FormData(); fd.append("image", S.vfile); fd.append("entry_id", S.report.entry_id); fd.append("boxes", JSON.stringify(px));
  S.rbusy = true; S.rerr = ""; render();
  try {
    const res = await api("/api/redact", { method: "POST", body: fd });
    const blob = await fetch(res.image_url).then((r) => r.blob());
    S.rbusy = false; S.boxes = []; S.red = false;
    await runVerify(new File([blob], "redacted.png", { type: "image/png" }), { tx: res.entry_id });
    S.rdl = res.image_url; render();
  } catch (e) { S.rbusy = false; S.rerr = e.message; render(); }
}

function bindViewer() {
  buildTreeSvg(); bindRedact(); const img = $("#vimg"); if (!img || !S.M) return;
  img.complete ? drawViewer() : img.addEventListener("load", drawViewer, { once: true });
  const stage = $("#stage");
  stage.addEventListener("pointermove", (e) => {
    if (S.red) return;
    const b = img.getBoundingClientRect(), M = S.M;
    const c = Math.floor(((e.clientX - b.left) / b.width) * M.cols), r = Math.floor(((e.clientY - b.top) / b.height) * M.rows);
    const i = c >= 0 && c < M.cols && r >= 0 && r < M.rows ? r * M.cols + c : null;
    if (i !== S.hover) { S.hover = i; S.hnode = null; drawViewer(); }
  });
  stage.addEventListener("click", () => { if (!S.red && S.hover != null) { S.pin = S.hover; drawViewer(); } });
  stage.addEventListener("pointerleave", () => { S.hover = null; drawViewer(); });
  $("#mtree")?.addEventListener("pointermove", (e) => { const rc = e.target.closest("rect"); if (!rc) return; const n = { k: +rc.dataset.k, j: +rc.dataset.j }; if (S.hnode?.k !== n.k || S.hnode?.j !== n.j) { S.hnode = n; S.hover = null; drawViewer(); } });
  $("#mtree")?.addEventListener("pointerleave", () => { S.hnode = null; drawViewer(); });
}
addEventListener("resize", () => drawViewer());
function foldToRoot() {
  const L = S.M.levels.length - 1; S.view = "merkle"; S.level = 0; render();
  const step = () => { if (S.view !== "merkle" || S.level >= L) return; S.level++; const sl = $("[data-level]"); if (sl) sl.value = S.level; drawViewer(); setTimeout(step, 260); };
  setTimeout(step, 300);
}

// ---------------------------------------------------------------- the page: Examine / Certify
const SIGN_MODES = [
  ["device", "Capture device", "Ed25519 + ML-DSA-87", "The accredited device's key signs every tile, with a post-quantum second signature."],
  ["passkey", "Touch ID passkey", "P-256", "Same, but the key never leaves this Mac's Secure Enclave."],
  ["anonymous", "Anonymous", "Groth16 ZK", "Proves an accredited device signed it, not which one. For sources."],
  ["ai", "AI generator", "Ed25519 + ML-DSA-87", "Declares the image as AI-generated, verifiably."],
];
const OPS = { capture: "Captured", edit: "Signed edit", develop: "Developed from the signed RAW", ai_generate: "AI-generated", redact: "Redacted" };
function modeNote(k) {
  if (k !== "passkey") return "";
  if (!passkeyCapable) return `<small class="warnline">This browser cannot use passkeys here.</small>`;
  if (S.pk?.attested) return "";
  if (S.pk?.registered) return `<small class="warnline">Saved on this Mac; the registry must attest it: <code>setup_testnet.py --passkey</code></small>`;
  return S.local ? `<small><button class="linkbtn" data-pksetup>Set up this Mac's passkey (Touch ID)</button></small>` : `<small class="warnline">Set it up from the laptop itself (localhost).</small>`;
}
const modeOff = (k) => k === "passkey" && !(passkeyCapable && S.pk?.attested);


// The verdict seal: an SVG stamp (circular legend, icon, verdict, date), slightly inked.
let sealN = 0;
const SEAL_ICON = {
  real: `<path d="M-13 1l9 9 18-20" fill="none" stroke="currentColor" stroke-width="4.5" stroke-linecap="round" stroke-linejoin="round"/>`,
  edited: `<path d="M-14 14h7l19-19-7-7-19 19z M5 -5l7 7" fill="none" stroke="currentColor" stroke-width="3.2" stroke-linejoin="round"/>`,
  ai: `<path d="M0-16l4 11 11 5-11 4-4 12-4-12-11-4 11-5z" fill="currentColor"/>`,
  unknown: `<text y="11" text-anchor="middle" font-size="34" font-weight="800" fill="currentColor">?</text>`,
};
function seal(kind, word, ledger, ts) {
  const id = `sl${++sealN}`, W = String(word).toUpperCase();
  const date = ts ? new Date(ts * 1000).toLocaleDateString("en-GB", { day: "2-digit", month: "short", year: "numeric" }).toUpperCase() : "XRP LEDGER";
  const legend = `VERIPRESS ✦ EXAMINED ON THE XRP LEDGER ✦ ${ledger ? `LEDGER #${ledger}` : "PROVENANCE RECORD"} ✦ `;
  return `<svg class="seal s-${kind}" viewBox="0 0 220 220" role="img" aria-label="${esc(word)}">
    <defs><path id="${id}p" d="M110,110 m-85,0 a85,85 0 1,1 170,0 a85,85 0 1,1 -170,0"/>
    <filter id="${id}f"><feTurbulence type="fractalNoise" baseFrequency=".85" numOctaves="2" seed="7"/><feDisplacementMap in="SourceGraphic" scale="2.4"/></filter></defs>
    <g filter="url(#${id}f)">
      <circle cx="110" cy="110" r="105" fill="none" stroke="currentColor" stroke-width="3.5"/>
      <circle cx="110" cy="110" r="99" fill="none" stroke="currentColor" stroke-width="1"/>
      <circle cx="110" cy="110" r="70" fill="none" stroke="currentColor" stroke-width="1.6"/>
      <text font-family="system-ui,sans-serif" font-size="11.5" font-weight="700" fill="currentColor"><textPath href="#${id}p" textLength="530" lengthAdjust="spacing">${esc(legend)}</textPath></text>
      <g transform="translate(110 78)">${SEAL_ICON[kind] || SEAL_ICON.unknown}</g>
      <text x="110" y="124" text-anchor="middle" font-family="system-ui,sans-serif" font-size="19" font-weight="800" letter-spacing="1.5" fill="currentColor" ${W.length > 9 ? 'textLength="118" lengthAdjust="spacingAndGlyphs"' : ""}>${esc(W)}</text>
      <line x1="72" x2="148" y1="134" y2="134" stroke="currentColor" stroke-width="1"/>
      <text x="110" y="150" text-anchor="middle" font-family="ui-monospace,Menlo,monospace" font-size="10" letter-spacing="1.5" fill="currentColor">${esc(date)}</text>
    </g></svg>`;
}

function certHtml(res) {
  const onchain = /^https:\/\/testnet\.xrpl\.org\//.test(res.explorer_url || "");
  const status = !onchain ? "Recorded on the offline demo ledger (not on chain)."
    : S.svalid > 0 ? `Validated on the XRP Ledger · ${when(S.svalid)}` : S.svalid === -1 ? "Still pending: check the explorer." : res.pending ? "Submitted to the XRP Ledger, waiting for validation…" : "Validated on the XRP Ledger.";
  const who = res.anonymous ? "An accredited device (hidden by a zero-knowledge proof)" : res.passkey ? `Capture device · Touch ID passkey · <span class="mono">${short(res.signer)}</span>` : `<span class="mono">${short(res.signer)}</span>`;
  const rows = [
    ["Public page", `<a href="/v/${encodeURIComponent(res.entry_id)}" target="_blank" rel="noopener">/v/${esc(short(res.entry_id, 8))} ↗</a>`],
    ["Transaction", onchain ? `<a class="mono" href="${esc(safeUrl(res.explorer_url))}" target="_blank" rel="noopener">${esc(short(res.tx_hash, 8))} ↗</a>` : `<span class="mono">${esc(short(res.tx_hash, 8))}</span>`],
    ["Signed by", who],
    res.registry_root && ["Registry root", `<span class="mono">${esc(short(res.registry_root, 8))}</span>`],
    ...(res.meta_claims || []).map((m) => [m.kind === "day" ? "Day (proven, ZK)" : "Area (proven, ZK)", esc(m.label)]),
    ["Manifest digest", `<span class="mono">${esc(short(res.digest, 10))}</span>`],
    ["Merkle roots", `<span class="mono">exact ${esc(short(res.roots?.exact))} · robust ${esc(short(res.roots?.robust))}</span>`],
    res.grid && ["Tiles", `${res.grid.cols} × ${res.grid.rows} = ${res.grid.cols * res.grid.rows} tiles of ${res.grid.tile} px`],
  ].filter(Boolean);
  return `<article class="doc cert"><div class="dochead"><div><div class="kicker">Certificate · record ${esc(short(res.entry_id, 8))}</div><h2>Certified.</h2><div class="${S.svalid > 0 || !res.pending ? "" : "pend"}">${status}</div></div>
      ${seal(S.mode === "ai" ? "ai" : "real", S.mode === "ai" ? "AI · declared" : "Certified", null, S.svalid > 0 ? S.svalid : Date.now() / 1000)}</div>
    <div class="certbody"><img src="${esc(safeUrl(res.image_url))}" alt="Certified image"><div><dl>${rows.map(([k, v]) => `<dt>${k}</dt><dd>${v}</dd>`).join("")}</dl>
      <p class="actions"><a class="primary" href="${esc(safeUrl(res.image_url))}" download>↓ Download the certified image</a>
      <button class="ghost" data-examine="${esc(res.image_url)}">Examine it</button></p>
      <p class="note" style="margin:0">Share the downloaded file anywhere, even through WhatsApp: it carries an invisible watermark that leads back to this record.</p></div></div></article>`;
}

function signHtml() {
  const busy = !!S.sbusy, b = S.bres;
  return `<div class="form">
    <div class="lab">I. The photo</div><div>${S.sfile ? `<div class="drop picked" data-pick><img src="${S.simg}" alt="" onerror="previewFallback(this,'sign')"><div><b>${esc(S.sfile.name)}</b><span>${(S.sfile.size / 1e6).toFixed(1)} MB · selected</span><span class="change">Change photo</span></div></div>${originalHtml()}` : `<div class="drop" data-pick><b>Choose or drop the photo to certify</b><span>JPEG, PNG, HEIC or camera RAW</span></div>`}</div>
    <div class="lab">II. Signed by</div><div>${SIGN_MODES.map(([k, t, p, d]) => `<label class="opt ${modeOff(k) ? "off" : ""}"><input type="radio" name="m" value="${k}" ${S.mode === k ? "checked" : ""} ${modeOff(k) ? "disabled" : ""}><span><b>${t}</b> <span class="mono">${p}</span><small>${d}</small>${modeNote(k)}</span></label>`).join("")}</div>
    <div class="lab">III. Record</div><div>
      <button class="primary" data-sign ${S.sfile && !busy && S.lk !== "busy" && !modeOff(S.mode) ? "" : "disabled"}>${busy ? esc(S.sbusy) : S.mode === "passkey" ? "Sign with Touch ID &amp; record on XRPL" : "Sign &amp; record on XRPL"}</button>
      ${busy ? `<span class="spin"></span>` : ""}${S.serr ? `<p class="err">${esc(S.serr)}</p>` : ""}
      <details class="annex" ${S.bfiles.length || b ? "open" : ""}><summary>Several photos in one transaction</summary>
        <p class="hint">Up to 8 photos signed one by one, anchored by a single XRPL transaction (the Merkle root of the records); each photo gets a receipt. Uses the signer chosen above.</p>
        <input type="file" multiple accept="image/*,.heic,.heif,.dng,.cr2,.cr3,.nef,.arw,.raf,.rw2,.orf" data-batchfiles>
        <button class="ghost" data-batch ${S.bfiles.length && S.bfiles.length <= 8 && !S.bbusy ? "" : "disabled"}>${S.bbusy ? "Signing the batch…" : S.bfiles.length > 8 ? "At most 8 photos" : `Sign ${S.bfiles.length || ""} photo${S.bfiles.length === 1 ? "" : "s"} · one transaction`}</button>
        ${S.berr ? `<p class="err">${esc(S.berr)}</p>` : ""}
        ${b ? `<ul class="blist"><li><b>${b.size}</b> photo${b.size > 1 ? "s" : ""} anchored in <a class="mono" href="${esc(safeUrl(b.explorer_url))}" target="_blank" rel="noopener">${esc(short(b.tx_hash, 8))} ↗</a>${b.pending ? " · pending validation" : ""}</li>${b.entries.map((e) => e.entry_id
          ? `<li>✓ ${esc(e.name)} · <a href="${esc(safeUrl(e.image_url))}" download>download</a> · <a href="/v/${encodeURIComponent(e.entry_id)}" target="_blank" rel="noopener">public page ↗</a></li>`
          : `<li class="err">✗ ${esc(e.name)} · ${esc(e.error)}</li>`).join("")}</ul>` : ""}
      </details></div></div>
    ${S.sres ? certHtml(S.sres) : ""}`;
}

function verifyHtml() {
  const r = S.report;
  let body = `<div class="lede"><div><h1>Is this photo what it claims to be?</h1><p style="margin-top:14px">Submit any image, even one forwarded on WhatsApp. VeriPress finds its record on the XRP Ledger and checks it against what the camera signed.</p></div>
    <div><div class="drop" data-pick><b>Submit a photo for examination</b><span>Choose or drop it here · no account, nothing is published</span></div>
    ${S.specimens.length ? `<div class="samples">Specimens: ${S.specimens.map(([f, l]) => `<button data-sample="${esc(f)}">${esc(l)}</button>`).join("·")}</div>` : ""}
    <details class="txbox" ${S.tx ? "open" : ""}><summary>I know the record id</summary><input class="field mono" data-input="tx" value="${esc(S.tx)}" placeholder="tx hash (optional: skips the watermark lookup)" autocomplete="off" spellcheck="false">${S.vfile ? `<button class="ghost" data-reverify>Examine again</button>` : ""}</details></div></div>`;
  if (S.busy && !r) body += `<div class="busy"><span class="spin"></span> Examining… looking for the record, checking the signature, the ledger and every tile.</div>`;
  if (S.err) body += `<p class="err">${esc(S.err)}</p>`;
  if (r) body += reportHtml(r);
  return body;
}

function reportHtml(r) {
  const v = verdictOf(r), cs = checks(r), hist = r.history || [];
  return `<article class="doc"><div class="dochead"><div><div class="kicker">Report of examination · record ${esc(short(r.entry_id, 8))}${r.pending ? " · provisional, anchor not validated yet" : ""}${S.busy ? " · re-checking…" : ""}</div><h2>${v.word}.</h2><div>${esc(v.line)}</div></div>
      ${seal(r.verdict, v.word, r.time_window?.ledger_index, r.anchor?.timestamp)}</div>
      <div class="docbody"><figure>${viewerHtml(r)}
        <figcaption>Fig. 1 — ${r.tiles ? `the photo is cut into ${r.tiles.statuses.length} tiles; each one is a leaf of the Merkle tree whose root is anchored on the ledger.` : "the examined photo."}</figcaption></figure>
        <table>${cs.map((c, i) => `<tr><td class="n">§${i + 1}</td><td><b>${esc(c.title)}</b>${esc(c.value)}${c.link ? ` · <a href="${esc(safeUrl(c.link))}" target="_blank" rel="noopener">ledger ↗</a>` : ""}<br><small>${esc(c.plain)}</small></td><td class="r ${c.st}">${{ ok: "Verified", fail: c.k === "pixels" ? "Altered" : "Failed", warn: "Note", info: "Info" }[c.st]}</td></tr>`).join("")}</table></div>
      ${hist.length > 1 ? `<div class="annex"><div class="kicker">Version history</div><ol class="hist">${hist.map((h) => `<li class="${h.verified ? "" : "bad"}"><b>${esc(OPS[h.op] || h.op || "version")}</b> · ${esc(when(h.timestamp))} · <span class="mono">${esc(short(h.tx_hash))}</span>${h.verified ? " ✓" : " · not verified"}</li>`).join("")}</ol></div>` : ""}
      <details class="annex"><summary>Technical annex</summary><dl>
        ${r.entry_id && r.verdict !== "unknown" ? `<dt>Public page</dt><dd><a href="/v/${encodeURIComponent(r.entry_id)}" target="_blank" rel="noopener">/v/${esc(short(r.entry_id, 8))} ↗</a></dd>` : ""}
        <dt>Record id</dt><dd class="mono">${esc(r.entry_id || "—")}</dd><dt>Signer key</dt><dd class="mono">${esc(r.anchor?.signer || (r.anonymous ? "hidden (anonymous)" : "—"))}</dd>
        ${r.zk ? `<dt>Registry root</dt><dd class="mono">${esc(r.zk.registry_root)}</dd>` : ""}
        ${r.batch ? `<dt>Batch</dt><dd>record ${r.batch.index + 1} of ${r.batch.size} in <span class="mono">${esc(short(r.batch.tx_hash, 8))}</span></dd>` : ""}
        <dt>Ledger T0</dt><dd class="mono">#${esc(r.time_window?.ledger_index ?? "—")}</dd><dt>Disclosure (CID)</dt><dd class="mono">${esc(r.disclosure_cid || "—")}</dd>
        <dt>Tile grid</dt><dd class="mono">${r.tiles ? `${r.tiles.grid.cols}×${r.tiles.grid.rows} · ${r.tiles.grid.tile}px` : "—"}</dd></dl></details></article>`;
}

function publicHtml() {
  return `${S.report ? reportHtml(S.report) : ""}
    <p class="actions"><button class="primary" data-copy>${S.copied ? "✓ Link copied" : "Copy link"}</button>
    <a class="ghost" href="${esc(safeUrl(S.img))}" download>↓ Download the image</a> <a class="ghost" href="/">Examine your own photo</a></p>
    <p class="note" style="margin:0">This page re-verifies the stored image against its XRPL anchor each time it is opened.</p>`;
}

function page() {
  const r = S.report;
  if (r?.tiles?.statuses && (!S.M || S.M.st !== r.tiles.statuses)) { S.M = merkle(r); S.pin = null; S.view = r.tiles.counts.changed || r.tiles.counts.redacted ? "tiles" : "photo"; S.level = 0; S.off = {}; }
  if (!r?.tiles?.statuses) S.M = null;
  if (S.public) return `<div class="vA ${S.theme === "dark" ? "dark" : ""}"><div class="wrap"><header><div class="brand"><a href="/">VeriPress</a><small>public provenance record · read-only</small></div><nav><button class="theme" data-theme>${S.theme === "dark" ? "☀ Light" : "◐ Dark"}</button></nav></header>${publicHtml()}</div></div>`;
  const nav = `<nav><button data-tab="verify" aria-current="${S.tab === "verify"}">Examine a photo</button><button data-tab="sign" aria-current="${S.tab === "sign"}">Certify a photo</button>${pill()}<button class="theme" data-theme>${S.theme === "dark" ? "☀ Light" : "◐ Dark"}</button></nav>`;
  return `<div class="vA ${S.theme === "dark" ? "dark" : ""}"><div class="wrap"><header><div class="brand">VeriPress<small>photo provenance on the XRP Ledger</small></div>${nav}</header>${S.tab === "sign" ? signHtml() : verifyHtml()}</div></div>`;
}


// ---------------------------------------------------------------- proof replay, in the browser
// Everything below is recomputed here with WebCrypto: robust leaves from the public disclosure,
// the Merkle path of one tile, the root, the manifest digest; the anchor is read straight from a
// public XRPL node (WebSocket, no VeriPress server in between) and the Ed25519 signature checked.
const hx = (b) => [...new Uint8Array(b)].map((x) => x.toString(16).padStart(2, "0")).join("");
const unhx = (h) => Uint8Array.from(h.match(/../g) || [], (x) => parseInt(x, 16));
const cat = (...a) => { const o = new Uint8Array(a.reduce((n, x) => n + x.length, 0)); let p = 0; for (const x of a) { o.set(x, p); p += x.length; } return o; };
const sha = async (b) => new Uint8Array(await crypto.subtle.digest("SHA-256", b));
const u32 = (i) => Uint8Array.of(i >>> 24, (i >>> 16) & 255, (i >>> 8) & 255, i & 255);
const i16 = (v) => { const o = new Uint8Array(v.length * 2), d = new DataView(o.buffer); v.forEach((x, k) => d.setInt16(2 * k, x)); return o; };
const enc = new TextEncoder();
const h8 = (h) => `${h.slice(0, 8)}…${h.slice(-6)}`;

async function robustLeaf(t) {
  if (t.r) return unhx(t.r); // redacted tile: only its leaf hash is disclosed
  return sha(cat(Uint8Array.of(0), enc.encode("VPR1"), u32(t.i), unhx(t.salt), i16(t.f), t.g ? i16(t.g) : new Uint8Array()));
}
function xrplTx(hash) {
  return new Promise((ok, ko) => {
    const ws = new WebSocket("wss://s.altnet.rippletest.net:51233"), to = setTimeout(() => { ws.close(); ko(new Error("XRPL node timeout")); }, 9000);
    ws.onopen = () => ws.send(JSON.stringify({ id: 1, command: "tx", transaction: hash }));
    ws.onmessage = (e) => { clearTimeout(to); ws.close(); const m = JSON.parse(e.data); m.result ? ok(m.result) : ko(new Error(m.error || "tx not found")); };
    ws.onerror = () => { clearTimeout(to); ko(new Error("cannot reach the XRPL node")); };
  });
}

// Start tile: the one clicked, else the top-left tile (#0): climbing from there, each hash covers
// twice as many tiles in reading order (2, 4, 8…), sweeping down the photo until the root.
function replayTile(r) {
  return S.pin != null ? S.pin : 0;
}
function rpDraw(k, j, i) {
  const cv = $("#rpcv"), img = $("#rpimg"), M = S.M; if (!cv || !img.clientWidth) return;
  const dpr = devicePixelRatio || 1, W = img.clientWidth * dpr, H = img.clientHeight * dpr;
  cv.width = W; cv.height = H; const x = cv.getContext("2d"), tw = W / M.cols, th = H / M.rows;
  x.fillStyle = "rgba(10,9,7,.62)"; x.fillRect(0, 0, W, H);
  if (k != null) {
    const lo = j << k, hi = Math.min((j + 1) << k, M.n);
    for (let t = lo; t < hi; t++) {
      x.clearRect((t % M.cols) * tw, Math.floor(t / M.cols) * th, tw + .5, th + .5);
      if (M.st[t] === "changed") { x.fillStyle = "rgba(239,107,79,.55)"; x.fillRect((t % M.cols) * tw, Math.floor(t / M.cols) * th, tw + .5, th + .5); }
    }
    x.strokeStyle = "rgba(255,255,255,.9)"; x.lineWidth = 1.5 * dpr; x.beginPath();
    for (let t = lo; t < hi; t++) {
      const bx = (t % M.cols) * tw, by = Math.floor(t / M.cols) * th, c = t % M.cols, inN = (u) => u >= lo && u < hi;
      if (c === M.cols - 1 || !inN(t + 1)) { x.moveTo(bx + tw, by); x.lineTo(bx + tw, by + th); }
      if (c === 0 || !inN(t - 1)) { x.moveTo(bx, by); x.lineTo(bx, by + th); }
      if (!inN(t + M.cols)) { x.moveTo(bx, by + th); x.lineTo(bx + tw, by + th); }
      if (!inN(t - M.cols)) { x.moveTo(bx, by); x.lineTo(bx + tw, by); }
    }
    x.stroke();
  }
  if (i != null) { x.strokeStyle = M.st[i] === "changed" ? "#ef6b4f" : "#5cc48d"; x.lineWidth = 3 * dpr; x.strokeRect((i % M.cols) * tw + 1, Math.floor(i / M.cols) * th + 1, tw - 2, th - 2); }
}

async function replay() {
  const r = S.report, M = S.M, i = replayTile(r), run = (S.run = (S.run || 0) + 1);
  const box = document.createElement("div"); box.className = "rp"; box.id = "rp";
  box.innerHTML = `<div class="rpin"><div class="rphead"><div><div class="rpk">Proof replay · computed in this browser</div><h2>Don't trust us. Your browser checks it.</h2></div>
      <div><button class="rpb" data-rp="again">↻ Replay</button><button class="rpb" data-rp="close">✕</button></div></div>
    <div class="rpgrid"><div class="rpleft"><div class="ovl"><img id="rpimg" src="${S.img}" alt=""><canvas id="rpcv"></canvas></div><div class="rpcap" id="rpcap">${S.pin != null ? `Tile #${i}, the one you chose` : `Tile #${i}: top-left corner of the photo`}</div>
      <div class="rptk"><span>↑ root</span><span>Merkle tree</span></div><svg class="rptree" id="rptree" preserveAspectRatio="none"></svg><div class="rptk"><span>↓ leaves: one per tile</span><span></span></div></div>
    <ol class="rpsteps" id="rpsteps"></ol></div></div>`;
  $("#rp")?.remove(); document.body.appendChild(box);
  const img = $("#rpimg"); await new Promise((ok) => (img.complete ? ok() : img.addEventListener("load", ok, { once: true })));
  rpDraw(null, null, i);
  const rr = treeInto($("#rptree")), lit = (k, j) => {
    rr.flat().forEach((x) => x.classList.remove("path", "sib"));
    for (let q = 0, jj = i; q <= k; q++, jj >>= 1) { rr[q][jj].classList.add("path"); if (q === k && (jj ^ 1) < rr[q].length) rr[q][jj ^ 1].classList.add("sib"); }
  };
  lit(0, i);
  const steps = $("#rpsteps"), alive = () => S.run === run && document.body.contains(box);
  const step = (n, title, html = "") => { const li = document.createElement("li"); li.innerHTML = `<span class="rpn">${n}</span><div><b>${title}</b><div class="rpl">${html}</div></div><span class="rps">…</span>`; steps.appendChild(li); li.scrollIntoView({ block: "nearest", behavior: "smooth" }); return li; };
  const done = (li, ok, txt) => { li.classList.add(ok ? "ok" : "ko"); li.querySelector(".rps").textContent = txt || (ok ? "✓" : "✗"); };
  const line = (li, h) => { const d = document.createElement("div"); d.innerHTML = h; li.querySelector(".rpl").appendChild(d); return d; };
  try {
    // 1. public material
    let li = step(1, "Fetch the public record");
    const P = await fetch(`/api/proof/${r.entry_id}`).then((x) => x.json()), man = JSON.parse(P.manifest), tiles = P.disclosure.tiles;
    line(li, `manifest <code>${P.manifest.length} bytes</code> · disclosure <code>${tiles.length} tiles</code>`);
    line(li, `<span class="rpdim">served by anyone (here our server): nothing below takes it on trust</span>`);
    done(li, true); await sleep(900); if (!alive()) return;
    // 2. leaves
    li = step(2, `Rebuild the ${tiles.length} leaves`);
    line(li, `leaf = SHA-256( 00 ‖ "VPR1" ‖ index ‖ salt ‖ fingerprint )`);
    const t0 = performance.now(); let level = await Promise.all(tiles.map(robustLeaf)); const ms = performance.now() - t0;
    line(li, `${tiles.length} hashes in <code>${ms.toFixed(0)} ms</code> · tile #${i} → <code>${h8(hx(level[i]))}</code>`);
    done(li, true); await sleep(900); if (!alive()) return;
    // 3. climb
    li = step(3, `Climb the tree from tile #${i}`);
    const pathHashes = []; let j = i, k = 0, cur = level[i], seenEdit = M.st[i] === "changed";
    while (level.length > 1) {
      const next = [];
      for (let a = 0; a + 1 < level.length; a += 2) next.push(sha(cat(Uint8Array.of(1), level[a], level[a + 1])));
      if (level.length % 2) next.push(Promise.resolve(level.at(-1)));
      const sib = j ^ 1, nl = await Promise.all(next);
      const hasSib = sib < level.length; k++; j >>= 1; cur = nl[j];
      pathHashes.push(hx(cur));
      line(li, `<span class="rpdim">level ${String(k).padStart(2)}</span> ${hasSib ? `⊕ sibling <code>${h8(hx(level[sib]))}</code>` : `<span class="rpdim">(promoted)</span>`} → <code>${h8(hx(cur))}</code> <span class="rpdim">covers ${Math.min((j + 1) << k, M.n) - (j << k)} tiles</span>`);
      rpDraw(k, j, i); lit(k, j); $("#rpcap").textContent = `Level ${k}: this hash covers ${Math.min((j + 1) << k, M.n) - (j << k)} of ${M.n} tiles`;
      const lo = j << k, hi = Math.min((j + 1) << k, M.n), edited = M.st.slice(lo, hi).filter((s) => s === "changed").length;
      if (edited && !seenEdit) {
        seenEdit = true;
        line(li, `<span class="rped">⚠ this hash now covers ${edited} tiles of the submitted photo that no longer match their signed fingerprint (drift above ${TOL}): the edit is here.</span>`);
        await sleep(1400); if (!alive()) return;
      }
      level = nl; await sleep(420); if (!alive()) return;
    }
    done(li, true, `${k} hashes`); await sleep(500);
    // 4. root
    li = step(4, "Reach the root");
    const rootOk = hx(cur) === man.robust_root;
    line(li, `computed <code>${h8(hx(cur))}</code>`); line(li, `in the signed manifest <code>${h8(man.robust_root)}</code>`);
    done(li, rootOk); $("#rpcap").textContent = `The root: one hash for the whole photo`; await sleep(900); if (!alive()) return;
    // 5. manifest digest
    li = step(5, "Hash the signed manifest");
    const dig = hx(await sha(enc.encode(P.manifest)));
    line(li, `SHA-256(manifest) = <code>${h8(dig)}</code>`); line(li, `<span class="rpdim">it contains the root, the device key, ledger T0, the ZK commitment, the PQ key…</span>`);
    done(li, true); await sleep(900); if (!alive()) return;
    // 6. XRPL
    li = step(6, "Ask the XRP Ledger directly");
    line(li, `<span class="rpdim">wss://s.altnet.rippletest.net · tx ${h8(P.tx_hash)}</span>`);
    const tx = await xrplTx(P.tx_hash), memo = JSON.parse(new TextDecoder().decode(unhx(tx.Memos[0].Memo.MemoData)));
    const batch = !memo.d && memo.b; // aggregated anchoring: the memo holds the root of N records
    line(li, batch ? `${tx.validated ? "validated" : "pending"} in ledger <code>#${tx.ledger_index}</code> · batch of <code>${memo.n}</code> records, root <code>${h8(memo.b)}</code>`
      : `${tx.validated ? "validated" : "pending"} in ledger <code>#${tx.ledger_index}</code> · memo d = <code>${h8(memo.d)}</code>`);
    if (batch) line(li, `<span class="rpdim">this record's receipt (its leaf under that root) is checked by the server, not replayed here</span>`);
    const memoOk = batch ? null : memo.d === dig;
    done(li, memoOk !== false, batch ? "batch" : memoOk ? "= ✓" : "≠"); await sleep(900); if (!alive()) return;
    // 7. signature
    li = step(7, "Check the device's signature");
    let sigOk = null;
    if (memo.s && memo.k?.startsWith("ED")) {
      try {
        const key = await crypto.subtle.importKey("raw", unhx(memo.k.slice(2)), { name: "Ed25519" }, false, ["verify"]);
        sigOk = await crypto.subtle.verify({ name: "Ed25519" }, key, unhx(memo.s), unhx(dig));
      } catch { sigOk = undefined; }
      line(li, `Ed25519 · key <code>${h8(memo.k)}</code> = manifest.signer ${memo.k === man.signer ? "✓" : "✗"}`);
      line(li, sigOk === undefined ? `<span class="rpdim">this browser has no Ed25519 in WebCrypto</span>` : `signature over the digest: <b>${sigOk ? "valid" : "INVALID"}</b>`);
      done(li, sigOk !== false && memo.k === man.signer);
    } else {
      const how = r.anonymous ? "a Groth16 zero-knowledge proof (anonymous device)" : r.passkey ? "a Touch ID passkey (P-256 WebAuthn assertion)" : batch ? "a signature inside the batch receipt" : "a signature stored with the record";
      line(li, `signed with ${how}: checked by the server, not replayed here`);
      done(li, true, "—");
    }
    await sleep(700); if (!alive()) return;
    // verdict for this tile
    const d = M.d[i], changed = M.st[i] === "changed", full = rootOk && memoOk === true && sigOk === true, fin = document.createElement("div");
    fin.className = "rpfin " + (rootOk && memoOk !== false && sigOk !== false ? "good" : "bad");
    fin.innerHTML = full
      ? `<b>Proven in this browser:</b> tile #${i} belongs to what an accredited device signed on ${when(tx.date + 946684800)}, recorded on the XRP Ledger. No need to trust VeriPress: every step was recomputed here and checked against the public XRP Ledger.`
      : rootOk && memoOk !== false && sigOk !== false
        ? `<b>Proven in this browser up to the ledger:</b> tile #${i} is part of the record anchored on ${when(tx.date + 946684800)}; ${batch ? "the batch receipt and " : ""}the signature were checked by VeriPress' server.`
        : `<b>The proof does not hold:</b> what was recomputed here does not match the ledger.`;
    const nEdit = M.st.filter((s) => s === "changed").length;
    if (nEdit) fin.innerHTML += `<br><span class="rped">But ${nEdit} tiles of the photo you submitted no longer match what was signed (drift above ${TOL}, shown in red): it was edited there.</span>`;
    steps.appendChild(fin); fin.scrollIntoView({ block: "nearest", behavior: "smooth" });
  } catch (e) { step("!", "Stopped", esc(e.message)); }
}
document.addEventListener("click", (e) => {
  const b = e.target.closest("[data-rp]"); if (!b) return;
  if (b.dataset.rp === "close") { S.run++; $("#rp")?.remove(); }
  else if (b.dataset.rp === "again") replay();
  else if (b.dataset.rp === "open") replay();
});

// ---------------------------------------------------------------- render + events
function render() {
  const y = scrollY;
  $("#app").innerHTML = page();
  scrollTo(0, y);
  bindViewer();
}
$("#app").addEventListener("click", (e) => {
  const t = e.target.closest("[data-drift],[data-copy],[data-tab],[data-pick],[data-sample],[data-view],[data-off],[data-fold],[data-theme],[data-sign],[data-batch],[data-examine],[data-pksetup],[data-redstart],[data-redclear],[data-redcancel],[data-redapply],[data-reverify]");
  if (!t || t.disabled) return;
  const d = t.dataset;
  if ("drift" in d) { S.drift = !S.drift; render(); }
  else if ("copy" in d) { navigator.clipboard?.writeText(location.href).then(() => { S.copied = true; render(); }); }
  else if (d.tab) { S.tab = d.tab; if (d.tab === "sign") refreshPasskey(); render(); }
  else if (d.view) { S.view = d.view; render(); }
  else if (d.off) { S.off[d.off] = !S.off[d.off]; render(); }
  else if ("fold" in d) foldToRoot();
  else if ("theme" in d) { S.theme = S.theme === "dark" ? "light" : "dark"; localStorage.vpTheme = S.theme; render(); }
  else if ("pick" in d) pick();
  else if (d.sample) loadSpecimen(d.sample);
  else if ("sign" in d) runSign();
  else if ("batch" in d) runBatch();
  else if (d.examine) examineUrl(d.examine, "certified.png");
  else if ("pksetup" in d) { e.preventDefault(); setupPasskey(); }
  else if ("redstart" in d) { S.red = true; S.boxes = []; S.rerr = ""; render(); }
  else if ("redclear" in d) { S.boxes = []; render(); }
  else if ("redcancel" in d) { S.red = false; S.boxes = []; render(); }
  else if ("redapply" in d) applyRedaction();
  else if ("reverify" in d) runVerify(S.vfile, { tx: S.tx, again: true });
});
// Typing never re-renders (focus stays); choices that change what is enabled do.
$("#app").addEventListener("input", (e) => {
  const t = e.target;
  if ("level" in t.dataset) { S.level = +t.value; drawViewer(); }
  else if (t.dataset.input === "tx") S.tx = t.value;
});
$("#app").addEventListener("change", (e) => {
  const t = e.target;
  if (t.name === "m") { S.mode = t.value; render(); }
  else if (t.name === "ver") { S.ver = t.value; render(); }
  else if ("batchfiles" in t.dataset) { S.bfiles = [...t.files]; S.bres = null; render(); }
});
// Presentation mode (projector): larger type, full screen. Key P.
addEventListener("keydown", (e) => {
  if (e.key === "Escape" && $("#rp")) { S.run++; $("#rp").remove(); return; }
  if (e.key.toLowerCase() !== "p" || e.metaKey || e.ctrlKey || e.altKey || /^(INPUT|TEXTAREA|SELECT)$/.test(e.target.tagName)) return;
  const on = document.documentElement.classList.toggle("present");
  if (on && !document.fullscreenElement) document.documentElement.requestFullscreen?.().catch(() => {});
  if (!on && document.fullscreenElement) document.exitFullscreen?.().catch(() => {});
  drawViewer();
});
// The public page (/v/<id>) embeds the report: no tabs, no upload, a single verification.
const EMBEDDED = document.getElementById("report");
if (EMBEDDED) {
  Object.assign(S, { public: true, report: JSON.parse(EMBEDDED.textContent), img: $("#app").dataset.img });
  render();
  if (S.report.pending) setTimeout(() => location.reload(), 5000); // fast anchoring: until validated
} else {
  pollHealth(); refreshPasskey(); render();
  fetch("/api/demo").then((r) => r.json()).then((l) => { S.specimens = l; if (S.tab === "verify" && !S.report) render(); }).catch(() => {});
}

