/* VeriPress — verdict stamp and chain of evidence. OWNER: Dev B.
   Shared by the app (index.html) and the public link (view.html), from a /api/verify report
   (docs/interfaces.md). Every report value reaches the DOM through esc(), Number() or safeUrl(). */
(function () {
  "use strict";

  const SPRITE = `<svg id="vp-sprite" width="0" height="0" style="position:absolute" aria-hidden="true">
  <symbol id="vp-check" viewBox="0 0 24 24"><path d="M5 12.5l4.2 4.2L19 7"/></symbol>
  <symbol id="vp-cross" viewBox="0 0 24 24"><path d="M6.5 6.5l11 11M17.5 6.5l-11 11"/></symbol>
  <symbol id="vp-warn" viewBox="0 0 24 24"><path d="M12 4l9 16H3z"/><path d="M12 10v4.2M12 17.2v.1"/></symbol>
  <symbol id="vp-question" viewBox="0 0 24 24"><circle cx="12" cy="12" r="8.5"/><path d="M9.6 9.6a2.5 2.5 0 1 1 3.4 2.3c-.6.3-1 .8-1 1.5v.4M12 16.9v.1"/></symbol>
  <symbol id="vp-ai" viewBox="0 0 24 24"><path d="M10 4.5l1.6 4.4 4.4 1.6-4.4 1.6L10 16.5l-1.6-4.4L4 10.5l4.4-1.6z"/><path d="M17.5 14l.8 2.2 2.2.8-2.2.8-.8 2.2-.8-2.2-2.2-.8 2.2-.8z"/></symbol>
  <symbol id="vp-device" viewBox="0 0 24 24"><rect x="3" y="6.5" width="18" height="12.5" rx="2.5"/><circle cx="12" cy="12.7" r="3.3"/><path d="M8.2 6.5l1.4-2h4.8l1.4 2"/></symbol>
  <symbol id="vp-key" viewBox="0 0 24 24"><circle cx="8" cy="14" r="4"/><path d="M11 11.2L19.5 3M16 6.5l2.5 2.5M14 8.5l2 2"/></symbol>
  <symbol id="vp-mask" viewBox="0 0 24 24"><path d="M3 9c2.5-1.5 5.5-2 9-2s6.5.5 9 2c0 4.5-2 8-5 8-1.8 0-2.6-1.6-4-1.6S9.8 17 8 17c-3 0-5-3.5-5-8z"/><path d="M7.5 11.2h2.4M14.1 11.2h2.4"/></symbol>
  <symbol id="vp-shield" viewBox="0 0 24 24"><path d="M12 3l7.5 3v5.5c0 4.6-3.2 8.2-7.5 9.5-4.3-1.3-7.5-4.9-7.5-9.5V6z"/><rect x="9" y="11" width="6" height="5" rx="1"/><path d="M10.2 11V9.6a1.8 1.8 0 0 1 3.6 0V11"/></symbol>
  <symbol id="vp-clock" viewBox="0 0 24 24"><circle cx="12" cy="12" r="8.5"/><path d="M12 7.5V12l3 2"/></symbol>
  <symbol id="vp-chain" viewBox="0 0 24 24"><path d="M10 14a4 4 0 0 0 5.7 0l3-3a4 4 0 0 0-5.7-5.7l-1 1"/><path d="M14 10a4 4 0 0 0-5.7 0l-3 3a4 4 0 0 0 5.7 5.7l1-1"/></symbol>
  <symbol id="vp-pin" viewBox="0 0 24 24"><path d="M12 21s-6.5-5.6-6.5-11a6.5 6.5 0 0 1 13 0c0 5.4-6.5 11-6.5 11z"/><circle cx="12" cy="10" r="2.4"/></symbol>
  <symbol id="vp-tiles" viewBox="0 0 24 24"><rect x="4" y="4" width="7" height="7" rx="1.2"/><rect x="13" y="4" width="7" height="7" rx="1.2"/><rect x="4" y="13" width="7" height="7" rx="1.2"/><rect x="13" y="13" width="7" height="7" rx="1.2"/></symbol>
  <symbol id="vp-redact" viewBox="0 0 24 24"><rect x="3.5" y="5" width="17" height="14" rx="2"/><rect x="7" y="9" width="10" height="6" rx="1" fill="currentColor" stroke="none"/></symbol>
  <symbol id="vp-layers" viewBox="0 0 24 24"><path d="M12 4l8.5 4.5L12 13 3.5 8.5z"/><path d="M3.5 12.5L12 17l8.5-4.5M3.5 16.2L12 20.7l8.5-4.5"/></symbol>
  <symbol id="vp-info" viewBox="0 0 24 24"><circle cx="12" cy="12" r="8.5"/><path d="M12 11v5.2M12 7.8v.1"/></symbol>
  <symbol id="vp-hourglass" viewBox="0 0 24 24"><path d="M7 3.5h10M7 20.5h10M8 3.5c0 4.5 8 4.5 8 8.5s-8 4-8 8.5M16 3.5c0 4.5-8 4.5-8 8.5s8 4 8 8.5"/></symbol>
  <symbol id="vp-share" viewBox="0 0 24 24"><circle cx="6" cy="12" r="2.6"/><circle cx="18" cy="6" r="2.6"/><circle cx="18" cy="18" r="2.6"/><path d="M8.3 10.8l7.4-3.6M8.3 13.2l7.4 3.6"/></symbol>
  <symbol id="vp-verify" viewBox="0 0 24 24"><path d="M12 3l7.5 3v5.5c0 4.6-3.2 8.2-7.5 9.5-4.3-1.3-7.5-4.9-7.5-9.5V6z"/><path d="M8.5 12l2.5 2.5 4.5-5"/></symbol>
  <symbol id="vp-present" viewBox="0 0 24 24"><rect x="3" y="4" width="18" height="12" rx="1.5"/><path d="M12 16v4M8.5 20.5h7"/></symbol>
  <symbol id="vp-upload" viewBox="0 0 24 24"><path d="M12 16V4.5M7.5 9L12 4.5 16.5 9"/><path d="M4.5 15v3.5a2 2 0 0 0 2 2h11a2 2 0 0 0 2-2V15"/></symbol>
  <symbol id="vp-download" viewBox="0 0 24 24"><path d="M12 4.5V16M7.5 11.5L12 16l4.5-4.5"/><path d="M4.5 15v3.5a2 2 0 0 0 2 2h11a2 2 0 0 0 2-2V15"/></symbol>
  <symbol id="vp-external" viewBox="0 0 24 24"><path d="M14 4.5h5.5V10M19.5 4.5L11 13"/><path d="M18 14v4.5a1.5 1.5 0 0 1-1.5 1.5h-11A1.5 1.5 0 0 1 4 18.5v-11A1.5 1.5 0 0 1 5.5 6H10"/></symbol>
  <symbol id="vp-edit" viewBox="0 0 24 24"><path d="M4 20l1-4.5L15.5 5a2.1 2.1 0 0 1 3 3L8 18.5z"/><path d="M13.5 7l3 3"/></symbol>
</svg>`;

  const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
  const short = (h) => (h && h.length > 20 ? h.slice(0, 8) + "…" + h.slice(-6) : h || "");
  const safeUrl = (u) => { try { const x = new URL(u, location.href); return ["https:", "http:"].includes(x.protocol) ? x.href : "#"; } catch { return "#"; } };
  const hms = (t) => new Date(t * 1000).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" });
  const when = (t) => new Date(t * 1000).toLocaleString([], { day: "numeric", month: "short", hour: "2-digit", minute: "2-digit" });
  const icon = (id, cls = "vp-i") => `<svg class="${cls}" aria-hidden="true"><use href="#vp-${id}"/></svg>`;
  const ext = (href, text) => `<a href="${esc(safeUrl(href))}" target="_blank" rel="noopener">${esc(text)}${icon("external", "vp-i vp-ext")}</a>`;

  function sprite() {
    if (!document.getElementById("vp-sprite")) document.body.insertAdjacentHTML("afterbegin", SPRITE);
  }

  const VERDICT = {
    real: { title: "Real", sub: "verified on XRPL", cls: "v-real", icon: "check" },
    edited: { title: "Edited", sub: "changed since it was signed", cls: "v-edited", icon: "warn" },
    ai: { title: "AI-generated", sub: "declared and signed", cls: "v-ai", icon: "ai" },
    unknown: { title: "Unknown", sub: "no verifiable provenance (≠ fake)", cls: "v-unknown", icon: "question" },
  };

  // The verdict, stamped on the photo.
  function stamp(r) {
    const v = VERDICT[r.verdict] || VERDICT.unknown;
    let sub = v.sub;
    if (r.verdict === "real" && r.anonymous) sub = "accredited device · anonymous";
    if (r.pending) sub = "awaiting ledger validation…";
    return `<div class="vp-stamp ${v.cls}" role="status">${icon(v.icon)}<div><strong>${esc(v.title)}</strong><span>${esc(sub)}</span></div></div>`;
  }

  // One link per guarantee, in the order things happened. state: ok | fail | info | wait.
  function proofs(r, { onchain = true } = {}) {
    const out = [], a = r.anchor;
    if (!r.entry_id || !a) {
      out.push({ state: "info", icon: "question", title: "No signed record for this image",
        why: "No anchored signature matches these pixels. That does not make it fake: only images signed at capture can be proven." });
      return out;
    }
    // 1 · who signed
    if (r.anonymous) {
      const zk = r.zk || {}, ok = zk.proof_ok && zk.root_valid_at_anchor;
      out.push({ state: ok ? "ok" : "fail", icon: "mask", title: ok ? "Accredited device, anonymous" : "Anonymous proof rejected",
        val: ok ? "zero-knowledge proof" : zk.proof_ok ? "registry root not in force when anchored" : "proof invalid",
        why: "A zero-knowledge proof shows that one of the registry's accredited devices signed this image, without revealing which one." });
    } else {
      const ai = r.credential === "AI_GENERATOR", ok = r.signature_ok && r.credential;
      let why = ai ? "Signed by a generator holding an AI_GENERATOR credential: the image declares itself as AI-made."
        : r.passkey ? "Signed with a hardware passkey (Touch ID) that the registry attested for this accredited device."
        : "Signed by a device holding a CAPTURE_DEVICE credential, issued on the XRP Ledger by the registry.";
      if (r.signature_ok && !r.credential) why = "The signer held no valid credential when this image was anchored (never issued, or revoked before).";
      if (!r.signature_ok) why = "The signature does not match the anchored fingerprint.";
      if (r.credential_revoked_at) why += ` The device was revoked on ${when(r.credential_revoked_at)}, after this image was anchored, so the image stays valid.`;
      out.push({ state: ok ? "ok" : "fail", icon: ai ? "ai" : r.passkey ? "key" : "device",
        title: !r.signature_ok ? "Signature invalid" : !r.credential ? "No valid credential"
          : ai ? "Declared AI generator" : r.passkey ? "Accredited device · passkey" : "Accredited device",
        val: [r.credential, a.signer && short(a.signer)].filter(Boolean).join(" · "), why });
    }
    // 2 · post-quantum
    const pq = r.post_quantum;
    if (pq) {
      const ok = pq.signature_ok && pq.attested;
      out.push({ state: ok ? "ok" : "fail", icon: "shield", title: "Post-quantum",
        val: ok ? "Ed25519 + ML-DSA-87" : !pq.signature_ok ? "ML-DSA-87 signature invalid" : "key not attested by the registry",
        why: "Hybrid signature: classic Ed25519 plus ML-DSA-87 (FIPS 204), which a quantum computer cannot forge. The key is attested by the registry." });
    }
    // 3 · time window [T0, T1]
    const tw = r.time_window;
    if (tw && tw.ledger_index != null) {
      const n = Number(tw.ledger_index), led = onchain ? ext(`https://testnet.xrpl.org/ledgers/${n}`, `ledger #${n}`) : `ledger #${n}`;
      out.push(tw.t0_ok
        ? { state: "ok", icon: "clock", title: "Signed between", val: `${hms(tw.not_before)} → ${hms(tw.not_after)}`,
            why: `The signature contains the hash of XRPL ${led}, unknowable before it closed; the anchor closed ${Math.max(0, tw.not_after - tw.not_before)} s later.`, whyHtml: true }
        : { state: "fail", icon: "clock", title: "Signing time not confirmed", val: `ledger #${n}`,
            why: "The ledger named in the signature does not match the XRP Ledger: no lower bound on the signing time." });
    }
    // 4 · anchor
    const tx = onchain && a.explorer_url ? ext(a.explorer_url, `tx ${short(a.tx_hash)}`) : esc(`tx ${short(a.tx_hash)}`);
    const b = r.batch;
    out.push({ state: r.pending ? "wait" : "ok", icon: "chain",
      title: r.pending ? "Anchoring on XRPL" : onchain ? "Anchored on XRPL" : "Anchored (offline demo ledger)",
      valHtml: `${esc(when(a.timestamp))} · ${tx}${b ? ` · photo ${Number(b.index) + 1} of ${Number(b.size)} in one transaction` : ""}`,
      why: r.pending ? "Submitted to the XRP Ledger; this verdict is provisional until the transaction is validated, in a few seconds."
        : b ? "One transaction anchors a whole batch; this image's Merkle receipt proves it belongs to it. Nobody can edit or delete it."
        : "The image's fingerprint sits in a public XRP Ledger transaction that nobody can edit or delete." });
    // 5 · day and area proven in zero knowledge
    const claims = r.meta_claims || [];
    if (claims.length) {
      const ok = claims.every((c) => c.proof_ok);
      out.push({ state: ok ? "ok" : "fail", icon: "pin", title: ok ? "Day and area proven" : "Capture claims not proven",
        val: claims.map((c) => c.label).join(" · "),
        why: "Proven from the camera's metadata with a zero-knowledge proof: the exact time and GPS position stay private." });
    }
    // 6 · pixels, tile by tile
    const t = r.tiles;
    if (t && t.counts) {
      const c = t.counts, n = (c.exact || 0) + (c.robust || 0) + (c.changed || 0) + (c.redacted || 0), match = (c.exact || 0) + (c.robust || 0);
      if (c.changed) out.push({ state: "fail", icon: "tiles", title: "Edited areas", val: `${c.changed} of ${n} tiles changed`,
        why: "These tiles no longer match the fingerprint signed at capture; they are highlighted on the image." });
      else out.push({ state: "ok", icon: "tiles", title: c.robust ? "Content unchanged" : "Pixels unchanged",
        val: `${match} / ${n - (c.redacted || 0)} tiles match${c.robust ? " · recompressed" : ""}`,
        why: c.robust ? "Recompressed or resized, by a messaging app for instance, yet every tile still matches the fingerprint signed at capture."
          : "Every tile is identical to the fingerprint signed at capture; a single edited tile would show up." });
      if (c.redacted) out.push({ state: "info", icon: "redact", title: "Redacted on purpose", val: `${c.redacted} tiles`,
        why: "These tiles were blacked out after signing, e.g. to hide a face; the rest of the image stays verifiable." });
    }
    // 7 · version chain
    const hist = r.history || [];
    if (hist.length > 1) {
      const ok = hist.every((h) => h.verified);
      out.push({ state: ok ? "ok" : "fail", icon: "layers", title: ok ? "Signed version history" : "Version history broken",
        val: `${hist.length} versions`,
        why: "Each edit or development was signed and anchored in turn, back to the original capture." });
    }
    // 8 · C2PA, information only (security-review.md): anyone can write a manifest.
    if (r.c2pa) out.push({ state: "info", icon: "info", title: "C2PA manifest present",
      val: r.c2pa.matches_anchor ? "points to this same anchor" : "points to another anchor",
      why: "Content Credentials metadata, shown for information only: anyone can write one, so the verdict never relies on it."
        + (r.c2pa.signer_trusted ? "" : " Signed with a test certificate.") });
    else if (r.c2pa === null && r.found_by && r.found_by !== "tx_hash") out.push({ state: "info", icon: "info", title: "No C2PA manifest",
      val: "stripped when shared", why: "Messaging apps strip metadata such as C2PA. VeriPress recovered the provenance from the pixels themselves." });
    return out;
  }

  const MARK = { ok: "check", fail: "cross", wait: "hourglass" };

  function chain(r, opts) {
    return `<ol class="vp-chain">${proofs(r, opts).map((p) => `
      <li class="vp-${p.state}">
        <span class="vp-node">${icon(p.icon)}${MARK[p.state] ? `<span class="vp-mark">${icon(MARK[p.state])}</span>` : ""}</span>
        <div><b>${esc(p.title)}</b>${p.valHtml ? `<div class="vp-val">${p.valHtml}</div>` : p.val ? `<div class="vp-val">${esc(p.val)}</div>` : ""}
        <p class="vp-why">${p.whyHtml ? p.why : esc(p.why)}</p></div>
      </li>`).join("")}</ol>`;
  }

  window.VeriProof = { sprite, stamp, chain, proofs, icon, esc, short, safeUrl, when };
})();
