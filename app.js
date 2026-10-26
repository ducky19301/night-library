/* Library PWA — decrypts the bundle client-side (AES-256-GCM, key from passphrase via PBKDF2-SHA256). */
"use strict";
const TZ = "America/Los_Angeles";
const S = { key: null, data: null, search: null, byId: {}, urls: {}, aById: {}, pdfjs: null };
const $ = (s, el = document) => el.querySelector(s);
const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const view = () => $("#view");

/* ---------------- crypto ---------------- */
const b64d = (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
const b64e = (u8) => { let s = ""; for (const b of u8) s += String.fromCharCode(b); return btoa(s); };
async function deriveRaw(pass, info) {
  const base = await crypto.subtle.importKey("raw", new TextEncoder().encode(pass), "PBKDF2", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits({ name: "PBKDF2", hash: "SHA-256", salt: b64d(info.salt), iterations: info.iter }, base, 256);
  return new Uint8Array(bits);
}
const importAes = (raw) => crypto.subtle.importKey("raw", raw, { name: "AES-GCM" }, false, ["encrypt", "decrypt"]);
async function decryptBuf(buf) {
  const u = new Uint8Array(buf);
  return crypto.subtle.decrypt({ name: "AES-GCM", iv: u.slice(0, 12) }, S.key, u.slice(12));
}
async function encryptText(txt) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv }, S.key, new TextEncoder().encode(txt)));
  const out = new Uint8Array(12 + ct.length); out.set(iv); out.set(ct, 12);
  return b64e(out);
}
async function gunzip(buf) {
  if (typeof DecompressionStream === "undefined") throw new Error("This browser is too old to open the library (needs iOS 16.4+ / recent Chrome).");
  return new Response(new Blob([buf]).stream().pipeThrough(new DecompressionStream("gzip"))).arrayBuffer();
}
async function fetchDec(path, gz) {
  const r = await fetch(path, { cache: "no-cache" });
  if (!r.ok) throw new Error("HTTP " + r.status + " for " + path);
  let b = await decryptBuf(await r.arrayBuffer());
  if (gz) b = await gunzip(b);
  return b;
}
const fetchJson = async (p) => JSON.parse(new TextDecoder().decode(await fetchDec(p, true)));

/* key persistence: non-extractable CryptoKey in IndexedDB (falls back to raw bits in localStorage) */
function idb() {
  return new Promise((res, rej) => {
    const r = indexedDB.open("library", 1);
    r.onupgradeneeded = () => r.result.createObjectStore("k");
    r.onsuccess = () => res(r.result); r.onerror = () => rej(r.error);
  });
}
async function idbDo(mode, fn) {
  const db = await idb();
  return new Promise((res, rej) => {
    const tx = db.transaction("k", mode); const st = tx.objectStore("k");
    const q = fn(st); tx.oncomplete = () => res(q && q.result); tx.onerror = () => rej(tx.error);
  });
}
async function saveKey(key, raw) {
  try { await idbDo("readwrite", (st) => st.put(key, "aes")); localStorage.removeItem("k_raw"); }
  catch (e) { localStorage.setItem("k_raw", b64e(raw)); }
}
async function loadKey() {
  try { const k = await idbDo("readonly", (st) => st.get("aes")); if (k) return k; } catch (e) {}
  const raw = localStorage.getItem("k_raw");
  return raw ? importAes(b64d(raw)) : null;
}
async function forgetKey() {
  try { await idbDo("readwrite", (st) => st.delete("aes")); } catch (e) {}
  localStorage.removeItem("k_raw"); sessionStorage.clear();
}

/* ---------------- helpers ---------------- */
const fmtDate = (iso, o = { month: "short", day: "numeric" }) => iso ? new Intl.DateTimeFormat("en-US", { timeZone: TZ, ...o }).format(new Date(iso)) : "";
const ptDay = (d) => new Intl.DateTimeFormat("en-CA", { timeZone: TZ, year: "numeric", month: "2-digit", day: "2-digit" }).format(d instanceof Date ? d : new Date(d));
const fmtSize = (n) => n < 1024 ? n + " B" : n < 1048576 ? (n / 1024).toFixed(0) + " KB" : (n / 1048576).toFixed(1) + " MB";
const A = (id) => S.aById[id] || { name: "Other", emoji: "•", color: "#888", grad: ["#555", "#777"] };
const pins = () => { try { return JSON.parse(localStorage.getItem("pins") || "[]"); } catch (e) { return []; } };
const isPinned = (id) => pins().includes(id);
function togglePin(id) {
  const p = pins(); const i = p.indexOf(id);
  i >= 0 ? p.splice(i, 1) : p.unshift(id);
  localStorage.setItem("pins", JSON.stringify(p)); return i < 0;
}
function icon(f) {
  if (f.mislabeled) return "⚠️";
  if (f.job) return f.job.kind === "Cover letter" ? "✉️" : "📄";
  return { pdf: "📕", md: "📝", text: "📃", csv: "📊", json: "🧾", html: "🌐", image: "🖼", audio: "🎧", office: "📃" }[f.kind] || "📦";
}
function toast(msg) {
  const t = $("#toast"); t.textContent = msg; t.hidden = false;
  clearTimeout(toast._t); toast._t = setTimeout(() => (t.hidden = true), 2400);
}
const sortRecent = (a, b) => (b.noted || "").localeCompare(a.noted || "") || (b.mtime || "").localeCompare(a.mtime || "");
function fileRow(f, right) {
  const r = right ?? (f.mislabeled ? `<span class="flag">Mislabeled</span>` : `<span class="r">${esc(fmtDate(f.noted || f.mtime))}</span>`);
  return `<a class="li" href="#file/${f.id}"><span class="l"><span class="cdot" style="background:${A(f.a).color}"></span>${icon(f)} <span class="t">${esc(f.title)}</span></span>${r}</a>`;
}

/* ---------------- unlock ---------------- */
function renderLock(msg = "") {
  $("#tabs").hidden = true;
  view().innerHTML = `<div class="lock">
    <div class="logo">✦</div>
    <div class="title"><span>Library</span></div>
    <div class="mut" style="margin-bottom:22px">Enter your passphrase to unlock. Everything stays encrypted until it reaches this phone.</div>
    <form id="unlock" autocomplete="off">
      <input class="field" id="pass" type="password" placeholder="passphrase" autocapitalize="none" autocorrect="off" spellcheck="false" enterkeyhint="go">
      <label class="row" style="border:0;padding:12px 2px"><span>Remember on this phone</span><span class="sw"><input type="checkbox" id="rem" checked><i></i></span></label>
      <div class="err" id="err">${esc(msg)}</div>
      <button class="btn pri" style="width:100%;padding:14px 0" id="go">Unlock</button>
    </form></div>`;
  $("#unlock").onsubmit = async (e) => {
    e.preventDefault();
    const pass = $("#pass").value.trim().toLowerCase().replace(/\s+/g, "-");
    if (!pass) return;
    $("#go").textContent = "Unlocking…"; $("#err").textContent = "";
    try {
      const info = await (await fetch("keyinfo.json", { cache: "no-cache" })).json();
      const raw = await deriveRaw(pass, info);
      S.key = await importAes(raw);
      await loadData();
      if ($("#rem").checked) await saveKey(S.key, raw);
      route();
    } catch (err) {
      S.key = null;
      $("#go").textContent = "Unlock";
      $("#err").textContent = err && err.name === "OperationError" ? "That passphrase didn't work. Try again." : "Couldn't unlock: " + (err.message || err);
    }
  };
}

async function loadData() {
  const d = await fetchJson("data.bin");
  S.data = d; S.byId = {}; S.aById = {};
  d.files.forEach((f) => (S.byId[f.id] = f));
  d.assistants.forEach((a) => (S.aById[a.id] = a));
  S.search = null;
  fetchJson("search.bin").then((s) => (S.search = s)).catch(() => {});
  syncSettingsIfStale();
}

/* ---------------- router ---------------- */
async function route() {
  if (!S.key) {
    S.key = await loadKey();
    if (!S.key) return renderLock();
    try { await loadData(); } catch (e) { S.key = null; return renderLock(e.name === "OperationError" ? "Saved key no longer matches — enter the passphrase again." : "Offline and nothing cached yet."); }
  }
  if (!S.data) { try { await loadData(); } catch (e) { return renderLock(); } }
  $("#tabs").hidden = false;
  const h = (location.hash || "#today").slice(1);
  const [name, arg] = h.split("/");
  const tab = { today: "today", needs: "today", recap: "today", library: "library", a: "library", file: "library", search: "search", settings: "settings" }[name] || "today";
  document.querySelectorAll("#tabs a").forEach((a) => a.classList.toggle("on", a.dataset.tab === tab));
  closeReader();
  window.scrollTo(0, 0);
  const fn = { today: renderToday, needs: renderNeeds, recap: renderRecap, library: renderLibrary, a: renderAssistant, file: renderFile, search: renderSearch, settings: renderSettings }[name] || renderToday;
  try { await fn(arg && decodeURIComponent(arg)); } catch (e) { console.error(e); view().innerHTML = `<div class="empty">Something went wrong: ${esc(e.message)}</div>`; }
}
window.addEventListener("hashchange", () => { S.navCount = (S.navCount || 0) + 1; route(); });

/* ---------------- Today ---------------- */
function greeting() {
  const h = +new Intl.DateTimeFormat("en-US", { timeZone: TZ, hour: "numeric", hour12: false }).format(new Date());
  const name = esc(S.data.owner || "");
  return h < 12 ? `Good morning, ${name} ☀️` : h < 18 ? `Good afternoon, ${name} 🌤` : `Good evening, ${name} 🌙`;
}
function summarize(files) {
  const jobs = files.filter((f) => f.job);
  if (jobs.length && jobs.length === files.length) {
    const cl = jobs.filter((f) => f.job.kind === "Cover letter").length, rs = jobs.length - cl;
    return [cl && `${cl} cover letter${cl > 1 ? "s" : ""}`, rs && `${rs} resume${rs > 1 ? "s" : ""}`].filter(Boolean).join(" + ");
  }
  const t = files.slice(0, 2).map((f) => f.title).join(", ");
  return files.length > 2 ? `${t} +${files.length - 2} more` : t;
}
function isSundayPT() { return new Intl.DateTimeFormat("en-US", { timeZone: TZ, weekday: "short" }).format(new Date()) === "Sun"; }

function renderToday() {
  const d = S.data, run = d.run;
  const added = d.today.added.map((i) => S.byId[i]).filter(Boolean);
  const byA = {}; added.forEach((f) => (byA[f.a] = byA[f.a] || []).push(f));
  // donut segments per assistant
  let acc = 0; const segs = [];
  d.assistants.forEach((a) => { const n = (byA[a.id] || []).length; if (n) { const s = (acc / added.length) * 100; acc += n; segs.push(`${a.color} ${s}% ${(acc / added.length) * 100}%`); } });
  const donut = segs.length ? `conic-gradient(${segs.join(",")})` : "conic-gradient(#3a3450 0 100%)";
  const runDay = ptDay(run.run_at), today = ptDay(new Date());
  const title = runDay === today ? "Today" : "Latest update";
  const needs = d.needs || [];
  const recapCard = `<a class="card gl" href="#recap" style="display:flex;align-items:center;gap:10px"><span style="font-size:20px">🗓</span><span style="flex:1"><b>${isSundayPT() ? "Sunday recap is ready" : "Weekly recap"}</b><br><span class="mut small">${isSundayPT() ? "Your week in one place" : "See this week so far"}</span></span><span class="mut">›</span></a>`;
  view().innerHTML = `
  <div class="top"><div class="hello">${greeting()}</div><div class="h1">${title}</div>
    <div class="hello" style="margin-top:3px">Update from ${esc(fmtDate(run.run_at, { weekday: "short", month: "short", day: "numeric", hour: "numeric", minute: "2-digit" }))} PT</div></div>
  ${isSundayPT() ? recapCard : ""}
  <div class="gl ring"><div class="donut" style="background:${donut}"><div>${run.new}<small>NEW</small></div></div>
    <div class="stat"><b>${run.total}</b> files tracked<br><b>${run.refreshed}</b> refreshed<br>
    ${d.streak && d.streak.days >= 2 ? `🔥 ${d.streak.days} days in a row with new files` : `<span class="mut">${d.assistants.length} assistants</span>`}</div></div>
  ${needs.length ? `<a class="card urg" href="#needs">⚡ Needs you · ${needs.length} application${needs.length > 1 ? "s" : ""}<div class="chips">${needs.map((n) => `<span>${esc(n.company)}</span>`).join("")}</div></a>` : ""}
  <div class="card gl">${d.assistants.map((a) => {
    const fs = byA[a.id] || [];
    return `<button class="bot" data-a="${a.id}" ${fs.length ? "" : "disabled"}><div class="dot" style="background:${a.color}">${a.emoji}</div>
      <div class="nm">${esc(a.name)}<small>${fs.length ? esc(summarize(fs)) : "Nothing new today"}</small></div>
      <span class="badge ${fs.length ? "" : "zero"}">${fs.length}</span></button>
      <div class="sub" id="sub-${a.id}" hidden>${fs.map((f) => fileRow(f)).join("")}</div>`;
  }).join("")}</div>
  ${d.today.refreshed.length ? `<div class="sec">🔄 Refreshed</div><div class="card gl" style="padding:4px 14px">${d.today.refreshed.map((r) => {
    const f = S.byId[r.id]; return f ? `<a class="li" href="#file/${f.id}"><span class="l"><span class="cdot" style="background:${A(f.a).color}"></span><span>${esc(f.title)}<small>${esc(r.desc)}</small></span></span></a>` : "";
  }).join("")}</div>` : ""}
  ${isSundayPT() ? "" : recapCard}`;
  view().querySelectorAll(".bot[data-a]").forEach((b) => (b.onclick = () => { const s = $("#sub-" + b.dataset.a); s.hidden = !s.hidden; }));
}

/* ---------------- Needs you ---------------- */
function renderNeeds() {
  const needs = S.data.needs || [];
  view().innerHTML = `<div class="top"><a class="back" href="#today">‹ Today</a><div class="h1">Needs you</div>
    <div class="hello">${needs.length} application${needs.length === 1 ? "" : "s"} from this update are waiting on you</div></div>
    <div class="card gl">${needs.length ? needs.map((n) => `<div class="needitem"><div class="co">${esc(n.full_company || n.company)}</div>
      <div class="ro">${esc(n.role || "")} · ${esc(n.id)}</div><div class="nx">${esc(n.next || "")}</div>
      ${n.notes ? `<div class="mut small" style="margin-top:6px">${esc(n.notes)}</div>` : ""}
      <div class="chips">${(n.files || []).map((i) => S.byId[i]).filter(Boolean).map((f) => `<a href="#file/${f.id}">${icon(f)} ${esc(f.job ? f.job.kind : f.title)}</a>`).join("")}</div></div>`).join("") : `<div class="empty">Nothing is waiting on you. 🎉</div>`}</div>
    <div class="card gl small mut">The job tracker lists ${S.data.open_blocked} blocked items in total (older ones included). ${trackerLink()}</div>`;
}
function trackerLink() {
  const t = S.byId[S.data.tracker_id];
  return t ? `<a href="#file/${t.id}" style="color:#ffb0ec">Open the applications tracker ›</a>` : "";
}

/* ---------------- Weekly recap ---------------- */
function weekWindow() {
  // Mon–Sun week (PT). On Sunday: this week. Otherwise: show last full week + this week so far.
  const todayStr = ptDay(new Date());
  const t = new Date(todayStr + "T12:00:00Z");
  const dow = (t.getUTCDay() + 6) % 7; // Mon=0
  const mon = new Date(t); mon.setUTCDate(t.getUTCDate() - dow);
  const days = (start, n) => Array.from({ length: n }, (_, i) => { const x = new Date(start); x.setUTCDate(start.getUTCDate() + i); return x.toISOString().slice(0, 10); });
  const lastMon = new Date(mon); lastMon.setUTCDate(mon.getUTCDate() - 7);
  return { thisWeek: days(mon, 7), upTo: todayStr, lastWeek: days(lastMon, 7), sunday: dow === 6 };
}
function recapBlock(days, label, upTo) {
  const set = new Set(days);
  const fs = S.data.files.filter((f) => f.noted && set.has(ptDay(f.noted))).sort(sortRecent);
  const byA = {}; fs.forEach((f) => (byA[f.a] = (byA[f.a] || 0) + 1));
  const max = Math.max(1, ...Object.values(byA));
  const busiest = Object.entries(byA).sort((a, b) => b[1] - a[1])[0];
  const perDay = days.map((d) => fs.filter((f) => ptDay(f.noted) === d).length);
  const dmax = Math.max(1, ...perDay);
  const wd = (d) => new Date(d + "T12:00:00Z").toLocaleDateString("en-US", { weekday: "narrow", timeZone: "UTC" });
  return `<div class="sec">${esc(label)} <span>${esc(fmtDay(days[0]))} – ${esc(fmtDay(upTo && upTo < days[days.length - 1] ? upTo : days[days.length - 1]))}</span></div>
  <div class="card gl"><div style="font-size:15px"><b>${fs.length}</b> files new or updated${busiest ? ` · <b>${esc(A(busiest[0]).name)}</b> was busiest` : ""}</div>
    <div class="bars">${S.data.assistants.map((a) => `<div class="bar"><span class="lab">${a.emoji} ${esc(a.name)}</span><span class="trk"><span class="fill" style="display:block;width:${((byA[a.id] || 0) / max) * 100}%;background:${a.color}"></span></span><span class="n">${byA[a.id] || 0}</span></div>`).join("")}</div>
    <div class="days">${days.map((d, i) => `<div style="${upTo && d > upTo ? "opacity:.35" : ""}"><b>${perDay[i] || ""}</b><i style="height:${(perDay[i] / dmax) * 52}px"></i>${wd(d)}</div>`).join("")}</div></div>
  ${fs.length ? `<div class="card gl" style="padding:4px 14px">${fs.slice(0, 40).map((f) => fileRow(f)).join("")}${fs.length > 40 ? `<div class="empty">+${fs.length - 40} more</div>` : ""}</div>` : ""}`;
}
const fmtDay = (d) => new Date(d + "T12:00:00Z").toLocaleDateString("en-US", { month: "short", day: "numeric", timeZone: "UTC" });
function renderRecap() {
  const w = weekWindow();
  view().innerHTML = `<div class="top"><a class="back" href="#today">‹ Today</a><div class="h1">${w.sunday ? "Sunday recap" : "Weekly recap"}</div>
    <div class="hello">One summary instead of lots of small pings</div></div>
    ${recapBlock(w.thisWeek, w.sunday ? "This week" : "This week so far", w.upTo)}
    ${w.sunday ? "" : recapBlock(w.lastWeek, "Last week")}
    <div class="card small mut">Counts use the date the tracker last noted each file, so a refreshed file counts in the week it was refreshed.</div>`;
}

/* ---------------- Library ---------------- */
function renderLibrary() {
  const d = S.data;
  const p = pins().map((i) => S.byId[i]).filter(Boolean);
  const recent = [...d.files].sort(sortRecent).slice(0, 8);
  const mis = d.files.filter((f) => f.mislabeled);
  view().innerHTML = `<div class="top"><div class="hello">${d.files.length} files · ${d.assistants.length} assistants</div><div class="h1">Library</div></div>
  <a class="gl search" href="#search">🔍 <span class="mut" style="flex:1">Search names, text, people…</span></a>
  <div class="grid">${d.assistants.map((a) => `<a class="tile" href="#a/${a.id}" style="background:linear-gradient(135deg,${a.grad[0]},${a.grad[1]})">${a.emoji} ${esc(a.name)}<small>${a.count} files</small></a>`).join("")}
    <a class="tile pin" href="#a/pinned">⭐ Pinned<small>${p.length} file${p.length === 1 ? "" : "s"}</small></a></div>
  ${p.length ? `<div class="sec">Pinned</div><div class="card gl" style="padding:4px 14px">${p.slice(0, 6).map((f) => fileRow(f, `<span class="r">⭐</span>`)).join("")}</div>` : ""}
  <div class="sec">Recent</div><div class="card gl" style="padding:4px 14px">${recent.map((f) => fileRow(f)).join("")}</div>
  ${mis.length ? `<div class="sec">Needs review</div><div class="card gl" style="padding:4px 14px">${mis.map((f) => fileRow(f)).join("")}</div>` : ""}`;
}
function renderAssistant(id) {
  let fs, title, sub;
  if (id === "pinned") { fs = pins().map((i) => S.byId[i]).filter(Boolean); title = "⭐ Pinned"; sub = "Pins are saved on this phone"; }
  else { const a = A(id); fs = S.data.files.filter((f) => f.a === id).sort(sortRecent); title = `${a.emoji} ${a.name}`; sub = `${fs.length} files`; }
  const groups = {};
  fs.forEach((f) => (groups[id === "pinned" ? "Pinned" : (f.job ? "Applications" : (f.section || "Other").replace(" (new)", ""))] ||= []).push(f));
  view().innerHTML = `<div class="top"><a class="back" href="#library">‹ Library</a><div class="h1">${esc(title)}</div><div class="hello">${esc(sub)}</div></div>
  ${fs.length ? Object.entries(groups).map(([g, l]) => `<div class="sec">${esc(g)} <span>${l.length}</span></div><div class="card gl" style="padding:4px 14px">${l.map((f) => fileRow(f)).join("")}</div>`).join("")
    : `<div class="empty">Nothing pinned yet. Open any file and tap ⭐ Pin.</div>`}`;
}

/* ---------------- Search ---------------- */
function renderSearch() {
  const q0 = sessionStorage.getItem("q") || "", f0 = sessionStorage.getItem("qf") || "all";
  view().innerHTML = `<div class="top"><div class="h1">Search</div></div>
    <label class="gl search">🔍 <input id="q" type="search" placeholder="Search names, text, people…" value="${esc(q0)}" autocapitalize="none" enterkeyhint="search"></label>
    <div class="chips" style="margin:0 16px 4px" id="qf">${[["all", "All"], ...S.data.assistants.map((a) => [a.id, a.emoji + " " + a.name]), ["pinned", "⭐ Pinned"], ["mis", "⚠️ Mislabeled"]]
      .map(([k, l]) => `<button class="chip ${k === f0 ? "on" : ""}" data-k="${k}">${esc(l)}</button>`).join("")}</div>
    <div id="res"></div>`;
  const run = () => {
    const q = $("#q").value.trim().toLowerCase(), flt = sessionStorage.getItem("qf") || "all";
    sessionStorage.setItem("q", $("#q").value);
    let fs = S.data.files;
    if (flt === "pinned") fs = fs.filter((f) => isPinned(f.id));
    else if (flt === "mis") fs = fs.filter((f) => f.mislabeled);
    else if (flt !== "all") fs = fs.filter((f) => f.a === flt);
    let res;
    if (!q) res = [...fs].sort(sortRecent).slice(0, 60).map((f) => ({ f }));
    else {
      const terms = q.split(/\s+/);
      res = fs.map((f) => {
        const meta = `${f.title} ${f.name} ${f.desc} ${f.bot} ${f.section} ${f.rel} ${A(f.a).name} ${f.job ? f.job.company + " " + f.job.role : ""}`.toLowerCase();
        const body = (S.search && S.search[f.id] || "").toLowerCase();
        let score = 0, snip = "";
        for (const t of terms) {
          if (meta.includes(t)) score += 10;
          else { const i = body.indexOf(t); if (i >= 0) { score += 3; if (!snip) snip = body.slice(Math.max(0, i - 50), i + 70).replace(/\s+/g, " "); } else return null; }
        }
        return { f, score, snip };
      }).filter(Boolean).sort((a, b) => b.score - a.score || sortRecent(a.f, b.f)).slice(0, 80);
    }
    $("#res").innerHTML = `<div class="sec">${q ? `${res.length} result${res.length === 1 ? "" : "s"}` : "Recent"}${q && !S.search ? " <span>(text index loading…)</span>" : ""}</div>` +
      (res.length ? `<div class="card gl" style="padding:4px 14px">${res.map(({ f, snip }) => `<a class="li" href="#file/${f.id}"><span class="l"><span class="cdot" style="background:${A(f.a).color}"></span><span style="min-width:0">${icon(f)} ${esc(f.title)}<small>${snip ? "…" + esc(snip) + "…" : esc(f.desc || f.name)}</small></span></span>${f.mislabeled ? `<span class="flag">Mislabeled</span>` : ""}</a>`).join("")}</div>` : `<div class="empty">No matches.</div>`);
  };
  $("#q").oninput = run;
  $("#qf").onclick = (e) => { const b = e.target.closest("button"); if (!b) return; sessionStorage.setItem("qf", b.dataset.k); $("#qf").querySelectorAll("button").forEach((x) => x.classList.toggle("on", x === b)); run(); };
  run();
  if (!q0) setTimeout(() => $("#q") && $("#q").focus({ preventScroll: true }), 50);
}

/* ---------------- File view ---------------- */
async function fileBlob(f, which = "raw") {
  const src = which === "preview" && f.preview ? f.preview : f;
  const k = f.id + which;
  if (S.urls[k]) return S.urls[k];
  const buf = await fetchDec(src.b, src.gz);
  const mime = which === "preview" ? "application/pdf" : f.mime;
  const blob = new Blob([buf], { type: mime });
  S.urls[k] = { blob, buf, url: URL.createObjectURL(blob), mime };
  return S.urls[k];
}
function statusCard(f) {
  const st = f.job && f.job.status; if (!st) return "";
  if (st.state === "blocked") return `<a class="card warn" href="#needs" style="display:block"><b>⚡ Blocked · waiting on you</b> <span class="small">(${esc(st.id)})</span><div style="margin-top:4px">${esc(st.next)}</div></a>`;
  return `<div class="card gl small"><b>Tracker ${esc(st.id)}</b> · ${esc(st.state)}${st.date ? " " + esc(st.date) : ""}<div class="mut" style="margin-top:3px">${esc(st.company)} · ${esc(st.role)}${st.salary && st.salary !== "unknown" ? " · " + esc(st.salary) : ""}${st.next ? " · Next: " + esc(st.next) : ""}</div></div>`;
}
async function renderFile(id) {
  const f = S.byId[id];
  if (!f) { view().innerHTML = `<div class="empty">That file isn't in the library any more.</div>`; return; }
  const a = A(f.a);
  const links = (f.links || []).map((i) => S.byId[i]).filter(Boolean);
  view().innerHTML = `<div class="top"><a class="back" href="#library" id="bk">‹ Back</a>
    <div class="hello">${a.emoji} ${esc(a.name)} · ${esc(fmtDate(f.noted || f.mtime))}</div><div class="h1 sm">${esc(f.title)}</div></div>
    ${f.mislabeled ? `<div class="card warn">⚠️ ${esc(f.mislabeled)}</div>` : ""}
    ${statusCard(f)}
    <div id="pv" class="paper clip"><div class="spinner"></div></div>
    <div class="btns"><button class="btn pri" id="open">Open full</button><button class="btn gl" id="share">Share</button><button class="btn gl" id="pin">${isPinned(f.id) ? "★ Pinned" : "⭐ Pin"}</button></div>
    ${links.length ? `<div class="card gl small"><b>Linked files</b><div class="chips">${links.map((l) => `<a href="#file/${l.id}"><span class="cdot" style="background:${A(l.a).color};margin:0"></span>${esc(l.title)}</a>`).join("")}</div></div>` : ""}
    <button class="card gl small" id="ask" style="display:block;width:calc(100% - 32px);text-align:left"><b>Ask ${esc(a.name)} about this file</b><div class="mut" style="margin-top:4px">"Make this sound warmer…" — copies a ready-to-paste note</div></button>
    <div class="card gl"><div class="kv"><span>File</span><span>${esc(f.name)}</span><span>Size</span><span>${fmtSize(f.size)}</span><span>From</span><span>${esc(f.bot)} → ${esc(a.name)}</span>
      <span>Section</span><span>${esc(f.section)}</span><span>Location</span><span>${esc(f.rel)}</span>${f.desc ? `<span>About</span><span>${esc(f.desc)}</span>` : ""}</div></div>`;
  $("#bk").onclick = (e) => { if (history.length > 1 && S.navCount > 1) { e.preventDefault(); history.back(); } };
  $("#pin").onclick = () => { const on = togglePin(f.id); $("#pin").textContent = on ? "★ Pinned" : "⭐ Pin"; toast(on ? "Pinned to the top of your Library" : "Unpinned"); };
  $("#open").onclick = () => openReader(f);
  $("#share").onclick = () => shareFile(f);
  $("#ask").onclick = () => askSheet(f);
  try { await renderPreview(f, $("#pv"), false); } catch (e) { $("#pv").innerHTML = `<div class="empty" style="color:#555">Preview unavailable (${esc(e.message)}). Use Open full or Share.</div>`; }
}

async function renderPreview(f, el, full) {
  const kind = f.preview ? "pdf" : f.kind;
  const b = await fileBlob(f, f.preview ? "preview" : "raw");
  const text = () => new TextDecoder().decode(b.buf);
  el.classList.remove("pad");
  if (kind === "pdf") return renderPdf(b.buf, el, full);
  if (kind === "md") { el.classList.add("pad"); el.innerHTML = DOMPurify.sanitize(marked.parse(text())); el.querySelectorAll("a").forEach((x) => { x.target = "_blank"; x.rel = "noopener noreferrer"; }); return; }
  if (kind === "text" || kind === "json") { let t = text(); if (kind === "json") { try { t = JSON.stringify(JSON.parse(t), null, 2); } catch (e) {} } el.innerHTML = `<pre class="raw">${esc(t.length > 400000 ? t.slice(0, 400000) + "\n…(truncated, use Share to get the full file)" : t)}</pre>`; return; }
  if (kind === "csv") { el.classList.add("pad"); el.innerHTML = csvTable(text()); return; }
  if (kind === "html") { const fr = document.createElement("iframe"); fr.className = "frame"; fr.setAttribute("sandbox", "allow-scripts allow-popups allow-forms"); fr.srcdoc = text(); el.innerHTML = ""; el.appendChild(fr); return; }
  if (kind === "image") { el.innerHTML = `<img src="${b.url}" alt="" style="display:block;width:100%">`; return; }
  if (kind === "audio") { el.classList.add("pad"); el.innerHTML = `<div style="text-align:center;font-size:40px">🎧</div><audio controls preload="metadata" src="${b.url}" style="width:100%;margin-top:10px"></audio>`; return; }
  el.classList.add("pad"); el.innerHTML = `<div class="empty" style="color:#555">No preview for .${esc(f.ext)} files. Use Share to open it in another app.</div>`;
}
function csvTable(t) {
  const rows = []; let row = [], cell = "", q = false;
  for (let i = 0; i < t.length; i++) {
    const c = t[i];
    if (q) { if (c === '"' && t[i + 1] === '"') { cell += '"'; i++; } else if (c === '"') q = false; else cell += c; }
    else if (c === '"') q = true; else if (c === ",") { row.push(cell); cell = ""; } else if (c === "\n") { row.push(cell); rows.push(row); row = []; cell = ""; } else if (c !== "\r") cell += c;
  }
  if (cell || row.length) { row.push(cell); rows.push(row); }
  return `<table>${rows.map((r, i) => `<tr>${r.map((c) => i ? `<td>${esc(c)}</td>` : `<th>${esc(c)}</th>`).join("")}</tr>`).join("")}</table>`;
}
async function pdfLib() {
  if (!S.pdfjs) { S.pdfjs = await import("./vendor/pdf.min.mjs"); S.pdfjs.GlobalWorkerOptions.workerSrc = "./vendor/pdf.worker.min.mjs"; }
  return S.pdfjs;
}
async function renderPdf(buf, el, full) {
  const pdfjs = await pdfLib();
  const doc = await pdfjs.getDocument({ data: new Uint8Array(buf.slice(0)), standardFontDataUrl: "./vendor/standard_fonts/", isEvalSupported: false }).promise;
  el.innerHTML = `<div class="pdfpages"></div>`;
  const wrap = el.firstChild;
  const first = await doc.getPage(1); const vp1 = first.getViewport({ scale: 1 });
  const io = new IntersectionObserver((ents) => ents.forEach((en) => { if (en.isIntersecting) { io.unobserve(en.target); draw(en.target); } }), { root: full ? el.closest(".body") : el, rootMargin: "800px 0px" });
  async function draw(div) {
    const n = +div.dataset.n; const page = n === 1 ? first : await doc.getPage(n);
    const w = div.clientWidth || wrap.clientWidth - 20; const dpr = Math.min(window.devicePixelRatio || 1, 3) * (full ? 1.5 : 1);
    const vp = page.getViewport({ scale: (w / page.getViewport({ scale: 1 }).width) * dpr });
    const c = document.createElement("canvas"); c.width = vp.width; c.height = vp.height;
    await page.render({ canvasContext: c.getContext("2d"), viewport: vp }).promise;
    div.style.aspectRatio = ""; div.prepend(c);
  }
  for (let n = 1; n <= doc.numPages; n++) {
    const div = document.createElement("div"); div.className = "pg"; div.dataset.n = n;
    div.style.aspectRatio = `${vp1.width} / ${vp1.height}`;
    div.innerHTML = `<span class="pn">${n} / ${doc.numPages}</span>`;
    wrap.appendChild(div); io.observe(div);
  }
}
async function openReader(f) {
  closeReader();
  const r = document.createElement("div"); r.className = "reader"; r.id = "reader";
  r.innerHTML = `<div class="bar2"><button class="back" id="rx">‹ Done</button><b>${esc(f.title)}</b><button class="chip" id="rs">Share</button></div><div class="body"><div class="paper"><div class="spinner"></div></div></div>`;
  document.body.appendChild(r); document.body.style.overflow = "hidden";
  $("#rx").onclick = closeReader; $("#rs").onclick = () => shareFile(f);
  const el = r.querySelector(".paper");
  if (f.kind === "html" && !f.preview) el.style.height = "100%";
  try { await renderPreview(f, el, true); } catch (e) { el.innerHTML = `<div class="empty" style="color:#555">${esc(e.message)}</div>`; }
}
function closeReader() { const r = $("#reader"); if (r) { r.remove(); document.body.style.overflow = ""; } }
async function shareFile(f) {
  try {
    const b = await fileBlob(f);
    const file = new File([b.blob], f.name, { type: f.mime });
    if (navigator.canShare && navigator.canShare({ files: [file] })) { await navigator.share({ files: [file], title: f.title }); return; }
    const a = document.createElement("a"); a.href = b.url; a.download = f.name; document.body.appendChild(a); a.click(); a.remove();
    toast("Downloaded " + f.name);
  } catch (e) { if (e.name !== "AbortError") toast("Couldn't share: " + e.message); }
}
function askSheet(f) {
  const a = A(f.a);
  const txt = `Hi ${a.name}, about "${f.name}" (library: ${f.rel}): `;
  const sh = $("#sheet");
  sh.innerHTML = `<div><b>Ask ${esc(a.name)} about this file</b><div class="mut small" style="margin:4px 0 10px">Type your request, copy it, and paste it into your ${esc(a.name)} chat.</div>
    <textarea id="askt">${esc(txt)}</textarea><div class="btns" style="margin:12px 0 0"><button class="btn gl" id="askx">Cancel</button><button class="btn pri" id="askc">Copy note</button></div></div>`;
  sh.hidden = false;
  const ta = $("#askt"); ta.focus(); ta.setSelectionRange(ta.value.length, ta.value.length);
  $("#askx").onclick = () => (sh.hidden = true);
  sh.onclick = (e) => { if (e.target === sh) sh.hidden = true; };
  $("#askc").onclick = async () => {
    try { await navigator.clipboard.writeText(ta.value); toast(`Copied — paste it into ${a.name}`); sh.hidden = true; }
    catch (e) { ta.select(); toast("Select all and copy"); }
  };
}

/* ---------------- Settings (synced to the box through an encrypted ntfy message) ---------------- */
const DEFAULTS = { enabled: true, quiet: { on: true, start: "21:00", end: "08:00" } };
function getSettings() { try { return { ...DEFAULTS, ...JSON.parse(localStorage.getItem("settings") || "{}") }; } catch (e) { return { ...DEFAULTS }; } }
async function pushSettings(s) {
  const n = S.data.ntfy;
  const body = await encryptText(JSON.stringify(s));
  const r = await fetch(`${n.server}/${n.settings_topic}`, { method: "POST", body });
  if (!r.ok) throw new Error("ntfy " + r.status);
  localStorage.setItem("settings_pushed", String(Date.now()));
}
function boxHasCurrent(s) { const b = S.data.box_settings; return b && b.updated_at && s.updated_at && b.updated_at >= s.updated_at; }
function syncSettingsIfStale() {
  const s = getSettings();
  if (!s.updated_at || boxHasCurrent(s)) return;
  if (Date.now() - +(localStorage.getItem("settings_pushed") || 0) < 6 * 3600e3) return;
  pushSettings(s).catch(() => {});
}
function renderSettings() {
  const s = getSettings(), n = S.data.ntfy, b = S.data.box_settings;
  const syncLine = !s.updated_at ? "Using defaults (the box uses the same defaults)." : boxHasCurrent(s) ? `<span class="ok">✓ The update routine is using these settings.</span>` : "Saved on this phone and sent to the update routine; it applies them at its next run.";
  view().innerHTML = `<div class="top"><div class="h1">Settings</div></div>
  <div class="sec">Notifications</div>
  <div class="card gl">
    <label class="row"><span>New-file notifications<small>One ping after each daily library update with new files</small></span><span class="sw"><input type="checkbox" id="en" ${s.enabled ? "checked" : ""}><i></i></span></label>
    <label class="row"><span>Quiet hours<small>Pings that land in this window wait until it ends</small></span><span class="sw"><input type="checkbox" id="qh" ${s.quiet.on ? "checked" : ""}><i></i></span></label>
    <div class="row" id="qrow" ${s.quiet.on ? "" : "hidden"}><span>From <input type="time" id="qs" value="${esc(s.quiet.start)}"></span><span>to <input type="time" id="qe" value="${esc(s.quiet.end)}"></span></div>
    <div class="small mut" id="sync" style="padding-top:8px">${syncLine}</div>
  </div>
  <div class="sec">Get pings on this phone</div>
  <div class="card gl small" style="line-height:1.55">
    1. Install the free <b>ntfy</b> app (App Store or Google Play).<br>2. Tap <b>+</b>, subscribe to this topic on <b>ntfy.sh</b>:
    <div class="chips"><button class="chip" id="cp">📋 ${esc(n.topic)}</button></div>
    <div class="mut" style="margin-top:6px">Treat the topic like a password: anyone who knows it can read the ping text (counts and short titles, never file contents).</div>
  </div>
  <div class="sec">This phone</div>
  <div class="card gl">
    <div class="row"><span>Library data<small>Update ${esc(fmtDate(S.data.run.run_at, { month: "short", day: "numeric", hour: "numeric", minute: "2-digit" }))} PT · built ${esc(fmtDate(S.data.generated_at, { month: "short", day: "numeric", hour: "numeric", minute: "2-digit" }))} PT</small></span><button class="chip" id="rf">Refresh</button></div>
    <div class="row"><span>Pinned files<small>${pins().length} saved on this phone</small></span></div>
    <div class="row"><span>Lock the library<small>Forget the passphrase on this phone</small></span><button class="chip" id="lk">Lock</button></div>
  </div>
  <div class="card small mut">Files are encrypted (AES-256-GCM) before they leave the library box; only this phone, with your passphrase, can open them.</div>`;
  const save = async () => {
    const ns = { enabled: $("#en").checked, quiet: { on: $("#qh").checked, start: $("#qs").value || "21:00", end: $("#qe").value || "08:00" }, updated_at: new Date().toISOString() };
    localStorage.setItem("settings", JSON.stringify(ns));
    $("#qrow").hidden = !ns.quiet.on;
    $("#sync").textContent = "Saving…";
    try { await pushSettings(ns); $("#sync").textContent = "Saved on this phone and sent to the update routine; it applies them at its next run."; }
    catch (e) { $("#sync").textContent = "Saved on this phone. Couldn't reach the sync service; it will retry next time you open the app."; localStorage.removeItem("settings_pushed"); }
  };
  ["en", "qh", "qs", "qe"].forEach((id) => ($("#" + id).onchange = save));
  $("#cp").onclick = async () => { try { await navigator.clipboard.writeText(n.topic); toast("Topic copied"); } catch (e) { toast(n.topic); } };
  $("#rf").onclick = async () => { $("#rf").textContent = "…"; try { await loadData(); toast("Library is up to date"); renderSettings(); } catch (e) { toast("Offline — showing saved copy"); $("#rf").textContent = "Refresh"; } };
  $("#lk").onclick = async () => { await forgetKey(); S.key = null; S.data = null; location.hash = "#today"; renderLock(); };
}

/* ---------------- boot ---------------- */
if ("serviceWorker" in navigator) {
  navigator.serviceWorker.register("sw.js").then((reg) => {
    document.addEventListener("visibilitychange", () => { if (document.visibilityState === "visible") { reg.update().catch(() => {}); } });
  }).catch(() => {});
}
document.addEventListener("visibilitychange", async () => {
  if (document.visibilityState === "visible" && S.key && S.data) {
    const before = S.data.generated_at;
    try { await loadData(); if (S.data.generated_at !== before) route(); } catch (e) {}
  }
});
window.addEventListener("DOMContentLoaded", route);
