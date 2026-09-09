
const el = document.getElementById("list");
const searchEl = document.getElementById("search");
let tickets = [];
let current = "";
const SEVERITIES = ["low", "medium", "high", "critical"];
const CATEGORIES = ["parser", "save", "crash", "ui", "breeding",
                    "donations", "other"];

function esc(s) {
  return (s || "").replace(/[&<>"]/g, c => ({ "&": "&amp;", "<": "&lt;",
    ">": "&gt;", '"': "&quot;" }[c]));
}
function ago(ts) {
  const m = Math.round((Date.now() / 1000 - ts) / 60);
  if (m < 1) return "just now";
  if (m < 60) return m + "m ago";
  const h = Math.round(m / 60);
  return h < 24 ? h + "h ago" : Math.round(h / 24) + "d ago";
}

const ACT_ICONS = { created: "📝", status: "🔁", tags: "🏷️",
                     link: "🔗", comment: "💬", comment_removed: "🗑️",
                     auto_triage: "🤖" };
function actRow(ev, rid) {
  const ic = ACT_ICONS[ev.kind] || "•";
  const auto = (ev.kind === "auto_triage" || ev.role === "auto")
    ? ' <span class="autopill">auto</span>' : "";
  const who = esc(ev.actor || "system")
    + (ev.role && ev.role !== "auto"
      ? ` <span class="cmt-role">${esc(ev.role)}</span>` : "")
    + auto;
  const delBtn = (ev.kind === "comment" && !ev.deleted)
    ? `<button type="button" class="cmt-del" data-del-cmt="${ev.seq}" data-id="${rid}" title="remove comment">✕</button>`
    : "";
  return `<div class="cmt ${ev.kind === "comment_removed" ? "dim" : ""}">
    <div class="cmt-meta">${ic} ${who} · ${ago(ev.ts)} ${delBtn}</div>
    ${ev.text ? `<span class="ev-text">${esc(ev.text)}</span>` : ""}
    ${ev.body ? `<div class="cmt-body${ev.deleted ? " gone" : ""}">${esc(ev.body)}</div>` : ""}
  </div>`;
}

async function load() {
  const r = await fetch("/api/tickets");
  if (r.status === 401) { location.href = "/login"; return; }
  tickets = await r.json();
  const counts = { "": tickets.length };
  tickets.forEach(t => counts[t.status] = (counts[t.status] || 0) + 1);
  document.querySelectorAll("aside a[data-s]").forEach(a => {
    const c = document.getElementById("cnt-" + (a.dataset.s || "all"));
    if (c) c.textContent = counts[a.dataset.s] || 0;
  });
  render();
}

function visible() {
  let q = searchEl.value.trim().toLowerCase();
  if (q.startsWith("#")) q = q.slice(1).trim();   // #demo02 -> demo02
  return tickets.filter(t => {
    if (current && t.status !== current) return false;
    if (!q) return true;
    return [t.title, t.body, t.log, t.name, t.id, t.app_version]
      .join(" ").toLowerCase().includes(q);
  });
}

function render() {
  const rows = visible();
  document.getElementById("heading").textContent =
    (current ? current : "all") + " · " + rows.length + " report(s)";
  if (!rows.length) {
    el.innerHTML = '<div class="empty">No reports here 🐱</div>';
    return;
  }
  el.innerHTML = rows.map(card).join("");
}

function card(t) {
  const a = t.analysis || {};
  const relList = Array.isArray(t.related) ? t.related : [];
  const dupes = (a.dupe_ids || []).length
    ? '<div class="cause">⚠ likely dupe of: ' + a.dupe_ids.map(x => "#" + esc(x)).join(", ") + "</div>" : "";
  const sevCls = ["low","medium","high","critical"].includes(a.severity) ? a.severity : "";
  const sevSel = (a.severity || "medium");
  const catSel = (a.category || t.category || "other");
  const act = (t.activity || []);
  const preview = a.summary ? ""
    : (t.body ? `<div class="prev">${esc(t.body.replace(/\s+/g, " ")).slice(0, 200)}${t.body.length > 200 ? "…" : ""}</div>` : "");
  const rels = relList.length
    ? '<div class="rels">🔗 related: ' + relList.map(x => `<span class="chip" data-goto="${esc(x)}">#${esc(x)}</span>`).join(" ") + "</div>" : "";
  return `<div class="ticket">
    <div class="top">
      <span class="id">#${t.id}</span>
      <span class="title">${esc(t.title)}</span>
      ${a.severity ? `<span class="sev ${sevCls}">${esc(a.severity)}</span>` : ""}
      <span class="cat">${esc(a.category || t.category)}</span>
      <span class="status-tag">${t.status}</span>
    </div>
    <div class="meta">${ago(t.created)} · v${esc(t.app_version || "?")} · patch ${esc(t.game_patch || "?")}${t.name ? " · " + esc(t.name) : ""}</div>
    ${preview}
    ${a.summary ? `<div class="summary">${esc(a.summary)}</div>` : ""}
    ${a.likely_cause ? `<div class="cause">🔧 ${esc(a.likely_cause)}</div>` : ""}
    ${dupes}
    ${rels}
    <div class="tagsbar" data-tid="${t.id}">
      <label>Tags:</label>
      <select data-tag="severity" aria-label="Severity">
        ${SEVERITIES.map(s => `<option value="${s}" ${s === sevSel ? "selected" : ""}>${s}</option>`).join("")}
      </select>
      <select data-tag="category" aria-label="Category">
        ${CATEGORIES.map(c => `<option value="${c}" ${c === catSel ? "selected" : ""}>${c}</option>`).join("")}
      </select>
      <button type="button" data-save-tags>💾 Save tags</button>
      <span class="tagsaved" hidden>saved ✓</span>
    </div>
    <div class="cmts">
      <div class="cmt-head">🧾 Activity (${act.length}) — every action is logged, append-only</div>
      ${act.map(ev => actRow(ev, t.id)).join("")}
      <div class="cmt-add">
        <textarea data-id="${t.id}" rows="2" placeholder="Add a comment / note…"></textarea>
        <button type="button" data-add-cmt="${t.id}">Add</button>
      </div>
    </div>
    <button class="toggle" type="button">▸ show details</button>
    <div class="details" data-rid="${t.id}"></div>
    <div class="actions">
      <button data-act="triaged" data-id="${t.id}">Triaged</button>
      <button data-act="fixed" data-id="${t.id}">Fixed</button>
      <button data-act="duplicate" data-id="${t.id}">Duplicate</button>
      <button data-act="wontfix" data-id="${t.id}">Won't fix</button>
      <button data-link data-id="${t.id}">🔗 Link…</button>
      <button data-act="delete" data-id="${t.id}" class="del">Delete</button>
    </div>
  </div>`;
}

// event delegation: one listener handles toggles, links, tags, comments, actions
el.addEventListener("click", async (e) => {
  const addCmt = e.target.closest("[data-add-cmt]");
  if (addCmt) {
    const box = addCmt.parentElement.querySelector("textarea");
    const body = box.value.trim();
    if (!body) return;
    const r = await fetch(`/api/tickets/${addCmt.dataset.addCmt}/comments`, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: "body=" + encodeURIComponent(body),
    });
    if (!r.ok) alert("Comment failed: " + (await r.json()).error);
    load();
    return;
  }
  const delCmt = e.target.closest("[data-del-cmt]");
  if (delCmt) {
    const r = await fetch(`/api/tickets/${delCmt.dataset.id}/comments/delete`, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: "index=" + delCmt.dataset.delCmt,
    });
    if (!r.ok) alert("Delete failed: " + (await r.json()).error);
    load();
    return;
  }
  const saveTags = e.target.closest("[data-save-tags]");
  if (saveTags) {
    const bar = saveTags.closest(".tagsbar");
    const rid = bar.dataset.tid;
    const body = new URLSearchParams();
    body.set("severity", bar.querySelector('[data-tag="severity"]').value);
    body.set("category", bar.querySelector('[data-tag="category"]').value);
    const r = await fetch(`/api/tickets/${rid}/tags`, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: body.toString(),
    });
    if (!r.ok) alert("Save failed: " + (await r.json()).error);
    else {
      const ok = bar.querySelector(".tagsaved");
      ok.hidden = false;
      setTimeout(() => { ok.hidden = true; }, 1200);
    }
    load();
    return;
  }
  const toggle = e.target.closest("button.toggle");
  if (toggle) {
    const d = toggle.parentElement.querySelector(".details");
    const show = d.style.display !== "block";
    d.style.display = show ? "block" : "none";
    toggle.textContent = show ? "▾ hide details" : "▸ show details";
    if (show && !d.dataset.loaded) {
      d.textContent = "loading…";
      const r = await fetch(`/api/tickets/${d.dataset.rid}`);
      if (r.ok) {
        const det = await r.json();
        d.textContent = (det.body || "(no description)")
          + "\n" + "=".repeat(30) + "\n"
          + (det.log || "").slice(-6000);
        d.dataset.loaded = "1";
      } else d.textContent = "(could not load details)";
    }
    return;
  }
  const goto = e.target.closest("[data-goto]");
  if (goto) {
    current = "";
    document.querySelectorAll("aside a").forEach(x => x.classList.remove("active"));
    document.querySelector("aside a[data-s='']").classList.add("active");
    searchEl.value = "#" + goto.dataset.goto;
    render();
    return;
  }
  const link = e.target.closest("[data-link]");
  if (link) {
    const rid = link.dataset.id;
    const target = prompt("Link this ticket to the main ticket (#id)", "");
    if (!target) return;
    const r = await fetch(`/api/tickets/${rid}/link`, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: "target=" + encodeURIComponent(target.trim()),
    });
    if (!r.ok) alert("Link failed: " + (await r.json()).error);
    load();
    return;
  }
  const act = e.target.closest("[data-act]");
  if (act) {
    const rid = act.dataset.id;
    const a2 = act.dataset.act;
    await fetch(`/api/tickets/${rid}/${a2 === "delete" ? "delete" : "status"}`,
      a2 === "delete"
        ? { method: "POST" }
        : { method: "POST", headers: {"Content-Type": "application/x-www-form-urlencoded"},
            body: "status=" + a2 });
    load();
  }
});

document.querySelectorAll("aside a[data-s]").forEach(a => a.onclick = e => {
  e.preventDefault();
  document.querySelectorAll("aside a").forEach(x => x.classList.remove("active"));
  a.classList.add("active");
  current = a.dataset.s;
  render();
});
searchEl.addEventListener("input", render);
document.getElementById("tickets-trigger").addEventListener("click", (e) => {
  e.preventDefault();
  const sub = document.getElementById("tickets-sub");
  sub.classList.toggle("closed");
  document.getElementById("tickets-chev").textContent =
    sub.classList.contains("closed") ? "▸" : "▾";
});
load();
