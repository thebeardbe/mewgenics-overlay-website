
function escH(s) { return (s || "").replace(/[&<>]/g,
  c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;" }[c])); }
function escA(s) { return (s || "").replace(/[&<>"']/g,
  c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c])); }

async function load() {
  const r = await fetch("/api/users");
  if (r.status === 401) { location.href = "/login"; return; }
  if (r.status === 403) { location.href = "/admin"; return; }
  const users = await r.json();
  document.getElementById("list").innerHTML = users.map(u => {
    const canChange = u.role !== "owner";
    const statusTag = `<span class="tag ${u.status}">${u.status}</span>`;
    const roleTag = u.role === "owner"
      ? '<span class="tag owner">owner</span>' : "";
    let actions = "";
    if (canChange) {
      actions = `<span class="actions">
        ${u.status !== "approved" ? `<button class="btn ok" data-id="${u.id}" data-s="approved">Approve</button>` : ""}
        ${u.status === "approved" ? `<button class="btn" data-id="${u.id}" data-s="pending">Revoke</button>` : ""}
        ${u.status !== "denied" ? `<button class="btn no" data-id="${u.id}" data-s="denied">Deny</button>` : ""}
        <button class="btn no" data-id="${u.id}" data-del="1">Remove</button>
      </span>`;
    }
    const meta = u.github_login ? `github: ${u.github_login}` : "local";
    const shown = u.display_name || u.username;
    return `<div class="row">
      <div class="who">
        <div><span class="name">${escH(shown)}</span>
          ${roleTag} ${statusTag}</div>
        <div class="dnrow">
          <input data-uid="${u.id}" value="${escA(shown)}" maxlength="40"
                 title="Public name shown on ticket timelines">
          <button class="btn" data-dn="${u.id}">Save name</button>
        </div>
      </div>
      <span class="meta">${meta.replace(/[<>&]/g, "")}</span>
      ${actions}
    </div>`;
  }).join("");
  document.querySelectorAll("[data-id]").forEach(b => b.onclick = async () => {
    const id = b.dataset.id;
    if (b.dataset.del) {
      if (!confirm("Remove this user? Their sessions end immediately.")) return;
      await fetch(`/api/users/${id}/delete`, { method: "POST" });
    } else {
      await fetch(`/api/users/${id}/status`, {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: "status=" + b.dataset.s,
      });
    }
    load();
  });
  document.querySelectorAll("[data-dn]").forEach(b => b.onclick = async () => {
    const id = b.dataset.dn;
    const input = document.querySelector(`[data-uid="${id}"]`);
    await fetch(`/api/users/${id}/display-name`, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: "name=" + encodeURIComponent(input.value.trim()),
    });
    load();
  });
}

async function addUser() {
  const login = document.getElementById("gh_login").value.trim();
  if (!login) return;
  await fetch("/api/users/github", {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: "login=" + encodeURIComponent(login),
  });
  document.getElementById("gh_login").value = "";
  load();
}

load();
