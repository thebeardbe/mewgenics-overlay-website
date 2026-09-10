// Shared helpers for the admin UI.
function readCookie(name) {
  const m = document.cookie.match("(?:^|; )" + name + "=([^;]*)");
  return m ? decodeURIComponent(m[1]) : "";
}
function csrfToken() { return readCookie("bugbox_csrf"); }

// Attach the CSRF token to every state-changing same-origin request.
const _bugboxFetch = window.fetch.bind(window);
window.fetch = function (url, opts) {
  opts = opts || {};
  const method = (opts.method || "GET").toUpperCase();
  opts.headers = Object.assign({}, opts.headers || {},
                               { "Accept": "application/json" });
  if (method !== "GET" && method !== "HEAD") {
    const tok = csrfToken();
    if (tok) {
      opts.headers["X-Bugbox-CSRF"] = tok;
    }
  }
  return _bugboxFetch(url, opts);
};

// HTML-escape (also single quotes, for attribute safety).
function esc(s) {
  return (s || "").replace(/[&<>"']/g, c => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;",
    '"': "&quot;", "'": "&#39;",
  }[c]));
}

// Normalise API error payloads (string or {error:{code,message}}).
function errText(data) {
  const e = data && data.error;
  if (!e) return "unknown error";
  if (typeof e === "string") return e;
  return e.message || e.code || "error";
}
