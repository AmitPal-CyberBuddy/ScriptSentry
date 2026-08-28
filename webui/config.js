/* ScriptSentry frontend configuration
 * --------------------------------------
 * Privacy-first setup:
 *  - GitHub Pages hosts this UI.
 *  - The Python analyzer runs ONLY on the user's machine via `server.py`.
 *  - This file decides where the dashboard sends /api requests.
 *
 * Behavior:
 *  - When the page is already served from localhost/127.0.0.1 (local server),
 *    it talks to the same origin (your local server).
 *  - When the page is hosted on GitHub Pages, it talks to the user's local
 *    engine at http://127.0.0.1:8000 (default port).
 *
 * The engine requires a pairing token printed by server.py.  It is kept in
 * sessionStorage by app.js and is never placed in the URL or sent to a cloud.
 * Set SCRIPTSENTRY_API before this file if the engine is hosted elsewhere.
 */
(function () {
  var host = window.location.hostname || "";
  var isLocalHost = /^(localhost|127\.0\.0\.1|0\.0\.0\.0)$/.test(host);

  window.SCRIPTSENTRY_API = window.SCRIPTSENTRY_API || (isLocalHost
    ? window.location.origin  // served locally by server.py
    : "http://127.0.0.1:8000"); // hosted UI → user's local engine
  window.SCRIPTSENTRY_API_TOKEN = window.SCRIPTSENTRY_API_TOKEN || "";
})();
