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
 * 127.0.0.1 is more reliably treated as a secure/trusted local origin from an
 * HTTPS hosted page than `localhost`, and the server binds 0.0.0.0 so it is
 * reachable from both.
 *
 * If you change the local port, update the fallback below and tell users
 * to run `python3 server.py --port <port>` with the matching port.
 */
(function () {
  var host = window.location.hostname || "";
  var isLocalHost = /^(localhost|127\.0\.0\.1|0\.0\.0\.0)$/.test(host);

  window.SCRIPTSENTRY_API = isLocalHost
    ? window.location.origin  // served locally by server.py
    : "http://127.0.0.1:8000"; // hosted UI → user's local engine
})();
