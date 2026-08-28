/* ScriptSentry frontend configuration
 * --------------------------------------
 * Default: serve the dashboard and API from the same origin (local server).
 * On GitHub Pages you host ONLY this UI and point the API to your hosted
 * Python backend (Render / Railway / HuggingFace Spaces / VPS etc).
 *
 * Example:
 *   window.SCRIPTSENTRY_API = "https://your-backend.example.com";
 */
(function () {
  window.SCRIPTSENTRY_API = "";
})();
