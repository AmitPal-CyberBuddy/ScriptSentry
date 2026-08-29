// TRUE POSITIVE — inter-procedural DOM XSS.
// Untrusted query data flows through a helper into innerHTML.
function renderBanner(html) {
  document.getElementById("banner").innerHTML = html;
}
const q = new URLSearchParams(location.search).get("msg");
renderBanner(q);
