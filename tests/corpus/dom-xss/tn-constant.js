// TRUE NEGATIVE — only a constant string reaches innerHTML; no untrusted source.
function renderBanner() {
  document.getElementById("banner").innerHTML = "<b>Welcome</b>";
}
renderBanner();
