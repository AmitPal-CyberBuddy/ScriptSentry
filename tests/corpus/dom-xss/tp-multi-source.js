// TRUE POSITIVE — two independent untrusted sources can reach the same sink.
// Correlation must keep them distinguishable (2 flows), not collapse them.
window.addEventListener("message", function (event) {
  const fromHash = new URLSearchParams(location.hash.slice(1)).get("html");
  const fromMessage = event.data;
  document.getElementById("out").innerHTML = fromHash || fromMessage;
});
