const q = new URLSearchParams(location.search).get('q');
const clean = DOMPurify.sanitize(q);
document.body.innerHTML = clean;
