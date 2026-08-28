const q = new URLSearchParams(location.search).get('q');
document.getElementById('target').innerHTML = q;
