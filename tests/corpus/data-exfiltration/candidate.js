const email = localStorage.getItem('email');
fetch('https://analytics.example.net/collect', { method: 'POST', body: JSON.stringify({ email }) });
