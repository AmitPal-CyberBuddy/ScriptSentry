const q = new URLSearchParams(location.search).get('key');
Object.assign(config, JSON.parse(q));
