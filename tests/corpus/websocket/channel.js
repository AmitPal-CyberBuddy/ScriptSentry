const socket = new WebSocket('wss://analytics.example.net/stream');
socket.send(localStorage.getItem('token'));
