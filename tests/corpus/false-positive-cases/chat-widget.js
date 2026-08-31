// Chat/UI code with input-ish variable names.  The values are statically
// known or rendered through textContent, so none of these are data flows.
// The by-name identifier heuristic (message/data/input/payload are taint
// sources) must not fabricate flows for them.
function renderMessage(message) {
  const el = document.createElement('div');
  el.textContent = message;   // safe by construction
  chatBox.appendChild(el);
}

function updateUI(data) {
  statusEl.textContent = data;
  progressEl.textContent = data.status;
}

const input = 'welcome';
document.body.innerHTML = input;

const payload = { text: 'hello', code: 200 };
document.body.innerHTML = payload.text;

const message = 'static greeting';
const el2 = document.getElementById('out');
el2.innerHTML = message;
