import base64
import binascii
import re


SAFE_CHARS = re.compile(r'^[A-Za-z0-9+/=_-]{8,}$')
HEX_CHARS = re.compile(r'^(?:[A-Fa-f0-9]{8,})$')


def clean_value(value):
    if value is None:
        return ""
    return str(value).strip().strip('"').strip("'")


def try_decode_base64(value):
    text = clean_value(value)
    if not text or len(text) < 8:
        return None
    if not SAFE_CHARS.fullmatch(text):
        return None

    try:
        decoded = base64.b64decode(text + '=' * (-len(text) % 4), validate=True)
    except (binascii.Error, ValueError):
        try:
            decoded = base64.b64decode(text)
        except Exception:
            return None

    try:
        decoded_text = decoded.decode('utf-8')
    except UnicodeDecodeError:
        return None

    if len(decoded_text) < 3:
        return None

    if decoded_text.isprintable() and not decoded_text.isspace():
        return decoded_text
    return None


def try_decode_hex(value):
    text = clean_value(value)
    if not HEX_CHARS.fullmatch(text):
        return None
    try:
        raw = bytes.fromhex(text)
    except ValueError:
        return None
    try:
        decoded = raw.decode('utf-8')
    except UnicodeDecodeError:
        return None
    if len(decoded) >= 3 and decoded.isprintable():
        return decoded
    return None


def decode_candidate_strings(content):
    decoded = []
    patterns = [
        r'([A-Za-z0-9+/]{16,}={0,2})',
        r'([A-Fa-f0-9]{16,})'
    ]
    for pattern in patterns:
        for match in re.findall(pattern, content):
            candidate = match.strip()
            for decoder in (try_decode_base64, try_decode_hex):
                decoded_value = decoder(candidate)
                if decoded_value:
                    if decoded_value not in decoded:
                        decoded.append(decoded_value)
    return decoded


def extract_hidden_values(content):
    findings = []
    for pattern in [
        r'([A-Za-z0-9+/]{24,}={0,2})',
        r'([A-Fa-f0-9]{24,})'
    ]:
        for match in re.findall(pattern, content):
            cleaned = clean_value(match)
            decoded = try_decode_base64(cleaned) or try_decode_hex(cleaned)
            if decoded:
                if any(term in decoded.lower() for term in ['api', 'token', 'key', 'secret', 'user', 'auth', 'http']):
                    findings.append(decoded)
    return list(dict.fromkeys(findings))
