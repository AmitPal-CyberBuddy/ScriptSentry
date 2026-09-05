# ScriptSentry — local-only JS analysis engine with its web dashboard.
#
# Build:
#   docker build -t scriptsentry .
# Run (dashboard on the published port):
#   docker run --rm -p 8000:8000 scriptsentry
# One-shot CLI scan against a public site:
#   docker run --rm scriptsentry python main.py https://example.com --format all
#
# The image preinstalls the Playwright Chromium build so the optional
# runtime-evidence stage (dynamic analysis in a real browser) works out of
# the box. All analysis stays inside the container; nothing is uploaded.

FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt \
    && PLAYWRIGHT_BROWSERS_PATH=/opt/ms-playwright playwright install --with-deps chromium \
    && rm -rf /root/.cache

COPY . .

ENV PLAYWRIGHT_BROWSERS_PATH=/opt/ms-playwright \
    SCRIPTSENTRY_HOST=0.0.0.0

EXPOSE 8000

# The dashboard binds to 0.0.0.0 here because only published ports leave the
# container; on a normal laptop the default stays loopback. The engine prints
# its pairing token on startup (see logs).
CMD ["python", "main.py", "--serve", "--host", "0.0.0.0", "--port", "8000"]
