"""ScriptSentry's local HTTP API package.

The dashboard server used to be one 700-line ``server.py``; it is now split
along its real seams (see that module's docstring for the history):

  * :mod:`api.settings`  -- process-scoped settings: web root, body limits,
    the pairing token;
  * :mod:`api.auth`      -- pairing-token + origin-trust checks;
  * :mod:`api.cors`      -- CORS header handling and the OPTIONS preflight;
  * :mod:`api.http`      -- the stdlib handler base: JSON responses, body
    reading, static-UI serving quirks (404 page, no directory listings);
  * :mod:`api.analysis_routes` -- /api/health, /api/status, /api/result,
    /api/history*, /api/cancel, /api/analyze;
  * :mod:`api.report_routes`   -- /api/report (txt/html/csv/sarif/json/openapi);
  * :mod:`api.handlers`  -- assembles those mixins into ``DashboardHandler``
    and owns the GET/POST dispatch.

``server.py`` remains the thin loopback bootstrap (``make_server``/``main``)
so existing embedders keep working unchanged.
"""
from api.handlers import DashboardHandler  # noqa: F401
from api.settings import API_TOKEN, WEB_ROOT  # noqa: F401
