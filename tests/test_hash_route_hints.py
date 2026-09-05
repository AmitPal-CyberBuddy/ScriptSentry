"""SPA hash-route hints: `#/admin/users`-style client-side routes.

Hidden SPA routes (admin panels, debug screens, impersonation flows) are
prime review targets. They are *not* HTTP endpoints — the server always
answers with the same document — so they must surface as attack-surface
hints (dashboard, reports) and as an OpenAPI *extension*, never as paths.
"""
import json
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.attack_surface import HASH_ROUTE_CAP, _hash_route_sweep, extract_attack_surface
from core.reporter import build_dashboard_payload, build_report_model, generate_html_report, generate_openapi_report, generate_report


BUNDLE = """
const routes = { "#/admin/users": loadAdmin, fallback: "#/login" };
el.innerHTML = '<a href="#/settings/profile">Profile</a>';
track("#/img/logo.png");          // asset, not a route
track("#/12345");                 // no letters, not a route
routeTo('#/admin/users');         // duplicate, keeps first line
redirectTo(`#/support/tickets`);
"""


def _file_data(attack_surface):
    return {
        "findings": [], "risk_signals": [], "dataflows": [], "framework_findings": [],
        "finding_statuses": {}, "dependency_scan": [], "technology_stack": [],
        "attack_surface": attack_surface,
        "ast_analysis": {}, "obfuscation_analysis": {}, "notable_features": [],
        "file_size": 10,
    }


def _surface(routes):
    base = {"endpoints": [], "websockets": [], "sse": [],
            "graphql": {"urls": [], "operations": []}, "parameters": [],
            "domains": [], "headers": [], "body_fields": [], "auth_hints": [],
            "internal_endpoints": []}
    base["hash_routes"] = routes
    return base


class HashRouteExtractionTest(unittest.TestCase):
    def test_routes_found_assets_and_noise_skipped(self):
        surface = extract_attack_surface(BUNDLE)
        routes = [(r["route"], r["internal"], r["line"]) for r in surface["hash_routes"]]
        self.assertEqual(routes, [
            ("/admin/users", True, 2),      # "admin" -> internal hint
            ("/login", False, 2),
            ("/settings/profile", False, 3),
            ("/support/tickets", False, 7),
        ])

    def test_hash_routes_never_become_endpoints(self):
        surface = extract_attack_surface(BUNDLE)
        self.assertFalse([e for e in surface["endpoints"] if str(e.get("url", "")).startswith("#")])

    def test_cap(self):
        many = "\n".join(f'x("#/route{i:03d}/detail");' for i in range(HASH_ROUTE_CAP + 20))
        self.assertEqual(len(_hash_route_sweep(many)), HASH_ROUTE_CAP)

    def test_parametrised_templates_survive(self):
        routes = _hash_route_sweep('const t = "#/orders/:id/items";')
        self.assertEqual([r["route"] for r in routes], ["/orders/:id/items"])


class HashRouteReportingTest(unittest.TestCase):
    def results(self):
        return {
            "app.bundle.js": _file_data(_surface([
                {"route": "/admin/users", "line": 12, "internal": True},
                {"route": "/login", "line": 30, "internal": False},
            ])),
            "vendor.js": _file_data(_surface([
                # Same route, other file/line: must dedupe to the first hit.
                {"route": "/admin/users", "line": 900, "internal": True},
                {"route": "/reports/{id}", "line": 5, "internal": False},
            ])),
        }

    def test_model_merges_routes_across_files(self):
        model = build_report_model(self.results(), metadata={"source": "demo"})
        merged = [r["route"] for r in model["attack_surface"]["hash_routes"]]
        self.assertEqual(merged, ["/admin/users", "/login", "/reports/{id}"])

    def test_dashboard_payload_carries_routes(self):
        payload = build_dashboard_payload(self.results(), metadata={"source": "demo"})
        files = payload.get("files") or []
        counts = [len((f.get("attack_surface") or {}).get("hash_routes") or []) for f in files]
        self.assertEqual([c for c in counts if c], [2, 2])

    def test_openapi_exports_extension_not_paths(self):
        doc = json.loads(generate_openapi_report(self.results(), metadata={"source": "demo"}))
        self.assertEqual(doc["x-spa-hash-routes"], [
            {"route": "#/admin/users", "internal": True},
            {"route": "#/login", "internal": False},
            {"route": "#/reports/{id}", "internal": False},
        ])
        self.assertFalse([p for p in doc["paths"] if str(p).startswith("#")])

    def test_txt_and_html_reports_mention_routes(self):
        txt = generate_report(self.results(), metadata={"source": "demo"})
        self.assertIn("SPA hash routes", txt)
        self.assertIn("#/admin/users", txt)
        self.assertIn("[hidden/internal]", txt)
        html = generate_html_report(self.results(), metadata={"source": "demo"})
        self.assertIn("SPA route: #/admin/users", html)

    def test_dashboard_ui_has_hash_route_panel(self):
        # The shipped app.js is the build artifact the pages load.
        with open(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                               "webui", "app.js"), encoding="utf-8") as fh:
            app = fh.read()
        self.assertIn("SPA Hash Routes", app)
        self.assertIn("as.hash_routes || []", app)


if __name__ == "__main__":
    unittest.main()
