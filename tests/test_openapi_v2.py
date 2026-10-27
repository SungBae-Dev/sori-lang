"""IR v2 기반 OpenAPI 3.1 / AI 툴 스키마."""
import json
import unittest

from sori.tools.openapi_v2 import openapi, tool_schemas
from sori_util import ROOT


def _app(ex):
    from sori.framework.app import build_app
    app, _ = build_app(ROOT / "examples" / ex)
    return app


def _refs(obj):
    if isinstance(obj, dict):
        for k, v in obj.items():
            if k == "$ref":
                yield v
            else:
                yield from _refs(v)
    elif isinstance(obj, list):
        for v in obj:
            yield from _refs(v)


class OpenAPIv2(unittest.TestCase):
    def test_structure_and_refs_resolve(self):
        for ex in ("todo", "secure-api", "robot"):
            with self.subTest(ex=ex):
                app = _app(ex)
                spec = openapi(app.ir, app.config)
                self.assertEqual(spec["openapi"], "3.1.0")
                json.dumps(spec, allow_nan=False)
                for ref in _refs(spec):
                    name = ref.rsplit("/", 1)[1]
                    self.assertIn(name, spec["components"]["schemas"], ref)
                for path, item in spec["paths"].items():
                    for method, op in item.items():
                        self.assertIn(method, ("get", "post", "put", "patch", "delete"))
                        self.assertTrue(op["responses"])
                        for p in op.get("parameters", []):
                            if p["in"] == "path":
                                self.assertIn("{" + p["name"] + "}", path)
                                self.assertTrue(p["required"])

    def test_bearer_vs_custom_guard_are_not_conflated(self):
        app = _app("todo")
        spec = openapi(app.ir, app.config)
        guarded = spec["paths"]["/api/todos"]["post"]
        self.assertNotIn("security", guarded)  # 사용자 guard 를 bearer 로 표기하지 않음
        self.assertEqual(guarded["x-sori-access"], "guard:admin")
        self.assertIn("403", guarded["responses"])
        self.assertNotIn("securitySchemes", spec["components"])
        public = spec["paths"]["/api/todos"]["get"]
        self.assertEqual(public["security"], [])
        app2 = _app("secure-api")
        spec2 = openapi(app2.ir, app2.config)
        greet = spec2["paths"]["/greet"]["post"]
        self.assertEqual(greet["security"], [{"bearerAuth": []}])
        self.assertIn("401", greet["responses"])
        self.assertEqual(spec2["components"]["securitySchemes"]["bearerAuth"]["scheme"], "bearer")

    def test_bounds_params_bodies_and_responses(self):
        app = _app("todo")
        spec = openapi(app.ir, app.config)
        one = spec["paths"]["/api/todos/{id}"]["get"]
        self.assertEqual(one["parameters"][0]["schema"], {"type": "integer", "minimum": 1, "maximum": 1000000000})
        self.assertIn("404", one["responses"])
        search = spec["paths"]["/search"]["get"]["parameters"][0]
        self.assertEqual((search["in"], search["schema"]["maxLength"]), ("query", 100))
        new = spec["components"]["schemas"]["NewTodo"]
        self.assertEqual(new["properties"]["title"], {"type": "string", "minLength": 1, "maxLength": 200})
        self.assertFalse(new["additionalProperties"])
        created = spec["paths"]["/api/todos"]["post"]["responses"]["201"]
        self.assertEqual(created["content"]["application/json"]["schema"], {"$ref": "#/components/schemas/Todo"})
        html = spec["paths"]["/"]["get"]["responses"]["200"]["content"]
        self.assertIn("text/html", html)
        robot = openapi(_app("robot").ir)["paths"]["/target"]["post"]
        self.assertEqual(robot["responses"]["200"]["content"]["application/json"]["schema"]["properties"]["target"]["type"], "number")

    def test_upstream_effects_document_502(self):
        app = _app("secure-api")
        risk = openapi(app.ir, app.config)["paths"]["/risk"]["post"]
        self.assertIn("502", risk["responses"])
        self.assertIn("worker", risk["x-sori-effects"])

    def test_tool_schemas_are_self_contained(self):
        tools = tool_schemas(_app("todo").ir)
        names = {t["name"] for t in tools}
        self.assertIn("post_api_todos", names)
        t = next(t for t in tools if t["name"] == "post_api_todos")
        self.assertNotIn("$ref", json.dumps(t))
        self.assertIn("사용자 정의 guard admin", t["description"])
        self.assertEqual(t["input_schema"]["properties"]["body"]["properties"]["title"]["maxLength"], 200)


if __name__ == "__main__":
    unittest.main()
