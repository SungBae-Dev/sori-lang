# SORI — Secure, Observable, Reliable, Intelligent (working title)

> **Current release:** `0.2.0a1` — Phase B milestone B1, typed IR + static type checks + OpenAPI 3.1 + CLI project scaffolding/build + experimental VS Code TextMate grammar. **NOT production audited.**

## Phase B1 — what is new (2026-10-27)

New typed expression validation rejects invalid arithmetic and comparisons at **compile time**. `sori ir` emits a versioned deterministic JSON representation of route actions. `sori openapi` emits a conservative OpenAPI 3.1 specification with per-route bearer security, bounded input schemas, and worker outputs marked unknown. Worker invocation from `public` routes now fails compilation (breaking behavior change to the v0.1 prototype).

```bash
python -m sori new ./my-service
python -m sori check ./my-service/app.sori
python -m sori ir examples/hello.sori
python -m sori openapi examples/hello.sori
python -m sori build examples/hello.sori --out .sori-build
python -m sori test --start-directory tests
python -m sori dev examples/hello.sori  # alias of serve, not auto-reloading
```

**`build` creates three specification files** (`manifest.json`, `typed-ir.json`, `openapi.json`); **it does not create a native executable**. The Rust native runtime, production-grade policy engine, dependency locks/SBOM, and real AI/ROS 2 integration are still future milestones. See [`docs/MILESTONES.ko.md`](docs/MILESTONES.ko.md), [`docs/IR_SPEC.ko.md`](docs/IR_SPEC.ko.md).

Minimal VS Code syntax highlighting grammar: `editors/vscode`. This is not a published extension, formatter, or language server.

> **Status:** runnable research prototype, **NOT production audited**. SORI currently is a small **domain-specific programming language** for JSON APIs, not yet a general-purpose language or a replacement for PHP, Rust, Python, Spring, Next.js, or Nuxt. The runtime is written in Python and uses an ASGI server. Rust, browser UI, ROS 2, real ML and an independently secured tool runtime are planned, not implemented.

## Existing v0.1 features (still supported)

- `.sori` syntax parser; explicit `public` / `protected` policies for every route
- Input type and bounds validation, unknown field rejection, duplicate JSON key rejection, 64-KiB body limit
- Restricted expression evaluator with no `eval`, `exec`, imports or arbitrary Python calls from SORI programs
- Bearer API token, constant-time comparison, fail-closed process startup when missing
- Fixed-URL loopback worker protocol for a separate Python process, request timeout and no redirects/proxies
- Machine-readable `sori manifest` JSON intended for AI code generation tools
- ASGI web app, Docker/Compose example, Kubernetes deployment and network policy example
- CI test workflow with automatic tests. **This is not a comprehensive security scan.**

## Quick start

Python 3.12+ is required. Use a virtual environment. Installing the web server dependency requires internet access.

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e '.[server]'
python -m unittest discover -s tests -v
python -m sori check examples/hello.sori
python -m sori manifest examples/hello.sori
export SORI_API_TOKEN="$(python -c 'import secrets; print(secrets.token_urlsafe(40))')"
python -m sori serve examples/hello.sori --host 127.0.0.1 --port 8000
```

In a separate terminal, with the same `SORI_API_TOKEN` value:

```bash
curl -sS http://127.0.0.1:8000/health
curl -sS http://127.0.0.1:8000/greet \
  -H "Authorization: Bearer $SORI_API_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"name":"세계"}'
```

For the Python worker example (in a separate terminal):

```bash
python edge/worker.py
curl -sS http://127.0.0.1:8000/risk \
  -H "Authorization: Bearer $SORI_API_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"signal":0.93}'
```

Expected worker reply:

```json
{"risk":"high","kind":"demo_threshold_not_ai"}
```

**The bundled worker uses a fixed threshold, not an AI model.** It proves the Python/ROS/ML adapter protocol is executable. A real ML model and ROS 2 integration require additional dependencies, testing and isolation.

## Example language

```sori
app "SORI Secure API"
route GET "/health" public:
  return {"status": "ok"}
route POST "/greet" protected:
  input name: str(1, 80)
  return {"message": "안녕하세요, " + input.name}
worker "risk-model" "http://127.0.0.1:9010/invoke" timeout 1200
route POST "/risk" protected:
  input signal: float(0, 1)
  invoke "risk-model"
```

The language currently supports GET/POST with exact-match paths, JSON object `return`, literal values, `input.<field>`, addition/subtraction, numeric comparisons, lists/objects, and fixed named worker calls. No imports, loops, arbitrary functions, SQL, frontend rendering or file access. **Do not infer a feature exists simply because it is planned in the design.**

## Docker Compose (local testing)

```bash
python -c 'import secrets; from pathlib import Path; Path(".env").write_text("SORI_API_TOKEN="+secrets.token_urlsafe(40)+"\n")'
docker compose up --build
```

Compose binds the API to `127.0.0.1:8000` on your development machine, with a separate worker sharing the app's network namespace. That lets the worker bind to loopback, but **loopback does not sandbox a compromised worker**. Keep the worker trusted and separately hardened.

## Kubernetes (template; not zero-touch production deployment)

Build and publish an image to your registry first, replace `ghcr.io/REPLACE_ME/sori:prototype` in `k8s/deployment.yaml`, and preferably use an image **digest**. Supply a pre-created `sori-token` Kubernetes Secret whose key is `SORI_API_TOKEN`, then:

```bash
kubectl apply -f k8s/deployment.yaml
kubectl port-forward service/sori-demo 8000:80
```

The example applies non-root user, read-only root FS, seccomp RuntimeDefault, dropped capabilities, limited resources, Pod egress deny-all, and a loopback-only sidecar. Kubernetes networking, ingress TLS, secrets lifecycle, image attestation, observability and real security verification must still be provided by the operator.

## Verified tests and limitations

```bash
python -m unittest discover -s tests -v
```

Tests validate compiler rejection of unauthorized expression nodes, required access policy, typed inputs, bearer auth, invalid JSON, duplicate keys, request size, 404/405, worker timeout/error policy and an actual local HTTP worker invocation. They **do not prove** absence of vulnerabilities, compliance or suitability for medical/safety-critical robotics.

**Not implemented:** Rust native runtime, general purpose compiler, browser UI, SSR, SQL/ORM, automatic OpenAPI, multi-tenant RBAC/ABAC, Docker image digest lock, dependency lockfile/SBOM, vulnerability scanning, signed provenance, mutual TLS, production worker isolation, resource scheduling, audit log, distributed tracing, deterministic real-time robot control or ROS 2 connectors. See `docs/ARCHITECTURE.ko.md`, `docs/SECURITY.ko.md`, and `docs/ROADMAP.ko.md`.

## Legal

Research/demo software. Apache-2.0 license. SORI is a **provisional project name**, and availability of trademarks, domains, package names and repository names has not been cleared.