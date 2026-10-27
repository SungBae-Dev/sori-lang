# SORI — Secure, Observable, Reliable, Intelligent (working title)

> **Current version:** `0.3.0a1` (branch `integration/ara-sori-unified-core`, **under review, not merged**) — unified core: Ara general-purpose front end + versioned **Typed IR v2** + Python IR interpreter backend + experimental Rust backend slice. The B1 v0.1 DSL path is kept unchanged. **NOT production audited.**

## v0.3.0a1 — unified core (proposed)

```text
.sori (unified syntax) → lexer/parser → static checks (scope, types, permissions, effects, route policy, HTML context)
                       → Typed IR v2 (sori/ir/v2, deterministic JSON, JSON Schema)
                       → Python Backend (IR interpreter, no eval/exec)  |  Rust Backend slice (runtime-rs, std-only)
.sori (v0.1 DSL, first line `app "..."`) → B1 compiler/runtime, unchanged
```

```bash
python -m sori new ./my-app                  # sori.toml + app.sori (v0.3 syntax)
python -m sori check examples/todo --json    # JSON diagnostics (code, line, column, Korean message, hint)
python -m sori test examples/todo            # .sori test blocks
python -m sori dev examples/todo             # builtin dev server, detailed errors
python -m sori run examples/secure-api       # uvicorn by default; refuses unsafe startup
python -m sori ir examples/todo              # Typed IR v2
python -m sori openapi examples/todo         # OpenAPI 3.1 generated from IR v2
python -m sori build examples/todo --target spec   # typed-ir/openapi/manifest/tools JSON (default)
python -m sori build examples/todo --target oci    # Docker build context + sori.lock (does not run docker)
python -m sori k8s examples/secure-api       # manifests: permissions → NetworkPolicy, worker sidecars
python -m sori migrate examples/hello.sori   # v0.1 DSL → v0.3 syntax + report
```

**What works (local tests, 121 passing):**

- variables, functions, lambdas, loops, records, Korean identifiers
- every route requires an access policy: `public` / `guard bearer` / user guard
- bounded inputs are mandatory by default (`strict_inputs = true`)
- strict JSON
- `sql"..."` / `html"..."` safe types
- permission-checked db/http/fs/env
- effect analysis (public routes cannot reach workers, even through functions)
- loopback-only Python workers with typed responses
- AI tool schemas, periodic tasks
- fail-closed production startup (`SORI_ENV=production`): lock required, no bypass switch, uvicorn only
- `/metrics` private by default (`SORI_METRICS_TOKEN` bearer), lock covers static/fs_read files
- sori.toml values that end up in Dockerfile/YAML are validated (E204), Dockerfile uses exec-form `RUN`
- `sori k8s`: NetworkPolicy egress is cluster DNS only (verified on a kind cluster in CI). FQDN egress only via `--egress cilium`; that CiliumNetworkPolicy has only unit tests, it has not been verified on a real Cilium cluster
- file permissions (`fs_read`/`fs_write`) are project-relative only; absolute paths, `..` and symlinks escaping the project are refused
- v0.1 → v0.3 migration verified on 23 requests
- Python/Rust backend parity on 20 test vectors

**What this does not do:**

- `build` does **not** produce a native binary.
- The IR interpreter is **not an OS-level sandbox**.
- `use py` (in-process Python) is development-only.
- The Rust backend runs only a slice: no std modules, user functions or guards; it returns 501 for anything unsupported.
- CPU-heavy code is slower than native Python: 2.6–11× in measurements. Web routes measured equal or faster. See ADR 0001 §4.
- No security fuzzing or external audit has been done. Docker image build and hardened run happen in CI (`oci-image` job), not locally.
- It does not block all CVEs.

Docs:

- [ADR 0001](docs/adr/0001-unified-core.ko.md)
- [feature duplication/conflict table](docs/INTEGRATION_ANALYSIS.ko.md)
- [language](docs/LANGUAGE.ko.md)
- [IR v2 spec](docs/IR_SPEC.ko.md)
- [security & threat model](docs/SECURITY.ko.md)
- [migration](docs/MIGRATION-0.3.ko.md)
- [B2 Rust plan](docs/B2_RUST_PLAN.ko.md)

---

> The sections below describe **Phase B1 (`0.2.0a1`)** and the v0.1 DSL. They remain valid: v0.1 files run on the unchanged B1 path.

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