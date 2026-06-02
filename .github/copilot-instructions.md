# Copilot Instructions

## Build, Test, and Lint

**Prerequisites:** `uv` and `tox` must be installed.

```bash
# Install tox with uv backend
uv tool install tox --with tox-uv

# Format code
tox -e fmt

# Lint (codespell + ruff + mypy)
tox -e lint

# Unit tests with coverage
tox -e unit

# Static analysis (bandit)
tox -e static

# Integration tests (requires live Juju/k8s)
tox -e integration

# Run all basic checks
tox
```

**Run a single test:**
```bash
tox -e unit -- tests/unit/test_ingress.py::test_basic
```

**Build the charm:**
```bash
charmcraft pack
```

## Architecture

This is a [Juju charm](https://juju.is/docs/sdk) that creates and manages Kubernetes `Ingress`, `Service`, `Endpoints`, `EndpointSlice`, and `Secret` resources for an nginx ingress controller. It does **not** deploy nginx itself — it configures ingress rules for an already-running nginx ingress controller.

### Key components

- **`src/charm.py`** — `NginxIngressCharm(CharmBase)`: the entry point. All Juju events funnel through `_update_ingress()` → `_check_precondition()` → `_reconcile(definition)`.
- **`src/ingress_definition.py`** — `IngressDefinitionEssence` aggregates config + relation data; `IngressDefinition.from_essence()` validates and normalizes it into the final spec used by controllers.
- **`src/controller/resource.py`** — `ResourceController` protocol: base for all K8s resource controllers. Implements a reconcile-then-cleanup pattern: `define_resource()` creates/patches the desired resource; `cleanup_resources(exclude=...)` deletes all charm-managed resources that aren't the current one.
- **`src/controller/`** — concrete controllers: `IngressController`, `ServiceController`, `EndpointsController`, `EndpointSliceController`, `SecretController`.
- **`lib/charms/nginx_ingress_integrator/v0/`** — publishable charm libraries: `nginx_route.py` (provides the `nginx-route` relation interface) and `ingress.py`.

### Relation interfaces

The charm supports exactly **one** of these at a time (both present → `BlockedStatus`):

| Relation | Interface | Direction |
|----------|-----------|-----------|
| `nginx-route` | `nginx-route` | provides |
| `ingress` | `ingress` (traefik_k8s v2) | provides |
| `certificates` | `tls-certificates` | requires |

### Resource lifecycle

Resources are labeled with `nginx-ingress-integrator.charm.juju.is/managed-by=<app-name>` (`CREATED_BY_LABEL`). On each reconcile, the charm creates/patches the needed resources and deletes any previously created resources no longer needed. `_cleanup()` deletes all managed resources (called when no relation is present).

### TLS

TLS certs are keyed by hostname (dict). The `_get_tls_certs()` / `_get_tls_keys()` methods return `{hostname: cert/key}`. A `Secret` K8s resource is created per hostname that has a cert. The `tls-secret-name` config option overrides relation-provided certs entirely.

## Key Conventions

### PYTHONPATH
`tox.toml` sets `PYTHONPATH={toxinidir}:{toxinidir}/lib:{toxinidir}/src`, so imports from `src/` (e.g., `from consts import ...`) and `lib/` (e.g., `from charms.nginx_ingress_integrator...`) work without package installation.

### Linting scope
Ruff, mypy, and codespell run across `src/`, `tests/`, and `lib/charms/nginx_ingress_integrator/` together (defined as `all_path` in `tox.toml`). Tests relax docstring and security rules via `lint.per-file-ignores`.

- Line length: 99
- Docstring convention: Google
- Target: Python 3.10+
- Copyright header required on all files: `# Copyright <year> Canonical Ltd.`

### Unit test patterns

- Tests use `ops.testing.Harness` (old harness API) combined with `K8sStub` from `tests/unit/conftest.py`.
- `K8sStub` is an in-memory mock of the Kubernetes API; monkeypatched via the `k8s_stub` fixture.
- Test docstrings follow an `arrange/act/assert` comment structure.
- Coverage minimum: **88%** (`fail_under = 88` in `pyproject.toml`).

### Error handling
K8s 403 `ApiException`s are converted to `InvalidIngressError` by the `@_map_k8s_auth_exception` decorator in `resource.py`. `InvalidIngressError` is caught in `_update_ingress()` and sets `BlockedStatus`.

### Single-unit constraint
The charm enforces `unit.is_leader()` and only supports one unit. Scale-down instructions are embedded in the error message.

### Changelog
Add an entry to `docs/changelog.md` for every new feature, fix, or significant change, using the contribution date as the header.
