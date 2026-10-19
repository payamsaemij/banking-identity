# Banking Identity Service

Identity and authentication microservice for a banking platform. It owns
credentials and authentication identity: registration, email
verification, login sessions, password change/reset, and the identity
lifecycle. Customer profile data is owned by the separate Customer
Service; this service only keeps a stable reference to it.

## Scope

Implemented (v1):

- Register an identity (email + password) in `PENDING_VERIFICATION`
- Verify email with a single-use, expiring token
- Resend verification emails (older tokens are invalidated)
- Login with email + password → opaque, revocable session token
- Logout (immediate session revocation)
- Change password (requires current password, revokes all sessions)
- Request a password reset (enumeration-safe) and complete it with a
  single-use token
- Deactivate (self-service, password-confirmed) and reactivate
  (administrative, key-guarded)
- Rate limiting on sensitive endpoints, structured JSON logging with
  correlation IDs, health/readiness probes

Explicitly not implemented: customer profiles, employees/branches,
banking transactions or balances, a second auth framework, Kubernetes,
event infrastructure.

## Architecture

Pragmatic Clean Architecture with four layers and one dependency
direction (`presentation → application → domain ← infrastructure`):

```
src/identity_service/
├── domain/            # entities, enums, domain exceptions — no framework imports
│   ├── entities/      # Identity, OneTimeToken, AuthSession
│   └── exceptions.py
├── application/       # use cases, ports (Protocols), validation policies
│   ├── ports/         # repositories, hasher, token generator, senders,
│   │                  # clock, rate limiter
│   ├── use_cases/     # RegisterIdentity, VerifyEmail, Login, ...
│   ├── validators/    # email normalization + password policy
│   └── security.py    # token hashing (SHA-256)
├── infrastructure/    # SQLAlchemy models + repositories, Alembic wiring,
│   ├── config.py      # Pydantic Settings
│   ├── email/         # console (dev) and SMTP senders
│   ├── observability/ # JSON logging
│   ├── persistence/   # ORM models, engine, repositories
│   ├── rate_limit/    # in-process sliding window
│   └── security/      # Argon2id hasher, CSPRNG token generator
├── presentation/      # FastAPI routers, schemas, error mapping, DI wiring
└── main.py            # create_app() — the only composition boundary
```

- **Domain**: pure Python (dataclasses + enum + exceptions). Enforces the
  identity lifecycle and token invariants.
- **Application**: use cases depend only on ports (`Protocol`
  interfaces). No SQLAlchemy, FastAPI, or email clients here.
- **Infrastructure**: implements the ports against PostgreSQL, Argon2,
  SMTP, and the OS clock.
- **Presentation**: HTTP schemas, status-code mapping, dependency
  injection, middleware.

**Transactions**: one SQLAlchemy session per request; repositories
flush, the request boundary commits on success and rolls back on any
error. Use cases never commit.

**Modeling note — tokens**: verification/reset tokens are lightweight
domain records (`OneTimeToken`): their only invariants are single use
and expiry, enforced in `consume()`; the database additionally enforces
single-use *atomically* via a conditional `UPDATE`. Session tokens are
opaque random values; only their SHA-256 hash is persisted.

## Prerequisites

- Python 3.13+
- [uv](https://docs.astral.sh/uv/)
- Docker + Docker Compose
- The [`banking-infrastructure`](../banking-infrastructure/) repo checked
  out next to this one — it owns the shared PostgreSQL container
  (`banking-postgres`) and the Docker network every banking service joins

## Local setup

```bash
uv sync                      # create .venv and install everything
cp .env.example .env         # then edit DATABASE_URL etc.
```

Configuration is validated at startup; with a missing/empty
`DATABASE_URL` the service refuses to boot. Every setting is documented
in `.env.example`. Never commit real secrets.

### PostgreSQL

PostgreSQL is owned by `banking-infrastructure` — never start a second
instance for this service:

```bash
cd ../banking-infrastructure
cp .env.example .env          # set POSTGRES_PASSWORD once
docker compose up -d          # starts banking-postgres (127.0.0.1:5432)
```

The service owns its own database and login role (`banking_identity`),
created by the infrastructure init script. Then `cp .env.example .env`
here and adjust if needed:

```
DATABASE_URL=postgresql+psycopg://banking_identity:banking_identity_dev@localhost:5432/banking_identity
IDENTITY_DB_PASSWORD=banking_identity_dev   # used by docker-compose.yml, see below
```

(The `banking_identity_dev` password is a local-development default; see
the infrastructure repo for how to change it everywhere consistently.)

#### History: migrating off the shared `banking` database

Earlier revisions of this service connected to the shared `banking`
database with the shared `banking` superuser. It now uses its dedicated
`banking_identity` database and role. If you still have identity data in
the old `banking` database, copy it across (a dump/restore **copy** — the
old database is left untouched as a rollback):

```bash
cd ../banking-infrastructure
# 1. ensure the role + database exist (idempotent, safe on existing volumes)
docker compose exec -T postgres psql -U banking -d banking \
  < postgres/init/01-create-service-databases.sql

# 2. copy schema + data + alembic revision; ownership lands on banking_identity
docker compose exec -T postgres pg_dump -U banking -d banking \
  --no-owner --no-privileges > /tmp/identity-migration.sql
docker compose exec -T postgres psql -U banking_identity -d banking_identity \
  -v ON_ERROR_STOP=1 < /tmp/identity-migration.sql

# 3. verify, then point this service's .env at banking_identity (above)
```

After the switch, keep the old `banking` database around as a rollback
until the new setup is confirmed; drop it only when you no longer need
the safety net.

### Migrations

Alembic reads the URL from the application settings (`DATABASE_URL`),
never from `alembic.ini`:

```bash
uv run alembic upgrade head        # apply all migrations
uv run alembic downgrade base      # roll everything back (destructive!)
uv run alembic revision --autogenerate -m "..."   # after changing models
```

### Starting the service

```bash
uv run uvicorn identity_service.main:app --reload
# or, via the console script:
uv run banking-identity
```

Interactive API docs: http://localhost:8000/docs

For local flows the default `EMAIL_SENDER=console` logs the
verification/reset link to the console (the only way to complete email
flows without SMTP). The factory refuses `console` outside
`local`/`test` environments.

## API overview

All routes are versioned under `/api/v1/identity`. Errors use one
envelope everywhere:

```json
{"error": {"code": "invalid_credentials", "message": "...", "request_id": "..."}}
```

| Method | Path | Auth | Success | Notes |
|---|---|---|---|---|
| POST | `/register` | — | 201 | 409 on duplicate email; rate limited |
| POST | `/verify-email` | — | 200 | body `{token}`; 400 invalid/expired/used |
| POST | `/resend-verification` | — | 202 | generic response; rate limited |
| POST | `/login` | — | 200 | returns `access_token` (bearer); generic 401; rate limited |
| POST | `/logout` | session | 204 | revokes the presented session |
| POST | `/password/change` | session | 204 | needs `current_password`; revokes **all** sessions |
| POST | `/password/reset-request` | — | 202 | generic response; rate limited |
| POST | `/password/reset` | — | 204 | body `{token, new_password}` |
| POST | `/deactivate` | session | 204 | needs `current_password`; revokes everything |
| POST | `/reactivate` | admin key | 200 | header `X-Admin-Key`; 403 when unset/wrong |
| GET | `/health` | — | 200 | liveness (no DB) |
| GET | `/health/ready` | — | 200/503 | readiness (executes `SELECT 1`) |

### Authentication strategy

Opaque bearer session tokens. At login the service generates a
256-bit random token, returns it once, and stores only its SHA-256
hash with an expiry. Every authenticated request resolves the session
from the database, which makes revocation immediate:

- logout → that session is revoked
- password change/reset, deactivation → **all** sessions of the
  identity are revoked

JWTs were deliberately not chosen: stateless tokens cannot be
individually revoked without a denylist, and immediate revocation is a
hard requirement for the credential-changing flows above. The tradeoff
is one indexed database lookup per authenticated request.

### Token lifecycle

Verification and reset tokens are 256-bit random values, delivered by
email, stored only as SHA-256 hashes, expiring (24 h / 1 h by default),
and single-use. Consumption is one conditional
`UPDATE ... WHERE used_at IS NULL AND expires_at > now`, so concurrent
requests can never both succeed. Issuing a new verification/reset token
invalidates all previous ones for that identity.

### Email policies

- **Normalization**: trim surrounding whitespace, lowercase the whole
  address; plus-tags and dots are preserved. The same policy is applied
  before every lookup and insert; the DB unique constraint backs it up.
- **Enumeration safety**: resend and reset-request always return the
  same generic 202 whether or not the account exists; login failures
  are a single generic 401 for unknown email / wrong password / pending
  / deactivated, and an unknown email still performs a full-cost
  password check so timing does not leak existence.
- **Delivery**: a database transaction and an email send are never
  treated as one atomic unit. If sending fails after registration or a
  reset request, the failure is logged (not returned to the client) and
  the user can use the resend endpoint. For guaranteed delivery, a
  transactional outbox is the recommended next step (not implemented).

### Password policy

Minimum 12, maximum 128 characters, no composition rules (per NIST
SP 800-63B guidance — length beats forced symbols, which push users to
predictable patterns). Passwords are never trimmed, logged, or
modified. Hashing is Argon2id (`argon2-cffi`, library defaults:
m=64 MiB, t=3, p=4); hashes are re-hashed transparently at login if
parameters ever need raising.

### Rate limiting

Sliding-window limits per client IP, per process, on register, login,
resend, and reset-request (defaults in `.env.example`; 429 +
`Retry-After`). The limiter sits behind the `RateLimiter` port —
multi-replica deployments must provide a shared-store (e.g. Redis)
implementation of that port.

## Logging

Structured JSON on stdout (one object per line, `LOG_FORMAT=console`
for local dev): `timestamp`, `level`, `service`, `environment`,
`logger`, `message`, `request_id`, plus event-specific fields
(`event`, `identity_id`, `session_id`, `status`, `duration_ms`,
`route`, `client_ip`, ...). A middleware assigns/propagates
`X-Request-ID`, echoes it on responses, and writes one access-log line
per request; unexpected exceptions are logged once at the API boundary
with only the exception class name.

Never logged: passwords or hashes, session/verification/reset tokens,
secrets, full request bodies, or full email addresses in application
logs (identity IDs are used instead). The one exception is the dev-only
console email sender, which prints the flow link on purpose and is
blocked outside `local`/`test`.

## Testing

```bash
uv run pytest tests/unit -v          # fast, fully faked
uv run pytest                        # unit + integration
uv run pytest --cov=identity_service # with coverage
```

Integration tests need a reachable PostgreSQL at `TEST_DATABASE_URL`
(default `postgresql+psycopg://identity_test:identity_test@localhost:5432/banking_identity_test`)
and skip cleanly when it is absent. They create and drop the schema via
the real Alembic migrations for every test. Expiry behaviour is tested
with an injected clock — no sleeps anywhere.

## Quality gates

```bash
uv run mypy src
uv run ruff check src tests
uv run ruff format --check src tests
```

## Docker

The image is a multi-stage build (`uv` builder → slim runtime) that runs
as the non-root `identity` user, ships `alembic` alongside the app, and
keeps every secret out of the build context (`.dockerignore` excludes
`.env`, `.git`, `.venv`, caches, tests).

### Host URL vs Docker-internal URL

The same PostgreSQL has two addresses, and they are **not**
interchangeable:

| Where the code runs | Host in `DATABASE_URL` | Why |
|---|---|---|
| Your machine (uv, tests) | `localhost:5432` | `banking-postgres` publishes `127.0.0.1:5432` on the host |
| Inside a container | `banking-postgres:5432` | container DNS on the shared network; `localhost` inside a container is the container itself |

`docker-compose.yml` therefore does not reuse the `DATABASE_URL` from
`.env`: it rebuilds it as
`postgresql+psycopg://banking_identity:$IDENTITY_DB_PASSWORD@banking-postgres:5432/banking_identity`
and overrides the variable per container. Keep `DATABASE_URL` in `.env`
pointed at `localhost` for host-side tooling.

### Build and run (Compose, recommended)

```bash
# 1. infrastructure first (once): shared postgres + the shared `banking`
#    network that the next step joins
cd ../banking-infrastructure && docker compose up -d && cd ../banking-identity

# 2. apply migrations — an explicit, one-shot step from the same image;
#    it never runs on every startup and never races between replicas
docker compose run --rm identity alembic upgrade head

# 3. start the API (joins the external `banking` network; no postgres is
#    defined or duplicated here)
docker compose up -d identity

curl http://localhost:8000/health        # liveness
curl http://localhost:8000/health/ready  # readiness (SELECT 1 against postgres)
docker compose logs -f identity          # structured JSON, one object per line
docker compose down                      # stops identity only; postgres untouched
```

The service publishes only `127.0.0.1:8000:8000` (loopback, like the
infrastructure repo); remove the mapping entirely when running behind a
reverse proxy.

### Plain docker build/run

```bash
docker build -t banking-identity .
docker run --rm -p 8000:8000 --network banking \
  -e DATABASE_URL="postgresql+psycopg://banking_identity:<password>@banking-postgres:5432/banking_identity" \
  banking-identity
```

### Diagnosing connection problems

- `ready` returns 503 / logs show `health.database_unavailable` — the
  container cannot reach PostgreSQL: check `docker network inspect
  banking` lists `banking-identity`, that the infrastructure stack is
  up, and that `IDENTITY_DB_PASSWORD` in this repo's `.env` matches the
  `banking_identity` role password created by the infrastructure init
  script.
- Startup fails fast on configuration errors (missing/empty
  `DATABASE_URL`) — that is validation working, not a bug.
- The image's `HEALTHCHECK` polls `/health` (liveness only); DB
  readiness is always `GET /health/ready`.

### In-container migration commands

```bash
docker compose run --rm identity alembic current       # inspect revision
docker compose run --rm identity alembic upgrade head  # apply (idempotent)
```

## Security considerations and known limitations

- Secrets come only from the environment; nothing sensitive is
  committed or logged.
- Sessions are stored server-side; a database compromise allows
  session revocation analysis but not token replay (only hashes are
  stored).
- Rate limiting is per instance; use a shared-store implementation
  behind the port for multi-replica deployments.
- Login rate limiting keys on client IP only; behind a shared proxy the
  effective limit must account for that (e.g. trust `X-Forwarded-For`
  only from known proxies — not implemented here).
- Email delivery is best-effort (see above); transactional outbox is
  the recommended upgrade.
- No account lockout, no 2FA, no password-breach checks — candidates
  for v2.
- `customer_id` is a stable, optional, immutable reference; this
  service never reads or writes customer profile data.
- Having these controls in code is not a production security
  certification; run a proper review before going live.

## Next steps for the banking platform

1. Customer Service: create it referencing `identity.id` (or pass
   `customer_id` at registration) so profiles link to identities.
2. Transactional outbox for reliable email delivery.
3. Redis-backed rate limiter + per-account (not just per-IP) limits.
4. Session introspection endpoint for other services (gateway auth).
