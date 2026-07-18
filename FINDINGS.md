# FINDINGS

Part 1 hardening log. One section per finding: the Section 4 invariant it broke,
the attacker role that reaches it, the reproduction, the fix, and the re-run that
confirms the attack now fails.

Invariants are numbered in the order Section 4 lists them:

| # | Invariant |
|---|---|
| 1 | Adapters must never see provider API keys. |
| 2 | Every action must be checked against the actual user, tenant, and final arguments. |
| 3 | External content must always be treated as data, never as instructions. |
| 4 | A credential must work only for one specific tool call. |
| 5 | Each tenant must have separate memory, and every stored fact must record its source. |
| 6 | Dangerous or high-impact actions must be approved with their final parameters. |
| 7 | Components must not be able to edit or delete their own audit logs. |
| 8 | Every run must have hard limits on time, tokens, tool calls, and cost. |

Attacker roles, weakest to strongest: **(1)** outsider on the public internet with
no credentials, **(2)** normal channel user who controls only the text they type,
**(3)** attacker who has taken over a single adapter container, **(4)** attacker
with code execution inside the gateway process.

## Findings

| ID | Finding | Invariant | Attacker role | Status |
|---|---|---|---|---|
| F-01 | Unauthenticated gateway with a public OpenAPI map | 2 | 1 — outsider, no credentials | Fixed |
| F-02 | Config disclosure on the read endpoints (`/v1/status`, `/v1/providers`, `/v1/capabilities`) | 2 | 1 — outsider, no credentials | Fixed by F-01 |

---

## F-01 — Unauthenticated gateway with a public OpenAPI map

**Invariant broken:** **#2 — "Every action must be checked against the actual
user, tenant, and final arguments."** The gateway executed `/v1/chat`,
`/v1/vision`, `/v1/embed`, `/v1/transcribe` and `/v1/speak` with no principal
attached at all, and it is reachable by the weakest attacker role — an outsider
on the public internet with no credentials — who reads the public
`/openapi.json` to learn exactly which routes to call.

Secondary pressure: **#8** (an anonymous caller burns tokens and bills the
operator with no limit) and, indirectly, **#1** (the outsider gains *use* of the
provider keys without ever holding the key material).

**Attacker role:** (1) outsider on the public internet, no credentials. No
adapter compromise and no chat access needed — the URL is enough.

**Asset reached:** use of the seven provider API keys, the cost ledger, and the
privacy of every user's messages.

### Reproduction (before the fix)

```sh
# Free recon: the full route, method, and schema inventory.
curl -s "$URL/openapi.json"
# -> 200, large JSON enumerating every /v1/* route

# And the routes it names are open to anyone.
curl -s -X POST "$URL/v1/chat" -H 'content-type: application/json' -d '{...}'
# -> 200, a completion paid for by the operator's keys
```

### Fix

- **`glc/auth.py` (new)** — shared `require_install_token` FastAPI dependency,
  reusing the existing `get_or_create_install_token()` from `glc/config.py`.
  401 on a missing/malformed Bearer, 403 on a mismatch.
- **`glc/main.py`** — applies that dependency to the chat, transcribe and speak
  routers; gates `docs_url` / `redoc_url` / `openapi_url` on
  `GLC_ENV=production` so they 404 in prod; stops advertising `/docs` on the
  landing page in prod.
- **`glc/routes/control.py`** — `_require_token` now delegates to the shared
  dependency, so the check lives in one place.
- **`modal_app.py`** — sets `GLC_ENV=production` in the image env.

Because the dependency is attached to the whole `chat.py` router, it covers the
read endpoints on that router too — which is what closed **F-02** without a
second code change.

Deliberately **not** gated: `/v1/channels/{name}/webhook` stays public because
external providers (Twilio, LINE) cannot present the install token. The channels
WebSocket and `/v1/control/*` keep their existing token checks. `/healthz` and
`/` stay public.

### Confirmed after the fix

Local run in both modes (`GLC_ENV` unset vs `production`), via `TestClient`:

| Request | dev | prod |
|---|---|---|
| `GET /openapi.json` | 200 | **404** |
| `GET /docs` | 200 | **404** |
| `GET /healthz`, `GET /` | 200 | 200 |
| `POST /v1/chat` — no token | **401** | **401** |
| `POST /v1/chat` — wrong token | **403** | **403** |
| `POST /v1/chat` — correct token | past auth | past auth |
| `POST /v1/channels/twilio_sms/webhook` — no token | 200 | 200 |

The recon and the unauthenticated call both fail. The webhook still works.

Against the deployment, after `uv run modal deploy modal_app.py`:

```sh
curl -s -o /dev/null -w '%{http_code}\n' "$URL/openapi.json"   # -> 404
curl -s -o /dev/null -w '%{http_code}\n' -X POST "$URL/v1/chat" \
     -H 'content-type: application/json' -d '{}'               # -> 401
```

### Operational note

Callers now need the Bearer token, which lives on the Modal volume at
`/data/glc/install_token`. Since the endpoint was open before this fix, rotate
the provider keys and the install token in case they were probed.

---

## F-02 — Config disclosure on the read endpoints

**Invariant broken:** **#2 — "Every action must be checked against the actual
user, tenant, and final arguments."** The read endpoints answered anyone with
the provider order, the model behind each provider, and the exact rpm/rpd/tpm
limits without checking any principal, and they are reached by the weakest
attacker role — an outsider on the public internet with no credentials.

This is the same invariant as F-01, and deliberately so: same trust boundary
(outsider → gateway), same missing check, different assets behind it.

Secondary: **#8** — publishing the exact rate limits is reconnaissance *for
evading* them, since an attacker who knows rpm/rpd/tpm can tune abuse to sit
just under the ceiling.

**Attacker role:** (1) outsider on the public internet, no credentials.

**Asset reached:** internal configuration (provider order, model per provider,
rate limits) — and, via `/v1/calls` and `/v1/cost/by_agent`, the **cost
ledger**, a named Section 3 asset. This one is not purely about configuration.

### Reproduction (before the fix)

```sh
curl -s "$URL/v1/status"        # -> 200, provider list + models + rpm/rpd/tpm
curl -s "$URL/v1/providers"     # -> 200
curl -s "$URL/v1/capabilities"  # -> 200
```

### Fix

**No separate code change was required — F-01 already closed this.**

All of these routes are declared on the *same* `APIRouter` as `/v1/chat`
(`router = APIRouter()` at `glc/routes/chat.py:72`). F-01 attached
`dependencies=[Depends(require_install_token)]` to that entire router in
`glc/main.py`, so every read endpoint on it inherited the token check.

That is the argument for gating at the router rather than per-handler: the
config-disclosure endpoints were fixed before they were separately reported,
and any route added to that router in future is closed by default rather than
open by default.

### Confirmed after the fix

Every read endpoint on the router, in production mode:

| Endpoint | no token | with token |
|---|---|---|
| `GET /v1/status` | **401** | 200 |
| `GET /v1/providers` | **401** | 200 |
| `GET /v1/capabilities` | **401** | 200 |
| `GET /v1/embedders` | **401** | 200 |
| `GET /v1/routers` | **401** | 200 |
| `GET /v1/calls` | **401** | 200 |
| `GET /v1/cost/by_agent` | **401** | 200 |

The disclosure fails for an unauthenticated caller.
