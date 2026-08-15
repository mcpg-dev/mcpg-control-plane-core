# mcpg-control-plane-core

> Shared types, traits, schema migrations, and the gRPC agent contract every MCPG Control Plane component is built on.

The MCPG Control Plane is the multi-tenant service that gateways register with,
heartbeat to, and pull configuration from. This crate is the vocabulary all of
its components agree on: the typed tenant identifiers, the domain model, the
`mcpg.cp.v1` gRPC contract compiled from `proto/mcpg/cp/v1/agent.proto`, the
at-rest envelope-encryption primitive, the SQL migrations that define the
schema, and the small pieces of shared policy — the publish guard, the usage
report, the public-route rate limiter — where two services drifting apart would
be a security or billing bug. It is a library of contracts and shared
primitives; the HTTP API, the gRPC server, and the database access layer live in
`apps/control-plane/server`.

## What's here
- `proto` — the gRPC types generated from `proto/mcpg/cp/v1/agent.proto`. The
  `AgentControl` service (`Register`, `Channel`, `PullConfig`, `Heartbeat`,
  `Deregister`) and its messages, including `ConfigBundle`, `MetricsReport`,
  `LogBatch`, `QuotaStatus` and `CredentialRotation`. The `mcpg.cp.v1` package
  is a public stability commitment.
- `model` — `Org` (with `ORG_STATUS_ACTIVE` / `ORG_STATUS_SUSPENDED` /
  `ORG_STATUS_DECOMMISSIONING` and `is_suspended()` / `is_decommissioning()`),
  `Workspace`, `Environment`, `Instance` with `InstanceState`,
  `InstancePlacement`, `ProviderName`, `PluginSet` / `PluginEntry`, and `User`.
- `provider` — the `InstanceProvider` discovery trait (`name`, `list`, `watch`,
  and the optional `register` / `deregister`, which default to
  `Error::Unsupported`), plus `InstanceEvent`, `DepartedReason`,
  `RegistrationClaim`, `AddressableEndpoint` and `is_live()`.
- `ids` and `license`, re-exported from `mcpg-control-plane-license` so
  every control-plane component reads one definition of `OrgId`, `OrgSlug`,
  `LicenseClaims`, `Quotas` and the entitlement gates.
- `cipher` — the `EnvelopeCipher` trait and its implementations: `NoopCipher`
  (pass-through, for development and self-hosting without a key), `LocalCipher`
  (AES-256-GCM under a base64 32-byte master key), and, behind the non-default
  `kms` feature, `VaultTransitCipher` with `VaultKmsConfig`. Every call binds a
  caller-chosen `context` string into the AEAD associated data — a tenant slug
  for control-plane payloads, a cluster id for provisioner credentials — so one
  tenant's ciphertext cannot be decrypted as another's even under the same
  master key. `build()` selects an implementation from the configured key;
  `build_strict(key, require_encryption)` returns
  `CipherError::EncryptionRequired` instead of silently falling back to
  plaintext, which is what a production deployment passes.
- `publish_guard` — `check_published_config(raw)`, the pre-deploy guard for
  tenant-authored gateway configs. A published config runs in the tenant's own
  pod at config-origin trust, so the guard rejects the constructs that would
  read host state from there — `${env.…}` interpolation and `env://` / `file://`
  secret URIs — and the ones that would reach the pod's internal network:
  `allow_private_backends` and federation upstreams pointed at a literal private
  address. It inspects leaf string values only, never keys or comments, reports
  every violation at once, and fails closed on input that parses as neither YAML
  nor TOML. Credential URIs the tenant owns are allowed and merely checked for
  well-formedness, and a `tunnel://` upstream stays permitted because it egresses
  through the authenticated relay. `require_cloud_auth(raw)` is the companion
  check on the config's authentication posture.
- `usage_report` — `UsageReport` and `OrgUsage`, the one definition of the
  billing figures the control plane serves and the billing federation consumes.
  Two hand-written copies is exactly how a field rename silently deserializes to
  zero and bills a tenant nothing.
- `ratelimit::RateLimiter` — a dependency-light per-IP token bucket for
  unauthenticated public routes such as enrollment and login. It is pure: the
  caller extracts `X-Forwarded-For` and the transport peer, `client_ip()`
  resolves them (honouring the forwarded header only when `trust_proxy` is set,
  since it is otherwise spoofable), and the caller applies the verdict in its own
  middleware.
- `error::{Error, Result}`, `env_aliases::mirror_long_to_short()` (accepts
  `MCPG_CONTROL_PLANE_*` as a synonym for every `MCPG_CP_*` variable, with the
  short form winning; call it as the first statement in `main`), and
  `tls_init::install_default_crypto_provider()`, which pins a single rustls
  crypto provider at boot so a process linking both `aws-lc-rs` and `ring`
  starts deterministically.
- `migrations/sqlite/` and `migrations/postgres/` — the schema. The Postgres set
  carries the row-level-security policies that enforce per-tenant isolation
  against the `mcpg.org_id` session variable. `apps/control-plane/server` embeds
  these directories at compile time and runs them.
- Cargo features: `sqlite` (default) and `postgres` select the sqlx engines,
  with `tier0`, `tier1` and `tier2` as presets over that pair; `kms` adds the
  Vault Transit cipher and its HTTP client, and is off by default so builds that
  use no external KMS stay lean.

## Used by
- `apps/control-plane/server` — the `mcpg-cp` binary serving the HTTP API and
  the `AgentControl` gRPC service.
- `libs/control-plane/client` — the gateway-side agent, which speaks the
  generated `mcpg.cp.v1` types.
- `apps/gateway` under its embedded-control-plane feature, `mcpg-admin`, and the
  Cloud-only federation and provisioner services.

## Build / test
```bash
cargo build -p mcpg-control-plane-core
cargo test  -p mcpg-control-plane-core

# The row-level-security suite needs a real Postgres it is allowed to wipe.
export MCPG_POSTGRES_TEST_URL=postgres://postgres:postgres@127.0.0.1:5432/mcpg_test
cargo test -p mcpg-control-plane-core --features postgres --test postgres_rls
```

The build script compiles the protobuf contract with a vendored `protoc`, so no
system protobuf installation is required.

## Licence
Apache-2.0.

## See also
- [Cloud overview](https://mcpg.dev/docs/cloud/overview) — what the Control Plane does for an operator.
- [`mcpg cp` reference](https://mcpg.dev/docs/reference/cli/cp)
- `libs/control-plane/client` — the gateway side of the agent contract.
- `libs/control-plane/license` — the licensing types this crate re-exports.
