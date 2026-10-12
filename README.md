# Callback-only Render service

A standalone HTTP callback forwarder for an existing backend. This repository does not contain a Telegram bot, Telegram ingestion, an MCP server, subscription storage, a scheduler, or automatic replies. Local tests are not proof of a deployed or end-to-end working integration.

## Files and runtime

Requires Node.js 24 or newer. Uses only built-in Node.js modules; no package installation or private source directory is required. The Docker image runs as the unprivileged `node` user. `render.yaml` describes a Docker web service with automatic deploys disabled.

- `GET /healthz`: process liveness only.
- `POST /internal/callback`: accepts an HMAC-authenticated JSON envelope containing `url`, `body` (a string), and `headers`.
- Other routes, including query-string variants of these routes, are rejected.

Only `webhook-id`, `webhook-timestamp`, `webhook-signature`, and `X-MCP-Subscription-Id` are forwarded, with a fixed JSON content type. The upstream backend must produce valid signed event or verification payloads. The forwarder authenticates the envelope; it does not validate the receiver's event-signing secret or complete a subscription lifecycle on its own.

The callback must use HTTPS and an explicitly allowed DNS hostname. DNS results are checked for public addresses, and the connection is pinned to a validated address while preserving TLS hostname verification. Redirects are not followed. Request/response sizes, concurrency, and outbound duration are bounded. Responses to authenticated requests are signed and must be verified by the calling backend using the original request ID and response body.

## Configuration

Set these values through the hosting platform's secret/environment settings. Never commit live values to this repository, a YAML file, screenshots, or logs.

- `CALLBACK_HMAC_KEY`: `<CANONICAL_BASE64_32_BYTE_SERVICE_KEY>`
- `MCP_CALLBACK_HOSTS`: `<VERIFIED_CALLBACK_DNS_HOST>` or comma-separated verified exact DNS hosts
- `PORT`: supplied by the hosting platform; defaults to `10000`

Angle-bracket placeholders are documentation only and will not pass configuration validation. No working credentials are included. The service key must be dedicated to this callback connection and shared only with the calling backend. Do not configure Telegram tokens, owner identifiers, event-signing secrets, or unrelated application credentials here. The two required secrets/settings in `render.yaml` have no committed values (`sync: false`).

Publish or deploy only the files in this standalone directory at the repository root. Do not copy a larger application, local environment files, old archives, private documentation, or source history into it. Review repository access and the hosting provider's data handling before deployment: the service receives callback URLs, signed headers, and event bodies in memory. This code does not log or persist payloads; hosting-platform logging and access controls require a separate review.

## Local checks and deployment

Run `npm test` to execute the tests. Run `npm start` with valid configuration to start the service; missing or malformed required configuration fails closed. Test fixtures are synthetic, including their deterministic test key; never reuse them in production. The manifest's free plan is a pilot configuration, not an uptime guarantee. Confirm current plan availability, pricing, and limits with the provider before deploying.

The optional one-shot command below waits at most two minutes for process health at a verified Render service origin. Replace the placeholder with the actual service origin:

    node prewarm.mjs https://YOUR-SERVICE.onrender.com

It is an explicit operator action, not a scheduled keepalive. A successful health check means the process is awake, not that callback verification or delivery succeeded. Perform a real signed subscription-verification exchange after warming the process.

## Delivery and security limits

Cold starts can exceed the calling backend's request timeout. The calling system needs its own durable queue/retry behavior and stable event IDs; receivers must deduplicate events because a transport timeout does not prove non-delivery. This forwarder cannot recover abandoned deliveries or renew subscriptions autonomously.

The transport replay cache is bounded and in memory, retained for 610 seconds. It does not survive restarts or span instances. A previously captured signed request may therefore re-deliver its original event after a restart within the timestamp window. Use a shared replay store if cross-restart transport replay prevention is required, and durable receiver-side event deduplication in all cases.

Before relying on the service, validate the Docker build and hosting manifest, real DNS/TLS delivery, rejection of invalid signatures, synchronous challenge echo, response signatures, timeouts, duplicate delivery, cold starts, restart behavior, and the complete calling application's lifecycle. Local tests mock outbound transport and do not establish these live properties. No deployment or publication is performed by this package.
