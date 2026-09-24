# LEP billing events (informational)

> Status: informational companion to the frozen LEP v2 contract. This file
> does not change envelope encoding, CRCs, or TLV assignments — it documents
> how metering and entitlement signals already carried by the platform map to
> `billing-service` realtime events.

LEP v2 is frozen (`FREEZE.md`). Billing does not add wire types; it consumes
counters the pipeline already emits.

## Metering source

- Every accepted envelope increments the `events` meter (per org, per day).
- Relay reports `POST billing-service /v1/usage` every 60s with
  `Idempotency-Key: org:events:YYYYMMDDHHMM`.
- Simulator reports the same way (`org:sim:YYYYMMDDHH:MM`).
- Trace rollups feed `GET /v1/usage/charges` (base + overage per plan).

## Billing event mapping

| billing-service v2 / SSE | Trigger in the LEP pipeline |
|--------------------------|-----------------------------|
| `subscription.created|updated|canceled` | tier apply via trace admin API (`billing_event_id` idempotent) |
| `invoice.paid|failed` | provider webhook (`/webhooks/stripe|mercado-pago|crypto|nowpayments`) |
| `usage.limit_exceeded` | quota middleware deny in trace, cached-tier cap in relay |
| `dunning.escalated` | billing dunning worker after `BILLING_DUNNING_MAX_ATTEMPTS` |

## Verification

- Webhook receivers check `X-LastState-Signature: sha256=<hmac(secret, raw-body)>`
  and `X-LastState-Event: <type>`.
- Live tails use `GET billing-service /v1/billing/events/stream`
  (`organization_id` + `events` query filters, `: ping` every 15s).
- Golden vectors in `protocol/test-vectors` remain the conformance gate —
  billing mapping adds no new vectors by design.
