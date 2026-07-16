# Identity

Device and firmware identity for symbolication, tenancy, and deduplication.

## Header vs payload

| Field | Where in v1 |
|-------|-------------|
| `architecture` | Fixed header byte (numeric code) |
| `event_id`, `sequence` | Fixed header |
| Project / device / build strings | Payload **TLV type 1** (`IDENTITY`) |
| Reset / boot counters | Payload **TLV type 2** (`RESET`) |

## IDENTITY TLV (type = 1)

Value is a sequence of **nested string fields** (not top-level TLVs):

```
field = field_id (u8) || str_len (u8) || utf8_bytes[str_len]
```

- No NUL terminator.
- `str_len` is 0..255; producers SHOULD truncate longer strings and set envelope `TRUNCATED`.
- Empty string is valid (field present with `str_len = 0`).
- Unknown `field_id` values SHOULD be skipped by length for forward compatibility.

### Nested field IDs (Latch order)

| ID | Name | Requirement | Notes |
|---:|------|-------------|-------|
| 1 | `project_id` | Recommended | Tenant / project |
| 2 | `device_id` | Required* | Unique device; or anonymous id |
| 3 | `product` | Recommended | Product SKU / name |
| 4 | `hardware_revision` | Recommended | PCB rev |
| 5 | `bom_revision` | Optional | BOM |
| 6 | `manufacturing_batch` | Optional | Lot |
| 7 | `firmware_version` | Recommended | Human version string |
| 8 | `firmware_build_id` | Required* | Symbolication key |
| 9 | `bootloader_version` | Optional | |
| 10 | `git_commit` | Optional | |
| 11 | `variant` | Optional | Build flavor |
| 12 | `architecture` | Optional | String complement to header code |
| 13 | `rtos` | Optional | |
| 14 | `region` | Optional | |
| 15 | `device_group` | Optional | Fleet grouping |

\* **Required*** means: producers SHOULD always emit; consumers MUST tolerate absence for legacy/minimal events but MAY mark lower trust.

## Build ID

Inside nested field 8, v1 carries a **UTF-8 string** (often hex GNU build-id or custom). Binary-typed build IDs (`GNU_BUILD_ID`, raw SHA-256, UUID) are reserved for future TLV extensions (see registry). Consumers matching ELFs SHOULD:

1. Prefer exact string match on `firmware_build_id`.
2. Fall back to normalized hex (lowercase, no separators).

## Strings

| Rule | Value |
|------|-------|
| Encoding | UTF-8 |
| NUL inside string | MUST NOT be used by producers; consumers MAY reject or truncate at first NUL |
| Normalization | NFC recommended, not required in v1 |
| Max length | 255 per nested field; policy MAY impose lower |
| IDs charset (recommended) | `[A-Za-z0-9._:-]` for `project_id` / `device_id` |

## RESET TLV (type = 2) — boot context

| Offset | Size | Field |
|-------:|-----:|-------|
| 0 | 1 | `reason` (`ls_reset_reason` code) |
| 1 | 4 | `raw_reason` u32 |
| 5 | 4 | `boot_count` u32 |
| 9 | 4 | `previous_uptime_ms` u32 |
| 13 | 4 | `timestamp_ms` u32 (event time, uptime-based unless otherwise known) |
| 17 | 1 | `expected` (0/1) |
| 18 | 1 | `crash_pending` / previous crashed (0/1) |
| 19 | 1 | `boot_loop` (0/1) |

`boot_count` serves as a durable **boot identifier** when the device has persistence. Devices without NVM MAY use 0 and MUST accept reduced correlation quality.
