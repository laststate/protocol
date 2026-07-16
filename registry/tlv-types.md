# TLV registry

Unencrypted LEP v1 payload = contiguous TLVs, no padding:

```
type u16 LE | length u16 LE | value[length]
```

- `type == 0` is illegal.
- Unknown types: skip by length.
- Nested identity strings: `field_id u8 | str_len u8 | utf8[str_len]`.

## IDs

| Type | Name | Repeatable |
|-----:|------|:----------:|
| 0 | RESERVED | — |
| 1 | IDENTITY | no |
| 2 | RESET | no |
| 3 | EVENT | no |
| 4 | CPU | no |
| 5 | FAULT | no |
| 6 | BREADCRUMB | yes |
| 7 | METRIC | yes |
| 8 | POWER | yes |
| 9 | HEALTH | no |
| 10 | ASSERT | no |
| 11 | PERIPHERAL | no |
| 12 | LOG | no |
| 13 | MEMORY | yes |
| 14 | STACK | no |
| 15 | HEAP | no |
| 0x0010–0x0013 | build/project/release/hash extensions | — |
| 0x0020–0x0021 | attachment meta/chunk | yes (chunk) |
| 0x0030 | probe waveform (reserved) | — |
| 0x8000–0x8FFF | vendor | — |
| 0xF000–0xFFFE | experimental | — |

Header `event_type` (u8): 1 CRASH, 2 ERROR, 3 MESSAGE, 4 HEALTH, 5 RESET, 6 LOG, 7 PERIPHERAL, 8 COREDUMP.

Header flags: bit0 AUTH, 1 ENC, 2 AEAD, 3 TRUNCATED, 4 COMPRESSED. Known mask `0x1F`.

---

## 1 IDENTITY

Nested strings, field_id 1..15 in order:

| ID | Name |
|---:|------|
| 1 | project_id |
| 2 | device_id |
| 3 | product |
| 4 | hardware_revision |
| 5 | bom_revision |
| 6 | manufacturing_batch |
| 7 | firmware_version |
| 8 | firmware_build_id |
| 9 | bootloader_version |
| 10 | git_commit |
| 11 | variant |
| 12 | architecture |
| 13 | rtos |
| 14 | region |
| 15 | device_group |

## 2 RESET (20 bytes)

| Off | Size | Field |
|----:|-----:|-------|
| 0 | 1 | reason |
| 1 | 4 | raw_reason |
| 5 | 4 | boot_count |
| 9 | 4 | previous_uptime_ms |
| 13 | 4 | timestamp_ms |
| 17 | 1 | expected |
| 18 | 1 | previous_crashed |
| 19 | 1 | boot_loop |

reason: 0 UNKNOWN … 4 WATCHDOG, 5 IWDG, 6 WWDG, 7 BROWNOUT, … 13 CLOCK_FAILURE (see Latch `ls_reset_reason`).

## 3 EVENT (28 bytes)

| Off | Size | Field |
|----:|-----:|-------|
| 0 | 1 | priority |
| 1 | 1 | severity |
| 2 | 1 | capture_level |
| 3 | 4 | domain_hash |
| 7 | 4 | code |
| 11 | 4 | message_hash |
| 15 | 4 | fingerprint |
| 19 | 4 | repeat_count |
| 23 | 4 | first_seen_ms |
| 27 | 4 | last_seen_ms |

severity 0..4 = DEBUG..FATAL. capture_level 0..4 = METADATA..FULL.

## 4 CPU / 5 FAULT

See [`../spec/architectures.md`](../spec/architectures.md).

## 6 BREADCRUMB

`at_ms u32 | message_id u16 | severity u8 | category_hash u32 | message_hash u32`  
[+ optional nested strings 1=category, 2=message]  
`| value_count u8 | (key_id u16, type u8, value u32)×N`  
value type: 0=i32, 1=u32, 2=bool.

## 7 METRIC

`name_hash u32` [+ optional name string field 1] `| type u8 | value | previous | min | max | sum u64 | count u32 | window_count u8 | window[] u32`  
type: 1=i32, 2=u32, 3=bool, 4=counter.

## 8 POWER (16 bytes)

`timestamp_ms | vdd_mv | battery_mv | current_ma | temperature_c | charger_status | power_flags` (u32 + 6×u16).

## 9 HEALTH (10 bytes)

`watchdog_last_feed_ms u32 | checkpoint u16 | active_task_hash u32`

## 10 ASSERT

`line u32 | expression_hash u32 | file_hash u32` [+ optional nested strings expression/file/message].

## 11 PERIPHERAL (37 bytes)

`domain u8 | fault u16 | instance u16 | status u32 | address u32 | reg u32 | timeout_ms u32 | auxiliary[4] u32`  
domain: 0 I2C … 6 NETWORK.

## 12 LOG

`message_id u16 | format_id u16 | argument_count u8 | arguments[N] u32`

## 13 MEMORY

`name_hash | address | region_length | flags | data or hash or zeros`  
flags: SAFE, HASH, VOLATILE, SENSITIVE.

## 14 STACK

`stack_pointer u32 | length u32 | bytes[length]`

## 15 HEAP (20 bytes)

`free_bytes | minimum_free | largest_block | allocation_failures | pool_exhaustions`
