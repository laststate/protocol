# Architecture codes and CPU context

Header `architecture` (u8):

| Code | Name |
|-----:|------|
| 0 | unknown |
| 1 | cortex-m |
| 2 | riscv |
| 3 | xtensa |
| 4 | linux |
| ≥5 | future (e.g. arm-a) — allocate via RFC |

## CPU TLV (type 4) — Latch multi-arch container

| Order | Field | Size |
|------:|-------|-----:|
| 1 | architecture u8 | 1 |
| 2 | fault kind u8 | 1 |
| 3 | registers[32] u32 | 128 |
| 4 | specials[18] u32 | 72 |
| 5 | has_fpu u8 | 1 |
| 6 | fpu_lazy u8 | 1 |
| 7 | if has_fpu: s[16] + fpscr | 68 |

**specials order:**  
`lr, pc, xpsr, msp, psp, control, primask, basepri, faultmask, exc_return, mcause, mtval, mstatus, mepc, exccause, excvaddr, ps, sar`

Unused slots for the active arch are zero.

### fault kind

| 0 UNKNOWN | 1 HARD | 2 MEMMANAGE | 3 BUS | 4 USAGE | 5 NMI | 6 SECURE | 7 STACK | 8 ASSERT | 9 SIGNAL | 10 TRAP |

## FAULT TLV (type 5)

13 × u32 LE:  
`cfsr, hfsr, dfsr, afsr, mmfar, bfar, shcsr, icsr, vtor, sfsr, sfar, fault_address, signal_number`

Cortex-M uses CFSR/HFSR/…; RISC-V/Xtensa leave most zero and use specials for trap state.

Full TLV sizes: [`../registry/tlv-types.md`](../registry/tlv-types.md).
