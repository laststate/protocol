# Architecture

## Layers

```mermaid
flowchart TB
  app[Event / application TLVs]
  env[Envelope header + CRC]
  sec[Optional AEAD / HMAC / compress]
  frag[Optional fragmentation]
  frame[Framing Stream / COBS / …]
  tx[Transport UART / TCP / HTTP / …]
  app --> env --> sec --> frag --> frame --> tx
```

Validate in order: framing → envelope integrity → security → TLV parse → application.

The envelope does not embed transport headers. Same LEP bytes may go UART, file, or HTTP.
