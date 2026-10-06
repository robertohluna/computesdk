---
"@computesdk/miosa": patch
---

perf(miosa): send on the first ready HTTP/2 session instead of waiting for a quorum

Cold requests no longer wait for 8 of 16 pooled sessions to finish their TLS
handshakes (up to 250 ms after the first). A request is dispatched as soon as
any session is connected, round-robins across ready sessions, and the rest of
the pool keeps connecting in the background. Requests the server provably did
not process (REFUSED_STREAM, including streams above a GOAWAY last-stream-id,
or a session that closed before the stream opened) are resent up to twice;
GET and DELETE are also resent after transport failures. When no session can
connect, the connection error now surfaces immediately instead of after a 1 s
wait followed by a TypeError.
