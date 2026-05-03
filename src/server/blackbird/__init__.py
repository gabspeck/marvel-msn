"""Blackbird-side encoders that bridge authored `.ttl` content to MEDVIEW
wire bytes.

Submodules:

- `wire` — kind=5 raster, trailer, child-record, case-1 0xBF chunk
  builders consumed by `services.medview` to synthesise `bm<N>` baggage
  payloads (`docs/MEDVIEW.md` §10.2/§10.3, `docs/BLACKBIRD.md` §8).
- `ttl_inspect` — Blackbird `.ttl` (OLE2 compound file) parser
  (`docs/blackbird-title-format.md`).
- `m14_parse` — MediaView 1.4 cache/payload structural parser
  (`docs/mosview-mediaview-format.md` "Payload Grammar").
- `m14_synth` — `.ttl` → MediaView 1.4 payload synthesizer.
- `m14_payload` — wire-mode adapter for `services.medview`; handles
  missing/unsynthesizable `.ttl` files with an empty fallback and emits
  the live wire path's real section-0 font table plus code-proven
  fixed-record sections.
"""

from .m14_payload import (
    M14PayloadResult,
    TitleOpenMetadata,
    TopicEntry,
    build_empty_m14_payload,
    build_m14_payload_for_deid,
)

__all__ = [
    "M14PayloadResult",
    "TitleOpenMetadata",
    "TopicEntry",
    "build_empty_m14_payload",
    "build_m14_payload_for_deid",
]
