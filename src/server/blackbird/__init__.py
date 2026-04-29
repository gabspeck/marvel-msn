"""Blackbird-side encoders that bridge authored `.ttl` content to MEDVIEW
wire bytes.

The `wire` submodule contains the kind=5 raster + trailer + child-record
builders consumed by `services.medview` to synthesise `bm<N>` baggage
payloads from authored `CContent` and `CSection` data.

Format references — `docs/MEDVIEW.md` §10.2/§10.3 (trailer + child
record), `docs/BLACKBIRD.md` §8 (VIEWDLL Serialize methods).
"""
