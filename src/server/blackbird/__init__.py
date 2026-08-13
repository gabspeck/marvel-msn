"""Blackbird wire codecs.

Submodules:

- `wire` — kind=5 raster, trailer, child-record, case-1 0xBF chunk
  builders and shared varint helpers.  Consumed by `services.medview`.
- `irquery` — IQuerySpec decoder for the search request `services.bbir`
  receives on BBIRService.
"""
