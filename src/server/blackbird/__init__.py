"""Blackbird codecs and storage readers.

Submodules:

- `wire`: MEDVIEW baggage and cache-push encoders (kind=5 raster, trailer,
  case-1 0xBF chunk, type-0/3/4 notification frames). Used by
  `services.medview`.
- `cos`: reads published compound files and builds the object stream
  Bbird_OB serves.
- `irquery`: IQuerySpec decoder for BBIRService queries.
- `irindex`: text index over published titles for those queries.
- `irresults`: IR result-stream encoder for the replies.
"""
