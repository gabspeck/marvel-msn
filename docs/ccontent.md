# CContent — TextRuns body decoder

`server.services.medview.ccontent` decodes a CContent stream's
`TextRuns` payload into typed Python objects. PR1 scope: header pin
+ raw text extraction; style runs and TextTree decode are deferred.

## TextRuns header (empirical)

Pinned against `resources/titles/msn_today.ttl` `8/7/\x03object` (122 B,
type=`TextRuns`).

| Offset | Size | Field | Notes |
|---|---|---|---|
| `+0x00` | 1 | `version` | observed `0x02` (only value seen) |
| `+0x01` | 1 | `header_byte_1` | observed `0x00`; semantics unknown |
| `+0x02` | N | `raw_payload` | byte-for-byte CContent body |

`text` is `raw_payload.decode("ascii", errors="replace")`. The first
character of `raw_payload` for both observed samples is a single ASCII
letter (msn_today: `'S'`, showcase 9/1: `'3'`) which precedes the
prose body — likely an in-stream paragraph-style marker. PR2
(BBCTL.OCX + MVPUBKIT compiler RE) will pin its semantics. Until
then, consumers should match on **substring**, not equality
(`"This is an example of content" in text`).

## TextTree gate

`is_texttree(raw)` returns True when `raw[:2] == b"\x01\x05"` (matches
msn_today `8/6` and `8/2`). `decode_textruns` raises
`NotImplementedError` on this header so callers (`load_title`'s Story
chase) can defer cleanly. TextTree decoding (a richer text-with-style
container) is out of scope for PR1.

## Empty / short payloads

`8/3` (msn_today TextRuns placeholder) is the 2-byte sentinel
`00 00` — `decode_textruns` returns an empty container (no exception)
so the chase doesn't fail spuriously. Zero-length input is also
tolerated.

## Style runs (PR1: always empty)

`StyleRun(char_offset, char_length, style_id)` is the surface PR2
should populate from the in-stream style markers. `decode_textruns`
returns `style_runs = ()` in PR1; downstream lowering ignores the
field.

## Consumers

- `ttl_loader._chase_story_content` resolves a `StoryControl`'s body
  via the chase described in `docs/cvform-page-objects.md`. The
  decoded `TextRunsContent` is attached as `StoryControl.content`.
- PR3 wire-lowering will emit the per-page Story text into bm baggage
  metafiles using the resolved `content.text`.
