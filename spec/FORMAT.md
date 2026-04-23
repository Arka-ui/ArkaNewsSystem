# ANS1 file format

A `.ans` file is a UTF-8 text file with three sections separated by lines
containing exactly `---`.

```
ANS1
id: <hex sha256 of PAYLOAD>
author: <string>
timestamp: <ISO-8601 UTC, e.g. 2026-04-23T10:00:00Z>
---
title: <one-line string>
tags: <comma,separated,tags>          # optional
---
<markdown body, any length>
```

Appended to the file, on its own line after a blank line:

```
sig: <base64(Ed25519 signature over PAYLOAD)>
```

## What is `PAYLOAD`?

`PAYLOAD` = everything from the first byte of the file up to and including the
newline right before `sig:` (i.e. the file minus the trailing signature line
and the blank line preceding it).

The `id` field must equal `sha256(PAYLOAD without the id line substituted by a placeholder)`.
To keep this deterministic, the canonical algorithm is:

1. Build the file content with `id: ` left as `id: PENDING`.
2. `H = sha256(content_with_pending_id)` (hex).
3. Replace `PENDING` with `H` — that's the final `id`.
4. Sign the final content (with real id) with Ed25519, producing `sig`.

Verification does the inverse:
1. Strip the trailing `sig: ...` line to get PAYLOAD.
2. Verify Ed25519(PAYLOAD, sig) with the repo's public key.
3. Recompute `H'` by setting `id:` back to `PENDING` and hashing; require `H' == id`.

## Guarantees

- Any byte modified anywhere in the file invalidates either the hash or the signature.
- The `id` is content-addressed: two identical articles get the same id.
- The file is self-contained: no external references needed to verify it.
