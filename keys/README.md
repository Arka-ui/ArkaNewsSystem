# Keys

- `public.pem` — commit this. Readers use it to verify that news is genuine.
- `private.pem` — **NEVER commit.** This is your signing identity. If it leaks, anyone
  can publish news under your name; rotate it by running `keygen --force` and pushing
  the new `public.pem`. The `.gitignore` at repo root already excludes `private.pem`.

Generate with:

```
python tools/ans.py keygen
```
