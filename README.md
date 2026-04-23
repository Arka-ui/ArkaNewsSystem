# Arka News System (ANS)

A free, open-source, GitHub-hosted news publishing system.
You write, sign, and push — the world reads.

## What it is

- **A file format** (`.ans`) for compact, cryptographically signed news articles.
- **A static API** auto-generated from your repo and served by GitHub Pages.
- **A CLI** to create, sign, verify and build news.

No servers. No databases. No fees. Just Git + cryptography.

## How it works

```
    You                          GitHub                      The World
  ───────                       ──────────                   ───────────
  ans post  ──►  news/*.ans  ──► repo  ──► Action  ──► api/*.json ──► readers
    (sign)                          (verify + build)        (GitHub Pages)
```

1. You create a news article with `python tools/ans.py post`.
2. It signs the article with your private Ed25519 key (never leaves your machine).
3. You `git commit && git push`.
4. GitHub Action verifies every `.ans` signature. If any fails, the build stops.
5. The Action regenerates `api/` (static JSON + RSS) and deploys it to GitHub Pages.
6. Anyone can fetch news via the API, and anyone can re-verify signatures with your public key.

## Security model

- Only holder of the private key can produce valid news. Anyone else's commits will fail CI.
- Every article's ID is `sha256(payload)`. Content changes = ID changes = signature breaks.
- The public key lives in `keys/public.pem` so any consumer can verify locally.
- Embedders should include a link to `source_url` (the raw GitHub blob) — tamper-proof provenance for every reader.

## Quick start

```bash
# 1. Install dependency
pip install cryptography

# 2. Generate your keys (ONCE — keep private.pem SECRET, never commit)
python tools/ans.py keygen

# 3. Write a news
python tools/ans.py post --title "Hello world" --tags intro,news

# 4. Verify everything
python tools/ans.py verify

# 5. Build the API locally (optional — CI does this too)
python tools/ans.py build

# 6. Publish
git add news/ keys/public.pem
git commit -m "Post: Hello world"
git push
```

## Consuming the API

Base URL (after you enable GitHub Pages on your repo):
`https://<your-user>.github.io/<your-repo>/api/`

Endpoints (all static JSON):

| Path | Description |
|---|---|
| `api/index.json`       | All news, newest first, full metadata |
| `api/latest.json`      | The most recent news item |
| `api/news/<id>.json`   | A specific news item |
| `api/feed.xml`         | RSS 2.0 feed |
| `api/public_key.pem`   | Your public key (for independent verification) |

Each news JSON includes:
```json
{
  "id": "sha256:...",
  "title": "...",
  "author": "...",
  "timestamp": "2026-04-23T10:00:00Z",
  "tags": ["..."],
  "body": "...",
  "signature": "base64...",
  "source_url": "https://github.com/<user>/<repo>/blob/main/news/<id>.ans",
  "raw_url":    "https://raw.githubusercontent.com/<user>/<repo>/main/news/<id>.ans"
}
```

**Embedders:** always link the headline to `source_url` so readers can jump to the signed original.

## Repo layout

```
news/                    your signed .ans files (source of truth)
keys/
  public.pem             committed — anyone can verify with this
  private.pem            NEVER commit (gitignored)
api/                     auto-generated static API (built by CI)
tools/ans.py             the CLI (keygen, post, verify, build)
spec/FORMAT.md           the .ans file format spec
.github/workflows/       CI: verify + build + deploy Pages
```

## License

MIT. Do what you want.
