#!/usr/bin/env python3
"""Arka News System CLI: keygen | post | verify | build."""
from __future__ import annotations

import argparse
import base64
import getpass
import hashlib
import json
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from xml.sax.saxutils import escape as xml_escape

try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey,
        Ed25519PublicKey,
    )
    from cryptography.hazmat.primitives import serialization
    from cryptography.exceptions import InvalidSignature
except ImportError:
    sys.stderr.write("ERROR: install dependency first:  pip install cryptography\n")
    sys.exit(2)

ROOT = Path(__file__).resolve().parent.parent
NEWS_DIR = ROOT / "news"
KEYS_DIR = ROOT / "keys"
API_DIR = ROOT / "api"
CONFIG_FILE = ROOT / "ans.config.json"

PRIVATE_KEY_FILE = KEYS_DIR / "private.pem"
PUBLIC_KEY_FILE = KEYS_DIR / "public.pem"


def load_config() -> dict:
    if CONFIG_FILE.exists():
        return json.loads(CONFIG_FILE.read_text(encoding="utf-8"))
    return {}


def save_config(cfg: dict) -> None:
    CONFIG_FILE.write_text(json.dumps(cfg, indent=2), encoding="utf-8")


# ---------------------------------------------------------------------------
# key management
# ---------------------------------------------------------------------------
def cmd_keygen(args: argparse.Namespace) -> int:
    KEYS_DIR.mkdir(exist_ok=True)
    if PRIVATE_KEY_FILE.exists() and not args.force:
        print(f"refusing to overwrite {PRIVATE_KEY_FILE} (use --force)")
        return 1

    priv = Ed25519PrivateKey.generate()
    pub = priv.public_key()

    password = None
    if not args.no_password:
        p1 = getpass.getpass("Passphrase for private key (empty = no passphrase): ")
        if p1:
            p2 = getpass.getpass("Confirm passphrase: ")
            if p1 != p2:
                print("passphrases do not match")
                return 1
            password = p1.encode()

    enc = (
        serialization.BestAvailableEncryption(password)
        if password
        else serialization.NoEncryption()
    )
    PRIVATE_KEY_FILE.write_bytes(
        priv.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=enc,
        )
    )
    PUBLIC_KEY_FILE.write_bytes(
        pub.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )
    try:
        os.chmod(PRIVATE_KEY_FILE, 0o600)
    except OSError:
        pass

    print(f"wrote {PRIVATE_KEY_FILE}  (KEEP SECRET, do NOT commit)")
    print(f"wrote {PUBLIC_KEY_FILE}   (commit this)")
    return 0


def load_private_key() -> Ed25519PrivateKey:
    if not PRIVATE_KEY_FILE.exists():
        raise SystemExit(f"no private key at {PRIVATE_KEY_FILE}. Run: ans.py keygen")
    data = PRIVATE_KEY_FILE.read_bytes()
    try:
        key = serialization.load_pem_private_key(data, password=None)
    except TypeError:
        pw = getpass.getpass("Private key passphrase: ").encode()
        key = serialization.load_pem_private_key(data, password=pw)
    if not isinstance(key, Ed25519PrivateKey):
        raise SystemExit("private key is not Ed25519")
    return key


def load_public_key() -> Ed25519PublicKey:
    if not PUBLIC_KEY_FILE.exists():
        raise SystemExit(f"no public key at {PUBLIC_KEY_FILE}")
    key = serialization.load_pem_public_key(PUBLIC_KEY_FILE.read_bytes())
    if not isinstance(key, Ed25519PublicKey):
        raise SystemExit("public key is not Ed25519")
    return key


# ---------------------------------------------------------------------------
# .ans format
# ---------------------------------------------------------------------------
PLACEHOLDER = "PENDING"
SIG_RE = re.compile(r"\n\nsig: ([A-Za-z0-9+/=]+)\s*$")


def build_payload(
    author: str,
    timestamp: str,
    title: str,
    tags: list[str],
    body: str,
    id_value: str,
) -> str:
    tags_line = f"tags: {','.join(tags)}\n" if tags else ""
    return (
        f"ANS1\n"
        f"id: {id_value}\n"
        f"author: {author}\n"
        f"timestamp: {timestamp}\n"
        f"---\n"
        f"title: {title}\n"
        f"{tags_line}"
        f"---\n"
        f"{body.rstrip()}\n"
    )


def compute_id(author: str, timestamp: str, title: str, tags: list[str], body: str) -> str:
    pending = build_payload(author, timestamp, title, tags, body, PLACEHOLDER)
    return hashlib.sha256(pending.encode("utf-8")).hexdigest()


def parse_ans(text: str) -> tuple[str, str, dict, str]:
    """Return (payload, signature_b64, header_dict, body)."""
    m = SIG_RE.search(text)
    if not m:
        raise ValueError("missing trailing 'sig:' line")
    signature = m.group(1)
    payload = text[: m.start()] + "\n"  # keep final newline of payload

    parts = payload.split("\n---\n")
    if len(parts) < 3:
        raise ValueError("malformed: expected 3 sections separated by '---'")
    header_block, meta_block, body_block = parts[0], parts[1], "\n---\n".join(parts[2:])
    if not header_block.startswith("ANS1\n"):
        raise ValueError("missing ANS1 magic")

    header: dict = {}
    for line in header_block.splitlines()[1:]:
        if ":" in line:
            k, v = line.split(":", 1)
            header[k.strip()] = v.strip()
    meta: dict = {}
    for line in meta_block.splitlines():
        if ":" in line:
            k, v = line.split(":", 1)
            meta[k.strip()] = v.strip()
    header["title"] = meta.get("title", "")
    header["tags"] = [t.strip() for t in meta.get("tags", "").split(",") if t.strip()]
    body = body_block.rstrip("\n")
    return payload, signature, header, body


# ---------------------------------------------------------------------------
# post
# ---------------------------------------------------------------------------
def slugify(s: str) -> str:
    s = re.sub(r"[^A-Za-z0-9]+", "-", s.lower()).strip("-")
    return s or "untitled"


def cmd_post(args: argparse.Namespace) -> int:
    NEWS_DIR.mkdir(exist_ok=True)
    cfg = load_config()

    title = args.title or input("Title: ").strip()
    if not title:
        print("title required")
        return 1

    author = args.author or cfg.get("author")
    if not author:
        author = input("Author: ").strip() or "anonymous"
        cfg["author"] = author
        save_config(cfg)

    tags = [t.strip() for t in (args.tags or "").split(",") if t.strip()]

    if args.body:
        body = args.body
    elif args.file:
        body = Path(args.file).read_text(encoding="utf-8")
    else:
        print("Body (end with a single '.' on its own line):")
        lines: list[str] = []
        for line in sys.stdin:
            if line.strip() == ".":
                break
            lines.append(line.rstrip("\n"))
        body = "\n".join(lines)

    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    news_id = compute_id(author, timestamp, title, tags, body)
    payload = build_payload(author, timestamp, title, tags, body, news_id)

    priv = load_private_key()
    sig = priv.sign(payload.encode("utf-8"))
    sig_b64 = base64.b64encode(sig).decode("ascii")

    final = payload + "\nsig: " + sig_b64 + "\n"

    date = timestamp[:10]
    filename = f"{date}-{slugify(title)}-{news_id[:8]}.ans"
    out = NEWS_DIR / filename
    out.write_text(final, encoding="utf-8")
    print(f"wrote {out}")
    print(f"id={news_id}")
    return 0



# ---------------------------------------------------------------------------
# publish  (post + push to GitHub via Contents API — no git required)
# ---------------------------------------------------------------------------
def cmd_publish(args: argparse.Namespace) -> int:
    import urllib.request
    import urllib.error

    # 1. Reuse post logic to create the signed .ans in-memory
    NEWS_DIR.mkdir(exist_ok=True)
    cfg = load_config()

    title = args.title or input("Title: ").strip()
    if not title:
        print("title required"); return 1

    author = args.author or cfg.get("author")
    if not author:
        author = input("Author: ").strip() or "anonymous"
        cfg["author"] = author
        save_config(cfg)

    tags = [t.strip() for t in (args.tags or "").split(",") if t.strip()]

    if args.body:
        body = args.body
    elif args.file:
        body = Path(args.file).read_text(encoding="utf-8")
    else:
        print("Body (end with a single '.' on its own line):")
        lines: list[str] = []
        for line in sys.stdin:
            if line.strip() == ".":
                break
            lines.append(line.rstrip("\n"))
        body = "\n".join(lines)

    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    news_id = compute_id(author, timestamp, title, tags, body)
    payload = build_payload(author, timestamp, title, tags, body, news_id)

    priv = load_private_key()
    sig = priv.sign(payload.encode("utf-8"))
    sig_b64 = base64.b64encode(sig).decode("ascii")
    final = payload + "\nsig: " + sig_b64 + "\n"

    date = timestamp[:10]
    filename = f"{date}-{slugify(title)}-{news_id[:8]}.ans"

    # 2. Push via GitHub Contents API
    token = args.token or os.environ.get("GITHUB_TOKEN") or cfg.get("github_token")
    if not token:
        print("ERROR: no GitHub token — set GITHUB_TOKEN env var, pass --token, or add github_token to ans.config.json")
        return 1

    owner = cfg.get("github_owner")
    repo  = cfg.get("github_repo")
    branch = cfg.get("github_branch", "master")
    if not owner or not repo:
        print("ERROR: github_owner / github_repo missing from ans.config.json")
        return 1

    content_b64 = base64.b64encode(final.encode("utf-8")).decode("ascii")
    api_url = f"https://api.github.com/repos/{owner}/{repo}/contents/news/{filename}"
    payload_api = json.dumps({
        "message": f"Post: {title}",
        "content": content_b64,
        "branch": branch,
    }).encode("utf-8")

    req = urllib.request.Request(
        api_url,
        data=payload_api,
        method="PUT",
        headers={
            "Authorization": f"token {token}",
            "Accept": "application/vnd.github+json",
            "Content-Type": "application/json",
            "User-Agent": "ans-cli/1.0",
        },
    )
    try:
        with urllib.request.urlopen(req) as resp:
            result = json.loads(resp.read())
        sha = result["content"]["sha"][:8]
        html = result["content"]["html_url"]
        print(f"published: {filename}")
        print(f"id={news_id}")
        print(f"sha={sha}  url={html}")
        print("CI will verify + rebuild the API automatically.")
        return 0
    except urllib.error.HTTPError as e:
        body_err = e.read().decode()
        print(f"GitHub API error {e.code}: {body_err}")
        return 1

# ---------------------------------------------------------------------------
# verify
# ---------------------------------------------------------------------------
def verify_file(path: Path, pub: Ed25519PublicKey) -> tuple[bool, str, dict | None, str | None]:
    try:
        text = path.read_text(encoding="utf-8")
        payload, sig_b64, header, body = parse_ans(text)
    except Exception as e:
        return False, f"parse error: {e}", None, None

    try:
        pub.verify(base64.b64decode(sig_b64), payload.encode("utf-8"))
    except InvalidSignature:
        return False, "bad signature", None, None
    except Exception as e:
        return False, f"verify error: {e}", None, None

    declared_id = header.get("id", "")
    recomputed = compute_id(
        header.get("author", ""),
        header.get("timestamp", ""),
        header.get("title", ""),
        header.get("tags", []),
        body,
    )
    if declared_id != recomputed:
        return False, f"id mismatch (declared {declared_id[:12]}, computed {recomputed[:12]})", None, None

    header["body"] = body
    header["signature"] = sig_b64
    return True, "ok", header, payload


def cmd_verify(args: argparse.Namespace) -> int:
    pub = load_public_key()
    files = sorted(NEWS_DIR.glob("*.ans"))
    if not files:
        print("no news files found")
        return 0
    failures = 0
    for p in files:
        ok, msg, _, _ = verify_file(p, pub)
        status = "OK  " if ok else "FAIL"
        print(f"{status}  {p.name}  — {msg}")
        if not ok:
            failures += 1
    if failures:
        print(f"\n{failures} invalid file(s)")
        return 1
    print(f"\nAll {len(files)} file(s) verified.")
    return 0


# ---------------------------------------------------------------------------
# build
# ---------------------------------------------------------------------------
def github_urls(cfg: dict, filename: str) -> tuple[str, str]:
    owner = cfg.get("github_owner", "OWNER")
    repo = cfg.get("github_repo", "REPO")
    branch = cfg.get("github_branch", "main")
    src = f"https://github.com/{owner}/{repo}/blob/{branch}/news/{filename}"
    raw = f"https://raw.githubusercontent.com/{owner}/{repo}/{branch}/news/{filename}"
    return src, raw


def cmd_build(args: argparse.Namespace) -> int:
    pub = load_public_key()
    cfg = load_config()

    API_DIR.mkdir(exist_ok=True)
    (API_DIR / "news").mkdir(exist_ok=True)

    items: list[dict] = []
    files = sorted(NEWS_DIR.glob("*.ans"))
    for p in files:
        ok, msg, header, _ = verify_file(p, pub)
        if not ok:
            raise SystemExit(f"verification failed for {p.name}: {msg}")
        src_url, raw_url = github_urls(cfg, p.name)
        item = {
            "id": header["id"],
            "title": header["title"],
            "author": header.get("author", ""),
            "timestamp": header.get("timestamp", ""),
            "tags": header.get("tags", []),
            "body": header["body"],
            "signature": header["signature"],
            "source_url": src_url,
            "raw_url": raw_url,
            "filename": p.name,
        }
        items.append(item)
        (API_DIR / "news" / f"{header['id']}.json").write_text(
            json.dumps(item, indent=2, ensure_ascii=False), encoding="utf-8"
        )

    items.sort(key=lambda x: x["timestamp"], reverse=True)
    index = {
        "system": "Arka News System",
        "version": 1,
        "count": len(items),
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "public_key_url": "public_key.pem",
        "news": [
            {k: v for k, v in it.items() if k != "body"}  # index is light
            for it in items
        ],
    }
    (API_DIR / "index.json").write_text(
        json.dumps(index, indent=2, ensure_ascii=False), encoding="utf-8"
    )
    if items:
        (API_DIR / "latest.json").write_text(
            json.dumps(items[0], indent=2, ensure_ascii=False), encoding="utf-8"
        )

    # public key copy for consumers
    (API_DIR / "public_key.pem").write_bytes(PUBLIC_KEY_FILE.read_bytes())

    # rss
    site_title = cfg.get("site_title", "Arka News System")
    site_url = cfg.get("site_url", "")
    rss_items = []
    for it in items[:50]:
        rss_items.append(
            "<item>"
            f"<title>{xml_escape(it['title'])}</title>"
            f"<link>{xml_escape(it['source_url'])}</link>"
            f"<guid isPermaLink=\"false\">{it['id']}</guid>"
            f"<pubDate>{xml_escape(it['timestamp'])}</pubDate>"
            f"<author>{xml_escape(it['author'])}</author>"
            f"<description>{xml_escape(it['body'])}</description>"
            "</item>"
        )
    rss = (
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<rss version="2.0"><channel>'
        f"<title>{xml_escape(site_title)}</title>"
        f"<link>{xml_escape(site_url)}</link>"
        f"<description>{xml_escape(site_title)} feed</description>"
        + "".join(rss_items)
        + "</channel></rss>"
    )
    (API_DIR / "feed.xml").write_text(rss, encoding="utf-8")

    # tiny landing page
    links = "".join(
        f'<li><a href="news/{it["id"]}.json">{xml_escape(it["title"])}</a> '
        f'— <a href="{xml_escape(it["source_url"])}">source</a></li>'
        for it in items
    )
    (API_DIR / "index.html").write_text(
        f"""<!doctype html><meta charset="utf-8">
<title>{xml_escape(site_title)}</title>
<h1>{xml_escape(site_title)}</h1>
<p>Static API powered by <a href="https://github.com/{cfg.get('github_owner','OWNER')}/{cfg.get('github_repo','REPO')}">Arka News System</a>.</p>
<ul><li><a href="index.json">index.json</a></li>
<li><a href="latest.json">latest.json</a></li>
<li><a href="feed.xml">feed.xml</a></li>
<li><a href="public_key.pem">public_key.pem</a></li></ul>
<h2>Articles</h2><ul>{links}</ul>""",
        encoding="utf-8",
    )

    print(f"built api/ with {len(items)} article(s).")
    return 0


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------
def main() -> int:
    p = argparse.ArgumentParser(prog="ans", description="Arka News System CLI")
    sub = p.add_subparsers(dest="cmd", required=True)

    k = sub.add_parser("keygen", help="Generate an Ed25519 keypair")
    k.add_argument("--force", action="store_true", help="overwrite existing keys")
    k.add_argument("--no-password", action="store_true", help="do not encrypt the private key")
    k.set_defaults(func=cmd_keygen)

    po = sub.add_parser("post", help="Create and sign a news file")
    po.add_argument("--title")
    po.add_argument("--author")
    po.add_argument("--tags", help="comma-separated")
    po.add_argument("--body", help="body text inline")
    po.add_argument("--file", help="read body from this file")
    po.set_defaults(func=cmd_post)

    pub_cmd = sub.add_parser("publish", help="Create, sign and push directly to GitHub (no git needed)")
    pub_cmd.add_argument("--title")
    pub_cmd.add_argument("--author")
    pub_cmd.add_argument("--tags", help="comma-separated")
    pub_cmd.add_argument("--body", help="body text inline")
    pub_cmd.add_argument("--file", help="read body from this file")
    pub_cmd.add_argument("--token", help="GitHub personal access token (overrides env/config)")
    pub_cmd.set_defaults(func=cmd_publish)

    v = sub.add_parser("verify", help="Verify all .ans files")
    v.set_defaults(func=cmd_verify)

    b = sub.add_parser("build", help="Build static API into api/")
    b.set_defaults(func=cmd_build)

    args = p.parse_args()
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
