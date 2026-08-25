#!/usr/bin/env python3
"""X Ads API helper for tidex6 ceremony campaigns.

Uses OAuth 1.0a against ads-api.x.com/12 (campaign management).
Pixel/CAPI token (X-Pixel-Token) is a different product — it cannot create ads.

Credentials (single home for all X keys):
  ~/.config/x-api/credentials.env

Optional project override (gitignored):
  docs/ads/x_ads.env

Usage:
  python3 x_ads_cli.py whoami
  python3 x_ads_cli.py list
  python3 x_ads_cli.py launch --tweet-id <id>

Requires: requests, requests-oauthlib
  python3 -m pip install --user requests requests-oauthlib
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

try:
    from requests_oauthlib import OAuth1Session
except ImportError:
    print("python3 -m pip install --user requests requests-oauthlib", file=sys.stderr)
    sys.exit(2)

API = "https://ads-api.x.com/12"
HERE = Path(__file__).resolve().parent
HOME_CREDS = Path.home() / ".config" / "x-api" / "credentials.env"


def load_env(path: Path) -> None:
    if not path.is_file():
        return
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, _, v = line.partition("=")
        k, v = k.strip(), v.strip().strip('"').strip("'")
        if k and k not in os.environ:
            os.environ[k] = v


def load_all_creds() -> None:
    """Prefer ~/.config/x-api/credentials.env, then project docs/ads/x_ads.env."""
    load_env(HOME_CREDS)
    load_env(HERE / "x_ads.env")


def _first(*names: str) -> str:
    for n in names:
        v = os.environ.get(n, "").strip()
        if v:
            return v
    return ""


def session() -> tuple[OAuth1Session, str]:
    load_all_creds()
    # Canonical X_ADS_* plus aliases if you paste portal names.
    ck = _first("X_ADS_CONSUMER_KEY", "X_CONSUMER_KEY", "CONSUMER_KEY", "API_KEY")
    cs = _first(
        "X_ADS_CONSUMER_SECRET",
        "X_CONSUMER_SECRET",
        "CONSUMER_SECRET",
        "API_KEY_SECRET",
    )
    at = _first("X_ADS_ACCESS_TOKEN", "X_OAUTH1_ACCESS_TOKEN", "ACCESS_TOKEN")
    ats = _first(
        "X_ADS_ACCESS_TOKEN_SECRET",
        "X_OAUTH1_ACCESS_TOKEN_SECRET",
        "ACCESS_TOKEN_SECRET",
    )
    acct = _first("X_ADS_ACCOUNT_ID", "X_ACCOUNT_ID", "ACCOUNT_ID")

    # OAuth2 user token lives in the same file as X_ACCESS_TOKEN — NOT for Ads API.
    oauth2_only = bool(_first("X_ACCESS_TOKEN", "X_CLIENT_ID")) and not (ck and cs and at and ats)

    missing = [
        n
        for n, v in [
            ("X_ADS_CONSUMER_KEY (OAuth 1.0 Consumer Key)", ck),
            ("X_ADS_CONSUMER_SECRET", cs),
            ("X_ADS_ACCESS_TOKEN (OAuth 1.0 Access Token)", at),
            ("X_ADS_ACCESS_TOKEN_SECRET", ats),
        ]
        if not v
    ]
    if missing:
        print("Missing OAuth 1.0a keys for Ads API:", file=sys.stderr)
        for n in missing:
            print(f"  - {n}", file=sys.stderr)
        print(f"\nPrimary file: {HOME_CREDS}", file=sys.stderr)
        print(
            "Add OAuth 1.0 Keys from developer.x.com → App → Keys and tokens:\n"
            "  X_ADS_CONSUMER_KEY=...\n"
            "  X_ADS_CONSUMER_SECRET=...\n"
            "  X_ADS_ACCESS_TOKEN=...\n"
            "  X_ADS_ACCESS_TOKEN_SECRET=...\n"
            "  X_ADS_ACCOUNT_ID=...   # optional until whoami\n",
            file=sys.stderr,
        )
        if oauth2_only:
            print(
                "NOTE: file currently has OAuth 2.0 (X_CLIENT_ID / X_ACCESS_TOKEN) —\n"
                "that is for api.x.com v2 (tweets), NOT ads-api.x.com campaigns.\n"
                "Keep OAuth2 lines; APPEND OAuth 1.0a lines in the same file.",
                file=sys.stderr,
            )
        sys.exit(1)
    s = OAuth1Session(ck, client_secret=cs, resource_owner_key=at, resource_owner_secret=ats)
    return s, acct


def req(s: OAuth1Session, method: str, path: str, **kwargs):
    url = path if path.startswith("http") else f"{API}{path}"
    r = s.request(method, url, **kwargs)
    try:
        body = r.json()
    except Exception:
        body = {"raw": r.text[:2000]}
    if r.status_code >= 400:
        print(json.dumps({"status": r.status_code, "error": body}, indent=2), file=sys.stderr)
        r.raise_for_status()
    return body


def cmd_whoami(_: argparse.Namespace) -> None:
    s, _ = session()
    data = req(s, "GET", "/accounts")
    print(json.dumps(data, indent=2))
    # Hint account_id for .env
    for a in data.get("data") or []:
        print(
            f"# candidate X_ADS_ACCOUNT_ID={a.get('id')} name={a.get('name')}",
            file=sys.stderr,
        )


def cmd_list(_: argparse.Namespace) -> None:
    s, acct = session()
    if not acct:
        print("Set X_ADS_ACCOUNT_ID (from whoami)", file=sys.stderr)
        sys.exit(1)
    camps = req(s, "GET", f"/accounts/{acct}/campaigns", params={"with_deleted": "false"})
    print("=== campaigns ===")
    print(json.dumps(camps, indent=2))
    lines = req(s, "GET", f"/accounts/{acct}/line_items", params={"with_deleted": "false"})
    print("=== line_items ===")
    print(json.dumps(lines, indent=2))
    try:
        prom = req(
            s, "GET", f"/accounts/{acct}/promoted_tweets", params={"with_deleted": "false"}
        )
        print("=== promoted_tweets ===")
        print(json.dumps(prom, indent=2))
    except Exception as e:
        print(f"(promoted_tweets skipped: {e})", file=sys.stderr)


def cmd_funding(_: argparse.Namespace) -> None:
    s, acct = session()
    if not acct:
        print("Set X_ADS_ACCOUNT_ID", file=sys.stderr)
        sys.exit(1)
    data = req(s, "GET", f"/accounts/{acct}/funding_instruments")
    print(json.dumps(data, indent=2))


def cmd_pause_halted(_: argparse.Namespace) -> None:
    """Best-effort: pause line items / campaigns that look stopped. List first for control."""
    s, acct = session()
    if not acct:
        print("Set X_ADS_ACCOUNT_ID", file=sys.stderr)
        sys.exit(1)
    camps = req(s, "GET", f"/accounts/{acct}/campaigns", params={"with_deleted": "false"})
    for c in camps.get("data") or []:
        cid = c.get("id")
        ent = c.get("entity_status") or c.get("status")
        print(f"campaign {cid} status={ent} name={c.get('name')}")
        if str(ent).upper() in ("ACTIVE", "PAUSED"):
            # Operator control: only PAUSE if --yes later; default dry list
            pass
    print("Dry list only. To pause a campaign: launch pause-campaign --id <id>")


def cmd_pause_campaign(args: argparse.Namespace) -> None:
    s, acct = session()
    if not acct:
        sys.exit(1)
    body = req(
        s,
        "PUT",
        f"/accounts/{acct}/campaigns/{args.id}",
        params={"entity_status": "PAUSED"},
    )
    print(json.dumps(body, indent=2))


def cmd_launch(args: argparse.Namespace) -> None:
    """Create Website-traffic style campaign + line item + promote tweet.

    Steps mirror Ads UI: funding → campaign → line_item → promoted_tweet.
    Tweet must already exist (organic post id).
    """
    s, acct = session()
    if not acct:
        print("Set X_ADS_ACCOUNT_ID", file=sys.stderr)
        sys.exit(1)
    tweet_id = (args.tweet_id or os.environ.get("X_ADS_TWEET_ID") or "").strip()
    if not tweet_id:
        print("Need --tweet-id (numeric id of the NEW compliant post)", file=sys.stderr)
        sys.exit(1)

    funds = req(s, "GET", f"/accounts/{acct}/funding_instruments")
    fi = None
    for f in funds.get("data") or []:
        if f.get("able_to_fund") or f.get("entity_status") == "ACTIVE":
            fi = f
            break
    if not fi and funds.get("data"):
        fi = funds["data"][0]
    if not fi:
        print("No funding_instrument on account", file=sys.stderr)
        sys.exit(1)
    fi_id = fi["id"]
    print(f"funding_instrument={fi_id}", file=sys.stderr)

    from datetime import datetime, timedelta, timezone

    name = args.name or os.environ.get("X_ADS_CAMPAIGN_NAME") or "tidex6-ceremony-compliant"
    daily = int(
        args.daily_budget_micros
        or os.environ.get("X_ADS_DAILY_BUDGET_MICROS")
        or "5000000"
    )
    now = datetime.now(timezone.utc).replace(microsecond=0)
    start = now.isoformat().replace("+00:00", "Z")
    end = (now + timedelta(days=7)).isoformat().replace("+00:00", "Z")
    status = "PAUSED" if args.paused else "ACTIVE"

    # Campaign — WEBSITE_CLICKS / website traffic objective naming varies by API version.
    camp = req(
        s,
        "POST",
        f"/accounts/{acct}/campaigns",
        params={
            "name": name,
            "funding_instrument_id": fi_id,
            "entity_status": status,
            "daily_budget_amount_local_micro": daily,
        },
    )
    camp_id = (camp.get("data") or {}).get("id")
    print(json.dumps(camp, indent=2))
    if not camp_id:
        sys.exit(1)

    # Line item — product type PROMOTED_TWEETS, objective WEBSITE_CLICKS
    # Ads API 12 requires start_time on line items.
    line = req(
        s,
        "POST",
        f"/accounts/{acct}/line_items",
        params={
            "campaign_id": camp_id,
            "name": f"{name}-line",
            "product_type": "PROMOTED_TWEETS",
            "placements": "ALL_ON_TWITTER",
            "objective": "WEBSITE_CLICKS",
            "entity_status": status,
            "bid_strategy": "AUTO",
            "goal": "LINK_CLICKS",
            "start_time": start,
            "end_time": end,
        },
    )
    print(json.dumps(line, indent=2))
    line_id = (line.get("data") or {}).get("id")
    if not line_id:
        print("line_item create failed — check objective/placements for your API access", file=sys.stderr)
        sys.exit(1)

    # Optional website URL card targeting is on the tweet/card itself.
    # API expects tweet_ids (plural), not tweet_id.
    prom = req(
        s,
        "POST",
        f"/accounts/{acct}/promoted_tweets",
        params={"line_item_id": line_id, "tweet_ids": tweet_id},
    )
    print(json.dumps(prom, indent=2))
    print(
        json.dumps(
            {
                "ok": True,
                "account_id": acct,
                "campaign_id": camp_id,
                "line_item_id": line_id,
                "tweet_id": tweet_id,
                "paused": bool(args.paused),
            },
            indent=2,
        )
    )


def main() -> None:
    p = argparse.ArgumentParser(description="tidex6 X Ads API CLI")
    sub = p.add_subparsers(dest="cmd", required=True)

    sub.add_parser("whoami", help="List ads accounts (get account_id)")
    sub.add_parser("list", help="List campaigns / line items / promoted tweets")
    sub.add_parser("funding", help="List funding instruments")
    sub.add_parser("pause-halted", help="List campaigns (dry)")
    sp = sub.add_parser("pause-campaign", help="PAUSED a campaign by id")
    sp.add_argument("--id", required=True)

    lp = sub.add_parser("launch", help="Create campaign + line item + promote tweet")
    lp.add_argument("--tweet-id", default="")
    lp.add_argument("--name", default="")
    lp.add_argument("--daily-budget-micros", type=int, default=0)
    lp.add_argument(
        "--paused",
        action="store_true",
        help="Create PAUSED so you review in UI before spend",
    )

    args = p.parse_args()
    {
        "whoami": cmd_whoami,
        "list": cmd_list,
        "funding": cmd_funding,
        "pause-halted": cmd_pause_halted,
        "pause-campaign": cmd_pause_campaign,
        "launch": cmd_launch,
    }[args.cmd](args)


if __name__ == "__main__":
    main()
