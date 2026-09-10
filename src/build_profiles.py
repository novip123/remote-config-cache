# -*- coding: utf-8 -*-
import json, os, sys, time, urllib.request
from pathlib import Path
from subscription_converter import subscription_to_mihomo, add_happ_metadata, subscription_to_happ_text

ROOT=Path(__file__).resolve().parents[1]
SITE=ROOT/"site"

def fetch(p, attempts=4, user_agent_override=None):
    h={
        "User-Agent": user_agent_override or p.get("user_agent","Clash-Verge"),
        "X-HWID":p["hwid"],
        "Accept":"*/*"
    }
    for header,key in (
        ("X-Device-OS","device_os"),
        ("X-Ver-OS","os_version"),
        ("X-Device-Model","device_model")
    ):
        v=str(p.get(key,"")).strip()
        if v:h[header]=v

    req=urllib.request.Request(p["subscription_url"],headers=h,method="GET")
    last=None
    for i in range(1,attempts+1):
        try:
            with urllib.request.urlopen(req,timeout=int(p.get("timeout",25))) as r:
                return r.read(),r.status,i
        except Exception as e:
            last=e
            print(f"[{p.get('slug','?')}] attempt {i}/{attempts} UA={h['User-Agent']}: {e}")
            if i<attempts:time.sleep(i)
    raise last

def valid_slug(s):
    return bool(s) and len(s)<=120 and all(c.isalnum() or c in "-_" for c in s)

def main():
    raw=os.environ.get("PROFILES_JSON","").strip()
    if not raw:raise SystemExit("PROFILES_JSON secret is empty")
    ps=json.loads(raw)
    if not isinstance(ps,list):raise SystemExit("PROFILES_JSON must be a JSON array")

    SITE.mkdir(exist_ok=True)
    (SITE/".nojekyll").write_text("",encoding="utf-8")
    (SITE/"index.html").write_text(
        "<!doctype html><meta charset='utf-8'><title>Remote Config</title>"
        "<body>Remote configuration service is running.</body>",
        encoding="utf-8"
    )

    failed=0
    for p in ps:
        s=str(p.get("slug","")).strip()
        if not valid_slug(s):raise ValueError(f"Invalid slug {s!r}")
        try:
            # Request 1: format intended for Clash/Mihomo.
            clash_raw,clash_status,clash_attempt=fetch(
                p,
                user_agent_override=p.get("user_agent","Clash-Verge")
            )
            out,fmt,warnings=subscription_to_mihomo(clash_raw)
            out=add_happ_metadata(
                out,
                p.get("profile_title",s),
                p.get("profile_update_interval_minutes",60),
                p.get("subscription_userinfo",""),
                p.get("support_url",""),
                p.get("profile_web_page_url",""),
                p.get("description","")
            )
            (SITE/(s+".yaml")).write_bytes(out)

            # Request 2: neutral/fallback UA for Happ. Remnawave normally falls
            # back to XRAY_BASE64 / URI subscription for an unknown UA.
            happ_ua=p.get("happ_user_agent","RemnaHWIDFetcher/1.0")
            happ_raw,happ_status,happ_attempt=fetch(
                p,
                user_agent_override=happ_ua
            )
            happ_out,happ_fmt=subscription_to_happ_text(
                happ_raw,
                p.get("profile_title",s),
                p.get("profile_update_interval_minutes",60),
                p.get("subscription_userinfo",""),
                p.get("support_url",""),
                p.get("profile_web_page_url",""),
                p.get("description","")
            )
            (SITE/(s+".txt")).write_bytes(happ_out)

            print(
                f"[{s}] OK "
                f"clash_http={clash_status} clash_ua={p.get('user_agent','Clash-Verge')} clash={fmt} "
                f"happ_http={happ_status} happ_ua={happ_ua} happ={happ_fmt} "
                f"yaml={len(out)} txt={len(happ_out)} "
                f"attempts={clash_attempt}/{happ_attempt}"
            )
            for w in (warnings or [])[:10]:
                print(f"[{s}] WARNING {w}")
        except Exception as e:
            failed+=1
            print(f"[{s}] FAILED {type(e).__name__}: {e}",file=sys.stderr)

    from datetime import datetime, timezone
    (SITE/"worker.log").write_text(
        "Remote config worker\n"
        +"last_update_utc="+datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")+"\n"
        +"profiles_total="+str(len(ps))+"\n"
        +"profiles_success="+str(len(ps)-failed)+"\n"
        +"profiles_failed="+str(failed)+"\n", encoding="utf-8")

    if failed:raise SystemExit(1)

if __name__=="__main__":
    main()
