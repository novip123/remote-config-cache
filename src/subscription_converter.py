# -*- coding: utf-8 -*-
import base64, json
from urllib.parse import urlparse, parse_qs, unquote

def _b64decode_loose(s):
    s = "".join(s.strip().split())
    s += "=" * ((4 - len(s) % 4) % 4)
    for fn in (base64.b64decode, base64.urlsafe_b64decode):
        try:
            return fn(s.encode()).decode("utf-8", errors="replace")
        except Exception:
            pass
    raise ValueError("invalid base64")

def decode_subscription_text(data):
    text = data.decode("utf-8", errors="replace").strip()
    if "://" in text:
        return text
    try:
        decoded = _b64decode_loose(text).strip()
        if "://" in decoded:
            return decoded
    except Exception:
        pass
    return text

def _first(q, key, default=None):
    v = q.get(key)
    return v[0] if v else default

def _bool(v, default=False):
    if v is None: return default
    return str(v).lower() in ("1","true","yes","on")

def _int(v, default=None):
    try: return int(v)
    except: return default

def parse_vless(uri):
    p=urlparse(uri)
    q=parse_qs(p.query)
    name=unquote(p.fragment) or f"VLESS {p.hostname}"
    x={
        "name":name,"type":"vless","server":p.hostname,"port":p.port,
        "uuid":unquote(p.username or ""),"udp":True
    }
    flow=_first(q,"flow")
    if flow: x["flow"]=flow
    network=_first(q,"type","tcp")
    x["network"]=network
    sec=_first(q,"security")
    if sec=="tls":
        x["tls"]=True
        sni=_first(q,"sni")
        if sni: x["servername"]=sni
        fp=_first(q,"fp")
        if fp: x["client-fingerprint"]=fp
        if _bool(_first(q,"allowInsecure")): x["skip-cert-verify"]=True
    elif sec=="reality":
        x["tls"]=True
        x["reality-opts"]={}
        pbk=_first(q,"pbk")
        sid=_first(q,"sid")
        if pbk: x["reality-opts"]["public-key"]=pbk
        if sid: x["reality-opts"]["short-id"]=sid
        sni=_first(q,"sni")
        if sni: x["servername"]=sni
        fp=_first(q,"fp")
        if fp: x["client-fingerprint"]=fp
    if network=="ws":
        path=_first(q,"path","/")
        host=_first(q,"host")
        x["ws-opts"]={"path":path}
        if host: x["ws-opts"]["headers"]={"Host":host}
    elif network=="grpc":
        svc=_first(q,"serviceName") or _first(q,"service-name")
        x["grpc-opts"]={}
        if svc: x["grpc-opts"]["grpc-service-name"]=svc
    return x

def parse_trojan(uri):
    p=urlparse(uri); q=parse_qs(p.query)
    x={"name":unquote(p.fragment) or f"Trojan {p.hostname}",
       "type":"trojan","server":p.hostname,"port":p.port,
       "password":unquote(p.username or ""),"udp":True}
    sni=_first(q,"sni") or _first(q,"peer")
    if sni:x["sni"]=sni
    if _bool(_first(q,"allowInsecure")):x["skip-cert-verify"]=True
    net=_first(q,"type")
    if net=="ws":
        x["network"]="ws"
        x["ws-opts"]={"path":_first(q,"path","/")}
        host=_first(q,"host")
        if host:x["ws-opts"]["headers"]={"Host":host}
    elif net=="grpc":
        x["network"]="grpc"
        svc=_first(q,"serviceName") or _first(q,"service-name")
        if svc:x["grpc-opts"]={"grpc-service-name":svc}
    return x

def parse_ss(uri):
    raw=uri[5:]
    frag=""
    if "#" in raw:
        raw,frag=raw.split("#",1)
    name=unquote(frag) or "Shadowsocks"
    # ss://base64(method:password)@host:port OR base64(method:pass@host:port)
    if "@" in raw:
        auth,hostport=raw.split("@",1)
        try:
            auth_dec=_b64decode_loose(auth)
        except:
            auth_dec=unquote(auth)
        method,password=auth_dec.split(":",1)
        hp=urlparse("ss://x@"+hostport)
        return {"name":name,"type":"ss","server":hp.hostname,"port":hp.port,
                "cipher":method,"password":password,"udp":True}
    decoded=_b64decode_loose(raw)
    methodpass,hostport=decoded.rsplit("@",1)
    method,password=methodpass.split(":",1)
    hp=urlparse("ss://x@"+hostport)
    return {"name":name,"type":"ss","server":hp.hostname,"port":hp.port,
            "cipher":method,"password":password,"udp":True}

def parse_vmess(uri):
    raw=uri[len("vmess://"):]
    obj=json.loads(_b64decode_loose(raw))
    x={
        "name":obj.get("ps") or f"VMess {obj.get('add','')}",
        "type":"vmess","server":obj.get("add"),"port":int(obj.get("port")),
        "uuid":obj.get("id"),"alterId":int(obj.get("aid",0) or 0),
        "cipher":obj.get("scy") or "auto","udp":True
    }
    net=obj.get("net") or "tcp"
    x["network"]=net
    if str(obj.get("tls","")).lower() in ("tls","1","true"):
        x["tls"]=True
        sni=obj.get("sni") or obj.get("host")
        if sni:x["servername"]=sni
        if str(obj.get("allowInsecure","")).lower() in ("1","true"):x["skip-cert-verify"]=True
    if net=="ws":
        x["ws-opts"]={"path":obj.get("path") or "/"}
        if obj.get("host"):x["ws-opts"]["headers"]={"Host":obj["host"]}
    elif net=="grpc":
        svc=obj.get("path") or obj.get("serviceName")
        if svc:x["grpc-opts"]={"grpc-service-name":svc}
    return x

def parse_hysteria2(uri):
    p=urlparse(uri);q=parse_qs(p.query)
    x={"name":unquote(p.fragment) or f"Hysteria2 {p.hostname}",
       "type":"hysteria2","server":p.hostname,"port":p.port,
       "password":unquote(p.username or ""), "udp":True}
    sni=_first(q,"sni")
    if sni:x["sni"]=sni
    if _bool(_first(q,"insecure")):x["skip-cert-verify"]=True
    obfs=_first(q,"obfs")
    obfs_password=_first(q,"obfs-password") or _first(q,"obfsPassword")
    if obfs:
        x["obfs"]=obfs
        if obfs_password:x["obfs-password"]=obfs_password
    return x

def parse_tuic(uri):
    p=urlparse(uri);q=parse_qs(p.query)
    user=unquote(p.username or "")
    pwd=unquote(p.password or "")
    x={"name":unquote(p.fragment) or f"TUIC {p.hostname}",
       "type":"tuic","server":p.hostname,"port":p.port,
       "uuid":user,"password":pwd,"udp":True}
    sni=_first(q,"sni")
    if sni:x["sni"]=sni
    cc=_first(q,"congestion_control") or _first(q,"congestion-control")
    if cc:x["congestion-controller"]=cc
    alpn=_first(q,"alpn")
    if alpn:x["alpn"]=[a for a in alpn.split(",") if a]
    if _bool(_first(q,"allow_insecure")) or _bool(_first(q,"insecure")):
        x["skip-cert-verify"]=True
    return x

def parse_uri(uri):
    uri=uri.strip()
    if not uri:return None
    if uri.startswith("vless://"): return parse_vless(uri)
    if uri.startswith("vmess://"): return parse_vmess(uri)
    if uri.startswith("trojan://"): return parse_trojan(uri)
    if uri.startswith("ss://"): return parse_ss(uri)
    if uri.startswith(("hysteria2://","hy2://")): return parse_hysteria2(uri)
    if uri.startswith("tuic://"): return parse_tuic(uri)
    return None

def yaml_scalar(v):
    if v is None:return "null"
    if isinstance(v,bool):return "true" if v else "false"
    if isinstance(v,(int,float)):return str(v)
    s=str(v)
    if s=="" or any(c in s for c in ":#{}[],&*?|-<>=!%@\\\"'") or s.strip()!=s:
        return json.dumps(s,ensure_ascii=False)
    return s

def dump_yaml_obj(obj, indent=0):
    out=[]
    sp=" " * indent
    if isinstance(obj,dict):
        for k,v in obj.items():
            if isinstance(v,(dict,list)):
                out.append(f"{sp}{k}:")
                out.extend(dump_yaml_obj(v,indent+2))
            else:
                out.append(f"{sp}{k}: {yaml_scalar(v)}")
    elif isinstance(obj,list):
        for v in obj:
            if isinstance(v,dict):
                out.append(f"{sp}-")
                out.extend(dump_yaml_obj(v,indent+2))
            elif isinstance(v,list):
                out.append(f"{sp}-")
                out.extend(dump_yaml_obj(v,indent+2))
            else:
                out.append(f"{sp}- {yaml_scalar(v)}")
    return out

def subscription_to_mihomo(data):
    text=data.decode("utf-8",errors="replace").lstrip()
    # Already a full-ish YAML.
    if any(x in text for x in ("proxies:","proxy-groups:","rules:")) and ":" in text:
        return data, "yaml-pass-through", None

    decoded=decode_subscription_text(data)
    lines=[ln.strip() for ln in decoded.replace("\r","\n").split("\n") if ln.strip()]
    proxies=[]
    errors=[]
    for ln in lines:
        if "://" not in ln: continue
        try:
            p=parse_uri(ln)
            if p:proxies.append(p)
            else:errors.append("unsupported: "+ln[:24])
        except Exception as e:
            errors.append(f"{ln[:20]}... -> {e}")

    if not proxies:
        raise ValueError("Не удалось получить ни одной поддерживаемой ноды из Base64/URI подписки.")

    # Ensure unique names because Mihomo expects proxy names to be unique.
    seen={}
    for p in proxies:
        n=p["name"]
        if n in seen:
            seen[n]+=1
            p["name"]=f"{n} #{seen[n]}"
        else:
            seen[n]=1

    names=[p["name"] for p in proxies]
    cfg={
        "mixed-port":7890,
        "allow-lan":False,
        "mode":"rule",
        "log-level":"info",
        "ipv6":True,
        "proxies":proxies,
        "proxy-groups":[
            {"name":"PROXY","type":"select","proxies":names+["DIRECT"]},
            {"name":"AUTO","type":"url-test","proxies":names,
             "url":"https://www.gstatic.com/generate_204","interval":300,"tolerance":100},
        ],
        "rules":["MATCH,PROXY"]
    }
    yaml="\n".join(dump_yaml_obj(cfg))+"\n"
    return yaml.encode("utf-8"), f"converted-uri-list ({len(proxies)} nodes)", errors



import base64 as _meta_base64

def add_happ_metadata(yaml_data, title="", update_interval_minutes=None,
                      subscription_userinfo="", support_url="", web_page_url="",
                      description=""):
    """Prepend Happ subscription metadata as YAML comments."""
    lines = []

    title = str(title or "").strip()
    if title:
        title = title[:25]
        try:
            title.encode("ascii")
            title_value = title
        except UnicodeEncodeError:
            title_value = "base64:" + _meta_base64.b64encode(title.encode("utf-8")).decode("ascii")
        lines.append(f"#profile-title: {title_value}")

    # Happ accepts the update interval in HOURS only.
    if update_interval_minutes not in (None, ""):
        try:
            minutes = int(update_interval_minutes)
            if minutes >= 60 and minutes % 60 == 0:
                lines.append(f"#profile-update-interval: {minutes // 60}")
        except Exception:
            pass

    subscription_userinfo = str(subscription_userinfo or "").strip()
    support_url = str(support_url or "").strip()
    web_page_url = str(web_page_url or "").strip()
    description = str(description or "").strip()

    if subscription_userinfo:
        lines.append(f"#subscription-userinfo: {subscription_userinfo}")
    if support_url:
        lines.append(f"#support-url: {support_url}")
    if web_page_url:
        lines.append(f"#profile-web-page-url: {web_page_url}")
    if description:
        # Happ announce supports text or base64. Base64 avoids problems with
        # spaces/non-ASCII/special characters in a comment metadata line.
        raw = description[:200].encode("utf-8")
        encoded = _meta_base64.b64encode(raw).decode("ascii")
        lines.append(f"#announce: base64:{encoded}")

    if not lines:
        return yaml_data

    prefix = ("\n".join(lines) + "\n").encode("utf-8")

    # Remove metadata previously injected by this helper.
    try:
        text = yaml_data.decode("utf-8", errors="replace")
        removable = (
            "#profile-title:",
            "#profile-update-interval:",
            "#subscription-userinfo:",
            "#support-url:",
            "#profile-web-page-url:",
            "#announce:",
        )
        while any(text.startswith(x) for x in removable):
            parts = text.split("\n", 1)
            text = parts[1] if len(parts) == 2 else ""
        body = text.encode("utf-8")
    except Exception:
        body = yaml_data

    return prefix + body


def subscription_to_happ_text(data, title="", update_interval_minutes=None,
                              subscription_userinfo="", support_url="",
                              web_page_url="", description=""):
    """Build a Happ-native standard subscription: metadata comments + URI list."""
    decoded = decode_subscription_text(data)
    lines = [ln.strip() for ln in decoded.replace("\r", "\n").split("\n") if ln.strip()]
    supported = ("vless://", "vmess://", "trojan://", "ss://", "hysteria2://", "hy2://", "socks://")
    uri_lines = [ln for ln in lines if ln.startswith(supported)]
    if not uri_lines:
        raise ValueError("Источник не содержит URI-ноды для Happ. Выберите User-Agent, при котором Remnawave возвращает Base64/URI-подписку.")

    meta=[]
    title=str(title or "").strip()
    if title:
        title=title[:25]
        try:
            title.encode("ascii")
            v=title
        except UnicodeEncodeError:
            v="base64:"+_meta_base64.b64encode(title.encode("utf-8")).decode("ascii")
        meta.append(f"#profile-title: {v}")
    if update_interval_minutes not in (None, ""):
        try:
            mins=int(update_interval_minutes)
            if mins>=60 and mins%60==0:
                meta.append(f"#profile-update-interval: {mins//60}")
        except Exception:
            pass
    if subscription_userinfo:
        meta.append(f"#subscription-userinfo: {str(subscription_userinfo).strip()}")
    if support_url:
        meta.append(f"#support-url: {str(support_url).strip()}")
    if web_page_url:
        meta.append(f"#profile-web-page-url: {str(web_page_url).strip()}")
    if description:
        enc=_meta_base64.b64encode(str(description)[:200].encode('utf-8')).decode('ascii')
        meta.append(f"#announce: base64:{enc}")
    meta.append("#subscription-auto-update-enable: 1")
    return ("\n".join(meta+uri_lines)+"\n").encode('utf-8'), f"happ-uri-list ({len(uri_lines)} nodes)"
