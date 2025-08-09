#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import re
import sys
import time
import json
import ipaddress
import requests
from typing import Iterable, Set, Tuple, List
from requests.adapters import HTTPAdapter, Retry

SOURCES = [
    "https://cf.vvhan.com",
    "https://cf.090227.xyz",
    "https://ip.164746.xyz",
    "https://stock.hostmonit.com/CloudFlareYes",
]

UA = "cf-ip-collector/1.0 (+https://github.com/yourname/yourrepo)"

def session() -> requests.Session:
    s = requests.Session()
    retries = Retry(
        total=3,
        connect=3,
        read=3,
        backoff_factor=0.5,
        status_forcelist=[429, 500, 502, 503, 504],
        allowed_methods=["GET"],
        raise_on_status=False,
    )
    adapter = HTTPAdapter(max_retries=retries, pool_connections=10, pool_maxsize=10)
    s.mount("http://", adapter)
    s.mount("https://", adapter)
    s.headers.update({"User-Agent": UA, "Accept-Encoding": "gzip, deflate, br"})
    return s

def fetch_text(s: requests.Session, url: str) -> str:
    r = s.get(url, timeout=15)
    r.raise_for_status()
    # 某些源返回 JSON；统一转为文本处理
    try:
        if "application/json" in r.headers.get("content-type", ""):
            return json.dumps(r.json(), ensure_ascii=False)
    except Exception:
        pass
    r.encoding = r.encoding or "utf-8"
    return r.text

# 基础正则候选
RE_IPV4_PORT = re.compile(r"\b(?P<ip>(?:\d{1,3}\.){3}\d{1,3})(?::\d{1,5})?\b")
RE_IPV6_BRACKET = re.compile(r"\[(?P<ip6>[0-9A-Fa-f:]+)\](?::\d{1,5})?")
RE_IPV6_BARE = re.compile(r"(?<!:)(?P<ip6b>(?:[0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f]{0,4})(?!:)")

def extract_ips(text: str) -> Set[str]:
    found: Set[str] = set()

    # IPv4（可带端口）
    for m in RE_IPV4_PORT.finditer(text):
        raw = m.group("ip")
        try:
            ip = ipaddress.ip_address(raw)
            if isinstance(ip, ipaddress.IPv4Address) and all(0 <= int(o) <= 255 for o in raw.split(".")):
                found.add(ip.exploded)
        except Exception:
            continue

    # IPv6 带中括号（可带端口）
    for m in RE_IPV6_BRACKET.finditer(text):
        raw = m.group("ip6")
        try:
            ip = ipaddress.ip_address(raw)
            if isinstance(ip, ipaddress.IPv6Address):
                found.add(ip.compressed)
        except Exception:
            continue

    # IPv6 裸地址（不在中括号中）
    for m in RE_IPV6_BARE.finditer(text):
        raw = m.group("ip6b")
        try:
            ip = ipaddress.ip_address(raw)
            if isinstance(ip, ipaddress.IPv6Address):
                found.add(ip.compressed)
        except Exception:
            continue

    return found

def sort_ips(ips: Iterable[str]) -> List[str]:
    v4, v6 = [], []
    for s in ips:
        ip = ipaddress.ip_address(s)
        (v4 if isinstance(ip, ipaddress.IPv4Address) else v6).append(ip)
    v4.sort()
    v6.sort()
    return [str(ip) for ip in v4] + [str(ip) for ip in v6]

def main() -> int:
    s = session()
    all_ips: Set[str] = set()
    per_source_counts: List[Tuple[str, int]] = []

    for url in SOURCES:
        try:
            txt = fetch_text(s, url)
            ips = extract_ips(txt)
            per_source_counts.append((url, len(ips)))
            all_ips.update(ips)
        except Exception as e:
            per_source_counts.append((url, 0))
            print(f"[warn] fetch failed: {url}: {e}", file=sys.stderr)

    sorted_ips = sort_ips(all_ips)
    ts = time.strftime("%Y-%m-%d %H:%M:%S %z", time.localtime())

    header = [
        "# Cloudflare 优选 IP 聚合",
        f"# 更新时间: {ts}",
        f"# 来源统计: " + "; ".join([f"{u}={n}" for u, n in per_source_counts]),
        f"# 合并去重: {len(sorted_ips)} 个",
        "# ------------------------------",
    ]

    with open("ip.txt", "w", encoding="utf-8") as f:
        f.write("\n".join(header) + "\n")
        for ip in sorted_ips:
            f.write(ip + "\n")

    print(f"Done. merged {len(sorted_ips)} IPs -> ip.txt")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
