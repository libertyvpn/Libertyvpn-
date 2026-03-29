import sys
import argparse
import urllib.request
import base64
from urllib.parse import unquote, urlparse, parse_qs
import json


def fetch_url(url):
    with urllib.request.urlopen(url) as response:
        return response.read().decode("utf-8", errors="ignore")


def extract_vless_from_html(html_text):
    decoded_bytes = base64.b64decode(html_text)
    decoded_string = decoded_bytes.decode("utf-8")

    return decoded_string.split("\n")


def parse_vless(link):
    parsed = urlparse(link)
    params = parse_qs(parsed.query)

    return {
        "uuid": parsed.username,
        "host": parsed.hostname,
        "port": parsed.port,
        "flow": params.get("flow", [""])[0],
        "security": params.get("security", ["none"])[0],
        "sni": params.get("sni", [""])[0],
        "fp": params.get("fp", ["chrome"])[0],
        "pbk": params.get("pbk", [""])[0],
        "sid": params.get("sid", [""])[0],
        "remark": unquote(parsed.fragment) if parsed.fragment else ""
    }

def build_config(v):
    return {
        "dns": {
            "hosts": {
                "domain:googleapis.cn": "googleapis.com"
            },
            "queryStrategy": "UseIPv4",
            "servers": [
                "1.1.1.1",
                {
                    "address": "1.1.1.1",
                    "domains": [
                    ],
                    "port": 53
                },
                {
                    "address": "8.8.8.8",
                    "domains": [
                    ],
                    "port": 53
                }
            ]
        },
        "log": {
            "loglevel": "warning"
        },
        "inbounds": [
            {
                "listen": "127.0.0.1",
                "port": 10808,
                "protocol": "socks",
                "settings": {
                    "auth": "noauth",
                    "udp": True,
                    "userLevel": 8
                },
                "sniffing": {
                    "destOverride": [
                        "http",
                        "tls",
                        "quic"
                    ],
                    "enabled": True
                },
                "tag": "socks"
            },
            {
                "listen": "127.0.0.1",
                "port": 10809,
                "protocol": "http",
                "settings": {
                    "userLevel": 8
                },
                "sniffing": {
                    "destOverride": [
                        "http",
                        "tls",
                        "quic"
                    ],
                    "enabled": True
                },
                "tag": "http"
            },
            {
                "listen": "127.0.0.1",
                "port": 11111,
                "protocol": "dokodemo-door",
                "settings": {
                    "address": "127.0.0.1"
                },
                "tag": "metrics_in"
            }
        ],
        "remarks": v["remark"],
        "outbounds": [
            {
                "mux": {
                    "concurrency": -1,
                    "enabled": False,
                    "xudpConcurrency": 8,
                    "xudpProxyUDP443": ""
                },
                "protocol": "vless",
                "settings": {
                    "vnext": [
                        {
                            "address": v["host"],
                            "port": v["port"],
                            "users": [
                                {
                                    "id": v["uuid"],
                                    "encryption": "none",
                                    "flow": v["flow"],
                                    "security": "auto"
                                }
                            ]
                        }
                    ]
                },
                "streamSettings": {
                    "network": "tcp",
                    "security": "reality",
                    "realitySettings": {
                        "serverName": v["sni"],
                        "fingerprint": v["fp"],
                        "publicKey": v["pbk"],
                        "shortId": v["sid"],
                        "spiderX": "/"
                    }
                }
            }
        ],
        "routing": {
            "domainStrategy": "IPIfNonMatch",
            "rules": [
                {
                    "inboundTag": [
                        "metrics_in"
                    ],
                    "outboundTag": "metrics_out"
                },
                {
                    "inboundTag": [
                        "socks"
                    ],
                    "outboundTag": "proxy",
                    "port": "53"
                },
                {
                    "ip": [
                        "1.1.1.1"
                    ],
                    "outboundTag": "proxy",
                    "port": "53"
                },
                {
                    "ip": [
                        "8.8.8.8"
                    ],
                    "outboundTag": "direct",
                    "port": "53"
                }
            ]
        }
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--url", help="URL страницы")

    args = parser.parse_args()

    if not args.url:
        print("Укажите --url")
        sys.exit(1)

    if args.url.startswith("http://") or args.url.startswith("https://"):
        links = extract_vless_from_html(fetch_url(args.url))
    
    if args.url.startswith("vless://"):
        links = [args.url]

    if not links:
        print("VLESS ссылки не найдены")
        return

    print(f"Найдено {len(links)} ссылок:\n")

    for link, num in zip(links, range(len(links))):
        with open(f"config{num}.json", "w") as f:
            json.dump(build_config(parse_vless(link)), f, indent=2)


if __name__ == "__main__":
    main()