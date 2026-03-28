# Установка прокси на Ubuntu без GUI

1. Установите Xray командой ниже (для установки нужны рут права).
```bash
bash -c "$(curl -Ls https://github.com/XTLS/Xray-install/raw/main/install-release.sh)"
```
2. Создайте из подписки json конфиги для Xray (для этого я написал python скрипт). Сохраните его в папке, где будут хранится конфиги
```py
#!/usr/bin/env python3

import sys
import argparse
import urllib.request
import base64
from urllib.parse import urlparse, parse_qs
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
        "sid": params.get("sid", [""])[0]
    }

def build_config(v):
    return {
        "log": {
            "loglevel": "warning"
        },
        "inbounds": [
            {
                "listen": "127.0.0.1",
                "port": 1080,
                "protocol": "socks",
                "settings": {
                    "udp": True
                }
            }
        ],
        "outbounds": [
            {
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
                                    "flow": v["flow"]
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
        ]
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--url", help="URL страницы")

    args = parser.parse_args()

    if not args.url:
        print("Укажите --url")
        sys.exit(1)
    else:
        html_text = fetch_url(args.url)

    links = extract_vless_from_html(html_text)

    if not links:
        print("VLESS ссылки не найдены")
        return

    print(f"Найдено {len(links)} ссылок:\n")

    for link, num in zip(links, range(len(links))):
        with open(f"config{num}.json", "w") as f:
            json.dump(build_config(parse_vless(link)), f, indent=2)


if __name__ == "__main__":
    main()
```
3. Запустите скрипт. Пример использования представлен ниже. Он создаст конфиги для Xray в папке
```bash
python3 main.py --url https://example.ru/sub
```
4. Запустите Xray. Пример использования представлен ниже (Xray можно так же запустить через systemctl)
```bash
xray --config config.json
```
5. Проверьте работу прокси через curl
Этот пример должен вывести IP пользователя
```bash
curl https://api.ipify.org
```
Этот пример должен вывести IP VPN сервера
```bash
curl --socks5 127.0.0.1:1080 https://api.ipify.org
```

# Включение режима TUN
1. Скачиваем sing-box через wget
```bash
wget https://github.com/SagerNet/sing-box/releases/download/v1.13.0/sing-box_1.13.0_linux_amd64.deb
```
2. Устанавливаем (нужны рут права)
```bash
dpkg -i sing-box_1.13.0_linux_amd64.deb
```
3. Пишем конфиг для sing-box
```json
{
    "inbounds": [
        {
            "address": [
                "172.18.0.1/30"
            ],
            "auto_route": true,
            "mtu": 1500,
            "stack": "mixed",
            "strict_route": true,
            "tag": "tun-in",
            "type": "tun"
        }
    ],
    "log": {
        "level": "info",
        "timestamp": true
    },
    "outbounds": [
        {
            "server": "127.0.0.1",
            "server_port": 1080,
            "tag": "proxy",
            "type": "socks",
            "udp_fragment": true
        },
        {
            "type": "direct",
            "tag": "direct"
        }
    ],
    "route": {
        "auto_detect_interface": true,
        "final": "proxy",
        "rules": [
            {
                "outbound": "direct",
                "process_name": [
                    "xray",
                    "sing-box"
                ]
            }
        ]
    }
}
```
4. Запускаем sing-box (Нужны рут права)
```bash
sing-box run -c config.json
```
5. Проверяем работу (Должен вывестись IP VPN, к которому подключен Xray)
```bash
curl https://api.ipify.org
```