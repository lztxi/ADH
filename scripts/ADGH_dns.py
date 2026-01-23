import yaml
import requests
import socket
from datetime import datetime
import pytz
import tldextract
import os

# 脚本现在在 scripts/ 文件夹里运行，所有输入输出文件路径都相对于 scripts/
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))

SOURCE_FILE    = os.path.join(SCRIPT_DIR, "sources.yml")
OUTPUT_DNS     = os.path.join(SCRIPT_DIR, "..", "adguard_dns.txt")     # 输出到根目录
OUTPUT_README  = os.path.join(SCRIPT_DIR, "..", "README.md")           # 输出到根目录

extractor = tldextract.TLDExtract(suffix_list_urls=None)

def normalize_domain(domain):
    domain = domain.strip().lower()
    domain = domain.lstrip("+.").lstrip("*.")

    ext = extractor(domain)
    if not ext.domain or not ext.suffix:
        return None

    return f"{ext.domain}.{ext.suffix}"


def domain_alive(domain):
    try:
        socket.setdefaulttimeout(2)
        socket.getaddrinfo(domain, None)
        return True
    except:
        return False


def fetch_domains(url):
    domains = set()
    print(f"[FETCH] {url}")

    try:
        r = requests.get(url, timeout=30)
        r.raise_for_status()

        for line in r.text.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue

            if line.startswith("domain:"):
                raw = line.replace("domain:", "").strip()
            elif line.startswith("full:"):
                raw = line.replace("full:", "").strip()
            else:
                raw = line

            d = normalize_domain(raw)
            if d:
                domains.add(d)

    except Exception as e:
        print(f"[ERROR] fetch failed: {e}")

    print(f"[OK] got {len(domains)} domains")
    return domains


def chunk_list(lst, size):
    for i in range(0, len(lst), size):
        yield lst[i:i + size]


def load_sources():
    with open(SOURCE_FILE, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)


def generate_data(data):
    category_data = {}
    all_domains = set()
    stats = {}

    for category, cfg in data.get("categories", {}).items():
        dns = cfg.get("dns", "")
        urls = cfg.get("urls", [])

        raw_domains = set()
        for url in urls:
            raw_domains.update(fetch_domains(url))

        alive_domains = set()
        for d in raw_domains:
            if domain_alive(d):
                alive_domains.add(d)

        category_data[category] = {
            "dns": dns,
            "domains": sorted(alive_domains),
            "raw_count": len(raw_domains),
            "alive_count": len(alive_domains)
        }

        stats[category] = len(alive_domains)
        all_domains.update(alive_domains)

        print(f"[FILTER] {category}: {len(raw_domains)} → {len(alive_domains)}")

    return category_data, all_domains, stats


def write_dns(category_data):
    with open(OUTPUT_DNS, "w", encoding="utf-8") as f:
        # 完全不写任何头部注释，直接开始写规则

        for category, info in category_data.items():
            domains = info["domains"]
            dns = info["dns"]

            if not domains:
                continue

            # 不写 "# {category} ({len(domains)} domains)\n" 这行

            for chunk in chunk_list(domains, 200):   # 或你喜欢的数字，比如 60/100/200
                merged = "/".join(chunk)
                f.write(f"[/{merged}/]{dns}\n")

            # 可以选择在类别之间加一个空行，也可以不加
            f.write("\n")   # ← 这行可选，看你喜不喜欢类别间有分隔

def write_readme(all_domains, category_data):
    beijing = pytz.timezone("Asia/Shanghai")
    now = datetime.now(beijing).strftime("%Y-%m-%d %H:%M:%S")

    lines = [
        "# 自动生成 AdGuardHome DNS 分流规则",
        "",
        f"最后生成时间（北京时间）：{now}",
        "",
        f"最终域名总数：{len(all_domains)}",
        "",
        "## 分类统计"
    ]

    for cat, info in category_data.items():
        lines.append(
            f"- {cat}: {info['alive_count']} / {info['raw_count']}（已过滤 {info['raw_count'] - info['alive_count']}）"
        )

    with open(OUTPUT_README, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))


def main():
    print("=== Program start ===")
    data = load_sources()
    print("[OK] sources.yml loaded")

    category_data, all_domains, stats = generate_data(data)

    write_dns(category_data)
    write_readme(all_domains, category_data)

    print(f"=== Done: {len(all_domains)} domains ===")


if __name__ == "__main__":
    main()
