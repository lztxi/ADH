import yaml
import requests
from datetime import datetime
import pytz
import tldextract
import os

# 脚本现在在 scripts/ 文件夹里运行，所有输入输出文件路径都相对于 scripts/
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
SOURCE_FILE = os.path.join(SCRIPT_DIR, "sources.yml")
OUTPUT_DNS = os.path.join(SCRIPT_DIR, "..", "adguard_dns.txt")       # 输出到根目录
OUTPUT_README = os.path.join(SCRIPT_DIR, "..", "README.md")        # 输出到根目录

extractor = tldextract.TLDExtract(suffix_list_urls=None)


def normalize_domain(domain):
    domain = domain.strip().lower()
    domain = domain.lstrip("+.").lstrip("*.")
    ext = extractor(domain)
    if not ext.domain or not ext.suffix:
        return None
    return f"{ext.domain}.{ext.suffix}"


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

        # 不再进行 DNS 验证，所有原始域名都视为存活
        alive_domains = raw_domains

        category_data[category] = {
            "dns": dns,
            "domains": sorted(alive_domains),
            "raw_count": len(raw_domains),
            "alive_count": len(alive_domains),
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
            for chunk in chunk_list(domains, 200):  # 或你喜欢的数字，比如 60/100/200
                merged = "/".join(chunk)
                f.write(f"[/{merged}/]{dns}\n")

            # 可以选择在类别之间加一个空行，也可以不加
            f.write("\n")  # ← 这行可选，看你喜不喜欢类别间有分隔


def write_readme(all_domains, category_data):
    beijing = pytz.timezone("Asia/Shanghai")
    now = datetime.now(beijing).strftime("%Y-%m-%d %H:%M:%S")
    
    # 计算总数用于徽章展示
    total_count = len(all_domains)
    # 格式化时间用于徽章 (去掉空格和冒号，或者只保留日期)
    date_badge = datetime.now(beijing).strftime("%Y-%m-%d")

    # 构建统计表格的行
    table_rows = []
    total_raw = 0
    total_filtered = 0

    for cat, info in category_data.items():
        raw = info['raw_count']
        alive = info['alive_count']
        filtered = raw - alive
        
        total_raw += raw
        total_filtered += filtered
        
        table_rows.append(
            f"| {cat} | {alive:,} | {raw:,} | {filtered} |"
        )

    # 总计行
    table_rows.append(
        f"| **总计** | **{total_count:,}** | **{total_raw:,}** | **{total_filtered}** |"
    )

    content = f"""# 🛡️ AdGuardHome DNS 分流规则

![Total Domains](https://img.shields.io/badge/域名总数-{total_count}-blue?style=flat-square)
![Last Update](https://img.shields.io/badge/最后更新-{date_badge}-green?style=flat-square)

> 🤖 本文件由脚本自动生成，用于 AdGuardHome 的 DNS 分流配置。

---

## 📊 数据统计

| 分类 | 有效域名 | 原始数量 | 过滤数量 |
| :--- | :---: | :---: | :---: |
{chr(10).join(table_rows)}

---

## 📝 使用说明

1.  复制仓库根目录下的 `adguard_dns.txt` 文件内容。
2.  打开 AdGuardHome 管理面板。
3.  进入 **设置** -> **DNS 服务**。
4.  在 **上游 DNS 服务器** 配置中，找到或新建对应的服务器规则（通常是特定域名的分流）。
5.  将内容粘贴并保存应用即可。

---

## ⏰ 更新记录

- **生成时间**: {now} (北京时间)
- **生成脚本**: `scripts/ADGH_dns.py`
"""
    with open(OUTPUT_README, "w", encoding="utf-8") as f:
        f.write(content)


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
