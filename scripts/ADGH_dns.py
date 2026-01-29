import yaml
import requests
from datetime import datetime
import pytz
import tldextract
import os
import json

# 脚本现在在 scripts/ 文件夹里运行，所有输入输出文件路径都相对于 scripts/
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
SOURCE_FILE = os.path.join(SCRIPT_DIR, "..", "config", "sources.yml")
OUTPUT_DNS = os.path.join(SCRIPT_DIR, "..", "adguard_dns.txt")       # 输出到根目录
OUTPUT_README = os.path.join(SCRIPT_DIR, "..", "README.md")        # 输出到根目录
STATS_FILE = os.path.join(SCRIPT_DIR, "..", "config", "ADGH_dns_stats.json")  # 存储在 config 文件夹

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


def load_stats():
    """读取上次运行的统计数据"""
    if not os.path.exists(STATS_FILE):
        return {}
    try:
        with open(STATS_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception as e:
        print(f"[WARN] Failed to load stats file: {e}")
        return {}


def save_stats(stats):
    """保存本次运行的统计数据"""
    try:
        with open(STATS_FILE, "w", encoding="utf-8") as f:
            json.dump(stats, f, ensure_ascii=False, indent=2)
    except Exception as e:
        print(f"[WARN] Failed to save stats file: {e}")


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

            for chunk in chunk_list(domains, 200):  # 或你喜欢的数字，比如 60/100/200
                merged = "/".join(chunk)
                f.write(f"[/{merged}/]{dns}\n")

            f.write("\n")  # 类别间加分隔


def write_readme(all_domains, category_data, prev_stats):
    beijing = pytz.timezone("Asia/Shanghai")
    now = datetime.now(beijing).strftime("%Y-%m-%d %H:%M:%S")
    date_badge = datetime.now(beijing).strftime("%Y-%m-%d")

    total_count = len(all_domains)

    # 构建统计表格
    table_rows = []

    # 计算上一次的总数，用于表格底部对比
    prev_total = 0
    for cat, info in category_data.items():
        prev_total += prev_stats.get(cat, 0)

    for cat, info in category_data.items():
        current = info['alive_count']
        # 获取上次数量，如果没有则默认为 0
        prev = prev_stats.get(cat, 0)

        # 计算变化
        diff = current - prev

        # 格式化变化显示：带颜色和箭头
        if diff > 0:
            diff_str = f"🔼 +{diff}"
        elif diff < 0:
            diff_str = f"🔽 {diff}"
        else:
            diff_str = "➖ 0"

        # 如果是第一次运行（prev == 0 且 current > 0），可以标记为 New
        if prev == 0 and current > 0:
            diff_str = "🆕 New"

        table_rows.append(
            f"| {cat} | {prev:,} | {current:,} | {diff_str} |"
        )

    # 计算总变化
    total_diff = total_count - prev_total
    if total_diff > 0:
        total_diff_str = f"🔼 +{total_diff}"
    elif total_diff < 0:
        total_diff_str = f"🔽 {total_diff}"
    else:
        total_diff_str = "➖ 0"

    # 总计行
    table_rows.append(
        f"| **总计** | **{prev_total:,}** | **{total_count:,}** | **{total_diff_str}** |"
    )

    content = f"""# 🛡️ AdGuardHome DNS 分流规则

![Total Domains](https://img.shields.io/badge/域名总数-{total_count}-blue?style=flat-square)
![Last Update](https://img.shields.io/badge/最后更新-{date_badge}-green?style=flat-square)

> 🤖 本文件由脚本自动生成，用于 AdGuardHome 的 DNS 分流配置。脚本会对比上次生成的数量，显示域名增减情况。

---

## 📊 数据统计

| 分类 | 上次更新 | 本次更新 | 更新变化 |
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

    # 1. 读取上次的统计数据
    prev_stats = load_stats()
    print("[OK] Previous stats loaded")

    # 2. 读取配置并生成数据
    data = load_sources()
    print("[OK] sources.yml loaded")
    category_data, all_domains, stats = generate_data(data)

    # 3. 保存这次的统计数据（供下次对比）
    save_stats(stats)
    print("[OK] Current stats saved")

    # 4. 写入 DNS 文件和 README
    write_dns(category_data)
    write_readme(all_domains, category_data, prev_stats)
    print(f"=== Done: {len(all_domains)} domains ===")


if __name__ == "__main__":
    main()
