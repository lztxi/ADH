#!/usr/bin/env python3
# ADH-AD.py

import re
import json
import sys
import os
import yaml
import requests
from pathlib import Path
from datetime import datetime, timedelta

# ================= Paths =================
BASE = Path(__file__).resolve().parents[1]
CFG = BASE / "config" / "ADH-AD.yaml"

if not CFG.exists():
    print(f"❌ 错误：找不到配置文件！")
    print(f"脚本正在寻找的路径是: {CFG}")
    print(f"请确保你已经将 ADH-AD.yaml 放在了 main/config 目录下。")
    sys.exit(1)

# ================= 输出目录 =================
out_dir = os.getenv("OUTPUT_DIR")
if out_dir:
    OUT = Path(out_dir).resolve()
else:
    OUT = BASE.parent / "release"

OUT.mkdir(parents=True, exist_ok=True)


# ================= Regex =================
DOMAIN_RE = re.compile(r"^(?:[a-z0-9-]+\.)+[a-z]{2,}$", re.I)


# ================= Parser =================
def parse_line(line: str):
    line = line.strip()

    if not line or line.startswith(("#", "!", "[")):
        return None, None

    is_whitelist = False
    if line.startswith("@@"):
        is_whitelist = True
        line = line[2:]

    # hosts format
    if line.startswith(("0.0.0.0", "127.0.0.1")):
        parts = line.split()
        if len(parts) < 2:
            return None, None
        domain = parts[1]
    else:
        domain = line.replace("||", "").replace("^", "").strip()

    if not DOMAIN_RE.match(domain):
        return None, None

    return domain.lower(), is_whitelist


# ================= 统计文件读写 =================
def load_stats():
    """读取上次运行的统计数据（按源记录）"""
    stats_file = OUT / "stats.json"
    if not stats_file.exists():
        return {}
    try:
        old_stats = json.loads(stats_file.read_text())
        # 兼容旧格式：如果只有 total/previous/delta/ratio，则返回空字典
        if isinstance(old_stats, dict) and "total" in old_stats:
            return {}
        return old_stats if isinstance(old_stats, dict) else {}
    except Exception as e:
        print(f"[WARN] 读取旧统计文件失败: {e}")
        return {}


def save_stats(new_stats):
    """保存本次运行的统计数据（按源记录）"""
    stats_file = OUT / "stats.json"
    try:
        stats_file.write_text(json.dumps(new_stats, indent=2), encoding="utf-8")
    except Exception as e:
        print(f"[WARN] 保存统计文件失败: {e}")


# ================= Main =================
block_rules: set[str] = set()
white_rules: set[str] = set()

# 用于记录每个源的统计信息：{ name: { url, count, status } }
source_stats = {}

try:
    cfg = yaml.safe_load(CFG.read_text(encoding="utf-8"))
except Exception as e:
    print(f"❌ 读取配置文件失败: {e}")
    sys.exit(1)

# 读取上次的统计数据
old_stats = load_stats()

for src in cfg.get("sources", []):
    if not src.get("enabled", True):
        continue

    url = src.get("url", "")
    name = src.get("name", "")
    
    # 如果配置里没有 name，用 URL 的文件名作为默认名称
    if not name and url:
        name = url.rstrip("/").split("/")[-1]
    if not name:
        name = "Unknown"

    temp_block = 0
    temp_white = 0
    status = "OK"
    
    try:
        resp = requests.get(url, timeout=30)
        resp.raise_for_status()
    except Exception as e:
        print(f"Error fetching {url}: {e}")
        status = "Failed"
        source_stats[name] = {
            "url": url,
            "count": 0,
            "status": status,
        }
        continue

    for raw in resp.text.splitlines():
        domain, is_white = parse_line(raw)
        if not domain:
            continue

        if is_white:
            white_rules.add(f"@@||{domain}^")
            temp_white += 1
        else:
            block_rules.add(f"||{domain}^")
            temp_block += 1
            
    source_stats[name] = {
        "url": url,
        "count": temp_block,
        "status": status,
    }

# 构建本次统计（按源记录）
new_stats = {}
total_count = 0
for name, info in source_stats.items():
    count = info["count"]
    new_stats[name] = count
    total_count += count

# 保存本次统计
save_stats(new_stats)


# ================= Threshold =================
threshold = cfg.get("threshold", {})
max_inc = threshold.get("max_increase", 0.2)
max_dec = threshold.get("max_decrease", 0.2)
force = os.getenv("FORCE_PASS", "false").lower() == "true"

# 计算上次总数用于阈值检查
old_total = sum(old_stats.values()) if isinstance(old_stats, dict) else 0
delta = total_count - old_total
ratio = (delta / old_total) if old_total else 0

# 变化显示（用于数据概览）
if delta > 0:
    total_diff_str = f"🔼 +{delta}"
elif delta < 0:
    total_diff_str = f"🔽 {delta}"
else:
    total_diff_str = "➖ 0"

if old_total and not force:
    if ratio > max_inc or ratio < -max_dec:
        print("❌ Rule change exceeds threshold")
        sys.exit(1)


# ================= Output =================

# AdGuardHome（包含白名单）
(OUT / "adguardhome.txt").write_text(
    "\n".join(sorted(white_rules | block_rules)) + "\n",
    encoding="utf-8",
)

# dnsmasq（仅阻断）
(OUT / "dnsmasq.conf").write_text(
    "\n".join(
        f"address=/{r[2:-1]}/0.0.0.0"
        for r in sorted(block_rules)
    ) + "\n",
    encoding="utf-8",
)

# Clash（仅阻断）
(OUT / "clash.yaml").write_text(
    "payload:\n"
    + "\n".join(f"  - '{r[2:-1]}'" for r in sorted(block_rules))
    + "\n",
    encoding="utf-8",
)


# ================= README 生成 =================
# 计算北京时间 (UTC+8)
now_utc = datetime.utcnow()
now_cst = now_utc + timedelta(hours=8)
time_str = now_cst.strftime('%Y-%m-%d %H:%M:%S')

# 生成上游源详情表格行
table_rows = []
total_diff_for_table = 0

for name, info in source_stats.items():
    current = info["count"]
    prev = old_stats.get(name, 0)
    diff = current - prev
    total_diff_for_table += diff
    url = info.get("url", "")
    status = info.get("status", "OK")
    
    # 变化显示
    if diff > 0:
        diff_str = f"🔼 +{diff}"
    elif diff < 0:
        diff_str = f"🔽 {diff}"
    else:
        diff_str = "➖ 0"
    
    if prev == 0 and current > 0:
        diff_str = "🆕 New"
    
    # 名称做成超链接
    if url:
        link_cell = f"[{name}]({url})"
    else:
        link_cell = name
    
    status_icon = "✅" if status == "OK" else "❌"
    table_rows.append(
        f"| {len(table_rows) + 1} | {link_cell} | {prev:,} | {current:,} | {diff_str} | {status_icon} |"
    )

# 总计变化（用于表格底部）
if total_diff_for_table > 0:
    total_diff_table_str = f"🔼 +{total_diff_for_table}"
elif total_diff_for_table < 0:
    total_diff_table_str = f"🔽 {total_diff_for_table}"
else:
    total_diff_table_str = "➖ 0"

table_rows.append(
    f"| **总计** | **{len(source_stats)} 个源** | **{old_total:,}** | **{total_count:,}** | **{total_diff_table_str}** | |"
)

readme_content = f"""# ADH-AD 订阅统计

> 数据最后合并时间 (北京时间): **{time_str}**

---

## 📊 数据概览

| 项目 | 上次更新 | 本次更新 | 更新变化 |
| :--- | :---: | :---: | :---: |
| 🚫 黑名单规则 | {old_total:,} | {total_count:,} | {total_diff_str} |
| ⚪ 白名单规则 | - | {len(white_rules):,} | - |

---

## 📡 上游源详情

共 **{len(source_stats)}** 个订阅源参与了合并。

| 序号 | 订阅源 | 上次更新 | 本次更新 | 更新变化 | 状态 |
| :--- | :--- | :---: | :---: | :---: | :---: |
{chr(10).join(table_rows)}

---

🤖 Generated by [GitHub Actions](https://github.com/{os.getenv('GITHUB_REPOSITORY', 'lztxi/ADH')}/actions)
"""

(OUT / "README.md").write_text(readme_content, encoding="utf-8")

print(
    f"✔ Build success | block={len(block_rules)} whitelist={len(white_rules)}"
)
