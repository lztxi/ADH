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

print(f"[DEBUG] BASE: {BASE}")
print(f"[DEBUG] CFG: {CFG}")
print(f"[DEBUG] CFG absolute: {CFG.resolve()}")

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
print(f"[DEBUG] OUT: {OUT}")
print(f"[DEBUG] OUT absolute: {OUT.resolve()}")


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
    """读取上次运行的统计数据（记录黑名单和白名单）"""
    stats_file = BASE / "config" / "ADH_AD_stats.json"
    stats_abs = stats_file.resolve()
    
    print(f"[INFO] Loading stats from: {stats_abs}")
    
    if not stats_file.exists():
        print(f"[INFO] Stats file not found, starting fresh.")
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
    """保存本次运行的统计数据（记录黑名单和白名单）"""
    stats_file = BASE / "config" / "ADH_AD_stats.json"
    stats_abs = stats_file.resolve()
    
    try:
        # 关键修改：确保目录存在
        stats_dir = stats_file.parent
        if not stats_dir.exists():
            stats_dir.mkdir(parents=True, exist_ok=True)
            print(f"[INFO] Created directory: {stats_dir.resolve()}")
        else:
            print(f"[INFO] Directory already exists: {stats_dir.resolve()}")
        
        stats_file.write_text(json.dumps(new_stats, indent=2), encoding="utf-8")
        
        # 验证文件是否真的写成功了
        if stats_file.exists():
            print(f"[INFO] Stats saved successfully to: {stats_abs}")
            print(f"[INFO] File size: {stats_file.stat().st_size} bytes")
        else:
            print(f"[ERROR] File not found after save attempt: {stats_abs}")
    except Exception as e:
        print(f"[ERROR] 保存统计文件失败: {e}")
        import traceback
        traceback.print_exc()


# ================= Main =================
block_rules: set[str] = set()
white_rules: set[str] = set()

# 用于记录每个源的统计信息：{ name: { url, block_count, white_count, status } }
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
            "block_count": 0,
            "white_count": 0,
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
        "block_count": temp_block,
        "white_count": temp_white,
        "status": status,
    }

# 构建本次统计（记录黑名单和白名单）
new_stats = {}
total_block_count = 0
total_white_count = 0
for name, info in source_stats.items():
    block_count = info["block_count"]
    white_count = info["white_count"]
    new_stats[name] = {
        "block_count": block_count,
        "white_count": white_count,
    }
    total_block_count += block_count
    total_white_count += white_count

# 保存本次统计
save_stats(new_stats)


# ================= Threshold =================
threshold = cfg.get("threshold", {})
max_inc = threshold.get("max_increase", 0.2)
max_dec = threshold.get("max_decrease", 0.2)
force = os.getenv("FORCE_PASS", "false").lower() == "true"

# 计算上次总数用于阈值检查（仍然只检查黑名单）
old_total = sum(v.get("block_count", 0) for v in old_stats.values()) if isinstance(old_stats, dict) else 0
delta = total_block_count - old_total
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
total_block_diff = 0
total_white_diff = 0

for name, info in source_stats.items():
    current_block = info["block_count"]
    current_white = info["white_count"]
    prev = old_stats.get(name, {})
    prev_block = prev.get("block_count", 0)
    prev_white = prev.get("white_count", 0)

    block_diff = current_block - prev_block
    white_diff = current_white - prev_white

    total_block_diff += block_diff
    total_white_diff += white_diff

    url = info.get("url", "")
    status = info.get("status", "OK")

    # 黑名单变化显示
    if block_diff > 0:
        block_diff_str = f"🔼 +{block_diff}"
    elif block_diff < 0:
        block_diff_str = f"🔽 {block_diff}"
    else:
        block_diff_str = "➖ 0"

    if prev_block == 0 and current_block > 0:
        block_diff_str = "🆕 New"

    # 白名单变化显示
    if white_diff > 0:
        white_diff_str = f"🔼 +{white_diff}"
    elif white_diff < 0:
        white_diff_str = f"🔽 {white_diff}"
    else:
        white_diff_str = "➖ 0"

    if prev_white == 0 and current_white > 0:
        white_diff_str = "🆕 New"

    # 名称做成超链接
    if url:
        link_cell = f"[{name}]({url})"
    else:
        link_cell = name

    status_icon = "✅" if status == "OK" else "❌"
    table_rows.append(
        f"| {len(table_rows) + 1} | {link_cell} | {prev_block:,} / {prev_white:,} | {current_block:,} / {current_white:,} | {block_diff_str} / {white_diff_str} | {status_icon} |"
    )

# 总计变化（用于表格底部）
if total_block_diff > 0:
    total_block_diff_str = f"🔼 +{total_block_diff}"
elif total_block_diff < 0:
    total_block_diff_str = f"🔽 {total_block_diff}"
else:
    total_block_diff_str = "➖ 0"

if total_white_diff > 0:
    total_white_diff_str = f"🔼 +{total_white_diff}"
elif total_white_diff < 0:
    total_white_diff_str = f"🔽 {total_white_diff}"
else:
    total_white_diff_str = "➖ 0"

table_rows.append(
    f"| **总计** | **{len(source_stats)} 个源** | **{old_total:,} / -** | **{total_block_count:,} / {total_white_count:,}** | **{total_block_diff_str} / {total_white_diff_str}** | |"
)

# 计算白名单上次总数
old_total_white = sum(v.get("white_count", 0) for v in old_stats.values()) if isinstance(old_stats, dict) else 0

readme_content = f"""# ADH-AD 订阅统计

> 数据最后合并时间 (北京时间): **{time_str}**

---

## 📊 数据概览

| 项目 | 上次更新 | 本次更新 | 更新变化 |
| :--- | :---: | :---: | :---: |
| 🚫 黑名单规则 | {old_total:,} | {total_block_count:,} | {total_diff_str} |
| ⚪ 白名单规则 | {old_total_white:,} | {total_white_count:,} | {total_white_diff_str} |

---

## 📡 上游源详情

共 **{len(source_stats)}** 个订阅源参与了合并。

| 序号 | 订阅源 | 上次更新 (黑/白) | 本次更新 (黑/白) | 更新变化 (黑/白) | 状态 |
| :--- | :--- | :---: | :---: | :---: | :---: |
{chr(10).join(table_rows)}

---

🤖 Generated by [GitHub Actions](https://github.com/{os.getenv('GITHUB_REPOSITORY', 'lztxi/ADH')}/actions)
"""

(OUT / "README.md").write_text(readme_content, encoding="utf-8")

print(
    f"✔ Build success | block={len(block_rules)} whitelist={len(white_rules)}"
)
