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


# ================= Main =================
block_rules: set[str] = set()
white_rules: set[str] = set()

# 新增：用于记录上游源统计
source_stats = []

try:
    cfg = yaml.safe_load(CFG.read_text(encoding="utf-8"))
except Exception as e:
    print(f"❌ 读取配置文件失败: {e}")
    sys.exit(1)

for src in cfg.get("sources", []):
    if not src.get("enabled", True):
        continue

    url = src.get("url", "Unknown")
    # 临时统计该源的规则数
    temp_block = 0
    temp_white = 0
    
    try:
        resp = requests.get(url, timeout=30)
        resp.raise_for_status()
    except Exception as e:
        print(f"Error fetching {url}: {e}")
        # 即使请求失败，也记录一下
        source_stats.append({"url": url, "count": 0, "status": "Failed"})
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
            
    source_stats.append({"url": url, "count": temp_block, "status": "OK"})


# ================= Stats =================
stats_file = OUT / "stats.json"
old_total = 0
if stats_file.exists():
    try:
        old_total = json.loads(stats_file.read_text()).get("total", 0)
    except:
        pass

new_total = len(block_rules)
delta = new_total - old_total
ratio = (delta / old_total) if old_total else 0

stats = {
    "total": new_total,
    "previous": old_total,
    "delta": delta,
    "ratio": round(ratio, 4),
}

stats_file.write_text(json.dumps(stats, indent=2), encoding="utf-8")


# ================= Threshold =================
threshold = cfg.get("threshold", {})
max_inc = threshold.get("max_increase", 0.2)
max_dec = threshold.get("max_decrease", 0.2)
force = os.getenv("FORCE_PASS", "false").lower() == "true"

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

# 变化样式
delta_str = f"+{delta}" if delta > 0 else str(delta)
if delta == 0: delta_str = "0"

# 生成 Markdown 内容
readme_content = f"""# ADH-AD 订阅统计

> 数据最后合并时间 (北京时间): **{time_str}**

---

## 📊 数据概览

| 指标 | 数量 | 说明 |
| :--- | :--- | :--- |
| 🚫 黑名单规则 | **{len(block_rules)}** | 包含所有阻断域名 |
| ⚪ 白名单规则 | **{len(white_rules)}** | 包含所有信任域名 |
| 📈 较上次变化 | **{delta_str}** | 上次总数: {old_total} |

---

## 📡 上游源详情

共 **{len(source_stats)}** 个订阅源参与了合并。

| 序号 | 订阅源 URL | 贡献规则数 (黑名单) | 状态 |
| :--- | :--- | :--- | :--- |
"""

for idx, src in enumerate(source_stats, 1):
    # 简单的 URL 截断显示，避免表格太宽
    display_url = src["url"]
    if len(display_url) > 60:
        display_url = display_url[:57] + "..."
    
    status_icon = "✅" if src["status"] == "OK" else "❌"
    readme_content += f"| {idx} | {display_url} | {src['count']} | {status_icon} |\n"

readme_content += f"""

---

🤖 Generated by [GitHub Actions](https://github.com/{os.getenv('GITHUB_REPOSITORY', 'lztxi/ADH')}/actions)
"""

(OUT / "README.md").write_text(readme_content, encoding="utf-8")

print(
    f"✔ Build success | block={len(block_rules)} whitelist={len(white_rules)}"
)
