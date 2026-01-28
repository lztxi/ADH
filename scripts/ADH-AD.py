#!/usr/bin/env python3
# ADH-AD.py

import re
import json
import sys
import os
import yaml
import requests
from pathlib import Path

# ================= Paths =================
# 获取脚本所在的绝对路径，然后向上两级回到 main 目录
# 脚本在 main/scripts/ADH-AD.py
# parents[1] 是 main
BASE = Path(__file__).resolve().parents[1]

# 👇 修改这里：配置文件路径放在 config 文件夹下
CFG = BASE / "config" / "ADH-AD.yaml"

# 检查文件是否存在
if not CFG.exists():
    print(f"❌ 错误：找不到配置文件！")
    print(f"脚本正在寻找的路径是: {CFG}")
    print(f"请确保你已经将 ADH-AD.yaml 放在了 main/config 目录下。")
    sys.exit(1)

# ================= 输出目录 =================
# 如果设置了 OUTPUT_DIR 环境变量就用它，否则默认使用 release 分支根目录
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

try:
    cfg = yaml.safe_load(CFG.read_text(encoding="utf-8"))
except Exception as e:
    print(f"❌ 读取配置文件失败: {e}")
    sys.exit(1)

for src in cfg.get("sources", []):
    if not src.get("enabled", True):
        continue

    try:
        resp = requests.get(src["url"], timeout=30)
        resp.raise_for_status()
    except Exception as e:
        print(f"Error fetching {src.get('url')}: {e}")
        continue

    for raw in resp.text.splitlines():
        domain, is_white = parse_line(raw)
        if not domain:
            continue

        if is_white:
            white_rules.add(f"@@||{domain}^")
        else:
            block_rules.add(f"||{domain}^")


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

print(
    f"✔ Build success | block={len(block_rules)} whitelist={len(white_rules)}"
)
