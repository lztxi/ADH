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

BASE = Path(__file__).resolve().parents[1]
CFG = BASE / "config" / "ADH-AD.yaml"

print("[DEBUG] BASE: " + str(BASE))
print("[DEBUG] CFG: " + str(CFG))
print("[DEBUG] CFG absolute: " + str(CFG.resolve()))

if not CFG.exists():
    print("错误：找不到配置文件！")
    print("脚本正在寻找的路径是: " + str(CFG))
    print("请确保你已经将 ADH-AD.yaml 放在了 main/config 目录下。")
    sys.exit(1)

out_dir = os.getenv("OUTPUT_DIR")
if out_dir:
    OUT = Path(out_dir).resolve()
else:
    OUT = BASE.parent / "release"

OUT.mkdir(parents=True, exist_ok=True)
print("[DEBUG] OUT: " + str(OUT))
print("[DEBUG] OUT absolute: " + str(OUT.resolve()))

DOMAIN_RE = re.compile(r"^(?:[a-z0-9-]+\.)+[a-z]{2,}$", re.I)

def parse_line(line):
    line = line.strip()
    if not line or line.startswith(("#", "!", "[")):
        return None, None
    is_whitelist = False
    if line.startswith("@@"):
        is_whitelist = True
        line = line[2:]
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

def load_stats():
    stats_file = BASE / "config" / "ADH_AD_stats.json"
    stats_abs = stats_file.resolve()
    print("[INFO] Loading stats from: " + str(stats_abs))
    if not stats_file.exists():
        print("[INFO] Stats file not found, starting fresh.")
        return {}
    try:
        old_stats = json.loads(stats_file.read_text())
        if isinstance(old_stats, dict) and "total" in old_stats:
            return {}
        return old_stats if isinstance(old_stats, dict) else {}
    except Exception as e:
        print("[WARN] 读取旧统计文件失败: " + str(e))
        return {}

def save_stats(new_stats):
    stats_file = BASE / "config" / "ADH_AD_stats.json"
    stats_abs = stats_file.resolve()
    try:
        stats_dir = stats_file.parent
        if not stats_dir.exists():
            stats_dir.mkdir(parents=True, exist_ok=True)
            print("[INFO] Created directory: " + str(stats_dir.resolve()))
        else:
            print("[INFO] Directory already exists: " + str(stats_dir.resolve()))
        stats_file.write_text(json.dumps(new_stats, indent=2), encoding="utf-8")
        if stats_file.exists():
            print("[INFO] Stats saved successfully to: " + str(stats_abs))
            print("[INFO] File size: " + str(stats_file.stat().st_size) + " bytes")
        else:
            print("[ERROR] File not found after save attempt: " + str(stats_abs))
    except Exception as e:
        print("[ERROR] 保存统计文件失败: " + str(e))
        import traceback
        traceback.print_exc()

block_rules = set()
white_rules = set()
source_stats = {}

try:
    cfg = yaml.safe_load(CFG.read_text(encoding="utf-8"))
except Exception as e:
    print("❌ 读取配置文件失败: " + str(e))
    sys.exit(1)

old_stats = load_stats()

for src in cfg.get("sources", []):
    if not src.get("enabled", True):
        continue
    url = src.get("url", "")
    name = src.get("name", "")
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
        print("Error fetching " + url + ": " + str(e))
        status = "Failed"
        source_stats[name] = {"url": url, "block_count": 0, "white_count": 0, "status": status}
        continue
    for raw in resp.text.splitlines():
        domain, is_white = parse_line(raw)
        if not domain:
            continue
        if is_white:
            white_rules.add("@@||" + domain + "^")
            temp_white += 1
        else:
            block_rules.add("||" + domain + "^")
            temp_block += 1
    source_stats[name] = {"url": url, "block_count": temp_block, "white_count": temp_white, "status": status}

new_stats = {}
total_block_count = 0
total_white_count = 0
for name, info in source_stats.items():
    block_count = info["block_count"]
    white_count = info["white_count"]
    new_stats[name] = {"block_count": block_count, "white_count": white_count}
    total_block_count += block_count
    total_white_count += white_count

threshold = cfg.get("threshold", {})
max_inc = threshold.get("max_increase", 0.2)
max_dec = threshold.get("max_decrease", 0.2)
force = os.getenv("FORCE_PASS", "false").lower() == "true"

old_total = sum(v.get("block_count", 0) for v in old_stats.values()) if isinstance(old_stats, dict) else 0
delta = total_block_count - old_total
ratio = (delta / old_total) if old_total else 0

if old_total and not force:
    if ratio > max_inc or ratio < -max_dec:
        print("❌ Rule change exceeds threshold")
        sys.exit(1)

adguardhome_rules = sorted(white_rules | block_rules)
adguardhome_content = "\n".join(adguardhome_rules) + "\n"
(OUT / "adguardhome.txt").write_text(adguardhome_content, encoding="utf-8")

dnsmasq_rules = sorted(block_rules)
dnsmasq_lines = []
for r in dnsmasq_rules:
    dnsmasq_lines.append("address=/" + r[2:-1] + "/0.0.0.0")
dnsmasq_content = "\n".join(dnsmasq_lines) + "\n"
(OUT / "dnsmasq.conf").write_text(dnsmasq_content, encoding="utf-8")

clash_rules = sorted(block_rules)
clash_lines = ["payload:"]
for r in clash_rules:
    clash_lines.append("  - '" + r[2:-1] + "'")
clash_content = "\n".join(clash_lines) + "\n"
(OUT / "clash.yaml").write_text(clash_content, encoding="utf-8")

adguardhome_count = len(adguardhome_rules)
dnsmasq_count = len(dnsmasq_rules)
clash_count = len(clash_rules)

new_stats["_output_files"] = {"adguardhome": adguardhome_count, "dnsmasq": dnsmasq_count, "clash": clash_count}
save_stats(new_stats)

now_utc = datetime.utcnow()
now_cst = now_utc + timedelta(hours=8)
time_str = now_cst.strftime("%Y-%m-%d %H:%M:%S")

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
    status = info.get("status",
