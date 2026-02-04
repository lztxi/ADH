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
    print("❌ 错误：找不到配置文件！")
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
        source_stats[name] = {
