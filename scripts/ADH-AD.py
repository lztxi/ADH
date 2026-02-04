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
    """读取上次运行的统计数据（记录黑名单、白名单和输出文件数量）"""
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
    """保存本次运行的统计数据（记录黑名单、白名单和输出文件数量）"""
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
