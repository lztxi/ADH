#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ADH-AD: Ad Domain Merge Tool
"""

import os
import re
import sys
import json
import time
import datetime
from pathlib import Path
from typing import Dict, List, Set, Tuple, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests
import yaml

# Environment variables
DEBUG = os.getenv("DEBUG", "false").lower() == "true"
DRY_RUN = os.getenv("DRY_RUN", "false").lower() == "true"
FORCE_PASS = os.getenv("FORCE_PASS", "false").lower() == "true"
GITHUB_REPO = os.getenv("GITHUB_REPOSITORY", "lztxi/ADH")

# Path configuration
BASE = Path(__file__).resolve().parent.parent
CFG = BASE / "config" / "ADH-AD.yaml"

output_dir_env = os.getenv("OUTPUT_DIR")
if output_dir_env:
    OUT = Path(output_dir_env).resolve()
else:
    OUT = BASE.parent / "release"

STATS_FILE = BASE / "config" / "ADH_AD_stats.json"

# Constants
DNSMASQ_BLOCK_IP = "0.0.0.0"
MAX_WORKERS = 5
REQUEST_TIMEOUT = 30
MAX_RETRIES = 3

DOMAIN_RE = re.compile(r"^(?:[a-z0-9-]+\.)+[a-z]{2,}$", re.I)

# Logging functions
def log(level: str, msg: str):
    timestamp = datetime.datetime.now().strftime("%H:%M:%S")
    print(f"[{timestamp}][{level}] {msg}")

def debug(msg: str):
    if DEBUG:
        log("DEBUG", msg)

def info(msg: str):
    log("INFO", msg)

def warn(msg: str):
    log("WARN", msg)

def error(msg: str):
    log("ERROR", msg)

# HTTP session with retry
def create_session() -> requests.Session:
    session = requests.Session()
    
    from requests.adapters import HTTPAdapter
    from urllib3.util.retry import Retry
    
    retry_strategy = Retry(
        total=MAX_RETRIES,
        backoff_factor=1,
        status_forcelist=[500, 502, 503, 504],
        allowed_methods=["HEAD", "GET", "OPTIONS"]
    )
    
    adapter = HTTPAdapter(max_retries=retry_strategy)
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    
    session.headers.update({
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) ADH-AD-Bot/1.0"
    })
    
    return session

# Load configuration
def load_config(cfg_path: Path) -> dict:
    try:
        if not cfg_path.exists():
            error(f"Config file not found: {cfg_path}")
            raise FileNotFoundError(f"Config file not found: {cfg_path}")
        
        with open(cfg_path, "r", encoding="utf-8") as f:
            cfg = yaml.safe_load(f)
        info(f"Loaded config file: {cfg_path}")
        return cfg
    except Exception as e:
        error(f"Failed to load config: {e}")
        raise

# Stats file handling
def load_stats(stats_path: Path) -> dict:
    if not stats_path.exists():
        debug(f"Stats file not found: {stats_path}")
        return {}
    
    try:
        with open(stats_path, "r", encoding="utf-8") as f:
            stats = json.load(f)
        info(f"Loaded stats file: {stats_path}")
        return stats
    except Exception as e:
        warn(f"Failed to load stats: {e}")
        return {}

def save_stats(stats_path: Path, stats: dict):
    try:
        stats_path.parent.mkdir(parents=True, exist_ok=True)
        with open(stats_path, "w", encoding="utf-8") as f:
            json.dump(stats, f, ensure_ascii=False, indent=2)
        info(f"Saved stats file: {stats_path}")
    except Exception as e:
        error(f"Failed to save stats: {e}")
        raise

# Domain parsing
def normalize_domain(domain: str) -> str:
    return domain.strip().lstrip(".")

def parse_line(line: str) -> Tuple[Optional[str], bool]:
    try:
        line = line.strip()
        
        if not line or line.startswith(("#", "!", "[")):
            return None, False
        
        is_whitelist = False
        
        if line.startswith("@@"):
            is_whitelist = True
            line = line[2:]
        
        if line.startswith("||") and "^" in line:
            match = re.match(r"^\|\|([^/\^]+)\^", line)
            if match:
                domain = normalize_domain(match.group(1))
                if DOMAIN_RE.match(domain):
                    return domain, is_whitelist
        
        parts = line.split()
        if len(parts) >= 2:
            if parts[0] in ("0.0.0.0", "127.0.0.1", "::"):
                domain = normalize_domain(parts[1])
                if DOMAIN_RE.match(domain):
                    return domain, is_whitelist
        
        domain = normalize_domain(line)
        if DOMAIN_RE.match(domain):
            return domain, is_whitelist
        
        return None, False
    except Exception as e:
        debug(f"Failed to parse line: {line[:50]}, error: {e}")
        return None, False

# Source fetching
def fetch_source_list(source: dict, session: requests.Session) -> Tuple[List[Tuple[str, bool]], dict]:
    url = source.get("url", "")
    name = source.get("name", url)
    
    info(f"Downloading: {name} <- {url}")
    
    try:
        resp = session.get(url, timeout=REQUEST_TIMEOUT)
        resp.raise_for_status()
        
        lines = resp.text.splitlines()
        domains = []
        block_count = 0
        white_count = 0
        
        for line in lines:
            try:
                domain, is_whitelist = parse_line(line)
                if domain:
                    domains.append((domain, is_whitelist))
                    if is_whitelist:
                        white_count += 1
                    else:
                        block_count += 1
            except Exception as e:
                debug(f"Failed to process line: {e}")
        
        stats = {
            "url": url,
            "block_count": block_count,
            "white_count": white_count,
            "total_lines": len(lines),
            "last_update": datetime.datetime.now().isoformat()
        }
        
        return domains, stats
        
    except Exception as e:
        error(f"Download failed [{name}]: {e}")
        return [], {
            "url": url,
            "error": str(e),
            "last_update": datetime.datetime.now().isoformat()
        }

def process_sources_parallel(sources: List[dict], old_stats: dict, max_workers: int = MAX_WORKERS) -> Tuple[Set[str], Set[str], dict]:
    block_rules = set()
    white_rules = set()
    source_stats = {}
    
    session = create_session()
    enabled_sources = [s for s in sources if s.get("enabled", True)]
    
    info(f"Starting parallel download of {len(enabled_sources)} sources (workers: {max_workers})")
    
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_source = {
            executor.submit(fetch_source_list, source, session): source 
            for source in enabled_sources
        }
        
        for future in as_completed(future_to_source):
            source = future_to_source[future]
            name = source.get("name", source.get("url", "unknown"))
            
            try:
                domains, stats = future.result()
                
                for domain, is_whitelist in domains:
                    if is_whitelist:
                        white_rules.add(domain)
                    else:
                        block_rules.add(domain)
                
                source_stats[name] = stats
                info(f"Parsed [{name}]: block {stats.get('block_count', 0)}, white {stats.get('white_count', 0)}")
                
            except Exception as e:
                error(f"Failed to process source [{name}]: {e}")
                source_stats[name] = {
                    "url": source.get("url", ""),
                    "error": str(e),
                    "last_update": datetime.datetime.now().isoformat()
                }
    
    return block_rules, white_rules, source_stats

def process_sources_sequential(sources: List[dict], old_stats: dict) -> Tuple[Set[str], Set[str], dict]:
    block_rules = set()
    white_rules = set()
    source_stats = {}
    
    session = create_session()
    
    for source in sources:
        if not source.get("enabled", True):
            debug(f"Skipping disabled source: {source.get('name', source.get('url'))}")
            continue
        
        name = source.get("name", source.get("url", "unknown"))
        
        try:
            domains, stats = fetch_source_list(source, session)
            
            for domain, is_whitelist in domains:
                if is_whitelist:
                    white_rules.add(domain)
                else:
                    block_rules.add(domain)
            
            source_stats[name] = stats
            info(f"Parsed [{name}]: block {stats.get('block_count', 0)}, white {stats.get('white_count', 0)}")
            
        except Exception as e:
            error(f"Failed to process source [{name}]: {e}")
            source_stats[name] = {
                "url": source.get("url", ""),
                "error": str(e),
                "last_update": datetime.datetime.now().isoformat()
            }
    
    return block_rules, white_rules, source_stats

# Output generation
def write_file(path: Path, content: str, name: str = ""):
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
        file_size = path.stat().st_size
        info(f"Saved file [{name or path.name}]: {file_size:,} bytes")
    except Exception as e:
        error(f"Failed to write file [{path}]: {e}")
        raise

def generate_outputs(block_rules: Set[str], white_rules: Set[str], out_dir: Path):
    info(f"Generating output files to: {out_dir}")
    
    try:
        out_dir.mkdir(parents=True, exist_ok=True)
        info(f"Output directory created: {out_dir}")
    except Exception as e:
        error(f"Failed to create output directory: {e}")
        raise
    
    total_block = len(block_rules)
    total_white = len(white_rules)
    info(f"Block domains: {total_block:,}, White domains: {total_white:,}")
    
    sorted_block = sorted(block_rules)
    sorted_white = sorted(white_rules)
    
    # AdGuard Home
    info("Generating AdGuard Home rules...")
    adguardhome_lines = []
    adguardhome_lines.append("! Title: ADH-AD Blocklist")
    adguardhome_lines.append(f"! Updated: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M UTC')}")
    adguardhome_lines.append(f"! Total rules: {total_block + total_white:,}")
    adguardhome_lines.append(f"! Block rules: {total_block:,}")
    adguardhome_lines.append(f"! White rules: {total_white:,}")
    adguardhome_lines.append(f"! Source: https://github.com/{GITHUB_REPO}")
    adguardhome_lines.append("!")
    
    for domain in sorted_white:
        adguardhome_lines.append(f"@@||{domain}^")
    
    for domain in sorted_block:
        adguardhome_lines.append(f"||{domain}^")
    
    write_file(out_dir / "adguardhome.txt", "\n".join(adguardhome_lines) + "\n", "adguardhome")
    
    # dnsmasq
    info("Generating dnsmasq rules...")
    dnsmasq_lines = []
    for domain in sorted_block:
        dnsmasq_lines.append(f"address=/{domain}/{DNSMASQ_BLOCK_IP}")
    
    write_file(out_dir / "dnsmasq.conf", "\n".join(dnsmasq_lines) + "\n", "dnsmasq")
    
    # Clash
    info("Generating Clash rules...")
    clash_lines = [
        "payload:",
        f"  # Updated: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M UTC')}",
        f"  # Total domains: {total_block:,}",
        f"  # Source: https://github.com/{GITHUB_REPO}",
        ""
    ]
    
    for domain in sorted_block:
        clash_lines.append(f"  - '{domain}'")
    
    write_file(out_dir / "clash.yaml", "\n".join(clash_lines) + "\n", "clash")

# Threshold check
def check_threshold(old_stats: dict, new_stats: dict, threshold_cfg: dict):
    if FORCE_PASS:
        info("Force mode enabled, skipping threshold check")
        return
    
    max_inc = threshold_cfg.get("max_increase", 0.2)
    max_dec = threshold_cfg.get("max_decrease", 0.2)
    
    old_total = sum(
        v.get("block_count", 0) 
        for v in old_stats.values() 
        if isinstance(v, dict)
    )
    
    new_total = sum(
        v.get("block_count", 0) 
        for v in new_stats.values() 
        if isinstance(v, dict)
    )
    
    if old_total == 0:
        info("First run, skipping threshold check")
        return
    
    delta = new_total - old_total
    ratio = delta / old_total
    
    info(f"Rule change: {old_total:,} -> {new_total:,} (delta: {delta:+,}, ratio: {ratio:+.2%})")
    
    if ratio > max_inc:
        error(f"Rule increase exceeds threshold: {ratio:.2%} > {max_inc:.2%}")
        sys.exit(1)
    
    if ratio < -max_dec:
        error(f"Rule decrease exceeds threshold: {ratio:.2%} < -{max_dec:.2%}")
        sys.exit(1)
    
    info(f"Threshold check passed (range: -{max_dec:.0%} ~ +{max_inc:.0%})")

# README generation - using simple string concatenation to avoid syntax issues

def generate_readme(source_stats, old_stats, out_dir):
    """生成漂亮的中文+Emoji README"""
    info("生成 README.md...")
    
    total_block = sum(v.get("block_count", 0) for v in source_stats.values() if isinstance(v, dict))
    total_white = sum(v.get("white_count", 0) for v in source_stats.values() if isinstance(v, dict))
    
    lines = []
    
    # 标题和简介
    lines.append("# 🛡️ ADH-AD 广告域名规则")
    lines.append("")
    lines.append("> ✨ 自动合并多个上游广告域名规则")
    lines.append("> 🎯 让你的网络环境更清爽，远离广告骚扰！")
    lines.append("")
    
    # 统计表格
    lines.append("## 📊 规则统计")
    lines.append("")
    lines.append("| 项目 | 数量 |")
    lines.append("|------|------|")
    update_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M UTC")
    lines.append(f"| 🕐 **更新时间** | {update_time} |")
    lines.append(f"| 📦 **黑名单域名** | {total_block:,} 个 |")
    lines.append(f"| 🎯 **白名单域名** | {total_white:,} 个 |")
    lines.append(f"| 📋 **上游源数量** | {len(source_stats)} 个 |")
    lines.append("")
    
    # 订阅地址
    lines.append("## 📥 快速订阅")
    lines.append("")
    lines.append("### 1️⃣ AdGuard Home 用户")
    lines.append("```")
    lines.append(f"https://raw.githubusercontent.com/{GITHUB_REPO}/release/adguardhome.txt")
    lines.append("```")
    lines.append("")
    lines.append("### 2️⃣ dnsmasq 用户")
    lines.append("```")
    lines.append(f"https://raw.githubusercontent.com/{GITHUB_REPO}/release/dnsmasq.conf")
    lines.append("```")
    lines.append("")
    lines.append("### 3️⃣ Clash 用户")
    lines.append("```")
    lines.append(f"https://raw.githubusercontent.com/{GITHUB_REPO}/release/clash.yaml")
    lines.append("```")
    lines.append("")
    
    # 上游源表格
    lines.append("## 📋 上游源详情")
    lines.append("")
    lines.append("| 名称 | 黑名单 | 白名单 | 状态 |")
    lines.append("|------|--------|--------|------|")
    
    for name, stats in sorted(source_stats.items()):
        if isinstance(stats, dict):
            block_count = stats.get("block_count", 0)
            white_count = stats.get("white_count", 0)
            error_msg = stats.get("error", "")
            status = "✅ 正常" if not error_msg else "❌ 失败"
            lines.append(f"| {name} | {block_count:,} | {white_count:,} | {status} |")
    
    lines.append("")
    
    # 使用指南
    lines.append("## 🔧 使用指南")
    lines.append("")
    lines.append("### 🏠 AdGuard Home 用户")
    lines.append("1. 打开 AdGuard Home 设置 → 过滤器")
    lines.append("2. 添加自定义过滤规则列表")
    lines.append("3. 粘贴上述订阅地址即可 ✅")
    lines.append("")
    lines.append("### 📱 dnsmasq 用户")
    lines.append("将 dnsmasq.conf 放置到配置目录，重启服务生效 🔄")
    lines.append("")
    lines.append("### 🌐 Clash 用户")
    lines.append("在配置文件中添加规则提供商配置即可 ⚙️")
    lines.append("")
    
    # 特色功能
    lines.append("## ✨ 特色功能")
    lines.append("")
    lines.append("- 🔥 **自动更新**：每日 00:00 和 12:00 UTC")
    lines.append("- 🎯 **多格式支持**：AdGuard + dnsmasq + Clash")
    lines.append("- 🛡️ **智能白名单**：自动处理上游规则")
    lines.append("- 📊 **变化监控**：超阈值自动回滚")
    lines.append("- 🚀 **高性能**：并行下载多源")
    lines.append("")
    
    # 许可证
    lines.append("## 📜 许可证")
    lines.append("")
    lines.append("规则来自各上游源，版权归原作者所有")
    lines.append("构建脚本由 ADH 项目维护")
    lines.append("")
    lines.append("---")
    lines.append("")
    lines.append("💡 **小贴士**：推荐使用 AdGuard Home，配置最简单！")
    lines.append("")
    lines.append("🌟 觉得有用就给个 Star 吧！")
    
    content = "\n".join(lines) + "\n"
    write_file(out_dir / "README.md", content, "README")

# Main function
def main():
    start_time = time.time()
    
    info("=" * 60)
    info("ADH-AD Ad Domain Merge Tool Started")
    info("=" * 60)
    info(f"Working directory: {BASE}")
    info(f"Config file: {CFG}")
    info(f"Output directory: {OUT}")
    info(f"Stats file: {STATS_FILE}")
    info(f"Mode: {'DRY RUN' if DRY_RUN else 'PRODUCTION'}")
    info(f"Force mode: {'enabled' if FORCE_PASS else 'disabled'}")
    info("=" * 60)
    
    try:
        OUT.mkdir(parents=True, exist_ok=True)
        info(f"Output directory created: {OUT}")
    except Exception as e:
        error(f"Failed to create output directory: {e}")
        raise
    
    try:
        cfg = load_config(CFG)
        sources = cfg.get("sources", [])
        threshold_cfg = cfg.get("threshold", {})
        info(f"Loaded {len(sources)} upstream sources")
    except Exception as e:
        error(f"Failed to load config: {e}")
        generate_outputs(set(), set(), OUT)
        generate_readme({}, {}, OUT)
        raise
    
    old_stats = load_stats(STATS_FILE)
    
    try:
        if len(sources) > 5:
            info("Using parallel download mode")
            block_rules, white_rules, source_stats = process_sources_parallel(sources, old_stats)
        else:
            info("Using sequential download mode")
            block_rules, white_rules, source_stats = process_sources_sequential(sources, old_stats)
        
        info(f"Parsing complete: block {len(block_rules):,}, white {len(white_rules):,}")
    except Exception as e:
        error(f"Failed to process upstream sources: {e}")
        block_rules = set()
        white_rules = set()
        source_stats = {}
    
    try:
        check_threshold(old_stats, source_stats, threshold_cfg)
    except SystemExit:
        raise
    except Exception as e:
        warn(f"Threshold check exception: {e}")
    
    try:
        generate_outputs(block_rules, white_rules, OUT)
    except Exception as e:
        error(f"Failed to generate output files: {e}")
        raise
    
    try:
        generate_readme(source_stats, old_stats, OUT)
    except Exception as e:
        warn(f"Failed to generate README: {e}")
    
    new_stats = {
        "last_update": datetime.datetime.now().isoformat(),
        "total_block": len(block_rules),
        "total_white": len(white_rules),
        "sources": source_stats
    }
    
    if not DRY_RUN:
        try:
            save_stats(STATS_FILE, new_stats)
        except Exception as e:
            warn(f"Failed to save stats: {e}")
    else:
        info("DRY RUN mode, skipping stats save")
    
    elapsed_time = time.time() - start_time
    info("=" * 60)
    info("Build complete!")
    info(f"Time elapsed: {elapsed_time:.2f} seconds")
    info(f"Block domains: {len(block_rules):,}")
    info(f"White domains: {len(white_rules):,}")
    info(f"Upstream sources: {len(source_stats)}")
    info("=" * 60)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        warn("User interrupted")
        sys.exit(130)
    except SystemExit:
        raise
    except Exception as e:
        error(f"Program exception: {e}")
        if DEBUG:
            import traceback
            traceback.print_exc()
        
        try:
            OUT.mkdir(parents=True, exist_ok=True)
            if not (OUT / "adguardhome.txt").exists():
                write_file(OUT / "adguardhome.txt", "! Error occurred during build", "error-file")
            if not (OUT / "dnsmasq.conf").exists():
                write_file(OUT / "dnsmasq.conf", "# Error occurred during build", "error-file")
            if not (OUT / "clash.yaml").exists():
                write_file(OUT / "clash.yaml", "payload: # Error occurred during build", "error-file")
            if not (OUT / "README.md").exists():
                write_file(OUT / "README.md", "# Error occurred", "error-file")
        except Exception as inner_e:
            error(f"Failed to create error files: {inner_e}")
        sys.exit(1)
