#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ADH-AD: Ad Domain Merge Tool
Merge ad domain rules from multiple sources
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
        
