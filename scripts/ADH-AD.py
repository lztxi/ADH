#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ADH-AD: 广告域名合并工具
从多个上游源合并广告域名规则，生成多种格式输出
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

# ==================== 环境变量配置 ====================
DEBUG = os.getenv("DEBUG", "false").lower() == "true"
DRY_RUN = os.getenv("DRY_RUN", "false").lower() == "true"
FORCE_PASS = os.getenv("FORCE_PASS", "false").lower() == "true"
GITHUB_REPO = os.getenv("GITHUB_REPOSITORY", "lztxi/ADH")

# ==================== 路径配置 ====================
# BASE 指向脚本所在目录的父目录（即 main 目录）
BASE = Path(__file__).resolve().parent.parent
CFG = BASE / "config" / "ADH-AD.yaml"

# 输出目录：优先使用环境变量 OUTPUT_DIR，否则使用 BASE.parent / "release"
# 这样在 GitHub Actions 中，OUTPUT_DIR 设置为 ${{ github.workspace }}/release
# 本地测试时，会输出到 BASE.parent / "release"（即 ADH 根目录的 release 子目录）
output_dir_env = os.getenv("OUTPUT_DIR")
if output_dir_env:
    OUT = Path(output_dir_env).resolve()
else:
    # 本地测试时，使用相对路径
    OUT = BASE.parent / "release"

STATS_FILE = BASE / "config" / "ADH_AD_stats.json"

# ==================== 常量配置 ====================
DNSMASQ_BLOCK_IP = "0.0.0.0"
MAX_WORKERS = 5  # 并发下载线程数
REQUEST_TIMEOUT = 30
MAX_RETRIES = 3

# 域名正则
DOMAIN_RE = re.compile(r"^(?:[a-z0-9-]+\.)+[a-z]{2,}$", re.I)

# ==================== 日志工具 ====================
def log(level: str, msg: str):
    """统一日志输出"""
    timestamp = datetime.datetime.now().strftime("%H:%M:%S")
    print(f"[{timestamp}][{level}] {msg}")

def debug(msg: str):
    """调试日志"""
    if DEBUG:
        log("DEBUG", msg)

def info(msg: str):
    """信息日志"""
    log("INFO", msg)

def warn(msg: str):
    """警告日志"""
    log("WARN", msg)

def error(msg: str):
    """错误日志"""
    log("ERROR", msg)

# ==================== HTTP 会话（带重试） ====================
def create_session() -> requests.Session:
    """创建带重试机制的 requests 会话"""
    session = requests.Session()
    
    # 配置重试策略
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
    
    # 设置 User-Agent
    session.headers.update({
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) ADH-AD-Bot/1.0"
    })
    
    return session

# ==================== 配置加载 ====================
def load_config(cfg_path: Path) -> dict:
    """加载 YAML 配置文件"""
    try:
        if not cfg_path.exists():
            error(f"配置文件不存在: {cfg_path}")
            raise FileNotFoundError(f"配置文件不存在: {cfg_path}")
        
        with open(cfg_path, "r", encoding="utf-8") as f:
            cfg = yaml.safe_load(f)
        info(f"加载配置文件: {cfg_path}")
        return cfg
    except Exception as e:
        error(f"加载配置文件失败: {e}")
        raise

# ==================== 统计文件处理 ====================
def load_stats(stats_path: Path) -> dict:
    """加载统计文件"""
    if not stats_path.exists():
        debug(f"统计文件不存在: {stats_path}")
        return {}
    
    try:
        with open(stats_path, "r", encoding="utf-8") as f:
