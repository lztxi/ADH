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
BASE = Path(__file__).resolve().parent.parent
CFG = BASE / "config" / "ADH-AD.yaml"
OUT = BASE / "out"
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
            stats = json.load(f)
        info(f"加载统计文件: {stats_path}")
        return stats
    except Exception as e:
        warn(f"读取统计文件失败: {e}")
        return {}

def save_stats(stats_path: Path, stats: dict):
    """保存统计文件"""
    try:
        stats_path.parent.mkdir(parents=True, exist_ok=True)
        with open(stats_path, "w", encoding="utf-8") as f:
            json.dump(stats, f, ensure_ascii=False, indent=2)
        info(f"保存统计文件: {stats_path}")
    except Exception as e:
        error(f"保存统计文件失败: {e}")
        raise

# ==================== 域名解析 ====================
def normalize_domain(domain: str) -> str:
    """规范化域名（去除前导点等）"""
    return domain.strip().lstrip(".")

def parse_line(line: str) -> Tuple[Optional[str], bool]:
    """
    解析单行规则，返回 (域名, 是否白名单)
    返回 None 表示该行应跳过
    """
    line = line.strip()
    
    # 跳过空行和注释
    if not line or line.startswith(("#", "!", "[")):
        return None, False
    
    is_whitelist = False
    
    # 白名单处理
    if line.startswith("@@"):
        is_whitelist = True
        line = line[2:]
    
    # AdGuard 格式: ||domain^
    if line.startswith("||") and "^" in line:
        # 提取 || 与 ^ 之间的内容
        match = re.match(r"^\|\|([^/\^]+)\^", line)
        if match:
            domain = normalize_domain(match.group(1))
            if DOMAIN_RE.match(domain):
                return domain, is_whitelist
    
    # Hosts 格式: 0.0.0.0 domain 或 127.0.0.1 domain
    parts = line.split()
    if len(parts) >= 2:
        if parts[0] in ("0.0.0.0", "127.0.0.1", "::"):
            domain = normalize_domain(parts[1])
            if DOMAIN_RE.match(domain):
                return domain, is_whitelist
    
    # 纯域名格式
    domain = normalize_domain(line)
    if DOMAIN_RE.match(domain):
        return domain, is_whitelist
    
    return None, False

# ==================== 源处理 ====================
def fetch_source_list(source: dict, session: requests.Session) -> Tuple[List[Tuple[str, bool]], dict]:
    """
    下载并解析单个上游源
    返回 (域名列表, 统计信息)
    """
    url = source.get("url", "")
    name = source.get("name", url)
    
    info(f"下载: {name} <- {url}")
    
    try:
        resp = session.get(url, timeout=REQUEST_TIMEOUT)
        resp.raise_for_status()
        
        lines = resp.text.splitlines()
        domains = []
        block_count = 0
        white_count = 0
        
        for line in lines:
            domain, is_whitelist = parse_line(line)
            if domain:
                domains.append((domain, is_whitelist))
                if is_whitelist:
                    white_count += 1
                else:
                    block_count += 1
        
        stats = {
            "url": url,
            "block_count": block_count,
            "white_count": white_count,
            "total_lines": len(lines),
            "last_update": datetime.datetime.now().isoformat()
        }
        
        return domains, stats
        
    except Exception as e:
        error(f"下载失败 [{name}]: {e}")
        return [], {
            "url": url,
            "error": str(e),
            "last_update": datetime.datetime.now().isoformat()
        }

def process_sources_parallel(sources: List[dict], old_stats: dict, max_workers: int = MAX_WORKERS) -> Tuple[Set[str], Set[str], dict]:
    """
    并行处理所有上游源
    返回 (黑名单集合, 白名单集合, 源统计信息)
    """
    block_rules = set()
    white_rules = set()
    source_stats = {}
    
    session = create_session()
    enabled_sources = [s for s in sources if s.get("enabled", True)]
    
    info(f"开始并行下载 {len(enabled_sources)} 个源 (并发数: {max_workers})")
    
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        # 提交所有任务
        future_to_source = {
            executor.submit(fetch_source_list, source, session): source 
            for source in enabled_sources
        }
        
        # 收集结果
        for future in as_completed(future_to_source):
            source = future_to_source[future]
            name = source.get("name", source.get("url", "unknown"))
            
            try:
                domains, stats = future.result()
                
                # 分类域名
                for domain, is_whitelist in domains:
                    if is_whitelist:
                        white_rules.add(domain)
                    else:
                        block_rules.add(domain)
                
                source_stats[name] = stats
                info(f"解析完成 [{name}]: 黑名单 {stats.get('block_count', 0)}, 白名单 {stats.get('white_count', 0)}")
                
            except Exception as e:
                error(f"处理源失败 [{name}]: {e}")
                source_stats[name] = {
                    "url": source.get("url", ""),
                    "error": str(e),
                    "last_update": datetime.datetime.now().isoformat()
                }
    
    return block_rules, white_rules, source_stats

def process_sources_sequential(sources: List[dict], old_stats: dict) -> Tuple[Set[str], Set[str], dict]:
    """
    顺序处理所有上游源（兼容模式）
    返回 (黑名单集合, 白名单集合, 源统计信息)
    """
    block_rules = set()
    white_rules = set()
    source_stats = {}
    
    session = create_session()
    
    for source in sources:
        if not source.get("enabled", True):
            debug(f"跳过已禁用的源: {source.get('name', source.get('url'))}")
            continue
        
        name = source.get("name", source.get("url", "unknown"))
        
        try:
            domains, stats = fetch_source_list(source, session)
            
            # 分类域名
            for domain, is_whitelist in domains:
                if is_whitelist:
                    white_rules.add(domain)
                else:
                    block_rules.add(domain)
            
            source_stats[name] = stats
            info(f"解析完成 [{name}]: 黑名单 {stats.get('block_count', 0)}, 白名单 {stats.get('white_count', 0)}")
            
        except Exception as e:
            error(f"处理源失败 [{name}]: {e}")
            source_stats[name] = {
                "url": source.get("url", ""),
                "error": str(e),
                "last_update": datetime.datetime.now().isoformat()
            }
    
    return block_rules, white_rules, source_stats

# ==================== 输出生成 ====================
def write_file(path: Path, content: str, name: str = ""):
    """写入文件并打印日志"""
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
        file_size = path.stat().st_size
        info(f"保存文件 [{name or path.name}]: {file_size:,} bytes")
    except Exception as e:
        error(f"写入文件失败 [{path}]: {e}")
        raise

def generate_outputs(block_rules: Set[str], white_rules: Set[str], out_dir: Path):
    """生成所有输出文件"""
    info(f"生成输出文件到: {out_dir}")
    
    # 统计信息
    total_block = len(block_rules)
    total_white = len(white_rules)
    info(f"黑名单域名: {total_block:,}, 白名单域名: {total_white:,}")
    
    # 只排序一次，复用结果
    sorted_block = sorted(block_rules)
    sorted_white = sorted(white_rules)
    
    # 1. AdGuard Home
    info("生成 AdGuard Home 规则...")
    adguardhome_lines = []
    adguardhome_lines.append("! Title: ADH-AD Blocklist")
    adguardhome_lines.append(f"! Updated: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M UTC')}")
    adguardhome_lines.append(f"! Total rules: {total_block + total_white:,}")
    adguardhome_lines.append(f"! Block rules: {total_block:,}")
    adguardhome_lines.append(f"! White rules: {total_white:,}")
    adguardhome_lines.append(f"! Source: https://github.com/{GITHUB_REPO}")
    adguardhome_lines.append("!")
    
    # 添加白名单
    for domain in sorted_white:
        adguardhome_lines.append(f"@@||{domain}^")
    
    # 添加黑名单
    for domain in sorted_block:
        adguardhome_lines.append(f"||{domain}^")
    
    write_file(out_dir / "adguardhome.txt", "\n".join(adguardhome_lines) + "\n", "adguardhome")
    
    # 2. dnsmasq
    info("生成 dnsmasq 规则...")
    dnsmasq_lines = []
    for domain in sorted_block:
        dnsmasq_lines.append(f"address=/{domain}/{DNSMASQ_BLOCK_IP}")
    
    write_file(out_dir / "dnsmasq.conf", "\n".join(dnsmasq_lines) + "\n", "dnsmasq")
    
    # 3. Clash
    info("生成 Clash 规则...")
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

# ==================== 阈值检查 ====================
def check_threshold(old_stats: dict, new_stats: dict, threshold_cfg: dict):
    """检查规则变化阈值"""
    if FORCE_PASS:
        info("已启用强制模式，跳过阈值检查")
        return
    
    max_inc = threshold_cfg.get("max_increase", 0.2)
    max_dec = threshold_cfg.get("max_decrease", 0.2)
    
    # 计算旧的总数
    old_total = sum(
        v.get("block_count", 0) 
        for v in old_stats.values() 
        if isinstance(v, dict)
    )
    
    # 计算新的总数
    new_total = sum(
        v.get("block_count", 0) 
        for v in new_stats.values() 
        if isinstance(v, dict)
    )
    
    if old_total == 0:
        info("首次运行，跳过阈值检查")
        return
    
    delta = new_total - old_total
    ratio = delta / old_total
    
    info(f"规则变化: {old_total:,} -> {new_total:,} (变化: {delta:+,}, 比例: {ratio:+.2%})")
    
    if ratio > max_inc:
        error(f"规则增长超过阈值: {ratio:.2%} > {max_inc:.2%}")
        sys.exit(1)
    
    if ratio < -max_dec:
        error(f"规则减少超过阈值: {ratio:.2%} < -{max_dec:.2%}")
        sys.exit(1)
    
    info(f"阈值检查通过 (允许范围: -{max_dec:.0%} ~ +{max_inc:.0%})")

# ==================== README 生成 ====================
def generate_readme(source_stats: dict, old_stats: dict, out_dir: Path):
    """生成 README.md 文件"""
    info("生成 README.md...")
    
    # 计算总数
    total_block = sum(v.get("block_count", 0) for v in source_stats.values() if isinstance(v, dict))
    total_white = sum(v.get("white_count", 0) for v in source_stats.values() if isinstance(v, dict))
    
    # 生成上游源表格
    source_table = []
    source_table.append("| 名称 | 黑名单 | 白名单 | 总行数 | 状态 |")
    source_table.append("|------|--------|--------|--------|------|")
    
    for name, stats in sorted(source_stats.items()):
        if isinstance(stats, dict):
            block_count = stats.get("block_count", 0)
            white_count = stats.get("white_count", 0)
            total_lines = stats.get("total_lines", 0)
            error_msg = stats.get("error", "")
            
            status = "✅" if not error_msg else f"❌ {error_msg[:20]}"
            
            source_table.append(f"| {name} | {block_count:,} | {white_count:,} | {total_lines:,} | {status} |")
    
    # 生成 README 内容
    readme_content = f"""# ADH-AD 广告域名规则

> 自动合并多个上游广告域名规则，支持 AdGuard Home、dnsmasq、Clash 等多种格式

## 📊 规则统计

- **更新时间**: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M UTC')}
- **黑名单域名**: {total_block:,}
- **白名单域名**: {total_white:,}
- **上游源数量**: {len(source_stats)}

## 📥 下载地址

### AdGuard Home
```
https://raw.githubusercontent.com/{GITHUB_REPO}/release/adguardhome.txt
```

### dnsmasq
```
https://raw.githubusercontent.com/{GITHUB_REPO}/release/dnsmasq.conf
```

### Clash
```yaml
https://raw.githubusercontent.com/{GITHUB_REPO}/release/clash.yaml
```

## 📋 上游源统计

{chr(10).join(source_table)}

## 🔧 使用方法

### AdGuard Home
1. 打开 AdGuard Home 设置 -> 过滤器
2. 添加自定义过滤规则列表
3. 粘贴上述订阅地址

### dnsmasq
将 `dnsmasq.conf` 放置到 dnsmasq 配置目录，重启服务即可

### Clash
在 Clash 配置文件中添加：
```yaml
rule-providers:
  adh-ad:
    type: http
    behavior: domain
    url: "https://raw.githubusercontent.com/{GITHUB_REPO}/release/clash.yaml"
    path: ./adh-ad.yaml
    interval: 86400

rules:
  - RULE-SET,adh-ad,REJECT
```

## 📝 说明

- 规则每日自动更新两次 (00:00, 12:00 UTC)
- 支持白名单规则（来自上游的 `@@` 开头规则）
- 自动去重和格式标准化
- 规则变化超过阈值会自动回滚

## 📜 许可证

本项目规则来自各上游源，版权归原作者所有
"""

    write_file(out_dir / "README.md", readme_content, "README")

# ==================== 主函数 ====================
def main():
    """主函数"""
    start_time = time.time()
    
    info("=" * 60)
    info("ADH-AD 广告域名合并工具启动")
    info("=" * 60)
    info(f"工作目录: {BASE}")
    info(f"配置文件: {CFG}")
    info(f"输出目录: {OUT}")
    info(f"统计文件: {STATS_FILE}")
    info(f"模式: {'DRY RUN' if DRY_RUN else 'PRODUCTION'}")
    info(f"强制模式: {'启用' if FORCE_PASS else '禁用'}")
    info("=" * 60)
    
    # 1. 加载配置
    cfg = load_config(CFG)
    sources = cfg.get("sources", [])
    threshold_cfg = cfg.get("threshold", {})
    
    info(f"加载 {len(sources)} 个上游源")
    
    # 2. 加载旧统计
    old_stats = load_stats(STATS_FILE)
    
    # 3. 处理上游源（根据源数量选择顺序或并行）
    if len(sources) > 5:
        info("启用并行下载模式")
        block_rules, white_rules, source_stats = process_sources_parallel(sources, old_stats)
    else:
        info("启用顺序下载模式")
        block_rules, white_rules, source_stats = process_sources_sequential(sources, old_stats)
    
    info(f"解析完成: 黑名单 {len(block_rules):,}, 白名单 {len(white_rules):,}")
    
    # 4. 阈值检查
    check_threshold(old_stats, source_stats, threshold_cfg)
    
    # 5. 生成输出文件
    generate_outputs(block_rules, white_rules, OUT)
    
    # 6. 生成 README
    generate_readme(source_stats, old_stats, OUT)
    
    # 7. 保存新统计
    new_stats = {
        "last_update": datetime.datetime.now().isoformat(),
        "total_block": len(block_rules),
        "total_white": len(white_rules),
        "sources": source_stats
    }
    
    if not DRY_RUN:
        save_stats(STATS_FILE, new_stats)
    else:
        info("DRY RUN 模式，跳过统计文件保存")
    
    # 8. 打印总结
    elapsed_time = time.time() - start_time
    info("=" * 60)
    info("构建完成！")
    info(f"耗时: {elapsed_time:.2f} 秒")
    info(f"黑名单域名: {len(block_rules):,}")
    info(f"白名单域名: {len(white_rules):,}")
    info(f"上游源数量: {len(source_stats)}")
    info("=" * 60)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        warn("用户中断")
        sys.exit(130)
    except Exception as e:
        error(f"程序异常: {e}")
        if DEBUG:
            import traceback
            traceback.print_exc()
        sys.exit(1)
