#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ADH-AD - AdGuard Home 广告拦截规则自动构建脚本
"""

import os
import sys
import json
import re
import argparse
from datetime import datetime, timezone
from concurrent.futures import ThreadPoolExecutor, as_completed

import yaml
import requests

# ============================================================
# 路径常量
# ============================================================
CONFIG_FILE = "config/ADH-AD.yaml"
STATS_FILE = "config/ADH_AD_stats.json"
OUTPUT_DIR = "release"

REQUEST_TIMEOUT = 30
MAX_RETRIES = 3
MAX_WORKERS = 5
PARALLEL_THRESHOLD = 5

# 需要跳过的规则模式
SKIP_PATTERNS = [
    re.compile(r'^##'),
    re.compile(r'^#\$#'),
    re.compile(r'^#@#'),
    re.compile(r'^#%#'),
    re.compile(r'\$.*~'),
    re.compile(r'\$.*domain='),
    re.compile(r'\$.*third-party'),
    re.compile(r'\$.*popup'),
    re.compile(r'\$.*script'),
    re.compile(r'\$.*image'),
    re.compile(r'\$.*xmlhttprequest'),
    re.compile(r'\*'),
    re.compile(r'/'),
    re.compile(r'\?'),
    re.compile(r'\$'),
]

INVALID_DOMAINS = {
    'localhost', 'localhost.localdomain', 'local', 'broadcasthost',
    'ip6-localhost', 'ip6-loopback', 'ip6-localnet', 'ip6-mcastprefix',
    'ip6-allnodes', 'ip6-allrouters', 'ip6-allhosts',
    '0.0.0.0', '127.0.0.1', '255.255.255.255', '::1', 'ff00::0',
    'ff02::1', 'ff02::2', 'ff02::3', 'fe80::1%lo0',
}


# ============================================================
# 工具函数
# ============================================================

def load_config():
    """加载 config/ADH-AD.yaml"""
    if not os.path.exists(CONFIG_FILE):
        print(f"[ERROR] 配置文件不存在: {CONFIG_FILE}")
        sys.exit(1)
    with open(CONFIG_FILE, 'r', encoding='utf-8') as f:
        config = yaml.safe_load(f)
    print(f"[CONFIG] 已加载: {CONFIG_FILE}")
    return config


def load_previous_stats():
    """加载 config/ADH_AD_stats.json"""
    if not os.path.exists(STATS_FILE):
        print(f"[STATS] 未找到 {STATS_FILE}，跳过阈值检查")
        return None
    try:
        with open(STATS_FILE, 'r', encoding='utf-8') as f:
            stats = json.load(f)
        print(f"[STATS] 已加载历史统计: {stats.get('timestamp', 'unknown')}")
        return stats
    except (json.JSONDecodeError, IOError) as e:
        print(f"[WARN] 历史统计读取失败: {e}")
        return None


def save_stats(stats):
    """保存统计到 config/ADH_AD_stats.json"""
    os.makedirs(os.path.dirname(STATS_FILE), exist_ok=True)
    with open(STATS_FILE, 'w', encoding='utf-8') as f:
        json.dump(stats, f, ensure_ascii=False, indent=2)
    print(f"[STATS] 已保存: {STATS_FILE}")


def is_valid_domain(domain):
    """验证域名合法性"""
    if not domain or len(domain) > 253:
        return False
    if domain in INVALID_DOMAINS:
        return False
    if domain.startswith('.') or domain.endswith('.'):
        return False
    if '..' in domain:
        return False
    pattern = re.compile(
        r'^[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?'
        r'(\.[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?)*'
        r'\.[a-zA-Z]{2,}$'
    )
    return bool(pattern.match(domain))


def should_skip_rule(line):
    """判断是否跳过该规则"""
    stripped = line.strip()
    if not stripped:
        return True
    for p in SKIP_PATTERNS:
        if p.search(stripped):
            return True
    return False


# ============================================================
# 下载模块
# ============================================================

def download_source(url, name, retries=MAX_RETRIES):
    """下载单个源，带重试"""
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
    }
    for attempt in range(1, retries + 1):
        try:
            print(f"[DOWNLOAD] ({attempt}/{retries}) {name}")
            resp = requests.get(url, headers=headers, timeout=REQUEST_TIMEOUT)
            resp.raise_for_status()
            resp.encoding = resp.apparent_encoding or 'utf-8'
            print(f"[DOWNLOAD] ✅ {name} - {len(resp.text):,} bytes")
            return resp.text
        except requests.RequestException as e:
            print(f"[WARN] ({attempt}/{retries}) {name} 失败: {e}")
            if attempt == retries:
                print(f"[ERROR] ❌ {name} 最终失败，跳过")
                return None
    return None


def download_all_sources(sources):
    """下载所有源"""
    results = {}
    if len(sources) > PARALLEL_THRESHOLD:
        print(f"[DOWNLOAD] 并行下载 (workers={MAX_WORKERS})")
        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
            futures = {
                executor.submit(download_source, src['url'], src['name']): src
                for src in sources
            }
            for future in as_completed(futures):
                src = futures[future]
                try:
                    content = future.result()
                    if content:
                        results[src['name']] = content
                except Exception as e:
                    print(f"[ERROR] {src['name']} 异常: {e}")
    else:
        for src in sources:
            content = download_source(src['url'], src['name'])
            if content:
                results[src['name']] = content

    print(f"[DOWNLOAD] 完成: {len(results)}/{len(sources)}")
    return results


# ============================================================
# 解析模块
# ============================================================

def parse_rules(content, source_name):
    """解析规则内容，返回 (block_set, whitelist_set)"""
    block_domains = set()
    whitelist_domains = set()

    for line in content.splitlines():
        stripped = line.strip()

        if not stripped:
            continue

        # 注释行
        if stripped.startswith('!'):
            continue
        if stripped.startswith('#') and not stripped.startswith('0.0.0.0') and not stripped.startswith('127.0.0.1'):
            continue

        # 白名单: @@||domain^
        if stripped.startswith('@@'):
            domain = stripped[2:].strip('|').strip('^').strip()
            if is_valid_domain(domain):
                whitelist_domains.add(domain.lower())
            continue

        # AdGuard 格式: ||domain^
        if stripped.startswith('||'):
            domain = stripped[2:].rstrip('^').rstrip('/')
            if should_skip_rule(domain):
                continue
            if is_valid_domain(domain):
                block_domains.add(domain.lower())
            continue

        # Hosts 格式: 0.0.0.0 domain / 127.0.0.1 domain
        if stripped.startswith('0.0.0.0') or stripped.startswith('127.0.0.1'):
            parts = stripped.split()
            if len(parts) >= 2:
                domain = parts[1].strip().lower()
                if is_valid_domain(domain):
                    block_domains.add(domain)
            continue

        # 跳过特殊规则
        if should_skip_rule(stripped):
            continue

        # 纯域名
        domain = stripped.lower().rstrip('.')
        if is_valid_domain(domain):
            block_domains.add(domain)

    return block_domains, whitelist_domains


# ============================================================
# 阈值检查
# ============================================================

def check_threshold(current_total, prev_stats, thresholds, force=False):
    """检查变化是否在阈值内"""
    if force:
        print("[THRESHOLD] 强制模式，跳过")
        return True
    if not prev_stats:
        print("[THRESHOLD] 无历史数据，跳过")
        return True

    prev_total = prev_stats.get("total_block", 0)
    if prev_total == 0:
        print("[THRESHOLD] 历史为 0，跳过")
        return True

    change_pct = (current_total - prev_total) / prev_total * 100
    max_inc = thresholds.get("max_increase", 15)
    max_dec = thresholds.get("max_decrease", 10)

    print(f"[THRESHOLD] 上次: {prev_total:,} | 本次: {current_total:,} | 变化: {change_pct:+.2f}%")

    if change_pct > max_inc:
        print(f"[ERROR] ❌ 增长 {change_pct:.2f}% 超过 +{max_inc}%，终止！")
        return False
    if change_pct < -max_dec:
        print(f"[ERROR] ❌ 减少 {abs(change_pct):.2f}% 超过 -{max_dec}%，终止！")
        return False

    print(f"[THRESHOLD] ✅ 在允许范围内")
    return True


# ============================================================
# 输出模块（全部写入 release/ 目录）
# ============================================================

def generate_adguardhome(block_domains, whitelist_domains):
    """生成 release/adguardhome.txt"""
    filepath = os.path.join(OUTPUT_DIR, "adguardhome.txt")
    try:
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write("! Title: ADH-AD 广告拦截规则\n")
            f.write(f"! Updated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}\n")
            f.write(f"! Total: {len(block_domains):,} block + {len(whitelist_domains):,} whitelist\n")
            f.write("!\n")
            for domain in sorted(whitelist_domains):
                f.write(f"@@||{domain}^\n")
            for domain in sorted(block_domains):
                f.write(f"||{domain}^\n")
        print(f"[OUTPUT] ✅ adguardhome.txt ({len(block_domains):,} + {len(whitelist_domains):,})")
    except IOError as e:
        print(f"[ERROR] adguardhome.txt 写入失败: {e}")
        open(filepath, 'w').close()


def generate_dnsmasq(block_domains):
    """生成 release/dnsmasq.conf"""
    filepath = os.path.join(OUTPUT_DIR, "dnsmasq.conf")
    try:
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(f"# ADH-AD dnsmasq 规则\n")
            f.write(f"# Updated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}\n")
            f.write(f"# Total: {len(block_domains):,}\n#\n")
            for domain in sorted(block_domains):
                f.write(f"address=/{domain}/0.0.0.0\n")
        print(f"[OUTPUT] ✅ dnsmasq.conf ({len(block_domains):,})")
    except IOError as e:
        print(f"[ERROR] dnsmasq.conf 写入失败: {e}")
        open(filepath, 'w').close()


def generate_clash(block_domains):
    """生成 release/clash.yaml"""
    filepath = os.path.join(OUTPUT_DIR, "clash.yaml")
    try:
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(f"# ADH-AD Clash 规则\n")
            f.write(f"# Updated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}\n")
            f.write(f"# Total: {len(block_domains):,}\n")
            f.write("payload:\n")
            for domain in sorted(block_domains):
                f.write(f"  - '+.{domain}'\n")
        print(f"[OUTPUT] ✅ clash.yaml ({len(block_domains):,})")
    except IOError as e:
        print(f"[ERROR] clash.yaml 写入失败: {e}")
        open(filepath, 'w').close()


def generate_readme(stats, prev_stats, sources_config):
    """
    生成 release/README.md 统计报告
    【修复】补全源详情表格 + 添加文件写入
    """
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    total_block = stats.get("total_block", 0)
    total_whitelist = stats.get("total_whitelist", 0)
    source_stats = stats.get("sources", {})

    # 计算与上次的变化量
    change_block = ""
    change_whitelist = ""
    if prev_stats:
        prev_block = prev_stats.get("total_block", 0)
        prev_wl = prev_stats.get("total_whitelist", 0)
        diff_b = total_block - prev_block
        diff_w = total_whitelist - prev_wl
        if diff_b > 0:
            change_block = f" (📈 +{diff_b:,})"
        elif diff_b < 0:
            change_block = f" (📉 {diff_b:,})"
        else:
            change_block = " (➡️ 无变化)"
        if diff_w > 0:
            change_whitelist = f" (📈 +{diff_w:,})"
        elif diff_w < 0:
            change_whitelist = f" (📉 {diff_w:,})"
        else:
            change_whitelist = " (➡️ 无变化)"

    # 构建 Markdown
    lines = []
    lines.append("# 🛡️ ADH-AD 广告拦截规则")
    lines.append("")
    lines.append("> 由 GitHub Actions 自动构建，每日 00:00 / 12:00 UTC 更新")
    lines.append("")
    lines.append(f"**最后更新：** {now}")
    lines.append("")
    lines.append("---")
    lines.append("")
    lines.append("## 📊 规则统计")
    lines.append("")
    lines.append("| 指标 | 数量 |")
    lines.append("|------|------|")
    lines.append(f"| 🚫 拦截规则 | **{total_block:,}**{change_block} |")
    lines.append(f"| ✅ 白名单规则 | **{total_whitelist:,}**{change_whitelist} |")
    lines.append(f"| 📦 规则源数量 | **{len(source_stats)}** |")
    lines.append("")
    lines.append("---")
    lines.append("")
    lines.append("## 📋 各规则源详情")
    lines.append("")
    lines.append("| # | 规则源 | 拦截规则 | 白名单 | 占比 |")
    lines.append("|---|--------|----------|--------|------|")

    sorted_sources = sorted(
        source_stats.items(),
        key=lambda x: x[1].get("block", 0),
        reverse=True
    )
    for idx, (name, data) in enumerate(sorted_sources, 1):
        b = data.get("block", 0)
        w = data.get("whitelist", 0)
        pct = (b / total_block * 100) if total_block > 0 else 0
        medal = {1: "🥇", 2: "🥈", 3: "🥉"}.get(idx, str(idx))
        lines.append(f"| {medal} | {name} | {b:,} | {w:,} | {pct:.1f}% |")

    lines.append("")
    lines.append("> ⚠️ 各源占比之和可能 > 100%，因为存在跨源重复域名，最终已去重。")
    lines.append("")
    lines.append("---")
    lines.append("")
    lines.append("## 📁 输出文件")
    lines.append("")
    lines.append("| 文件 | 格式 | 用途 |")
    lines.append("|------|------|------|")
    lines.append("| `adguardhome.txt` | AdGuard Home | 导入 AdGuard Home 自定义过滤规则 |")
    lines.append("| `dnsmasq.conf` | dnsmasq | OpenWrt / Pi-hole 等路由器 |")
    lines.append("| `clash.yaml` | Clash | Clash / Meta 代理客户端 |")
    lines.append("")
    lines.append("---")
    lines.append("")
    lines.append(f"*本文件由 ADH-AD 自动生成 · {now}*")
    lines.append("")

    content = "\n".join(lines)

    # ✅ 关键修复：写入 release/README.md
    readme_path = os.path.join(OUTPUT_DIR, "README.md")
    try:
        with open(readme_path, 'w', encoding='utf-8') as f:
            f.write(content)
        print(f"[OUTPUT] ✅ README.md ({len(content):,} bytes)")
    except IOError as e:
        print(f"[ERROR] README.md 写入失败: {e}")
        open(readme_path, 'w').close()

    return readme_path


# ============================================================
# 主流程
# ============================================================

def main():
    parser = argparse.ArgumentParser(description="ADH-AD 规则构建器")
    parser.add_argument('--dry-run', action='store_true', help='仅构建不提交')
    parser.add_argument('--force', action='store_true', help='跳过阈值检查')
    args = parser.parse_args()

    print("=" * 60)
    print("  ADH-AD 广告拦截规则构建器")
    print(f"  {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}")
    print("=" * 60)

    # 1. 加载配置 config/ADH-AD.yaml
    config = load_config()
    sources = config.get("sources", [])
    thresholds = config.get("thresholds", {"max_increase": 15, "max_decrease": 10})

    if not sources:
        print("[ERROR] 无规则源！")
        sys.exit(1)

    # 2. 加载历史统计 config/ADH_AD_stats.json
    prev_stats = load_previous_stats()

    # 3. 下载
    downloaded = download_all_sources(sources)
    if not downloaded:
        print("[ERROR] 所有源下载失败！")
        sys.exit(1)

    # 4. 解析
    print("\n[PARSE] 开始解析...")
    all_block = set()
    all_whitelist = set()
    source_stats = {}

    for src in sources:
        name = src.get("name", src.get("url", "unknown"))
        content = downloaded.get(name)
        if not content:
            print(f"[PARSE] ⚠️ {name} 无内容，跳过")
            source_stats[name] = {"block": 0, "whitelist": 0}
            continue
        block, whitelist = parse_rules(content, name)
        source_stats[name] = {"block": len(block), "whitelist": len(whitelist)}
        all_block.update(block)
        all_whitelist.update(whitelist)
        print(f"[PARSE] {name}: {len(block):,} 拦截 / {len(whitelist):,} 白名单")

    # 白名单优先
    all_block -= all_whitelist
    print(f"\n[RESULT] 去重后: {len(all_block):,} 拦截 / {len(all_whitelist):,} 白名单")

    # 5. 阈值检查
    if not check_threshold(len(all_block), prev_stats, thresholds, force=args.force):
        sys.exit(1)

    # 6. 构建统计
    current_stats = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "total_block": len(all_block),
        "total_whitelist": len(all_whitelist),
        "sources": source_stats
    }

    # 7. 输出到 release/ 目录
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    print(f"\n[OUTPUT] 输出目录: {OUTPUT_DIR}/")

    generate_adguardhome(all_block, all_whitelist)
    generate_dnsmasq(all_block)
    generate_clash(all_block)
    generate_readme(current_stats, prev_stats, sources)

    # 8. 保存统计到 config/ADH_AD_stats.json
    if not args.dry_run:
        save_stats(current_stats)
    else:
        print("[DRY-RUN] 跳过统计保存")

    print("\n" + "=" * 60)
    print("  ✅ 构建完成！")
    print("=" * 60)


if __name__ == "__main__":
    main()
