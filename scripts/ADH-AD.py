#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ADH-AD - AdGuard Home 广告拦截规则自动构建脚本
功能：从多个上游规则源下载、解析、去重、合并，输出多格式规则文件
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
# 常量配置
# ============================================================
CONFIG_FILE = "ADH-AD.yaml"
STATS_FILE = "ADH_AD_stats.json"
DEFAULT_OUTPUT_DIR = "release"
REQUEST_TIMEOUT = 30
MAX_RETRIES = 3
MAX_WORKERS = 5
PARALLEL_THRESHOLD = 5  # 源数量超过此值时启用并行下载

# 需要跳过的规则前缀/模式
SKIP_PATTERNS = [
    re.compile(r'^##'),           # CSS 元素隐藏规则
    re.compile(r'^#\$#'),         # CSS 扩展规则
    re.compile(r'^#@#'),          # CSS 白名单
    re.compile(r'^#%#'),          # 脚本注入规则
    re.compile(r'^\s*!'),         # 注释行
    re.compile(r'^\s*#'),         # 注释行（非 hosts 格式）
    re.compile(r'\$.*~'),         # 带排除选项的规则
    re.compile(r'\$.*domain='),   # 带 domain 选项的规则
    re.compile(r'\$.*third-party'),  # 带 third-party 选项
    re.compile(r'\$.*popup'),     # 弹窗规则
    re.compile(r'\$.*script'),    # 脚本规则
    re.compile(r'\$.*image'),     # 图片规则
    re.compile(r'\$.*xmlhttprequest'),  # XHR 规则
    re.compile(r'\*'),            # 通配符规则
    re.compile(r'/'),             # URL 路径规则
    re.compile(r'\?'),            # 带参数规则
    re.compile(r'\$'),            # 带选项的规则（兜底）
]

# Hosts 文件中的无效域名
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

def load_config(config_path=CONFIG_FILE):
    """加载 YAML 配置文件"""
    if not os.path.exists(config_path):
        print(f"[ERROR] 配置文件不存在: {config_path}")
        sys.exit(1)
    with open(config_path, 'r', encoding='utf-8') as f:
        config = yaml.safe_load(f)
    print(f"[CONFIG] 已加载配置: {config_path}")
    return config


def load_previous_stats(stats_path=STATS_FILE):
    """加载上次构建的统计数据"""
    if not os.path.exists(stats_path):
        print(f"[STATS] 未找到历史统计文件，跳过阈值检查")
        return None
    try:
        with open(stats_path, 'r', encoding='utf-8') as f:
            stats = json.load(f)
        print(f"[STATS] 已加载历史统计: {stats.get('timestamp', 'unknown')}")
        return stats
    except (json.JSONDecodeError, IOError) as e:
        print(f"[WARN] 历史统计文件读取失败: {e}")
        return None


def save_stats(stats, stats_path=STATS_FILE):
    """保存本次构建统计数据"""
    with open(stats_path, 'w', encoding='utf-8') as f:
        json.dump(stats, f, ensure_ascii=False, indent=2)
    print(f"[STATS] 统计数据已保存: {stats_path}")


def is_valid_domain(domain):
    """验证域名是否合法"""
    if not domain or len(domain) > 253:
        return False
    if domain in INVALID_DOMAINS:
        return False
    if domain.startswith('.') or domain.endswith('.'):
        return False
    if '..' in domain:
        return False
    # 基本域名格式检查
    pattern = re.compile(r'^[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?)*\.[a-zA-Z]{2,}$')
    return bool(pattern.match(domain))


def should_skip_rule(line):
    """判断规则行是否应被跳过"""
    stripped = line.strip()
    if not stripped:
        return True
    for pattern in SKIP_PATTERNS:
        if pattern.search(stripped):
            return True
    return False


# ============================================================
# 下载模块
# ============================================================

def download_source(url, name, retries=MAX_RETRIES):
    """下载单个规则源，带重试机制"""
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
    }
    for attempt in range(1, retries + 1):
        try:
            print(f"[DOWNLOAD] ({attempt}/{retries}) 正在下载: {name}")
            resp = requests.get(url, headers=headers, timeout=REQUEST_TIMEOUT)
            resp.raise_for_status()
            resp.encoding = resp.apparent_encoding or 'utf-8'
            print(f"[DOWNLOAD] ✅ {name} - {len(resp.text):,} bytes")
            return resp.text
        except requests.RequestException as e:
            print(f"[WARN] ({attempt}/{retries}) {name} 下载失败: {e}")
            if attempt == retries:
                print(f"[ERROR] ❌ {name} 最终下载失败，跳过")
                return None
    return None


def download_all_sources(sources):
    """下载所有规则源（自动判断是否并行）"""
    results = {}

    if len(sources) > PARALLEL_THRESHOLD:
        print(f"[DOWNLOAD] 启用并行下载 (workers={MAX_WORKERS})")
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

    print(f"[DOWNLOAD] 完成: {len(results)}/{len(sources)} 个源下载成功")
    return results


# ============================================================
# 解析模块
# ============================================================

def parse_rules(content, source_name):
    """
    解析规则内容，提取域名
    支持格式：
      - AdGuard: ||domain^
      - Hosts: 0.0.0.0 domain / 127.0.0.1 domain
      - 白名单: @@||domain^
      - 纯域名
    返回: (block_set, whitelist_set)
    """
    block_domains = set()
    whitelist_domains = set()

    for line in content.splitlines():
        stripped = line.strip()

        # 跳过空行和注释
        if not stripped or stripped.startswith('!') or stripped.startswith('#'):
            # 但 hosts 格式的 # 后面不是注释，需要特殊处理
            if not (stripped.startswith('0.0.0.0') or stripped.startswith('127.0.0.1')):
                continue

        # 白名单规则: @@||domain^
        if stripped.startswith('@@'):
            domain = stripped[2:]
            domain = domain.strip('|').strip('^').strip()
            if is_valid_domain(domain):
                whitelist_domains.add(domain.lower())
            continue

        # AdGuard 格式: ||domain^
        if stripped.startswith('||'):
            domain = stripped[2:]
            domain = domain.rstrip('^').rstrip('/')
            # 检查是否应跳过（含路径、参数等）
            if should_skip_rule(domain):
                continue
            if is_valid_domain(domain):
                block_domains.add(domain.lower())
            continue

        # Hosts 格式: 0.0.0.0 domain 或 127.0.0.1 domain
        if stripped.startswith('0.0.0.0') or stripped.startswith('127.0.0.1'):
            parts = stripped.split()
            if len(parts) >= 2:
                domain = parts[1].strip().lower()
                if is_valid_domain(domain):
                    block_domains.add(domain)
            continue

        # 跳过含特殊字符的规则（CSS、脚本等）
        if should_skip_rule(stripped):
            continue

        # 纯域名格式
        domain = stripped.lower().rstrip('.')
        if is_valid_domain(domain):
            block_domains.add(domain)

    return block_domains, whitelist_domains


# ============================================================
# 阈值检查
# ============================================================

def check_threshold(current_total, prev_stats, thresholds, force=False):
    """检查规则数量变化是否在阈值范围内"""
    if force:
        print("[THRESHOLD] 强制模式，跳过阈值检查")
        return True

    if not prev_stats:
        print("[THRESHOLD] 无历史数据，跳过阈值检查")
        return True

    prev_total = prev_stats.get("total_block", 0)
    if prev_total == 0:
        print("[THRESHOLD] 历史数据为 0，跳过阈值检查")
        return True

    change_pct = (current_total - prev_total) / prev_total * 100
    max_increase = thresholds.get("max_increase", 15)
    max_decrease = thresholds.get("max_decrease", 10)

    print(f"[THRESHOLD] 上次: {prev_total:,} | 本次: {current_total:,} | 变化: {change_pct:+.2f}%")

    if change_pct > max_increase:
        print(f"[ERROR] ❌ 规则增长 {change_pct:.2f}% 超过阈值 +{max_increase}%，构建终止！")
        print(f"[HINT] 使用 --force 参数可跳过此检查")
        return False

    if change_pct < -max_decrease:
        print(f"[ERROR] ❌ 规则减少 {abs(change_pct):.2f}% 超过阈值 -{max_decrease}%，构建终止！")
        print(f"[HINT] 使用 --force 参数可跳过此检查")
        return False

    print(f"[THRESHOLD] ✅ 变化在允许范围内 (+{max_increase}% / -{max_decrease}%)")
    return True


# ============================================================
# 输出模块
# ============================================================

def generate_adguardhome(output_dir, block_domains, whitelist_domains):
    """生成 AdGuard Home 格式规则文件"""
    filepath = os.path.join(output_dir, "adguardhome.txt")
    try:
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write("! Title: ADH-AD 广告拦截规则\n")
            f.write(f"! Updated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}\n")
            f.write(f"! Total: {len(block_domains):,} block + {len(whitelist_domains):,} whitelist\n")
            f.write("!\n")
            # 白名单优先
            for domain in sorted(whitelist_domains):
                f.write(f"@@||{domain}^\n")
            # 拦截规则
            for domain in sorted(block_domains):
                f.write(f"||{domain}^\n")
        print(f"[OUTPUT] ✅ adguardhome.txt ({len(block_domains):,} + {len(whitelist_domains):,})")
    except IOError as e:
        print(f"[ERROR] 写入 adguardhome.txt 失败: {e}")
        # 容错：生成空文件
        open(filepath, 'w').close()


def generate_dnsmasq(output_dir, block_domains):
    """生成 dnsmasq 格式规则文件"""
    filepath = os.path.join(output_dir, "dnsmasq.conf")
    try:
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(f"# ADH-AD dnsmasq 规则\n")
            f.write(f"# Updated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}\n")
            f.write(f"# Total: {len(block_domains):,}\n")
            f.write("#\n")
            for domain in sorted(block_domains):
                f.write(f"address=/{domain}/0.0.0.0\n")
        print(f"[OUTPUT] ✅ dnsmasq.conf ({len(block_domains):,})")
    except IOError as e:
        print(f"[ERROR] 写入 dnsmasq.conf 失败: {e}")
        open(filepath, 'w').close()


def generate_clash(output_dir, block_domains):
    """生成 Clash 格式规则文件"""
    filepath = os.path.join(output_dir, "clash.yaml")
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
        print(f"[ERROR] 写入 clash.yaml 失败: {e}")
        open(filepath, 'w').close()


def generate_readme(output_dir, stats, prev_stats, sources_config):
    """
    生成 README.md 统计报告并写入文件
    【已修复】补全源详情表格 + 文件写入逻辑
    """
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    total_block = stats.get("total_block", 0)
    total_whitelist = stats.get("total_whitelist", 0)
    source_stats = stats.get("sources", {})

    # ========== 计算与上次的变化量 ==========
    change_block = ""
    change_whitelist = ""
    if prev_stats:
        prev_block = prev_stats.get("total_block", 0)
        prev_whitelist = prev_stats.get("total_whitelist", 0)
        diff_block = total_block - prev_block
        diff_whitelist = total_whitelist - prev_whitelist

        if diff_block > 0:
            change_block = f" (📈 +{diff_block:,})"
        elif diff_block < 0:
            change_block = f" (📉 {diff_block:,})"
        else:
            change_block = " (➡️ 无变化)"

        if diff_whitelist > 0:
            change_whitelist = f" (📈 +{diff_whitelist:,})"
        elif diff_whitelist < 0:
            change_whitelist = f" (📉 {diff_whitelist:,})"
        else:
            change_whitelist = " (➡️ 无变化)"

    # ========== 构建 Markdown ==========
    lines = []
    lines.append("# 🛡️ ADH-AD 广告拦截规则")
    lines.append("")
    lines.append("> 由 GitHub Actions 自动构建，每日 00:00 / 12:00 UTC 更新")
    lines.append("")
    lines.append(f"**最后更新：** {now}")
    lines.append("")
    lines.append("---")
    lines.append("")

    # 总览表格
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

    # 各源详情表格
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
        block_count = data.get("block", 0)
        wl_count = data.get("whitelist", 0)
        pct = (block_count / total_block * 100) if total_block > 0 else 0
        medal = {1: "🥇", 2: "🥈", 3: "🥉"}.get(idx, str(idx))
        lines.append(f"| {medal} | {name} | {block_count:,} | {wl_count:,} | {pct:.1f}% |")

    lines.append("")
    lines.append("> ⚠️ 各源占比之和可能 > 100%，因为存在跨源重复域名，最终已去重。")
    lines.append("")
    lines.append("---")
    lines.append("")

    # 输出文件说明
    lines.append("## 📁 输出文件")
    lines.append("")
    lines.append("| 文件 | 格式 | 用途 |")
    lines.append("|------|------|------|")
    lines.append("| `adguardhome.txt` | AdGuard Home | 直接导入 AdGuard Home 自定义过滤规则 |")
    lines.append("| `dnsmasq.conf` | dnsmasq | 适用于 OpenWrt / Pi-hole 等路由器 |")
    lines.append("| `clash.yaml` | Clash | 适用于 Clash / Meta 代理客户端 |")
    lines.append("")
    lines.append("---")
    lines.append("")

    # 订阅地址
    lines.append("## 🔗 订阅地址")
    lines.append("")
    lines.append("```")
    lines.append("# AdGuard Home")
    lines.append("https://raw.githubusercontent.com/<OWNER>/<REPO>/release/adguardhome.txt")
    lines.append("")
    lines.append("# dnsmasq")
    lines.append("https://raw.githubusercontent.com/<OWNER>/<REPO>/release/dnsmasq.conf")
    lines.append("")
    lines.append("# Clash")
    lines.append("https://raw.githubusercontent.com/<OWNER>/<REPO>/release/clash.yaml")
    lines.append("```")
    lines.append("")
    lines.append("---")
    lines.append("")
    lines.append(f"*本文件由 ADH-AD 自动生成 · {now}*")
    lines.append("")

    content = "\n".join(lines)

    # ========== ✅ 关键修复：写入文件 ==========
    readme_path = os.path.join(output_dir, "README.md")
    try:
        with open(readme_path, 'w', encoding='utf-8') as f:
            f.write(content)
        print(f"[OUTPUT] ✅ README.md ({len(content):,} bytes)")
    except IOError as e:
        print(f"[ERROR] 写入 README.md 失败: {e}")
        open(readme_path, 'w').close()

    return readme_path


# ============================================================
# 主流程
# ============================================================

def main():
    parser = argparse.ArgumentParser(description="ADH-AD 规则构建器")
    parser.add_argument('--dry-run', action='store_true', help='仅构建不提交')
    parser.add_argument('--force', action='store_true', help='跳过阈值检查')
    parser.add_argument('--output', default=DEFAULT_OUTPUT_DIR, help='输出目录')
    args = parser.parse_args()

    print("=" * 60)
    print("  ADH-AD 广告拦截规则构建器")
    print(f"  时间: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}")
    print("=" * 60)

    # 1. 加载配置
    config = load_config()
    sources = config.get("sources", [])
    thresholds = config.get("thresholds", {"max_increase": 15, "max_decrease": 10})

    if not sources:
        print("[ERROR] 配置中无规则源！")
        sys.exit(1)

    # 2. 加载历史统计
    prev_stats = load_previous_stats()

    # 3. 下载所有源
    downloaded = download_all_sources(sources)

    if not downloaded:
        print("[ERROR] 所有源下载失败！")
        sys.exit(1)

    # 4. 解析规则
    print("\n[PARSE] 开始解析规则...")
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
        source_stats[name] = {
            "block": len(block),
            "whitelist": len(whitelist)
        }
        all_block.update(block)
        all_whitelist.update(whitelist)
        print(f"[PARSE] {name}: {len(block):,} 拦截 / {len(whitelist):,} 白名单")

    # 白名单优先：从拦截列表中移除白名单域名
    all_block -= all_whitelist

    print(f"\n[RESULT] 去重后总计: {len(all_block):,} 拦截 / {len(all_whitelist):,} 白名单")

    # 5. 阈值检查
    if not check_threshold(len(all_block), prev_stats, thresholds, force=args.force):
        sys.exit(1)

    # 6. 构建统计数据
    current_stats = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "total_block": len(all_block),
        "total_whitelist": len(all_whitelist),
        "sources": source_stats
    }

    # 7. 生成输出文件
    output_dir = args.output
    os.makedirs(output_dir, exist_ok=True)

    print(f"\n[OUTPUT] 输出目录: {output_dir}/")
    generate_adguardhome(output_dir, all_block, all_whitelist)
    generate_dnsmasq(output_dir, all_block)
    generate_clash(output_dir, all_block)

    # ✅ 修复：正确调用 generate_readme，传入完整参数
    generate_readme(
        output_dir=output_dir,
        stats=current_stats,
        prev_stats=prev_stats,
        sources_config=sources
    )

    # 8. 保存统计数据（供下次对比）
    if not args.dry_run:
        save_stats(current_stats)
    else:
        print("[DRY-RUN] 跳过统计数据保存")

    print("\n" + "=" * 60)
    print("  ✅ 构建完成！")
    print("=" * 60)


if __name__ == "__main__":
    main()
