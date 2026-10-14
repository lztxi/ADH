#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ADH-AD: Ad Domain Merge Tool

把多个上游广告过滤规则源合并去重，输出 AdGuard Home / dnsmasq / Clash 三种格式。

设计目标（按优先级）：
  1. 稳定 —— 任何单点故障都不能污染 release 分支的产物
  2. 正确 —— 输出严格符合 AdGuard Home 过滤列表语法
  3. 可观测 —— 每次构建的来源明细、失败原因、校验和都写进统计与 README

环境变量：
  DEBUG=true            打印逐行调试日志
  DRY_RUN=true          只生成产物，不写回 config/ADH_AD_stats.json
  FORCE_PASS=true       跳过阈值守卫（人工确认后强制发布）
  GITHUB_REPOSITORY     owner/repo，用于产物头部与 README 的订阅链接
  OUTPUT_DIR            产物输出目录，默认 <repo>/../release
"""

import argparse
import datetime
import hashlib
import json
import os
import re
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

import requests
import yaml
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# --------------------------------------------------------------------------
# 环境配置
# --------------------------------------------------------------------------

def _env_flag(name: str, default: str = "false") -> bool:
    return os.getenv(name, default).strip().lower() in ("1", "true", "yes", "on")

DEBUG = _env_flag("DEBUG")
DRY_RUN = _env_flag("DRY_RUN")
FORCE_PASS = _env_flag("FORCE_PASS")
GITHUB_REPO = os.getenv("GITHUB_REPOSITORY", "lztxi/ADH").strip() or "lztxi/ADH"

BASE = Path(__file__).resolve().parent.parent
CFG = BASE / "config" / "ADH-AD.yaml"
STATS_FILE = BASE / "config" / "ADH_AD_stats.json"

DEFAULT_USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) ADH-AD-Bot/2.0"

# 运行时默认值，可被 config/ADH-AD.yaml 的 runtime 段覆盖
MAX_WORKERS = 5
REQUEST_TIMEOUT = 30
MAX_RETRIES = 3
RETRY_BACKOFF = 1.0
# 单个来源解析出的黑名单域名低于此数视为「上游异常」，不计入有效来源
MIN_DOMAINS_PER_SOURCE = 100
# 有效来源占比低于此值视为「严重降级」
MIN_SUCCESS_RATIO = 0.6
# 黑名单绝对下限，低于此值直接判定构建失败（防止上游集体被投毒/清空）
MIN_TOTAL_DOMAINS = 50_000

# --------------------------------------------------------------------------
# 常量
# --------------------------------------------------------------------------

DNSMASQ_DEFAULT_IP = "0.0.0.0"

# 合法域名：每级标签 1-63 字符、字母数字连字符、不能以连字符开头/结尾，总长 ≤253
DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)"
    r"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
    r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$"
)

# hosts 格式的 IP 前缀
HOSTS_IPS = {"0.0.0.0", "127.0.0.1", "::", "::1", "0:0:0:0:0:0:0:0"}

# 行首注释 / 头部标记
COMMENT_PREFIXES = ("#", "!", ";", "[", "*")

_local = threading.local()

# --------------------------------------------------------------------------
# 日志
# --------------------------------------------------------------------------

def _ts() -> str:
    return datetime.datetime.now().strftime("%H:%M:%S")

def log(level: str, msg: str):
    print(f"[{_ts()}][{level}] {msg}", flush=True)

def debug(msg: str):
    if DEBUG:
        log("DEBUG", msg)

def info(msg: str):
    log("INFO", msg)

def warn(msg: str):
    log("WARN", msg)

def error(msg: str):
    log("ERROR", msg)

def utcnow() -> datetime.datetime:
    return datetime.datetime.now(datetime.timezone.utc)

def utc_stamp() -> str:
    return utcnow().strftime("%Y-%m-%d %H:%M UTC")

def human_bytes(n: int) -> str:
    step = 1024.0
    value = float(n)
    for unit in ("B", "KB", "MB", "GB"):
        if value < step:
            return f"{int(value)}B" if unit == "B" else f"{value:.1f}{unit}"
        value /= step
    return f"{value:.1f}TB"

# --------------------------------------------------------------------------
# HTTP
# --------------------------------------------------------------------------

def build_session(user_agent: str) -> requests.Session:
    """构造带重试的 Session。注意：Session 非线程安全，由 thread-local 分发。"""
    session = requests.Session()
    retry = Retry(
        total=MAX_RETRIES,
        connect=MAX_RETRIES,
        read=MAX_RETRIES,
        backoff_factor=RETRY_BACKOFF,
        status_forcelist=(429, 500, 502, 503, 504),
        allowed_methods=frozenset(["GET", "HEAD"]),
        raise_on_status=False,
        respect_retry_after_header=True,
    )
    adapter = HTTPAdapter(max_retries=retry, pool_connections=MAX_WORKERS, pool_maxsize=MAX_WORKERS)
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    session.headers.update({
        "User-Agent": user_agent,
        "Accept": "text/plain, */*",
        "Accept-Encoding": "gzip, deflate",
        "Connection": "keep-alive",
    })
    return session

def get_session(user_agent: str) -> requests.Session:
    """每个工作线程一个独立 Session，避免并发下连接池竞争。"""
    session = getattr(_local, "session", None)
    if session is None:
        session = build_session(user_agent)
        _local.session = session
    return session

def decode_body(raw: bytes) -> str:
    """按编码优先级解码，兼容 UTF-8 BOM 与 GB18030（国内规则源常见）。"""
    for enc in ("utf-8-sig", "utf-8", "gb18030", "big5"):
        try:
            return raw.decode(enc)
        except UnicodeDecodeError:
            continue
    return raw.decode("utf-8", errors="replace")

# --------------------------------------------------------------------------
# 域名规范化 & 规则解析
# --------------------------------------------------------------------------

def normalize_domain(raw: str) -> Optional[str]:
    """
    规范化并校验一个域名，合法返回小写域名，非法返回 None。

    拒绝：空值、IP 字面量、超长、TLD 为纯数字（伪装成域名的 IP）、非法字符。
    """
    if not raw:
        return None
    domain = raw.strip().strip(".").lower()
    if not domain or ".." in domain:
        return None
    if len(domain) > 253:
        return None
    # TLD 不能是纯数字，否则 1.2.3.4 这类 IP 会混进来
    tld = domain.rsplit(".", 1)[-1]
    if not tld or tld.isdigit():
        return None
    if not DOMAIN_RE.match(domain):
        return None
    return domain


def classify_line(line: str) -> Tuple[Optional[str], bool]:
    """
    解析单行规则。

    返回 (domain, is_whitelist)；无法安全使用时返回 (None, False)。

    刻意「宁少勿多」：只保留纯整域规则。任何 URL 级规则、带修饰符的条件规则、
    元素隐藏规则、通配符规则一律丢弃——DNS 层无法正确执行它们，留着反而
    会造成误杀。
    """
    try:
        line = line.strip()

        if not line:
            return None, False
        if line[0] in COMMENT_PREFIXES:
            return None, False

        is_whitelist = False

        # 白名单前缀
        if line.startswith("@@"):
            is_whitelist = True
            line = line[2:].strip()
            if not line:
                return None, False
            # @@|http://... 这类 URL 级白名单无法在 DNS 层执行。
            # 注意 @@||domain^ 整域白名单是合法的，只有单竖线才是 URL 级。
            if line.startswith("|") and not line.startswith("||"):
                debug(f"跳过 URL 级白名单：{line}")
                return None, False

        # 元素隐藏 / 注释型规则
        if "##" in line or "#?#" in line or "#@#" in line or "#$#" in line:
            debug(f"跳过元素隐藏规则：{line}")
            return None, False

        # AdGuard / ABP 整域规则 ||example.com^
        if line.startswith("||"):
            content = line[2:].strip()
            if not content:
                return None, False
            # 必须是 ^ 结尾且 ^ 后无内容，否则说明是 URL 级规则
            if "^" not in content:
                debug(f"跳过无边界规则：{line}")
                return None, False
            domain_part, sep, remaining = content.partition("^")
            if not sep or remaining.strip():
                debug(f"跳过非整域规则（^ 后有内容）：{line}")
                return None, False
            # 整域规则内部不允许出现的符号
            if any(ch in domain_part for ch in ("/", "$", "*", "\\", "|", ",", ":", "%", "@", "#")):
                debug(f"跳过含修饰符/通配符的规则：{line}")
                return None, False
            domain = normalize_domain(domain_part)
            return (domain, is_whitelist) if domain else (None, False)

        # 纯域名行中出现任何规则语法符号都不合法
        if any(ch in line for ch in ("/", "$", "*", "^", "|", ",", ":", "%", "@", "#", "\\")):
            debug(f"跳过含语法符号的行：{line}")
            return None, False

        # hosts 格式：<ip> <domain> [domain...]
        parts = line.split()
        if len(parts) >= 2 and parts[0].lower() in HOSTS_IPS:
            domain = normalize_domain(parts[1])
            return (domain, is_whitelist) if domain else (None, False)

        # 纯域名
        domain = normalize_domain(line)
        return (domain, is_whitelist) if domain else (None, False)

    except Exception as exc:  # noqa: BLE001 - 单行解析绝不能中断整体流程
        debug(f"解析异常：{exc}")
        return None, False


def parse_content(text: str) -> Tuple[Set[str], Set[str], int, int]:
    """解析整份规则文本，返回 (黑名单, 白名单, 黑名单计数, 白名单计数)。"""
    block: Set[str] = set()
    allow: Set[str] = set()
    lines = text.splitlines()

    for line in lines:
        domain, is_allow = classify_line(line)
        if domain:
            if is_allow:
                allow.add(domain)
            else:
                block.add(domain)

    return block, allow, len(block), len(allow)


# --------------------------------------------------------------------------
# 配置
# --------------------------------------------------------------------------

def load_config(cfg_path: Path) -> dict:
    if not cfg_path.exists():
        raise FileNotFoundError(f"配置文件不存在：{cfg_path}")
    with open(cfg_path, "r", encoding="utf-8") as fh:
        cfg = yaml.safe_load(fh) or {}
    if not isinstance(cfg, dict):
        raise ValueError("配置文件根节点必须是映射")
    if not isinstance(cfg.get("sources"), list) or not cfg["sources"]:
        raise ValueError("配置缺少非空的 sources 列表")
    return cfg


def apply_runtime_overrides(cfg: dict):
    """用配置文件的 runtime 段覆盖模块级默认值。"""
    global MAX_WORKERS, REQUEST_TIMEOUT, MAX_RETRIES, RETRY_BACKOFF
    global MIN_DOMAINS_PER_SOURCE, MIN_SUCCESS_RATIO, MIN_TOTAL_DOMAINS, DEFAULT_USER_AGENT

    rt = cfg.get("runtime") or {}
    if not isinstance(rt, dict):
        warn("runtime 配置段不是映射，已忽略")
        return

    def _int(key, current, minimum=1, maximum=None):
        val = rt.get(key)
        if val is None:
            return current
        try:
            val = int(val)
        except (TypeError, ValueError):
            warn(f"runtime.{key} 不是整数，已忽略：{val!r}")
            return current
        if val < minimum:
            warn(f"runtime.{key}={val} 小于最小值 {minimum}，已忽略")
            return current
        if maximum is not None and val > maximum:
            warn(f"runtime.{key}={val} 大于最大值 {maximum}，已截断")
            return maximum
        return val

    def _float(key, current, minimum=0.0, maximum=1.0):
        val = rt.get(key)
        if val is None:
            return current
        try:
            val = float(val)
        except (TypeError, ValueError):
            warn(f"runtime.{key} 不是数字，已忽略：{val!r}")
            return current
        if not (minimum <= val <= maximum):
            warn(f"runtime.{key}={val} 超出 [{minimum}, {maximum}]，已忽略")
            return current
        return val

    MAX_WORKERS = _int("max_workers", MAX_WORKERS, 1, 16)
    REQUEST_TIMEOUT = _int("request_timeout", REQUEST_TIMEOUT, 5, 300)
    MAX_RETRIES = _int("max_retries", MAX_RETRIES, 0, 10)
    RETRY_BACKOFF = rt.get("retry_backoff", RETRY_BACKOFF)
    MIN_DOMAINS_PER_SOURCE = _int("min_domains_per_source", MIN_DOMAINS_PER_SOURCE, 0)
    MIN_SUCCESS_RATIO = _float("min_success_ratio", MIN_SUCCESS_RATIO)
    MIN_TOTAL_DOMAINS = _int("min_total_domains", MIN_TOTAL_DOMAINS, 0)

    ua = rt.get("user_agent")
    if isinstance(ua, str) and ua.strip():
        DEFAULT_USER_AGENT = ua.strip()

    info(
        f"运行参数：workers={MAX_WORKERS} timeout={REQUEST_TIMEOUT}s "
        f"retries={MAX_RETRIES} min_per_source={MIN_DOMAINS_PER_SOURCE}"
    )


def load_stats(path: Path) -> dict:
    if not path.exists():
        debug(f"统计文件不存在，视为首次运行：{path}")
        return {}
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        return data if isinstance(data, dict) else {}
    except (json.JSONDecodeError, OSError) as exc:
        warn(f"统计文件损坏，按首次运行处理：{exc}")
        return {}

def save_stats(path: Path, stats: dict):
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(stats, fh, ensure_ascii=False, indent=2)
        fh.write("\n")
    os.replace(tmp, path)


# --------------------------------------------------------------------------
# 抓取
# --------------------------------------------------------------------------

def looks_like_html(text: str) -> bool:
    head = text.lstrip()[:400].lower()
    return head.startswith("<!doctype html") or head.startswith("<html") or "<head" in head


def fetch_source(source: dict, user_agent: str) -> Tuple[Set[str], Set[str], dict]:
    """抓取并解析单个来源。任何异常都收敛为 stats['error']，不向上抛出。"""
    url = (source.get("url") or "").strip()
    name = (source.get("name") or url or "unknown").strip()
    try:
        min_domains = int(source.get("min_domains", MIN_DOMAINS_PER_SOURCE) or 0)
    except (TypeError, ValueError):
        min_domains = MIN_DOMAINS_PER_SOURCE

    if not url:
        return set(), set(), {"url": "", "error": "缺少 url"}

    info(f"下载：{name}")
    started = time.time()

    try:
        resp = get_session(user_agent).get(url, timeout=REQUEST_TIMEOUT, allow_redirects=True)

        if resp.status_code != 200:
            msg = f"HTTP {resp.status_code}"
            error(f"下载失败 [{name}]：{msg}")
            return set(), set(), {
                "url": url, "error": msg, "http_status": resp.status_code,
                "last_update": utcnow().isoformat(),
            }

        text = decode_body(resp.content)

        if looks_like_html(text):
            msg = "返回内容是 HTML 而非规则列表"
            error(f"下载失败 [{name}]：{msg}")
            return set(), set(), {
                "url": url, "error": msg, "http_status": resp.status_code,
                "last_update": utcnow().isoformat(),
            }

        block, allow, block_n, allow_n = parse_content(text)

        if block_n < min_domains:
            msg = f"仅解析出 {block_n} 条黑名单，低于期望下限 {min_domains}，判定上游异常"
            error(f"来源异常 [{name}]：{msg}")
            return set(), set(), {
                "url": url, "error": msg, "http_status": resp.status_code,
                "block_count": 0, "white_count": 0,
                "total_lines": len(text.splitlines()),
                "rejected_as_anomalous": True,
                "last_update": utcnow().isoformat(),
            }

        elapsed = time.time() - started
        stats = {
            "url": url,
            "http_status": resp.status_code,
            "bytes": len(resp.content),
            "block_count": block_n,
            "white_count": allow_n,
            "total_lines": len(text.splitlines()),
            "elapsed_sec": round(elapsed, 2),
            "last_update": utcnow().isoformat(),
        }
        info(f"解析 [{name}]：黑 {block_n:,} / 白 {allow_n:,}（{elapsed:.1f}s，{human_bytes(len(resp.content))}）")
        return block, allow, stats

    except requests.exceptions.RequestException as exc:
        msg = f"{type(exc).__name__}: {exc}"
        error(f"下载异常 [{name}]：{msg}")
        return set(), set(), {"url": url, "error": msg, "last_update": utcnow().isoformat()}
    except Exception as exc:  # noqa: BLE001
        msg = f"{type(exc).__name__}: {exc}"
        error(f"处理异常 [{name}]：{msg}")
        return set(), set(), {"url": url, "error": msg, "last_update": utcnow().isoformat()}


def collect_sources(sources: List[dict]) -> Tuple[Set[str], Set[str], dict, List[str]]:
    """并发抓取所有启用的来源。返回 (黑名单, 白名单, 来源明细, 失败来源名列表)。"""
    block_rules: Set[str] = set()
    white_rules: Set[str] = set()
    source_stats: Dict[str, dict] = {}
    failed: List[str] = []

    enabled = [s for s in sources if s.get("enabled", True)]
    disabled = [s for s in sources if not s.get("enabled", True)]
    if disabled:
        info(f"已跳过 {len(disabled)} 个未启用来源")

    if not enabled:
        return block_rules, white_rules, source_stats, failed

    info(f"开始并发抓取 {len(enabled)} 个来源（workers={MAX_WORKERS}）")

    with ThreadPoolExecutor(max_workers=min(MAX_WORKERS, len(enabled))) as pool:
        futures = {pool.submit(fetch_source, src, DEFAULT_USER_AGENT): src for src in enabled}
        for future in as_completed(futures):
            src = futures[future]
            name = (src.get("name") or src.get("url") or "unknown").strip()
            try:
                block, allow, stats = future.result()
            except Exception as exc:  # noqa: BLE001 - 双保险
                block, allow = set(), set()
                stats = {"url": src.get("url", ""), "error": f"{type(exc).__name__}: {exc}"}
            block_rules |= block
            white_rules |= allow
            source_stats[name] = stats
            if stats.get("error"):
                failed.append(name)

    return block_rules, white_rules, source_stats, failed


# --------------------------------------------------------------------------
# 守卫
# --------------------------------------------------------------------------

def resolve_conflicts(block: Set[str], white: Set[str]) -> Tuple[Set[str], Set[str], dict]:
    """
    消解黑名单与白名单的冲突。

    AdGuard 例外规则（@@）的优先级**硬性高于**屏蔽规则，与书写顺序无关。
    而 `||domain^` 会匹配该域名**及其所有子域**。因此若直接输出
        @@||aa.com^
        ||ads.aa.com^
    AdGuard 会认为 ads.aa.com 被例外规则放行，黑名单形同虚设。

    解决方式：白名单改用**精确匹配** `|aa.com^`（单竖线），
    只放行该域名本身，不影响其子域的屏蔽状态。

    返回 (修正后黑名单, 修正后白名单, 冲突统计)
    """
    if not white:
        return block, white, {}

    # 白名单域名自身若在黑名单中，白名单优先，直接从黑名单移除
    self_conflict = block & white
    block = block - white

    # 找出「白名单父域 → 黑名单子域」的潜在阴影（精确匹配后这些不受影响，
    # 但保留统计用于人工审计上游规则冲突）
    shadowed: List[str] = []
    for w in white:
        suffix = "." + w
        for b in block:
            if b.endswith(suffix):
                shadowed.append(f"{w} -> {b}")

    stats = {
        "self_conflict": len(self_conflict),
        "shadowed_subdomains": len(shadowed),
        "examples": shadowed[:5],
    }
    if self_conflict:
        warn(f"{len(self_conflict)} 个域名同时出现在黑白名单，白名单优先")
    if shadowed:
        debug(f"{len(shadowed)} 条黑名单子域位于白名单域名之下，"
              f"已用精确匹配 |domain^ 避免被例外规则放行")
    return block, white, stats


def check_threshold(old_stats: dict, new_total: int, threshold_cfg: dict, degraded: bool) -> None:
    """
    规则量变化守卫。越界则 sys.exit(1)，让 CI 红灯，不发布可疑产物。

    degraded=True 表示已知有来源抓取失败，此时规则量下降是可解释的，
    只告警不拦截——真正的异常由 per-source error 兜底。
    """
    max_inc = float(threshold_cfg.get("max_increase", 0.15))
    max_dec = float(threshold_cfg.get("max_decrease", 0.10))

    if FORCE_PASS:
        warn("FORCE_PASS=true，跳过阈值守卫")
        return

    old_total = 0
    if isinstance(old_stats, dict) and isinstance(old_stats.get("total_block"), int):
        old_total = old_stats["total_block"]

    if old_total <= 0:
        info("首次运行或无历史基线，跳过阈值守卫")
        return

    delta = new_total - old_total
    ratio = delta / old_total
    info(f"规则量变化：{old_total:,} → {new_total:,}（{delta:+,}，{ratio:+.2%}）")

    if ratio > max_inc:
        if degraded:
            warn(f"规则量上涨 {ratio:.2%} 超过阈值 {max_inc:.2%}，但存在来源失败，仅告警")
        else:
            error(f"规则量涨幅 {ratio:.2%} 超过阈值 {max_inc:.2%}，判定上游异常，中止发布")
            sys.exit(1)
    elif ratio < -max_dec:
        if degraded:
            warn(f"规则量下降 {ratio:.2%} 超过阈值 {max_dec:.2%}，但存在来源失败，仅告警")
        else:
            error(f"规则量降幅 {ratio:.2%} 超过阈值 {max_dec:.2%}，判定上游异常，中止发布")
            sys.exit(1)
    else:
        info(f"阈值检查通过（允许区间 -{max_dec:.0%} ~ +{max_inc:.0%}）")


def guard_sanity(
    total: int,
    enabled_count: int,
    ok_count: int,
    failed: List[str],
    threshold_cfg: dict,
) -> Tuple[bool, bool]:
    """
    构建前的硬性检查。返回 (是否放行, 是否降级)。

    - 全部来源失败 → 绝不放行（否则会用空规则覆盖 release 分支）
    - 黑名单绝对值过低 → 绝不放行（防上游被投毒 / 集体清空）
    - 有效来源占比过低 → 放行但标记降级
    """
    floor = int(threshold_cfg.get("min_total_domains", MIN_TOTAL_DOMAINS) or 0)
    degraded = False

    if enabled_count == 0:
        error("没有任何启用的来源")
        return False, True

    if ok_count == 0:
        error(f"全部 {enabled_count} 个来源均抓取失败，拒绝生成产物以保护 release 分支现有规则")
        for name in failed:
            error(f"  - 失败来源：{name}")
        return False, True

    if failed:
        ratio = ok_count / enabled_count
        warn(f"{len(failed)}/{enabled_count} 个来源抓取失败：{', '.join(failed)}")
        if ratio < MIN_SUCCESS_RATIO:
            degraded = True
            error(f"有效来源占比 {ratio:.0%} 低于下限 {MIN_SUCCESS_RATIO:.0%}，本次构建标记为降级")
        else:
            warn(f"有效来源占比 {ratio:.0%}，尚在容忍范围内")

    if floor > 0 and total < floor:
        error(f"黑名单总量 {total:,} 低于安全下限 {floor:,}，疑似上游异常，中止发布")
        return False, degraded

    return True, degraded


# --------------------------------------------------------------------------
# 产物输出
# --------------------------------------------------------------------------

def write_atomic(path: Path, content: str) -> int:
    """原子写入：先写临时文件再 rename，避免中途失败留下半截文件。"""
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    with open(tmp, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(content)
    os.replace(tmp, path)
    return path.stat().st_size


def render_adguard_home(block: List[str], white: List[str], repo: str, expires: str) -> str:
    """
    生成 AdGuard Home 过滤列表。

    头部元数据（! Title: / ! Version: / ! Expires: 等）会被 AdGuard Home
    客户端解析并展示在订阅信息里，务必带上。

    关键：白名单用**单竖线精确匹配** `|domain^` 而非 `||domain^`。
    因为 `||` 会连带放行所有子域，导致 `||ads.example.com^` 这类
    黑名单规则被白名单父域意外覆盖而失效。
    """
    now = utc_stamp()
    version = utcnow().strftime("%Y.%m.%d.%H%M")
    lines = [
        "! Title: ADH-AD 广告过滤规则",
        "! Description: 由多个主流上游广告过滤源自动合并去重生成，仅含整域规则，可安全用于 DNS 层过滤",
        f"! Version: {version}",
        f"! Expires: {expires}",
        f"! Last modified: {now}",
        f"! Homepage: https://github.com/{repo}",
        "! License: MIT",
        f"! SupportURL: https://github.com/{repo}/issues",
        "!",
        "! 规则统计",
        f"!   黑名单域名: {len(block):,}",
        f"!   白名单域名: {len(white):,}",
        f"!   生成时间: {now}",
        "!",
        "! 语法说明",
        "!   黑名单 ||domain^ —— 拦截该域名及其所有子域名",
        "!   白名单 |domain^  —— 仅放行该域名本身，不影响其子域",
        "!   （例外规则优先级高于屏蔽规则，若白名单写成 ||domain^ 会连带",
        "!     放行全部子域，使子域上的黑名单规则失效）",
        "",
    ]
    for domain in white:
        lines.append(f"@@|{domain}^")
    for domain in block:
        lines.append(f"||{domain}^")
    return "\n".join(lines) + "\n"


def render_dnsmasq(block: Set[str], white: Set[str], ip: str, repo: str) -> str:
    """
    生成 dnsmasq 配置。

    dnsmasq 没有例外规则概念，且 `address=/domain/` 会匹配该域**及所有子域**。
    因此白名单域名本身、以及位于白名单域名之下的所有黑名单子域，
    都必须从 dnsmasq 黑名单中剔除，否则 `@@|example.com^` 的放行意图
    在 dnsmasq 下会被父域屏蔽规则彻底架空。
    """
    effective = set(block)
    removed = 0
    for w in white:
        suffix = "." + w
        descendants = {b for b in effective if b.endswith(suffix)}
        if descendants:
            effective -= descendants
            removed += len(descendants)

    lines = [
        "# ADH-AD 广告过滤规则（dnsmasq / OpenWrt / 路由器）",
        f"# 更新时间: {utc_stamp()}",
        f"# 规则数量: {len(effective):,}",
        f"# 来源: https://github.com/{repo}",
        "#",
        "# 用法: 在 dnsmasq 配置中引入",
        "#   conf-file=/etc/dnsmasq.d/adh-ad.conf",
        "#",
        f"# 注意: dnsmasq 无例外规则概念。已剔除白名单域名 {len(white)} 条、",
        f"#       白名单域名下的黑名单子域 {removed} 条，以保持放行效果。",
        "#       若需放行，请自行用 server=/domain/ 显式指定上游。",
        "",
    ]
    lines.extend(f"address=/{domain}/{ip}" for domain in sorted(effective))
    return "\n".join(lines) + "\n"


def render_clash(block: Set[str], white: Set[str], repo: str) -> str:
    """
    生成 Clash / Mihomo rule-provider payload。

    Clash 的 DOMAIN 是精确匹配，DOMAIN-SUFFIX 才匹配子域。
    因此白名单用 DOMAIN 表达（放行该域名本身），
    白名单域名之下的黑名单子域同样需要剔除，避免被后缀规则覆盖。
    """
    effective = set(block)
    removed = 0
    for w in white:
        suffix = "." + w
        descendants = {b for b in effective if b.endswith(suffix)}
        if descendants:
            effective -= descendants
            removed += len(descendants)

    lines = [
        "# ADH-AD 广告过滤规则（Clash / Mihomo rule-provider payload）",
        f"# 更新时间: {utc_stamp()}",
        f"# 规则数量: {len(effective):,}",
        f"# 来源: https://github.com/{repo}",
        "#",
        "# 用法: 在配置中引用",
        "#   rule-providers:",
        "#     adh-ad:",
        "#       type: http",
        f"#       url: https://raw.githubusercontent.com/{repo}/release/clash.yaml",
        "#       path: ./rules/adh-ad.yaml",
        "#   rules:",
        "#     - RULE-SET,adh-ad",
        "#",
        f"# 白名单域名 {len(white)} 条、白名单下的黑名单子域 {removed} 条已剔除。",
        "# 如需放行白名单域名，请在 rules 中用 DOMAIN,xxx 精确匹配，",
        "# 不要用 DOMAIN-SUFFIX,xxx（后者会连带放行其子域）。",
        "",
        "payload:",
    ]
    lines.extend(f"  - DOMAIN,{domain}" for domain in sorted(effective))
    return "\n".join(lines) + "\n"


def generate_outputs(block: Set[str], white: Set[str], out_dir: Path, cfg: dict) -> Dict[str, int]:
    out_cfg = cfg.get("output") or {}
    expires = str(out_cfg.get("adguard_expires", "2 days"))
    dnsmasq_ip = str(out_cfg.get("dnsmasq_block_ip", DNSMASQ_DEFAULT_IP)).strip() or DNSMASQ_DEFAULT_IP

    sorted_block = sorted(block)
    sorted_white = sorted(white)

    info("生成产物文件...")
    sizes: Dict[str, int] = {}
    sizes["adguardhome.txt"] = write_atomic(
        out_dir / "adguardhome.txt",
        render_adguard_home(sorted_block, sorted_white, GITHUB_REPO, expires),
    )
    sizes["dnsmasq.conf"] = write_atomic(
        out_dir / "dnsmasq.conf",
        render_dnsmasq(block, white, dnsmasq_ip, GITHUB_REPO),
    )
    sizes["clash.yaml"] = write_atomic(
        out_dir / "clash.yaml",
        render_clash(block, white, GITHUB_REPO),
    )

    for name, size in sizes.items():
        info(f"  {name}: {human_bytes(size)}")
    return sizes


def sha256_of(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def render_readme(
    block: Set[str],
    white: Set[str],
    source_stats: dict,
    old_stats: dict,
    degraded: bool,
    failed: List[str],
    elapsed: float,
    checksums: Dict[str, str],
) -> str:
    total_block = len(block)
    total_white = len(white)

    last_block = 0
    last_white = 0
    last_update = "首次运行"
    if isinstance(old_stats, dict) and isinstance(old_stats.get("total_block"), int):
        last_block = old_stats["total_block"]
        last_white = int(old_stats.get("total_white", 0) or 0)
        last_update = str(old_stats.get("last_update", "未知时间"))

    def fmt_change(change: int, base: int) -> str:
        if base == 0:
            return "首次统计"
        if change == 0:
            return "无变化"
        pct = change / base * 100
        return f"📈 +{change:,} (+{pct:.2f}%)" if change > 0 else f"📉 {change:,} ({pct:.2f}%)"

    now = utc_stamp()
    last_day = last_update.split("T")[0] if "T" in last_update else last_update

    L: List[str] = []
    L.append("# 🛡️ ADH-AD 广告过滤规则")
    L.append("")
    L.append("> 每 12 小时自动合并 8+ 个主流上游广告过滤源，去重后输出三种格式。")
    L.append("> 只包含**整域规则**，可直接用于 DNS 层过滤，不会误杀正常请求。")
    L.append("")

    if degraded:
        L.append("> [!WARNING]")
        L.append(f"> **本次为降级构建**：{len(failed)} 个来源抓取失败，规则量低于正常水平。")
        L.append("")
        L.append(f"> 失败来源：{', '.join(failed)}")
        L.append("")

    L.append("## 📊 规则统计")
    L.append("")
    L.append("| 项目 | 本次 | 上次 | 变化 |")
    L.append("|------|------|------|------|")
    L.append(f"| 🕐 更新时间 | {now} | {last_day} | - |")
    L.append(f"| 📦 黑名单域名 | {total_block:,} | {last_block:,} | {fmt_change(total_block - last_block, last_block)} |")
    L.append(f"| 🎯 白名单域名 | {total_white:,} | {last_white:,} | {fmt_change(total_white - last_white, last_white)} |")
    L.append(f"| 📋 上游来源 | {len(source_stats)} 个 | - | - |")
    L.append(f"| ⏱️ 构建耗时 | {elapsed:.1f}s | - | - |")
    L.append("")

    if abs(total_block - last_block) > 500:
        delta = total_block - last_block
        L.append(f"> 💡 黑名单本次变化 **{abs(delta):,}** 条规则"
                 f"（{'新增拦截' if delta > 0 else '移除，多为失效域名'}）。")
        L.append("")

    L.append("## 📥 订阅链接")
    L.append("")
    L.append("| 客户端 | 订阅地址 |")
    L.append("|--------|----------|")
    L.append(f"| AdGuard Home | `https://raw.githubusercontent.com/{GITHUB_REPO}/release/adguardhome.txt` |")
    L.append(f"| dnsmasq / 路由器 | `https://raw.githubusercontent.com/{GITHUB_REPO}/release/dnsmasq.conf` |")
    L.append(f"| Clash / Mihomo | `https://raw.githubusercontent.com/{GITHUB_REPO}/release/clash.yaml` |")
    L.append("")
    L.append("**AdGuard Home 添加路径**：筛选器 → DNS 过滤 → 添加过滤器 → 粘贴上面的链接 → 保存。")
    L.append("")

    L.append("## 📋 上游来源明细")
    L.append("")
    L.append("| 名称 | 黑名单 | 白名单 | 大小 | 状态 |")
    L.append("|------|--------|--------|------|------|")
    for name, st in source_stats.items():
        if not isinstance(st, dict):
            continue
        if "error" in st:
            L.append(f"| {name} | - | - | - | ❌ {st['error']} |")
        else:
            L.append(
                f"| {name} | {int(st.get('block_count', 0)):,} | {int(st.get('white_count', 0)):,} "
                f"| {human_bytes(int(st.get('bytes', 0)))} | ✅ |"
            )
    L.append("")

    L.append("## 🔐 产物校验和")
    L.append("")
    L.append("订阅拉取异常时，可用以下 SHA256 校验文件是否被截断或篡改：")
    L.append("")
    L.append("| 文件 | SHA256 |")
    L.append("|------|--------|")
    for fname, digest in checksums.items():
        L.append(f"| `{fname}` | `{digest}` |")
    L.append("")

    L.append("## ⚙️ 规则说明")
    L.append("")
    L.append("| 语法 | 含义 |")
    L.append("|------|------|")
    L.append("| `\\|\\|domain^` | **黑名单** —— 拦截该域名**及其所有子域名** |")
    L.append("| `\\|domain^` | **白名单** —— 仅放行该域名本身，不影响其子域 |")
    L.append("")
    L.append("> ⚠️ **为什么白名单用单竖线？**")
    L.append(">")
    L.append("> AdGuard 中例外规则（`@@`）的优先级**硬性高于**屏蔽规则，与书写顺序无关。")
    L.append("> 而 `||domain^` 会连带匹配所有子域。若白名单写成 `@@||example.com^`，")
    L.append("> 则 `ads.example.com`、`track.example.com` 等子域上的黑名单规则会全部失效。")
    L.append("> 因此本列表统一使用精确匹配 `|domain^`，只放行该域名本身。")
    L.append("")
    L.append("- 刻意**不含** URL 级规则（`||a.com/path^`）、带修饰符的条件规则、"
             "元素隐藏规则与通配符规则——DNS 层无法正确执行这些语法。")
    L.append("- dnsmasq / Clash 格式同样剔除了白名单域名之下的黑名单子域，"
             "保证三端行为一致。")
    L.append("")

    L.append("---")
    L.append("")
    L.append("- 🔄 自动更新：每 12 小时（GitHub Actions cron）")
    L.append(f"- ⏰ 最近构建：{now}")
    L.append(f"- 📦 项目地址：[GitHub](https://github.com/{GITHUB_REPO})")
    L.append("")
    return "\n".join(L)


# --------------------------------------------------------------------------
# 自检
# --------------------------------------------------------------------------

SELFTEST_CASES = [
    # (输入行, 期望域名 or None, 期望是否白名单)
    ("||example.com^", "example.com", False),
    ("||ads.tracker.net^", "ads.tracker.net", False),
    ("@@||whitelist.example.org^", "whitelist.example.org", True),
    ("||example.com/path^", None, False),
    ("||example.com^$third-party", None, False),
    ("||*.example.com^", None, False),
    ("||example.com^banner", None, False),
    ("example.com##.ad", None, False),
    ("0.0.0.0 blocked.example.com", "blocked.example.com", False),
    ("127.0.0.1 tracker.example.net extra", "tracker.example.net", False),
    ("bare.example.com", "bare.example.com", False),
    ("UPPER.EXAMPLE.COM", "upper.example.com", False),
    (".leading.dot.example.com", "leading.dot.example.com", False),
    ("1.2.3.4", None, False),
    ("0.0.0.0 1.2.3.4", None, False),
    ("! 注释行", None, False),
    ("# 注释行", None, False),
    ("[Adblock Plus 2.0]", None, False),
    ("", None, False),
    ("   ", None, False),
    ("@@||example.com^$important", None, False),
]


def run_selftest() -> int:
    failures = 0
    for line, want_domain, want_allow in SELFTEST_CASES:
        got_domain, got_allow = classify_line(line)
        expect_allow = want_allow if want_domain else False
        if got_domain != want_domain or got_allow != expect_allow:
            failures += 1
            print(f"  FAIL  输入={line!r}  期望=({want_domain!r}, {expect_allow})  "
                  f"实际=({got_domain!r}, {got_allow})")
        else:
            debug(f"  ok    {line!r} → {got_domain!r} (白名单={expect_allow})")

    # 集成校验：混合内容解析
    sample = "\n".join([
        "! Title: t",
        "||a.com^",
        "@@||b.com^",
        "0.0.0.0 c.com",
        "||d.com/path^",
        "||A.COM^",
    ])
    block, white, bn, wn = parse_content(sample)
    checks = [
        (block == {"a.com", "c.com"}, f"黑名单解析错误：{block}"),
        (white == {"b.com"}, f"白名单解析错误：{white}"),
        (bn == 2 and wn == 1, f"计数错误：block={bn} white={wn}"),
    ]
    for ok, msg in checks:
        if not ok:
            failures += 1
            print(f"  FAIL  {msg}")

    # 冲突消解：白名单父域不能带走黑名单子域
    b2, w2, _ = resolve_conflicts(
        {"example.com", "ads.example.com", "cdn.other.com"},
        {"example.com"},
    )
    conflict_checks = [
        (b2 == {"ads.example.com", "cdn.other.com"},
         f"冲突消解后黑名单错误：{b2}"),
        (w2 == {"example.com"}, f"冲突消解后白名单错误：{w2}"),
    ]
    for ok, msg in conflict_checks:
        if not ok:
            failures += 1
            print(f"  FAIL  {msg}")

    # 白名单渲染必须是精确匹配（单竖线），不能是 @@||domain^
    rendered = render_adguard_home(["ads.example.com"], ["example.com"], "o/r", "2 days")
    conflict_checks += [
        ("@@|example.com^" in rendered, "白名单未使用精确匹配 @@|domain^"),
        ("@@||example.com^" not in rendered, "白名单错误地使用了 @@||domain^（会影子覆盖黑名单子域）"),
    ]
    for ok, msg in conflict_checks[len(checks):]:
        if not ok:
            failures += 1
            print(f"  FAIL  {msg}")

    total = len(SELFTEST_CASES) + len(checks) + len(conflict_checks)
    if failures:
        error(f"自检未通过：{failures}/{total} 项失败")
        return 1
    info(f"自检通过：{total}/{total} 项")
    return 0


# --------------------------------------------------------------------------
# 主流程
# --------------------------------------------------------------------------

def build(out_dir: Path) -> int:
    start = time.time()

    info("=" * 64)
    info("ADH-AD 广告规则合并工具")
    info("=" * 64)
    info(f"配置：{CFG}")
    info(f"输出：{out_dir}")
    info(f"统计：{STATS_FILE}")
    info(f"模式：{'DRY RUN（不写回统计）' if DRY_RUN else '正常'}"
         f"{'｜FORCE（跳过阈值）' if FORCE_PASS else ''}")
    info("=" * 64)

    # 1. 配置
    try:
        cfg = load_config(CFG)
    except Exception as exc:  # noqa: BLE001
        error(f"配置加载失败：{exc}")
        return 2
    apply_runtime_overrides(cfg)

    sources = cfg["sources"]
    threshold_cfg = cfg.get("threshold") or {}
    old_stats = load_stats(STATS_FILE)

    # 2. 抓取
    block_raw, white_raw, source_stats, failed = collect_sources(sources)
    enabled_count = len([s for s in sources if s.get("enabled", True)])
    ok_count = len([s for s in source_stats.values() if not s.get("error")])

    # 3. 消解黑白名单冲突（白名单改用精确匹配，避免影子覆盖黑名单子域）
    block, white, conflict_stats = resolve_conflicts(block_raw, white_raw)
    info(f"合并完成：黑名单 {len(block):,} 条，白名单 {len(white):,} 条")
    if conflict_stats:
        info(f"冲突消解：自身冲突 {conflict_stats['self_conflict']} 条，"
             f"父域阴影 {conflict_stats['shadowed_subdomains']} 条")

    # 4. 守卫
    allowed, degraded = guard_sanity(len(block), enabled_count, ok_count, failed, threshold_cfg)
    if not allowed:
        error("构建中止，未生成任何产物")
        return 3

    check_threshold(old_stats, len(block), threshold_cfg, degraded)

    # 5. 产物
    try:
        sizes = generate_outputs(block, white, out_dir, cfg)
    except Exception as exc:  # noqa: BLE001
        error(f"产物生成失败：{exc}")
        return 4

    checksums = {
        name: sha256_of(out_dir / name)
        for name in ("adguardhome.txt", "dnsmasq.conf", "clash.yaml")
    }

    # 6. README
    elapsed = time.time() - start
    try:
        readme = render_readme(block, white, source_stats, old_stats, degraded, failed, elapsed, checksums)
        sizes["README.md"] = write_atomic(out_dir / "README.md", readme)
        info(f"  README.md: {human_bytes(sizes['README.md'])}")
    except Exception as exc:  # noqa: BLE001
        error(f"README 生成失败：{exc}")
        return 5

    # 7. 写回统计
    if DRY_RUN:
        info("DRY RUN 模式，跳过统计写回")
    else:
        new_stats = {
            "last_update": utcnow().isoformat(),
            "total_block": len(block),
            "total_white": len(white),
            "degraded": degraded,
            "failed_sources": failed,
            "conflicts": conflict_stats,
            "checksums": checksums,
            "sources": source_stats,
        }
        try:
            save_stats(STATS_FILE, new_stats)
            info(f"统计已写回：{STATS_FILE}")
        except OSError as exc:
            warn(f"统计写回失败：{exc}")

    info("=" * 64)
    info("构建完成")
    info(f"耗时：{time.time() - start:.1f}s")
    info(f"黑名单：{len(block):,}  白名单：{len(white):,}  "
         f"来源：{ok_count}/{enabled_count}{'（降级）' if degraded else ''}")
    for name, size in sizes.items():
        info(f"  {name:<16} {human_bytes(size):>10}")
    info("=" * 64)
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="ADH-AD 广告规则合并工具")
    parser.add_argument("--output", help="产物输出目录（默认 <repo>/../release）")
    parser.add_argument("--dry-run", action="store_true", help="不写回统计文件")
    parser.add_argument("--force", action="store_true", help="跳过阈值守卫")
    parser.add_argument("--debug", action="store_true", help="输出逐行调试日志")
    parser.add_argument("--selftest", action="store_true", help="运行解析器自检并退出")
    args = parser.parse_args()

    global DEBUG, DRY_RUN, FORCE_PASS
    if args.debug:
        DEBUG = True
    if args.dry_run:
        DRY_RUN = True
    if args.force:
        FORCE_PASS = True

    if args.selftest:
        return run_selftest()

    if args.output:
        out_dir = Path(args.output).expanduser().resolve()
    else:
        env_out = os.getenv("OUTPUT_DIR")
        out_dir = Path(env_out).expanduser().resolve() if env_out else BASE.parent / "release"

    try:
        out_dir.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        error(f"无法创建输出目录 {out_dir}：{exc}")
        return 6

    try:
        return build(out_dir)
    except KeyboardInterrupt:
        warn("用户中断")
        return 130


if __name__ == "__main__":
    try:
        sys.exit(main())
    except SystemExit:
        raise
    except Exception as exc:  # noqa: BLE001
        error(f"未捕获异常：{type(exc).__name__}: {exc}")
        if DEBUG:
            import traceback
            traceback.print_exc()
        sys.exit(1)
