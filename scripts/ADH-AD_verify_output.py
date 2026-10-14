"""产物合规校验：确保输出严格符合 AdGuard Home / dnsmasq / Clash 格式。"""
import re
import sys
from pathlib import Path

import yaml

OUT = Path(sys.argv[1] if len(sys.argv) > 1 else ".")
fails = []

# ---------- adguardhome.txt ----------
txt = (OUT / "adguardhome.txt").read_text(encoding="utf-8")
lines = txt.splitlines()
rules = [l for l in lines if not l.startswith("!") and l.strip()]
blk = [l for l in rules if l.startswith("||") and not l.startswith("@@")]
wht = [l for l in rules if l.startswith("@@|")]
other = [l for l in rules if not (l.startswith("||") or l.startswith("@@|"))]
print(f"adguardhome: 黑 {len(blk)} / 白 {len(wht)} / 杂项 {len(other)}")
if other:
    fails.append(f"存在杂项行: {other[:3]}")

# 白名单必须用单竖线精确匹配；@@|| 会连带放行子域，导致黑名单失效
if any(l.startswith("@@||") for l in rules):
    fails.append("白名单使用了 @@||domain^，会影子覆盖子域黑名单（应为 @@|domain^）")

# 每条黑名单都必须是纯整域 ||domain^
blk_pat = re.compile(
    r"^\|\|([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
    r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\^$"
)
# 每条白名单都必须是精确匹配 |domain^
wht_pat = re.compile(
    r"^@@\|[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
    r"(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+\^$"
)
bad = [l for l in blk if not blk_pat.match(l)]
if bad:
    fails.append(f"黑名单非法规则 {len(bad)} 条: {bad[:3]}")
badw = [l for l in wht if not wht_pat.match(l)]
if badw:
    fails.append(f"白名单非法规则 {len(badw)} 条: {badw[:3]}")

bs = [l[2:-1] for l in blk]
ws = [l[4:-1] for l in wht]

if len(bs) != len(set(bs)):
    fails.append("黑名单存在重复域名")
if len(ws) != len(set(ws)):
    fails.append("白名单存在重复域名")
if any(b != b.lower() for b in bs):
    fails.append("黑名单含未规范化的大写域名")

inter = set(bs) & set(ws)
if inter:
    fails.append(f"黑白名单交叉 {len(inter)} 条: {list(inter)[:3]}")

# ---------- dnsmasq.conf ----------
dlines = (OUT / "dnsmasq.conf").read_text(encoding="utf-8").splitlines()
dr = [l for l in dlines if l and not l.startswith("#")]
print(f"dnsmasq: {len(dr)} 条")
badm = [l for l in dr if not re.match(r"^address=/[a-z0-9.-]+/0\.0\.0\.0$", l)]
if badm:
    fails.append(f"dnsmasq 非法行 {len(badm)}: {badm[:3]}")
d_domains = {l.split("/")[1] for l in dr}
if d_domains & set(ws):
    fails.append("dnsmasq 仍包含白名单域名本身")
# dnsmasq 的 address=/d/ 同样匹配子域，白名单子域下的黑名单也必须剔除
shadowed_d = {x for x in d_domains for w in ws if x.endswith("." + w)}
if shadowed_d:
    fails.append(f"dnsmasq 含白名单父域下的黑名单子域 {len(shadowed_d)} 条: {list(shadowed_d)[:3]}")

# ---------- clash.yaml ----------
clash = yaml.safe_load((OUT / "clash.yaml").read_text(encoding="utf-8"))
if not isinstance(clash, dict) or "payload" not in clash:
    fails.append("clash.yaml 结构异常，缺少 payload")
elif len(clash["payload"]) != len(dr):
    fails.append(f"clash 数量 {len(clash['payload'])} != dnsmasq {len(dr)}")
else:
    payload = clash["payload"]
    badc = [p for p in payload if not re.match(
        r"^DOMAIN,[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
        r"(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$", p)]
    if badc:
        fails.append(f"clash 非法条目 {len(badc)}: {badc[:3]}")
    elif sorted(p.split(",", 1)[1] for p in payload) != sorted(d_domains):
        fails.append("clash 内容与 dnsmasq 不一致")
    else:
        print(f"clash: payload {len(payload)} 条，DOMAIN 格式，YAML 解析正常")

# ---------- README.md ----------
rd = (OUT / "README.md").read_text(encoding="utf-8")
for kw in ("订阅链接", "SHA256", "上游来源明细"):
    if kw not in rd:
        fails.append(f"README 缺少章节: {kw}")

print()
print("=== 合规校验结果 ===")
if fails:
    for f in fails:
        print("  FAIL:", f)
    sys.exit(1)
print("  全部通过 ✅")