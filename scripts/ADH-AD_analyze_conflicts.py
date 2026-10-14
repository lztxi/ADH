"""验证：白名单父域不再阴影黑名单子域（三端一致性）。"""
import re
import sys
from pathlib import Path

OUT = Path(sys.argv[1] if len(sys.argv) > 1 else ".")

txt = (OUT / "adguardhome.txt").read_text(encoding="utf-8").splitlines()
blk = {l[2:-1] for l in txt if l.startswith("||") and not l.startswith("@@")}
wht = {l[4:-1] for l in txt if l.startswith("@@|")}

d_domains = {
    l.split("/")[1]
    for l in (OUT / "dnsmasq.conf").read_text(encoding="utf-8").splitlines()
    if l.startswith("address=/")
}

print(f"AdGuard 黑名单 {len(blk)} / 白名单 {len(wht)} / dnsmasq {len(d_domains)}\n")

# AdGuard 侧：精确匹配后，白名单父域的黑名单子域应当**保留**（不被放行）
adg_shadowed = [b for b in blk for w in wht if b.endswith("." + w)]
print("A. AdGuard 中白名单父域下的黑名单子域")
print(f"   {len(adg_shadowed)} 条 —— 期望 >0，表示这些规则能正常生效")
if adg_shadowed:
    for b in sorted(adg_shadowed)[:6]:
        w = next(w for w in wht if b.endswith("." + w))
        print(f"     ||{b}^  受 ||{w}^ 的子域匹配影响，但被 @@|{w}^ 精确放行豁免")

# dnsmasq 侧：没有例外规则，必须剔除这些子域才有一致行为
d_shadowed = [b for b in d_domains for w in wht if b.endswith("." + w)]
print()
print("B. dnsmasq 中白名单父域下的黑名单子域")
print(f"   {len(d_shadowed)} 条 —— 期望 0，已剔除保证三端一致")
if d_shadowed:
    for b in sorted(d_shadowed)[:6]:
        w = next(w for w in wht if b.endswith("." + w))
        print(f"     address=/{b}/ 仍在dnsmasq 中，但 AdGuard 已放行 —— 不一致！")

# 白名单自身绝不能出现在任何黑名单里
d_self = d_domains & wht
print()
print("C. 白名单域名本身误入黑名单")
print(f"   dnsmasq {len(d_self)} 条，AdGuard {len(blk & wht)} 条 —— 均应为 0")

ok = len(d_shadowed) == 0 and len(d_self) == 0 and len(blk & wht) == 0
print()
print("=== 结论:", "三端行为一致 ✅" if ok else "存在不一致 ❌", "===")
sys.exit(0 if ok else 1)