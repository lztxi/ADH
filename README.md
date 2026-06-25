# ADH-AD Blocklist

Auto-merge multiple upstream ad domain rules
Supports: AdGuard Home, dnsmasq, Clash

## Statistics

Updated: 2026-06-25 14:13 UTC
Block domains: 314,584
White domains: 848
Upstream sources: 8

## Download URLs

### AdGuard Home
https://raw.githubusercontent.com/lztxi/ADH/release/adguardhome.txt

### dnsmasq
https://raw.githubusercontent.com/lztxi/ADH/release/dnsmasq.conf

### Clash
https://raw.githubusercontent.com/lztxi/ADH/release/clash.yaml

## Upstream Sources

| Name | Block | White | Total | Status |
|------|-------|-------|-------|--------|
| AdGuard DNS Filter（DNS 层拦截广告 / 跟踪器 / 恶意软件） | 158,215 | 172 | 160,733 | OK |
| AdGuard 中文 | 6,971 | 379 | 23,688 | OK |
| EasyPrivacy（隐私保护 / 跟踪器） | 46,853 | 180 | 56,211 | OK |
| I-Don't-Care-About-Cookies | 80 | 0 | 24,339 | OK |
| anti-AD（中文区主要规则） | 96,866 | 105 | 97,075 | OK |
| cjx-annoyance（弹窗 / 跳转 / 自我推广） | 197 | 1 | 1,861 | OK |
| 大萌主（轻量去除色情 / 悬浮广告） | 4,502 | 11 | 5,889 | OK |
| 秋风（适配路由器） | 900 | 0 | 916 | OK |

## Features

- Auto-update twice daily (00:00, 12:00 UTC)
- Multiple format support (AdGuard, dnsmasq, Clash)
- Smart whitelist handling
- Threshold monitoring
- Parallel download for high performance

## License

Rules from upstream sources, copyright belongs to original authors
Build script maintained by ADH project
