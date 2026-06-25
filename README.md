# ADH-AD Ad Domain Rules

> Auto-merge multiple upstream ad domain rules, supports AdGuard Home, dnsmasq, Clash formats

## Stats

- Updated: 2026-06-25 13:55 UTC
- Block domains: 314,584
- White domains: 848
- Upstream sources: 8

## Download URLs

### AdGuard Home
```
https://raw.githubusercontent.com/lztxi/ADH/release/adguardhome.txt
```

### dnsmasq
```
https://raw.githubusercontent.com/lztxi/ADH/release/dnsmasq.conf
```

### Clash
```yaml
https://raw.githubusercontent.com/lztxi/ADH/release/clash.yaml
```

## Upstream Sources

| Name | Block | White | Total Lines | Status |
|------|-------|-------|-------------|--------|
| AdGuard DNS Filter（DNS 层拦截广告 / 跟踪器 / 恶意软件） | 158,215 | 172 | 160,733 | OK |
| AdGuard 中文 | 6,971 | 379 | 23,688 | OK |
| EasyPrivacy（隐私保护 / 跟踪器） | 46,853 | 180 | 56,211 | OK |
| I-Don't-Care-About-Cookies | 80 | 0 | 24,339 | OK |
| anti-AD（中文区主要规则） | 96,866 | 105 | 97,075 | OK |
| cjx-annoyance（弹窗 / 跳转 / 自我推广） | 197 | 1 | 1,861 | OK |
| 大萌主（轻量去除色情 / 悬浮广告） | 4,502 | 11 | 5,889 | OK |
| 秋风（适配路由器） | 900 | 0 | 916 | OK |

## Usage

### AdGuard Home
1. Open AdGuard Home Settings -> Filters
2. Add custom filter list
3. Paste the subscription URL above

### dnsmasq
Place dnsmasq.conf in dnsmasq config directory, restart service

### Clash
Add to Clash config:
```yaml
rule-providers:
  adh-ad:
    type: http
    behavior: domain
    url: "https://raw.githubusercontent.com/lztxi/ADH/release/clash.yaml"
    path: ./adh-ad.yaml
    interval: 86400

rules:
  - RULE-SET,adh-ad,REJECT
```

## Notes

- Auto-updated twice daily (00:00, 12:00 UTC)
- Supports whitelist rules (from upstream @@ prefix rules)
- Auto deduplication and format standardization
- Auto rollback if rule change exceeds threshold

## License

Rules from upstream sources, copyright belongs to original authors
