# 🛡️ ADH-AD 广告过滤规则

> 每 12 小时自动合并 8+ 个主流上游广告过滤源，去重后输出三种格式。
> 只包含**整域规则**，可直接用于 DNS 层过滤，不会误杀正常请求。

## 📊 规则统计

| 项目 | 本次 | 上次 | 变化 |
|------|------|------|------|
| 🕐 更新时间 | 2026-10-25 15:05 UTC | 2026-10-25 | - |
| 📦 黑名单域名 | 223,622 | 223,444 | 📈 +178 (+0.08%) |
| 🎯 白名单域名 | 127 | 127 | 无变化 |
| 📋 上游来源 | 8 个 | - | - |
| ⏱️ 构建耗时 | 11.0s | - | - |

## 📥 订阅链接

| 客户端 | 订阅地址 |
|--------|----------|
| AdGuard Home | `https://raw.githubusercontent.com/lztxi/ADH/release/adguardhome.txt` |
| dnsmasq / 路由器 | `https://raw.githubusercontent.com/lztxi/ADH/release/dnsmasq.conf` |
| Clash / Mihomo | `https://raw.githubusercontent.com/lztxi/ADH/release/clash.yaml` |

**AdGuard Home 添加路径**：筛选器 → DNS 过滤 → 添加过滤器 → 粘贴上面的链接 → 保存。

## 📋 上游来源明细

| 名称 | 黑名单 | 白名单 | 大小 | 状态 |
|------|--------|--------|------|------|
| 秋风（适配路由器） | 969 | 0 | 22.9KB | ✅ |
| 大萌主（轻量去除色情 / 悬浮广告） | 4,509 | 4 | 126.1KB | ✅ |
| cjx-annoyance（弹窗 / 跳转 / 自我推广） | 115 | 0 | 55.9KB | ✅ |
| AdGuard DNS Filter（DNS 层拦截广告 / 跟踪器 / 恶意软件） | 190,872 | 11 | 4.6MB | ✅ |
| AdGuard 中文 | 5,746 | 11 | 736.6KB | ✅ |
| EasyPrivacy（隐私保护 / 跟踪器） | 43,290 | 4 | 1.4MB | ✅ |
| I-Don't-Care-About-Cookies | 81 | 0 | 779.2KB | ✅ |
| anti-AD（中文区主要规则） | 98,086 | 108 | 2.1MB | ✅ |

## 🔐 产物校验和

订阅拉取异常时，可用以下 SHA256 校验文件是否被截断或篡改：

| 文件 | SHA256 |
|------|--------|
| `adguardhome.txt` | `84049943ea0ee4ed2d14b43a6f99f1ae5598c74336628b21d5d41cb7de40db73` |
| `dnsmasq.conf` | `86b782aacc7468cbe2cd8fa8c0b5c68586edec476fe6f4db121ab1b8e9701ee3` |
| `clash.yaml` | `cdf8d173e238525377424ebb72f5253c52378166547551d0717b31485dcd0650` |

## ⚙️ 规则说明

| 语法 | 含义 |
|------|------|
| `\|\|domain^` | **黑名单** —— 拦截该域名**及其所有子域名** |
| `\|domain^` | **白名单** —— 仅放行该域名本身，不影响其子域 |

> ⚠️ **为什么白名单用单竖线？**
>
> AdGuard 中例外规则（`@@`）的优先级**硬性高于**屏蔽规则，与书写顺序无关。
> 而 `||domain^` 会连带匹配所有子域。若白名单写成 `@@||example.com^`，
> 则 `ads.example.com`、`track.example.com` 等子域上的黑名单规则会全部失效。
> 因此本列表统一使用精确匹配 `|domain^`，只放行该域名本身。

- 刻意**不含** URL 级规则（`||a.com/path^`）、带修饰符的条件规则、元素隐藏规则与通配符规则——DNS 层无法正确执行这些语法。
- dnsmasq / Clash 格式同样剔除了白名单域名之下的黑名单子域，保证三端行为一致。

---

- 🔄 自动更新：每 12 小时（GitHub Actions cron）
- ⏰ 最近构建：2026-10-25 15:05 UTC
- 📦 项目地址：[GitHub](https://github.com/lztxi/ADH)
