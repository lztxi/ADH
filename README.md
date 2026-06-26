# 🛡️ ADH-AD 广告域名规则

> ✨ 自动合并多个上游广告域名规则
> 🎯 让你的网络环境更清爽，远离广告骚扰！

## 📊 规则统计

| 项目 | 数量 |
|------|------|
| 🕐 **更新时间** | 2026-06-26 09:29 UTC |
| 📦 **黑名单域名** | 310,545 个 |
| 🎯 **白名单域名** | 318 个 |
| 📋 **上游源数量** | 8 个 |

## 📥 快速订阅

### 1️⃣ AdGuard Home 用户
```
https://raw.githubusercontent.com/lztxi/ADH/release/adguardhome.txt
```

### 2️⃣ dnsmasq 用户
```
https://raw.githubusercontent.com/lztxi/ADH/release/dnsmasq.conf
```

### 3️⃣ Clash 用户
```
https://raw.githubusercontent.com/lztxi/ADH/release/clash.yaml
```

## 📋 上游源详情

| 名称 | 黑名单 | 白名单 | 状态 |
|------|--------|--------|------|
| AdGuard DNS Filter（DNS 层拦截广告 / 跟踪器 / 恶意软件） | 158,484 | 172 | ✅ 正常 |
| AdGuard 中文 | 6,380 | 33 | ✅ 正常 |
| EasyPrivacy（隐私保护 / 跟踪器） | 42,613 | 4 | ✅ 正常 |
| I-Don't-Care-About-Cookies | 80 | 0 | ✅ 正常 |
| anti-AD（中文区主要规则） | 97,476 | 105 | ✅ 正常 |
| cjx-annoyance（弹窗 / 跳转 / 自我推广） | 120 | 0 | ✅ 正常 |
| 大萌主（轻量去除色情 / 悬浮广告） | 4,492 | 4 | ✅ 正常 |
| 秋风（适配路由器） | 900 | 0 | ✅ 正常 |

## 🔧 使用指南

### 🏠 AdGuard Home 用户
1. 打开 AdGuard Home 设置 → 过滤器
2. 添加自定义过滤规则列表
3. 粘贴上述订阅地址即可 ✅

### 📱 dnsmasq 用户
将 dnsmasq.conf 放置到配置目录，重启服务生效 🔄

### 🌐 Clash 用户
在配置文件中添加规则提供商配置即可 ⚙️

## ✨ 特色功能

- 🔥 **自动更新**：每日 00:00 和 12:00 UTC
- 🎯 **多格式支持**：AdGuard + dnsmasq + Clash
- 🛡️ **智能白名单**：自动处理上游规则
- 📊 **变化监控**：超阈值自动回滚
- 🚀 **高性能**：并行下载多源

## 📜 许可证

规则来自各上游源，版权归原作者所有
构建脚本由 ADH 项目维护

---

💡 **小贴士**：推荐使用 AdGuard Home，配置最简单！

🌟 觉得有用就给个 Star 吧！
