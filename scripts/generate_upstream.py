import requests
from datetime import datetime
from urllib.parse import urlparse

# DNS 配置（腾讯/阿里 DoH，字节 IP）
TENCENT_DNS = 'https://doh.pub/dns-query'
BYTEDANCE_DNS = '180.184.1.1 180.184.2.2'
ALIBABA_DNS = 'https://dns.alidns.com/dns-query'

# 新源地址（MetaCubeX 更全更活跃～）
SOURCE_URLS = {
    'tencent': 'https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/refs/heads/meta/geo/geosite/tencent.list',
    'bytedance': 'https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/refs/heads/meta/geo/geosite/bytedance.list',
    'alibaba': 'https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/refs/heads/meta/geo/geosite/alibaba.list'
}

CATEGORIES = {
    'tencent': ('腾讯系', TENCENT_DNS),
    'bytedance': ('字节系', BYTEDANCE_DNS),
    'alibaba': ('阿里系', ALIBABA_DNS)
}

def get_root_domain(domain):
    """提取根域名（二级域名，如 sub.qq.com → qq.com）"""
    parts = domain.split('.')
    if len(parts) <= 2:
        return domain
    return '.'.join(parts[-2:])  # 简单处理，假设常见 .com/.cn 等

def fetch_domains(url):
    try:
        response = requests.get(url, timeout=30)
        response.raise_for_status()
    except Exception as e:
        print(f"下载 {url} 失败: {e}")
        return set()
    
    root_domains = set()
    for line in response.text.splitlines():
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        # 直接取域名（MetaCubeX 列表是纯域名）
        domain = line.lower()
        if domain and '.' in domain:
            root = get_root_domain(domain)
            root_domains.add(root)
    
    return root_domains

print("开始从 MetaCubeX 下载三大公司根域名列表（去重整合）...")
company_domains = {}
total_domains = 0
stats = {}

for cat, (name, _) in CATEGORIES.items():
    url = SOURCE_URLS[cat]
    domains = fetch_domains(url)
    company_domains[cat] = domains
    count = len(domains)
    total_domains += count
    stats[cat] = count
    print(f"{name} 根域名数量: {count}")

update_time = datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')

def generate_upstream_lines(domains, dns_server, max_per_line=50):
    lines = []
    domain_list = sorted(domains)
    for i in range(0, len(domain_list), max_per_line):
        group = domain_list[i:i + max_per_line]
        domain_str = '/' + '/'.join(group) + '/'
        lines.append(f'[{domain_str}]{dns_server}')
    return lines

output_lines = [
    "# AdGuardHome Upstream DNS 文件 - 自动生成（MetaCubeX 源 + 根域名整合）",
    f"# 更新时间: {update_time}",
    f"# 腾讯系根域名: {stats.get('tencent', 0)} → DoH {TENCENT_DNS}",
    f"# 字节系根域名: {stats.get('bytedance', 0)} → IP {BYTEDANCE_DNS}",
    f"# 阿里系根域名: {stats.get('alibaba', 0)} → DoH {ALIBABA_DNS}",
    f"# 兜底说明: 请在 AdGuard Home 主 Upstream 最下面加 202.98.0.68",
    f"# 总根域名数量: {total_domains}",
    f"# 总 upstream 条目: 0（下方计算）",
    ""
]

all_lines_count = 0
for cat, (_, dns) in CATEGORIES.items():
    if company_domains[cat]:
        lines = generate_upstream_lines(company_domains[cat], dns)
        all_lines_count += len(lines)
        output_lines.extend(lines)
        output_lines.append("")

output_lines[7] = f"# 总 upstream 条目: {all_lines_count}"

with open('upstream_dns.txt', 'w', encoding='utf-8') as f:
    f.write('\n'.join(output_lines) + '\n')

print(f"生成成功！MetaCubeX 源更全，共 {total_domains} 个根域名，{all_lines_count} 条规则～")
