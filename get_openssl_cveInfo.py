import requests
from bs4 import BeautifulSoup
import re
import pandas as pd
import openpyxl

# 输入需要爬取的网页列表
urls = [
    'https://openssl-library.org/news/vulnerabilities-0.9.6/',
    'https://openssl-library.org/news/vulnerabilities-0.9.7/',
    'https://openssl-library.org/news/vulnerabilities-0.9.8/',
    'https://openssl-library.org/news/vulnerabilities-1.0.0/',
    'https://openssl-library.org/news/vulnerabilities-1.0.1/',
    'https://openssl-library.org/news/vulnerabilities-1.0.2/',
    'https://openssl-library.org/news/vulnerabilities-1.1.0/',
    'https://openssl-library.org/news/vulnerabilities-1.1.1/'
]

def fetch_cve_data(url):
    try:
        # 发送请求获取网页内容
        response = requests.get(url)
        response.raise_for_status()  # 检查请求是否成功

        # 解析网页内容
        soup = BeautifulSoup(response.text, 'html.parser')

        # 找到所有CVE信息的h4标签---通过观察网页源代码，发现CVE信息都放在h4标签下
        cve_headers = soup.find_all('h4', id=re.compile(r'CVE-\d{4}-\d+'))

        # 存储CVE数据
        cve_data = []

        for i, cve_header in enumerate(cve_headers):
            cve_id = cve_header.find('a').text  # 提取CVE编号

            # 提取下一个CVE编号前的所有文本
            next_cve_header = cve_headers[i + 1] if i + 1 < len(cve_headers) else None
            function_names = set()  # 用于存储函数名

            # 获取当前CVE编号下的所有兄弟元素
            sibling = cve_header.find_next_sibling()
            while sibling and (next_cve_header is None or sibling != next_cve_header):
                text = sibling.get_text()

                # 匹配函数名
                # 每个CVE编号下：在 in the 或 in 或 function 前后的 含有下划线_ 或者 以()结尾的函数名
                function_names.update(re.findall(r'\b(?:in the|in|function)\s+(\w+_\w+\w*|\w+\w*_\w+)\b', text))
                function_names.update(re.findall(r'\b(?:in the|in|function)\s+(\w+\(\))\b', text))
                function_names.update(re.findall(r'\b(\w+_\w+\w*|\w+\w*_\w+)\s+(?:in the|in|function)\b', text))
                function_names.update(re.findall(r'\b(\w+\(\))\s+(?:in the|in|function)\b', text))

                # 过滤掉以 .c 结尾的文件名 或者 系统命名 或者 版本名 尤其是 x86_64 出现最多
                function_names = {name.rstrip('()') for name in function_names if
                                  not name.endswith('.c') and not re.match(r'^[A-Z0-9_]+$', name) and 'x86_64' not in name}

                sibling = sibling.find_next_sibling()

            # 提取"Fixed in OpenSSL"后的内容---版本号都放在其后面---为修改漏洞后的版本号
            fixed_in_open_ssl = cve_header.find_next('ul')
            if fixed_in_open_ssl:
                version_match = re.search(r'Fixed in OpenSSL\s+([0-9]+\.[0-9]+\.[0-9]+[a-z]+[a-z]?)',
                                          str(fixed_in_open_ssl))
                version = version_match.group(1) if version_match else None

                # 组合数据
                if function_names and version:
                    cve_data.append((cve_id, ', '.join(function_names), version))

        return cve_data
    except Exception as e:
        print(f"Error fetching data from {url}: {e}")
        return []


# 存储所有爬取的数据
all_cve_data = []

# 依次爬取每个网页
for url in urls:
    cve_data = fetch_cve_data(url)
    all_cve_data.extend(cve_data)

# 将数据存储到DataFrame
df = pd.DataFrame(all_cve_data, columns=['CVE', 'Function Name', 'Version'])

# 将DataFrame存储到XLSX文件
output_file = 'C:\cve_data.xlsx'
df.to_excel(output_file, index=False)

print(f"OK啦，数据已成功存储到 {output_file}")