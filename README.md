# probekit

[![Python](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Detectors](https://img.shields.io/badge/detectors-4-blue.svg)](#支持的检测器)

**异步 Web 漏洞启发式扫描器** —— 纯 Python / `asyncio` / `aiohttp`，面向**已授权目标**的快速初筛。

> ⚠️ 仅用于你拥有书面授权的目标或自有靶场。对未授权系统扫描可能违反《刑法》285/286 条、《网络安全法》及 CFAA。使用者自行承担法律责任。

---

## 为什么写它

市面扫描器要么重（Nessus/Burp）、要么黑盒（sqlmap 偏单点）。probekit 的定位是：
**轻量、可嵌入、代码可读**，方便二次开发（加检测器、接 CI、接资产 pipeline）。
架构清晰，单个检测器 < 100 行，新人能读懂也能改。

## 特性

- 全异步：并发请求 + 信号量限流，不阻塞
- 四类检测器：SQLi（报错/布尔/时间）、反射 XSS、SSRF、开放重定向
- 可扩展：新增检测器只需继承 `Detector` 实现 `scan()`
- 双输出：人类可读文本 / 机器 JSON
- 自带测试：本地漏洞模拟服务 + 断言，**`python tests/test_detectors.py` 全绿**

## 架构

```
CLI (__main__.py)
   └─ Scanner (engine.py)               解析 URL 参数，调度检测器
        ├─ Requester (http.py)          asyncio 客户端：限流/超时/代理/耗时
        └─ Detectors (detectors/*)      每个检测器对 (url, param) 返回 Finding
             ├─ SQLiDetector            报错型 / 布尔盲注 / 时间盲注
             ├─ XSSDetector             反射标记回显
             ├─ SSRFDetector            代发内网/云元数据探测
             └─ OpenRedirectDetector    3xx / meta / JS 跳转
   └─ report (report.py)                text / json
```

## 安装

```powershell
git clone https://github.com/kwekre/probekit
cd probekit
pip install -r requirements.txt
```

## 快速开始

```powershell
# 单 URL
python -m probekit -u "http://localhost:8080/sqli?id=1"

# 批量（每行一个 URL）
python -m probekit -f targets.txt --json-out out.json

# 走代理（如本地 7890）
python -m probekit -u "http://靶场/vul?id=1" --proxy http://127.0.0.1:7890
```

### 示例输出

```
[!] 发现 1 个疑似漏洞：

1. [High] sqli @ http://localhost:8080/sqli?id=1
   参数 : id
   Payload: 1'
   证据 : 响应命中数据库报错指纹: you have an error in your sql syntax
   描述 : 参数 'id' 存在 报错型 SQL 注入，攻击者可读取/篡改数据库。
   修复 : 使用参数化查询(预编译)；数据库账号最小权限；生产环境关闭详细报错；输入做白名单校验。
```

## 编程调用

```python
import asyncio
from probekit import Scanner, Config

async def run():
    s = Scanner(Config(timeout=8, concurrency=20))
    findings = await s.scan_url("http://localhost:8080/sqli?id=1")
    await s.close()
    for f in findings:
        print(f.detector, f.severity, f.payload)

asyncio.run(run())
```

## 支持的检测器

| 检测器 | 方法 | 严重度 | 原理 |
|--------|------|--------|------|
| SQLi | 报错 / 布尔 / 时间 | High | 报错指纹匹配；true/false 响应差异；`SLEEP()` 耗时 |
| XSS | 反射 | Medium | 唯一标记原样回显（未编码） |
| SSRF | 代发探测 | High | 向 169.254.169.254/127.0.0.1 发请求，比对回显 |
| 开放重定向 | 跳转 | Low | `Location` / `meta refresh` / `location.href` 含外部域 |

## 工作原理（简述）

1. `Scanner.extract_targets()` 用 `urlsplit` + `parse_qsl` 拆出每个查询参数作为入口
2. 对每个 `(url, param)` 并发跑全部检测器
3. 检测器用 `Requester` 发构造请求，依据响应差异产出 `Finding`
4. 结果经 `report` 输出；开放重定向要求 `follow_redirects=False` 以观察 3xx

## 局限 / Roadmap

当前为初筛级启发式，**不替代**深度人工测试。计划：

- [ ] 表单(POST)参数与 multipart 支持
- [ ] 简单爬虫：自动发现链接/表单
- [ ] 更多检测器：命令注入、路径遍历、JWT 弱点
- [ ] 接 Sigma/SOAR 输出、接资产管理系统

## 法律

见顶部声明。本项目不含任何攻击载荷库，仅做**请求构造与响应差异判断**。

---

仓库：https://github.com/kwekre/probekit
