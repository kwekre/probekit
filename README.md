# probekit

[![Python](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Detectors](https://img.shields.io/badge/detectors-9-blue.svg)](#支持的检测器)

**异步 Web 漏洞启发式扫描器** —— 纯 Python / `asyncio` / `aiohttp`，面向**已授权目标**的快速初筛与可嵌入的安全测试组件。

> ⚠️ 仅用于你拥有书面授权的目标或自有靶场。对未授权系统扫描可能违反《刑法》285/286 条、《网络安全法》及 CFAA。使用者自行承担法律责任。

---

## 为什么写它

市面扫描器要么重（Nessus/Burp）、要么黑盒（sqlmap 偏单点）。probekit 的定位是：
**轻量、可嵌入、代码可读**，方便二次开发（加检测器、接 CI、接资产 pipeline）。
架构清晰，单个检测器 < 100 行，新人能读懂也能改。

## 特性

- 全异步：并发请求 + 信号量限流，不阻塞
- **九类检测器**：SQLi / XSS / SSRF / 开放重定向 / 命令注入 / 路径遍历 / JWT 弱点 / 敏感信息泄露 / CORS 错误配置
- **GET 与 POST 表单**参数均支持（自动按参数位置 query/body 构造请求）
- **同源爬虫**：`--crawl` 自动发现链接与表单，扩展检测面
- **三重输出**：人类可读文本 / 机器 JSON / **SARIF（可接入 GitHub Code Scanning 等 CI）**
- **响应差异去噪**：比对响应前自动剥离 CSRF Token / 会话 ID / 时间戳 / 哈希 / JWT 等随机变量（`denoise.py`），只比“真实业务差异”，显著降低布尔盲注漏报与 SSRF 基线误判
- 可扩展：新增检测器只需实现 `scan()`
- 自带测试：本地漏洞模拟服务 + 断言，**`python tests/test_detectors.py` 全绿**（含去噪单测）

## 架构

```
CLI (__main__.py)
   └─ Scanner (engine.py)               解析 URL/表单参数，调度检测器；可选爬虫
        ├─ Requester (http.py)          asyncio 客户端：限流/超时/代理/耗时/自定义头
        ├─ Crawler (crawler.py)         同源 HTML 解析：链接(GET)+表单(GET/POST)
        └─ Detectors (detectors/*)      每个检测器对 (url, param) 返回 Finding
             ├─ SQLiDetector            报错型 / 布尔盲注 / 时间盲注
             ├─ XSSDetector             反射标记回显
             ├─ SSRFDetector            代发内网/云元数据探测（仅链路本地）
             ├─ OpenRedirectDetector    3xx / meta / JS 跳转
             ├─ CommandInjectionDetector 回显标记 / 时间盲注
             ├─ PathTraversalDetector   目录穿越读取系统文件
             ├─ JwtDetector             站点级：alg:none 接受 + 弱密钥伪造
             ├─ InfoLeakDetector        站点级：私钥/AK/内网IP/栈跟踪泄露
             └─ CorsDetector            站点级：反射 Origin+凭据的跨域泄露
   └─ report (report.py)                text / json / sarif
```

## 安装

```powershell
git clone https://github.com/kwekre/probekit
cd probekit
pip install -r requirements.txt
```

## 快速开始

```powershell
# 单 URL（GET）
python -m probekit -u "http://localhost:8080/sqli?id=1"

# 批量（每行一个 URL）
python -m probekit -f targets.txt --json-out out.json

# 带认证头 + 同源爬虫，自动发现表单
python -m probekit -u "http://localhost:8080/" --crawl \
    --header "Authorization: Bearer <token>" --header "Cookie: sid=xxx"

# 输出 SARIF 接 CI（GitHub Code Scanning / Defender for DevOps）
python -m probekit -f targets.txt --sarif-out results.sarif

# 走代理（如本地 7890）
python -m probekit -u "http://靶场/vul?id=1" --proxy http://127.0.0.1:7890
```

### 示例输出

```
[!] 发现 1 个疑似漏洞（High:1）：

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

| 检测器 | 位置 | 严重度 | 原理 |
|--------|------|--------|------|
| SQLi | query/body | High | 报错指纹匹配；true/false 响应差异；`SLEEP()` 耗时 |
| XSS | query/body | Medium | 唯一标记原样回显（未编码） |
| SSRF | query/body | High | 向 169.254.169.254/127.0.0.1 发请求，比对回显（仅链路本地） |
| 开放重定向 | query/body | Low | `Location` / `meta refresh` / `location.href` 含外部域 |
| 命令注入 | query/body | High | 回显标记 `;echo` / `SLEEP` 时间盲注 |
| 路径遍历 | query/body | High | `../../etc/passwd` 等穿越读取系统文件特征 |
| JWT 弱点 | 站点级 | High | alg:none 被接受 / 弱 HMAC 密钥可伪造（纯标准库实现） |
| 敏感信息泄露 | 站点级 | High/Medium/Low | 响应体匹配私钥/AWS·GCP Key/内网 IP/栈跟踪/JWT 高置信指纹 |
| CORS 错误配置 | 站点级 | High/Medium | 反射任意 Origin 且允许凭据 → 跨站读取带鉴权响应 |

## 工作原理（简述）

1. `Scanner.extract_targets()` 用 `urlsplit` + `parse_qsl` 拆出每个查询参数作为入口
2. 开启 `--crawl` 时，`Crawler` 解析页面同源链接与表单，补充 GET/POST 检测入口
3. 对每个 `(url, param)` 并发跑全部检测器；`Target.location` 决定参数走 query 还是 body
4. 检测器用 `Requester` 发构造请求，依据响应差异产出 `Finding`
5. 结果经 `report` 输出；开放重定向要求 `follow_redirects=False` 以观察 3xx
6. JWT / 信息泄露 / CORS 为站点级检测：先确认端点特征，再判定风险

## 局限 / Roadmap

当前为初筛级启发式，**不替代**深度人工测试。计划：

- [x] 响应式差异去噪：先基准后对比，降低误报（`denoise.py` 已实现）
- [ ] 更细的 POST/JSON/多步表单（含 CSRF Token 自动获取）
- [ ] 被动扫描模式：读取 Burp/ZAP 流量文件
- [ ] 接 Sigma/SOAR 输出、接资产/CMDB 系统

## 法律

见顶部声明。本项目不含任何攻击载荷库，仅做**请求构造与响应差异判断**；
SSRF 探测只发向公认链路本地/内网地址，不触碰任意外网。

---

仓库：https://github.com/kwekre/probekit
