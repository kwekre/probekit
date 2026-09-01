"""端到端检测验证：起本地漏洞模拟服务，逐一断言检测器能命中。
运行：在仓库根目录执行  $env:PYTHONPATH="." ; python -m pytest tests  (或 python tests/test_detectors.py)
"""
import asyncio
import json
import hmac
import hashlib
import uuid
import urllib.parse as up

from aiohttp import web

from probekit.config import Config
from probekit.denoise import normalize_body, normalize_headers, normalized_similar
from probekit.engine import Scanner
from probekit.crawler import targets_from_html
from probekit.models import Target
from probekit.detectors import (
    SQLiDetector, XSSDetector, SSRFDetector, OpenRedirectDetector,
    CommandInjectionDetector, PathTraversalDetector, JwtDetector,
    InfoLeakDetector, CorsDetector,
)
from probekit.detectors.jwt import _b64url_encode, _b64url_decode


# ---------- 模拟漏洞服务端 ----------
async def h_sqli(request):
    v = request.query.get("id", "")
    if "'" in v:
        return web.Response(status=500, text="You have an error in your SQL syntax")
    return web.Response(text="ok")


async def h_sqli_bool(request):
    # 布尔盲注模拟：每次响应都带不同的 CSRF token（旋转）。
    # true 条件(无 1=2)返回“有数据”的长页面；false 条件(1=2)返回短页面。
    # 未做去噪时，旋转 token 会让 baseline 与 true 相似度 < 0.9 -> 漏报；
    # 去噪后 token 被掩掉，baseline≈true（长页），false（短页）明显不同 -> 命中。
    v = request.query.get("id", "")
    token = uuid.uuid4().hex
    if "1=2" in v:
        return web.Response(
            text=f"<html>no results <input name=csrf value={token}></html>")
    return web.Response(
        text=f"<html>user list: alice,bob,carol,dave <input name=csrf value={token}></html>")


async def h_xss(request):
    v = request.query.get("q", "")
    return web.Response(text=f"<p>q={v}</p>")


async def h_ssrf(request):
    u = request.query.get("url", "")
    host = up.urlparse(u).hostname or ""
    if host in ("169.254.169.254", "127.0.0.1", "localhost"):
        return web.Response(text="ami-id: mock-instance")
    return web.Response(text="external")


async def h_redir(request):
    nxt = request.query.get("next", "")
    if nxt.startswith("http"):
        raise web.HTTPFound(nxt)
    return web.Response(text="ok")


async def h_cmd(request):
    v = request.query.get("cmd", "")
    if "PRBCMD7Z9" in v:
        return web.Response(text="result=PRBCMD7Z9")
    return web.Response(text="ok")


async def h_traversal(request):
    v = request.query.get("file", "")
    if ".." in v or "%2e%2e" in v or "%252e" in v or "..%2f" in v:
        return web.Response(text="root:x:0:0:root:/root:/bin/bash")
    return web.Response(text="ok")


async def h_xsspost(request):
    data = await request.post()
    v = data.get("q", "")
    return web.Response(text=f"<p>q={v}</p>")


SECRET = b"secret"


async def h_info(request):
    body = (
        "config: db_host=10.0.0.5, debug=true\n"
        "-----BEGIN RSA PRIVATE KEY-----\nMOCKKEY\n-----END RSA PRIVATE KEY-----\n"
        "Traceback (most recent call last):\n  File \"app.py\", line 1\n"
    )
    return web.Response(text=body)


async def h_cors(request):
    origin = request.headers.get("Origin")
    if origin:
        return web.Response(text="ok", headers={
            "Access-Control-Allow-Origin": origin,
            "Access-Control-Allow-Credentials": "true",
        })
    return web.Response(text="ok")


def h_jwt(request):
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        return web.Response(status=401, text="no auth")
    tok = auth[7:]
    try:
        hseg, pseg, sig = tok.split(".")
        hh = json.loads(_b64url_decode(hseg))
    except Exception:
        return web.Response(status=401, text="bad")
    alg = hh.get("alg")
    if alg == "none":                      # 故意 Vulnerable：接受 alg=none
        return web.Response(text="authed")
    if alg == "HS256":
        expect = _b64url_encode(hmac.new(SECRET, f"{hseg}.{pseg}".encode(),
                                         hashlib.sha256).digest())
        if sig == expect:
            return web.Response(text="authed")
        return web.Response(status=401, text="bad sig")
    return web.Response(status=401, text="unsupported")


def build_app():
    app = web.Application()
    app.router.add_get("/sqli", h_sqli)
    app.router.add_get("/sqli_bool", h_sqli_bool)
    app.router.add_get("/xss", h_xss)
    app.router.add_get("/ssrf", h_ssrf)
    app.router.add_get("/redir", h_redir)
    app.router.add_get("/cmd", h_cmd)
    app.router.add_get("/traversal", h_traversal)
    app.router.add_post("/xsspost", h_xsspost)
    app.router.add_get("/jwt", h_jwt)
    app.router.add_get("/info", h_info)
    app.router.add_get("/cors", h_cors)
    return app


# ---------- 测试体 ----------
async def run_all(base):
    cfg = Config()
    s = Scanner(cfg)
    req = s.req
    results = {}

    t = Scanner.extract_targets(base + "/sqli?id=1")[0]
    results["sqli"] = await SQLiDetector(req, cfg).scan(t)

    t = Scanner.extract_targets(base + "/xss?q=x")[0]
    results["xss"] = await XSSDetector(req, cfg).scan(t)

    t = Scanner.extract_targets(base + "/ssrf?url=http://example.com/")[0]
    results["ssrf"] = await SSRFDetector(req, cfg).scan(t)

    t = Scanner.extract_targets(base + "/redir?next=/dashboard")[0]
    results["openredirect"] = await OpenRedirectDetector(req, cfg).scan(t)

    t = Scanner.extract_targets(base + "/cmd?cmd=")[0]
    results["command_injection"] = await CommandInjectionDetector(req, cfg).scan(t)

    t = Scanner.extract_targets(base + "/traversal?file=")[0]
    results["path_traversal"] = await PathTraversalDetector(req, cfg).scan(t)

    # POST 表单 XSS：手工构造 location=body 的 Target
    post_t = Target(url=base + "/xsspost", param="q", method="POST",
                    original="", body_params={"q": ""}, location="body")
    results["xss_post"] = await XSSDetector(req, cfg).scan(post_t)

    # JWT：提供合法 token（secret=secret），端点对 alg=none 与弱密钥均脆弱
    hseg = _b64url_encode(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
    pseg = _b64url_encode(json.dumps({"user": "admin"}).encode())
    valid = hseg + "." + pseg + "." + _b64url_encode(
        hmac.new(SECRET, f"{hseg}.{pseg}".encode(), hashlib.sha256).digest())
    cfg.headers = {"Authorization": "Bearer " + valid}
    site_t = Target(url=base + "/jwt", param="", is_site=True)
    results["jwt"] = await JwtDetector(req, cfg).scan(site_t)

    # 布尔盲注：去噪后应稳定命中（旋转 CSRF token 不再干扰 baseline 比对）
    b = Scanner.extract_targets(base + "/sqli_bool?id=1")[0]
    results["bool_sqli"] = await SQLiDetector(req, cfg).scan(b)

    # 站点级：敏感信息泄露
    info_t = Target(url=base + "/info", param="", is_site=True)
    results["info_leak"] = await InfoLeakDetector(req, cfg).scan(info_t)

    # 站点级：CORS 错误配置
    cors_t = Target(url=base + "/cors", param="", is_site=True)
    results["cors"] = await CorsDetector(req, cfg).scan(cors_t)

    # 爬虫：同源链接 + 表单
    html = (
        '<html><body>'
        '<a href="/page?id=5">x</a>'
        '<a href="https://evil.com/out">y</a>'
        '<form action="/login" method="POST">'
        '<input name="user" value=""><input name="pass" value=""></form>'
        '<form action="/search" method="GET">'
        '<input name="q" value=""></form>'
        '</body></html>'
    )
    ctargets = targets_from_html(html, base + "/")
    results["crawler_params"] = sorted({t.param for t in ctargets})
    results["crawler_post"] = any(t.location == "body" for t in ctargets)

    await s.close()
    return results


def main():
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    app = build_app()
    runner = web.AppRunner(app)

    async def boot():
        await runner.setup()
        site = web.TCPSite(runner, "127.0.0.1", 0)
        await site.start()
        host, port = runner.addresses[0]
        return f"http://{host}:{port}"

    base = loop.run_until_complete(boot())
    try:
        res = loop.run_until_complete(run_all(base))
    finally:
        loop.run_until_complete(runner.cleanup())

    # 断言
    checks = {
        "sqli": len(res["sqli"]) >= 1,
        "xss": len(res["xss"]) >= 1,
        "ssrf": len(res["ssrf"]) >= 1,
        "openredirect": len(res["openredirect"]) >= 1,
        "command_injection": len(res["command_injection"]) >= 1,
        "path_traversal": len(res["path_traversal"]) >= 1,
        "xss_post": len(res["xss_post"]) >= 1,
        "jwt": len(res["jwt"]) >= 2,   # alg=none + 弱密钥 secret
        "info_leak": len(res["info_leak"]) >= 3,  # 私钥+内网IP+栈跟踪
        "cors": len(res["cors"]) >= 1,                # 反射Origin+凭据
        "bool_sqli": len(res["bool_sqli"]) >= 1,      # 布尔盲注(去噪后命中)
        "crawler_has_id": "id" in res["crawler_params"],
        "crawler_has_post": res["crawler_post"],
        "crawler_has_q": "q" in res["crawler_params"],
    }
    print("RESULTS:", {k: (len(v) if isinstance(v, list) else v)
                       for k, v in res.items()})
    failed = [k for k, ok in checks.items() if not ok]
    if failed:
        print("[FAIL]", failed)
        raise SystemExit(1)
    print("[PASS] 全部检测通过:", ", ".join(checks))
    print("[PASS] 检测器数量:", sum(len(res[k]) for k in
          ["sqli", "xss", "ssrf", "openredirect", "command_injection",
           "path_traversal", "jwt", "xss_post", "info_leak", "cors",
           "bool_sqli"]))


def test_denoise():
    """去噪模块单测：证明随机变量被剥离、真实差异保留。"""
    # 1) 仅差一个旋转 CSRF token -> 去噪后应完全相同
    a = "<html>welcome guest <input name=csrf value=abc123def456></html>"
    b = "<html>welcome guest <input name=csrf value=zzz999yyy888></html>"
    assert normalized_similar(a, b) == 1.0, "CSRF token 抖动应被去噪消除"

    # 2) 真实 DB 报错文本应保留（不被误当成噪声），故两响应不相似
    normal = "<html>welcome guest <input name=csrf value=abc></html>"
    errored = normal + " You have an error in your SQL syntax near '1'"
    assert normalized_similar(normal, errored) < 0.9, "报错文本不应被去噪抹掉"

    # 3) JWT / UUID / 时间戳 / 哈希 等被替换为占位符
    raw = ('auth: eyJhbGc.eyJ1c2.S.x; '
           'sid=3f2a11b9-4c5d-4e6f-8a9b-0c1d2e3f4a5b; '
           'at=2026-09-01T10:00:00; '
           'h=9f86d081884c7d659a2feaa0c55ad015')
    n = normalize_body(raw)
    assert "<JWT>" in n and "<UUID>" in n and "<TS>" in n and "<H32>" in n, n

    # 4) 易变响应头被丢弃
    hdrs = {"Content-Type": "text/html", "Set-Cookie": "sid=1", "Date": "now"}
    nh = normalize_headers(hdrs)
    assert "Set-Cookie" not in nh and "Date" not in nh and "Content-Type" in nh
    print("[PASS] test_denoise: 去噪模块单测通过")


if __name__ == "__main__":
    test_denoise()
    main()
