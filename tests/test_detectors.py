"""
真实可运行测试：起一个本地漏洞模拟服务，跑 probekit 全部检测器并断言命中。

运行：  python tests/test_detectors.py
（需 aiohttp：pip install -r requirements.txt）
"""
import asyncio
import sys

from aiohttp import web

from probekit.config import Config
from probekit.engine import Scanner
from probekit.models import Finding

# ---------- 漏洞模拟服务 ----------
async def h_sqli(request):
    qid = request.query.get("id", "1")
    if "'" in qid:
        return web.Response(text="You have an error in your SQL syntax near ''",
                            status=500)
    if "1=2" in qid:
        return web.Response(text="<html>no rows</html>")
    return web.Response(text="<html>user: alice</html>")

async def h_xss(request):
    q = request.query.get("q", "")
    return web.Response(text=f"<html>search: {q}</html>")

async def h_ssrf(request):
    url = request.query.get("url", "")
    if "169.254.169.254" in url:
        return web.Response(text="MOCK_METADATA:ami-id i-0123")
    return web.Response(text="fetched external ok")

async def h_redir(request):
    nxt = request.query.get("next", "")
    if nxt.startswith("//") or nxt.startswith("http"):
        raise web.HTTPFound(nxt)
    return web.Response(text="<html>home</html>")

def make_app():
    app = web.Application()
    app.router.add_get("/sqli", h_sqli)
    app.router.add_get("/xss", h_xss)
    app.router.add_get("/ssrf", h_ssrf)
    app.router.add_get("/redir", h_redir)
    return app

# ---------- 断言 ----------
def assert_find(findings, detector):
    names = {f.detector for f in findings}
    assert detector in names, f"未检测到 {detector}，实际: {names}"

async def main():
    app = make_app()
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, "127.0.0.1", 0)
    await site.start()
    port = runner.addresses[0][1]
    base = f"http://127.0.0.1:{port}"

    cfg = Config(follow_redirects=False, timeout=5, concurrency=5)
    scanner = Scanner(cfg)

    cases = {
        "sqli":  f"{base}/sqli?id=1",
        "xss":   f"{base}/xss?q=hi",
        "ssrf":  f"{base}/ssrf?url=http://example.com/",
        "openredirect": f"{base}/redir?next=home",
    }

    ok = True
    for name, url in cases.items():
        findings = await scanner.scan_url(url)
        try:
            assert_find(findings, name)
            print(f"[PASS] {name}: 检测到 {[f.detector for f in findings]}")
        except AssertionError as e:
            ok = False
            print(f"[FAIL] {name}: {e}")

    await scanner.close()
    await runner.cleanup()
    print("\n结果:", "全部通过" if ok else "存在失败")
    return 0 if ok else 1

if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
