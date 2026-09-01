"""命令行入口：python -m probekit -u http://靶场/vul?id=1"""
import argparse
import asyncio
import sys

from .config import Config
from .engine import Scanner
from .report import to_text, to_json, to_sarif


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        prog="probekit",
        description="异步 Web 漏洞启发式扫描器（仅用于已授权目标）。",
    )
    ap.add_argument("-u", "--url", help="单个目标 URL（含查询参数）")
    ap.add_argument("-f", "--file", help="包含多行 URL 的文件")
    ap.add_argument("--format", choices=["text", "json", "sarif"], default="text")
    ap.add_argument("--json-out", help="把 JSON 结果另存到此路径")
    ap.add_argument("--sarif-out", help="把 SARIF 结果另存到此路径（接 CI）")
    ap.add_argument("--crawl", action="store_true",
                    help="对目标做同源爬虫，自动发现链接与表单")
    ap.add_argument("--header", action="append", default=[], metavar="NAME:VALUE",
                    help="附加请求头（可重复），如 --header 'Authorization: Bearer xxx'")
    ap.add_argument("--no-verify-ssl", action="store_true")
    ap.add_argument("--concurrency", type=int, default=10)
    ap.add_argument("--timeout", type=float, default=10.0)
    ap.add_argument("--proxy", help="如 http://127.0.0.1:7890")
    return ap


def parse_headers(items):
    headers = {}
    for it in items:
        name, _, val = it.partition(":")
        headers[name.strip()] = val.strip()
    return headers


def main(argv=None):
    args = build_parser().parse_args(argv)
    urls = []
    if args.url:
        urls.append(args.url)
    if args.file:
        with open(args.file, encoding="utf-8") as fh:
            urls += [ln.strip() for ln in fh if ln.strip()]
    if not urls:
        print("错误：需提供 -u 或 -f。仅用于已授权目标。", file=sys.stderr)
        sys.exit(2)

    cfg = Config(
        concurrency=args.concurrency,
        timeout=args.timeout,
        proxy=args.proxy,
        verify_ssl=not args.no_verify_ssl,
        follow_redirects=False,   # 便于检测开放重定向/3xx
        headers=parse_headers(args.header),
    )

    async def run():
        s = Scanner(cfg)
        findings = await s.scan_urls(urls, crawl=args.crawl)
        await s.close()
        return findings

    findings = asyncio.run(run())

    if args.format == "json":
        print(to_json(findings))
    elif args.format == "sarif":
        print(to_sarif(findings))
    else:
        print(to_text(findings))
    if args.json_out:
        with open(args.json_out, "w", encoding="utf-8") as fh:
            fh.write(to_json(findings))
        print(f"\n[+] JSON 已保存: {args.json_out}", file=sys.stderr)
    if args.sarif_out:
        with open(args.sarif_out, "w", encoding="utf-8") as fh:
            fh.write(to_sarif(findings))
        print(f"\n[+] SARIF 已保存: {args.sarif_out}", file=sys.stderr)


if __name__ == "__main__":
    main()
