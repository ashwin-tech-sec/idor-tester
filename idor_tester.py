"""
IDOR Tester — Insecure Direct Object Reference Scanner
Author: Ashwin Hari | Application Security Engineer
GitHub: https://github.com/ashwin-tech-sec

DISCLAIMER: Only use this tool on applications you own or have explicit
written permission to test. Unauthorised testing is illegal.
"""

import requests
import argparse
import json
import csv
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime


# ─────────────────────────────────────────────
# Colour output helpers
# ─────────────────────────────────────────────
class Colour:
    RED    = "\033[91m"
    GREEN  = "\033[92m"
    YELLOW = "\033[93m"
    CYAN   = "\033[96m"
    RESET  = "\033[0m"
    BOLD   = "\033[1m"


def banner():
    print(f"""
{Colour.CYAN}{Colour.BOLD}
 ██╗██████╗  ██████╗ ██████╗     ████████╗███████╗███████╗████████╗███████╗██████╗
 ██║██╔══██╗██╔═══██╗██╔══██╗    ╚══██╔══╝██╔════╝██╔════╝╚══██╔══╝██╔════╝██╔══██╗
 ██║██║  ██║██║   ██║██████╔╝       ██║   █████╗  ███████╗   ██║   █████╗  ██████╔╝
 ██║██║  ██║██║   ██║██╔══██╗       ██║   ██╔══╝  ╚════██║   ██║   ██╔══╝  ██╔══██╗
 ██║██████╔╝╚██████╔╝██║  ██║       ██║   ███████╗███████║   ██║   ███████╗██║  ██║
 ╚═╝╚═════╝  ╚═════╝ ╚═╝  ╚═╝       ╚═╝   ╚══════╝╚══════╝   ╚═╝   ╚══════╝╚═╝  ╚═╝
{Colour.RESET}
{Colour.YELLOW} Insecure Direct Object Reference Scanner{Colour.RESET}
{Colour.YELLOW} Author: Ashwin Hari | github.com/ashwin-tech-sec{Colour.RESET}
{Colour.RED} Only test applications you are authorised to test.{Colour.RESET}
""")


# ─────────────────────────────────────────────
# Core scanner
# ─────────────────────────────────────────────
class IDORTester:
    def __init__(self, args):
        self.base_url   = args.url.rstrip("/")
        self.start      = args.start
        self.end        = args.end
        self.method     = args.method.upper()
        self.cookies    = self._parse_cookies(args.cookies)
        self.headers    = self._parse_headers(args.headers)
        self.auth_token = args.token
        self.threads    = args.threads
        self.output     = args.output
        self.verbose    = args.verbose
        self.findings   = []

        if self.auth_token:
            self.headers["Authorization"] = f"Bearer {self.auth_token}"

    def _parse_cookies(self, cookie_str):
        if not cookie_str:
            return {}
        cookies = {}
        for pair in cookie_str.split(";"):
            pair = pair.strip()
            if "=" in pair:
                k, v = pair.split("=", 1)
                cookies[k.strip()] = v.strip()
        return cookies

    def _parse_headers(self, header_str):
        if not header_str:
            return {}
        headers = {}
        for pair in header_str.split(";"):
            pair = pair.strip()
            if ":" in pair:
                k, v = pair.split(":", 1)
                headers[k.strip()] = v.strip()
        return headers

    def _build_url(self, object_id):
        if "{id}" in self.base_url:
            return self.base_url.replace("{id}", str(object_id))
        return f"{self.base_url}/{object_id}"

    def _test_single(self, object_id):
        url = self._build_url(object_id)
        try:
            response = requests.request(
                method=self.method,
                url=url,
                cookies=self.cookies,
                headers=self.headers,
                timeout=10,
                allow_redirects=False,
            )
            return {
                "id":     object_id,
                "url":    url,
                "status": response.status_code,
                "length": len(response.content),
            }
        except requests.exceptions.RequestException as e:
            if self.verbose:
                print(f"{Colour.RED}  [ERROR] ID {object_id}: {e}{Colour.RESET}")
            return None

    def _classify(self, result):
        status = result["status"]
        if status == 200:
            return "ACCESSIBLE"
        elif status == 403:
            return "FORBIDDEN"
        elif status == 401:
            return "UNAUTHORISED"
        elif status == 404:
            return "NOT_FOUND"
        elif status in (301, 302):
            return "REDIRECT"
        else:
            return f"OTHER_{status}"

    def run(self):
        banner()
        total = self.end - self.start + 1
        print(f"{Colour.CYAN}[*] Target:    {self.base_url}{Colour.RESET}")
        print(f"{Colour.CYAN}[*] ID range:  {self.start} → {self.end} ({total} requests){Colour.RESET}")
        print(f"{Colour.CYAN}[*] Method:    {self.method}{Colour.RESET}")
        print(f"{Colour.CYAN}[*] Threads:   {self.threads}{Colour.RESET}\n")

        ids = range(self.start, self.end + 1)

        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {executor.submit(self._test_single, i): i for i in ids}
            for future in as_completed(futures):
                result = future.result()
                if result is None:
                    continue

                classification = self._classify(result)
                result["classification"] = classification

                if classification == "ACCESSIBLE":
                    print(
                        f"{Colour.GREEN}  [ACCESSIBLE]{Colour.RESET} "
                        f"ID {result['id']:>6}  →  {result['url']}  "
                        f"[{result['status']}] [{result['length']} bytes]"
                    )
                    self.findings.append(result)
                elif self.verbose:
                    colour = Colour.YELLOW if classification == "FORBIDDEN" else Colour.RESET
                    print(
                        f"{colour}  [{classification}]{Colour.RESET} "
                        f"ID {result['id']:>6}  →  {result['url']}  [{result['status']}]"
                    )

        self._print_summary()

        if self.output:
            self._save_output()

    def _print_summary(self):
        print(f"\n{Colour.BOLD}{'─' * 60}{Colour.RESET}")
        print(f"{Colour.BOLD} Summary{Colour.RESET}")
        print(f"{'─' * 60}")
        print(f"  Accessible resources found: {Colour.GREEN}{len(self.findings)}{Colour.RESET}")
        if self.findings:
            print(f"\n  {Colour.YELLOW}Accessible IDs:{Colour.RESET}")
            for f in self.findings:
                print(f"    → {f['url']}  [{f['status']}] [{f['length']} bytes]")
        print(f"{'─' * 60}\n")

    def _save_output(self):
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        if self.output.endswith(".json"):
            filename = self.output
            with open(filename, "w") as f:
                json.dump(self.findings, f, indent=2)
        elif self.output.endswith(".csv"):
            filename = self.output
            with open(filename, "w", newline="") as f:
                writer = csv.DictWriter(f, fieldnames=["id", "url", "status", "length", "classification"])
                writer.writeheader()
                writer.writerows(self.findings)
        else:
            filename = f"idor_results_{timestamp}.json"
            with open(filename, "w") as f:
                json.dump(self.findings, f, indent=2)

        print(f"{Colour.CYAN}[*] Results saved to: {filename}{Colour.RESET}\n")


# ─────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────
def parse_args():
    parser = argparse.ArgumentParser(
        description="IDOR Tester — Insecure Direct Object Reference Scanner",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog="""
Examples:
  Basic scan:
    python idor_tester.py -u http://localhost:5000/api/users/{id} -s 1 -e 100

  With session cookie:
    python idor_tester.py -u http://localhost:5000/api/invoices/{id} -s 1 -e 200 -c "session=abc123"

  With Bearer token, verbose, save to JSON:
    python idor_tester.py -u http://localhost:5000/api/orders/{id} -s 1 -e 50 -t "eyJ..." -v -o results.json

  With custom headers:
    python idor_tester.py -u http://localhost:5000/api/users/{id} -s 1 -e 100 -H "X-User-ID: 5; Accept: application/json"
        """
    )
    parser.add_argument("-u", "--url",     required=True,  help="Target URL. Use {id} as placeholder e.g. http://target.com/api/users/{id}")
    parser.add_argument("-s", "--start",   required=True,  type=int, help="Start of ID range")
    parser.add_argument("-e", "--end",     required=True,  type=int, help="End of ID range")
    parser.add_argument("-m", "--method",  default="GET",  help="HTTP method (default: GET)")
    parser.add_argument("-c", "--cookies", default=None,   help="Cookies as string e.g. 'session=abc; csrf=xyz'")
    parser.add_argument("-t", "--token",   default=None,   help="Bearer token for Authorization header")
    parser.add_argument("-H", "--headers", default=None,   help="Custom headers e.g. 'X-User-ID: 5; Accept: application/json'")
    parser.add_argument("-T", "--threads", default=10,     type=int, help="Number of threads (default: 10)")
    parser.add_argument("-o", "--output",  default=None,   help="Output file (.json or .csv)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Show all responses, not just accessible ones")
    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()
    tester = IDORTester(args)
    tester.run()
