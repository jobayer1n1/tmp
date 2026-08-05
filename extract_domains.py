import re
import json
import csv
from pathlib import Path
from typing import Set, Dict, List
from concurrent.futures import ThreadPoolExecutor, as_completed
from threading import Lock
import tldextract

# ============================================================
# Config
# ============================================================
MAX_WORKERS = 8          # Good starting point for I/O-heavy work
print_lock = Lock()

# ============================================================
# Regex patterns
# ============================================================
URL_PATTERN = re.compile(
    r'''(?i)\b((?:https?|ftp|ws|wss)://[^\s"'<>\\]+)|(?:www\.[^\s"'<>\\]+)'''
)

NAKED_HOST_PATTERN = re.compile(
    r'''(?:["'`<>])\s*((?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,18})\s*(?:["'`<>])''',
    re.IGNORECASE
)

IP_PATTERN = re.compile(
    r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
)

IGNORE_PREFIXES = (
    "chrome-extension://",
    "chrome://",
    "moz-extension://",
    "resource://",
    "data:",
    "blob:",
    "filesystem:",
    "about:",
    "javascript:",
    "file://",
)

IGNORE_DOMAINS = {
    "localhost",
    "127.0.0.1",
    "0.0.0.0",
    "example.com",
    "example.org",
    "test.com",
}

FILE_EXTENSIONS = ('.js', '.json', '.html', '.htm', '.png', '.jpg', '.jpeg', '.css', '.md', '.svg', '.gif', '.ts')


def is_noise(url_or_domain: str) -> bool:
    lower = url_or_domain.lower()
    for prefix in IGNORE_PREFIXES:
        if lower.startswith(prefix):
            return True
    return False


def extract_domain(url: str) -> str:
    try:
        ext = tldextract.extract(url)
        if ext.domain and ext.suffix:
            if len(ext.domain) <= 1 or ext.suffix.isdigit():
                return ""
            return f"{ext.domain}.{ext.suffix}".lower()
    except Exception:
        pass
    return ""


def extract_from_text(text: str) -> Dict[str, Set[str]]:
    urls = set()
    domains = set()
    ips = set()

    # 1. Explicit URLs
    for match in URL_PATTERN.findall(text):
        url = match.strip().rstrip('.,;)"\'>')
        if not url or is_noise(url):
            continue
        if url.startswith("www."):
            url = "http://" + url
        urls.add(url)
        domain = extract_domain(url)
        if domain and domain not in IGNORE_DOMAINS:
            domains.add(domain)

    # 2. Naked hostnames inside quotes
    for host in NAKED_HOST_PATTERN.findall(text):
        host_lower = host.strip().lower()
        if host_lower.endswith(FILE_EXTENSIONS):
            continue
        if any(char in host_lower for char in ('(', ')', '[', ']', '$', '{', '}', '=', '+', '/', '\\', ',')):
            continue
        domain = extract_domain(f"http://{host_lower}")
        if domain and domain not in IGNORE_DOMAINS:
            domains.add(domain)

    # 3. IPs
    for ip in IP_PATTERN.findall(text):
        if ip not in ("127.0.0.1", "0.0.0.0"):
            ips.add(ip)

    return {
        "urls": urls,
        "domains": domains,
        "ips": ips
    }


def parse_manifest_permissions(manifest_path: Path) -> Set[str]:
    domains = set()
    try:
        with open(manifest_path, "r", encoding="utf-8", errors="ignore") as f:
            data = json.load(f)
            permissions = []
            if "permissions" in data and isinstance(data["permissions"], list):
                permissions.extend(data["permissions"])
            if "host_permissions" in data and isinstance(data["host_permissions"], list):
                permissions.extend(data["host_permissions"])

            for item in permissions:
                if isinstance(item, str):
                    clean_item = item.replace("*.", "").replace("*", "")
                    if clean_item in ("", "<all_urls>"):
                        continue
                    if not is_noise(clean_item):
                        domain = extract_domain(clean_item if "://" in clean_item else f"http://{clean_item}")
                        if domain and domain not in IGNORE_DOMAINS:
                            domains.add(domain)

            csp = data.get("content_security_policy", "")
            if isinstance(csp, dict):
                csp = " ".join(csp.values())
            if isinstance(csp, str):
                res = extract_from_text(csp)
                domains.update(res["domains"])
    except Exception:
        pass
    return domains


def analyze_extension(ext_dir: Path) -> Dict:
    all_urls = set()
    all_domains = set()
    all_ips = set()

    extensions_to_scan = {".js", ".html", ".htm", ".json", ".css", ".txt", ".md", ".svg"}

    # 1. Parse manifest
    manifest_file = ext_dir / "manifest.json"
    if manifest_file.exists():
        all_domains.update(parse_manifest_permissions(manifest_file))

    # 2. Scan files
    for file_path in ext_dir.rglob("*"):
        if not file_path.is_file():
            continue
        if file_path.suffix.lower() not in extensions_to_scan:
            continue
        try:
            text = file_path.read_text(encoding="utf-8", errors="ignore")
            result = extract_from_text(text)
            all_urls.update(result["urls"])
            all_domains.update(result["domains"])
            all_ips.update(result["ips"])
        except Exception:
            continue

    return {
        "extension_id": ext_dir.name,
        "urls": sorted(list(all_urls)),
        "domains": sorted(list(all_domains)),
        "ips": sorted(list(all_ips)),
        "url_count": len(all_urls),
        "domain_count": len(all_domains),
        "ip_count": len(all_ips),
    }


def main():
    base_dir = Path(__file__).parent
    unpacked_dir = base_dir / "unzip"
    results_dir = base_dir / 'results' / 'domain'

    results_dir.mkdir(parents=True, exist_ok=True)

    if not unpacked_dir.exists():
        print("Unpacked directory not found.")
        return

    ext_folders = [d for d in unpacked_dir.iterdir() if d.is_dir()]
    total = len(ext_folders)
    print(f"Found {total} extensions")
    print(f"Using {MAX_WORKERS} parallel workers\n")

    results = []
    completed = 0

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        future_to_ext = {
            executor.submit(analyze_extension, ext_dir): ext_dir
            for ext_dir in ext_folders
        }

        for future in as_completed(future_to_ext):
            result = future.result()
            results.append(result)
            completed += 1

            with print_lock:
                if result["domains"]:
                    preview = ", ".join(result["domains"][:5])
                    extra = " ..." if result["domain_count"] > 5 else ""
                    print(f"[{completed:03d}/{total}] {result['extension_id']} → "
                          f"Domains ({result['domain_count']}): {preview}{extra}")
                else:
                    print(f"[{completed:03d}/{total}] {result['extension_id']} → No external domains found")

    # ===== Save full JSON =====
    out_json = results_dir / "domain_extraction_results.json"
    with open(out_json, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)
    print(f"\n[OK] Full results saved → {out_json}")

    # ===== Save Summary CSV =====
    out_csv = results_dir / "domain_extraction_summary.csv"
    with open(out_csv, "w", newline="", encoding="utf-8-sig") as f:
        writer = csv.DictWriter(f, fieldnames=[
            "extension_id", "domain_count", "url_count", "ip_count", "domains", "ips"
        ])
        writer.writeheader()
        for r in sorted(results, key=lambda x: x["domain_count"], reverse=True):
            writer.writerow({
                "extension_id": r["extension_id"],
                "domain_count": r["domain_count"],
                "url_count": r["url_count"],
                "ip_count": r["ip_count"],
                "domains": " | ".join(r["domains"]),
                "ips": " | ".join(r["ips"]),
            })
    print(f"[OK] Summary CSV saved → {out_csv}")

    # ===== Stats =====
    total_with_domains = sum(1 for r in results if r["domain_count"] > 0)
    print("\n" + "=" * 60)
    print(f"Extensions with external domains : {total_with_domains} / {len(results)}")
    print("=" * 60)


if __name__ == "__main__":
    main()