import json
import subprocess
import csv
from pathlib import Path
from typing import Dict, List, Set
from concurrent.futures import ThreadPoolExecutor, as_completed
from threading import Lock

# ============================================================
# Config
# ============================================================
MAX_WORKERS = 5          # Recommended: 4–6 (Semgrep is heavy)
print_lock = Lock()


def run_semgrep_on_extension(ext_dir: Path, rules_file: Path) -> List[Dict]:
    """Run Semgrep on one extension and return findings."""
    try:
        cmd = [
            "semgrep",
            "--config", str(rules_file),
            "--json",
            "--quiet",
            str(ext_dir)
        ]
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=90
        )

        if result.returncode not in (0, 1):
            return []

        data = json.loads(result.stdout)
        findings = []

        for item in data.get("results", []):
            meta = item.get("extra", {}).get("metadata", {})
            findings.append({
                "check_id": item.get("check_id"),
                "path": item.get("path"),
                "start_line": item.get("start", {}).get("line"),
                "message": item.get("extra", {}).get("message"),
                "api": meta.get("api"),
                "category": meta.get("category"),
            })
        return findings

    except subprocess.TimeoutExpired:
        return []
    except Exception:
        return []


def summarize_findings(findings: List[Dict]) -> Dict:
    """Create a clean summary from Semgrep findings."""
    apis: Set[str] = set()
    categories: Set[str] = set()

    for f in findings:
        if f.get("api"):
            apis.add(f["api"])
        if f.get("category"):
            categories.add(f["category"])

    apis_list = sorted(list(apis))
    categories_list = sorted(list(categories))

    return {
        "apis_detected": apis_list,
        "categories": categories_list,
        "total_findings": len(findings),
        "has_activity": "activity" in categories,
        "has_cookies": "cookies" in categories,
        "has_storage": "storage" in categories,
        "has_network": "network" in categories,
        "has_identity": "identity" in categories,
        "has_injection": "injection" in categories,
        "has_high_privilege": "high_privilege" in categories,
        "has_media": "media" in categories,
        "has_settings": "settings" in categories,
        "has_device": "device" in categories,
        "has_other": "other" in categories,
    }


def process_one_extension(ext_dir: Path, rules_file: Path) -> Dict:
    """Process a single extension (runs in a thread)."""
    ext_id = ext_dir.name
    findings = run_semgrep_on_extension(ext_dir, rules_file)
    summary = summarize_findings(findings)

    return {
        "extension_id": ext_id,
        **summary,
        "findings": findings
    }


def main():

    base_dir = Path(__file__).parent
    unpacked_dir = base_dir / 'unzip'
    rules_file = base_dir / 'chrome-privacy-apis.yml'
    results_dir = base_dir / 'results' / 'api_detection'
    # base_dir = Path(r"/home/akm/Documents/Static Analysis/downloaded_crx_no_dashboard_no_link")
    # unpacked_dir = base_dir / "unpacked"
    # rules_file = Path("/home/akm/Documents/Static Analysis/chrome-privacy-apis.yml")
    # results_dir = Path(r"/home/akm/Documents/Static Analysis/results/apis")

    results_dir.mkdir(parents=True, exist_ok=True)

    if not rules_file.exists():
        print(f"[ERROR] Rules file not found: {rules_file}")
        return

    if not unpacked_dir.exists():
        print(f"[ERROR] Unpacked directory not found: {unpacked_dir}")
        return

    # Check Semgrep is available
    try:
        subprocess.run(["semgrep", "--version"], capture_output=True, check=True)
    except Exception:
        print("[ERROR] Semgrep is not installed or not in PATH.")
        print("Install with: pip install semgrep")
        return

    ext_folders = [d for d in unpacked_dir.iterdir() if d.is_dir()]
    total = len(ext_folders)
    print(f"Found {total} unpacked extensions")
    print(f"Using {MAX_WORKERS} parallel workers\n")

    results = []
    completed = 0

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        future_to_ext = {
            executor.submit(process_one_extension, ext_dir, rules_file): ext_dir
            for ext_dir in ext_folders
        }

        for future in as_completed(future_to_ext):
            record = future.result()
            results.append(record)
            completed += 1

            with print_lock:
                apis = record.get("apis_detected", [])
                if apis:
                    print(f"[{completed:03d}/{total}] {record['extension_id']} → {', '.join(apis)}")
                else:
                    print(f"[{completed:03d}/{total}] {record['extension_id']} → No sensitive APIs found")

    # ===== Save full JSON =====
    out_json = results_dir / "api_detection_results.json"
    with open(out_json, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)
    print(f"\n[OK] Full results saved → {out_json}")

    # ===== Save Summary CSV =====
    out_csv = results_dir / "api_detection_summary.csv"
    fieldnames = [
        "extension_id", "total_findings", "apis_detected", "categories",
        "has_activity", "has_cookies", "has_storage", "has_network",
        "has_identity", "has_injection", "has_high_privilege",
        "has_media", "has_settings", "has_device", "has_other"
    ]

    summary_rows = []
    for r in results:
        summary_rows.append({
            "extension_id": r["extension_id"],
            "total_findings": r["total_findings"],
            "apis_detected": " | ".join(r["apis_detected"]),
            "categories": " | ".join(r["categories"]),
            "has_activity": r["has_activity"],
            "has_cookies": r["has_cookies"],
            "has_storage": r["has_storage"],
            "has_network": r["has_network"],
            "has_identity": r["has_identity"],
            "has_injection": r["has_injection"],
            "has_high_privilege": r["has_high_privilege"],
            "has_media": r["has_media"],
            "has_settings": r["has_settings"],
            "has_device": r["has_device"],
            "has_other": r["has_other"],
        })

    with open(out_csv, "w", newline="", encoding="utf-8-sig") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for row in sorted(summary_rows, key=lambda x: x["total_findings"], reverse=True):
            writer.writerow(row)

    print(f"[OK] Summary CSV saved → {out_csv}")

    # ===== Final Statistics =====
    print("\n" + "=" * 70)
    print("DETECTION SUMMARY")
    print("=" * 70)
    print(f"Total extensions analyzed     : {len(results)}")
    print(f"Extensions with any findings  : {sum(1 for r in results if r['total_findings'] > 0)}")
    print()
    print(f"Has Activity APIs             : {sum(1 for r in results if r['has_activity'])}")
    print(f"Has Cookies API               : {sum(1 for r in results if r['has_cookies'])}")
    print(f"Has Storage API               : {sum(1 for r in results if r['has_storage'])}")
    print(f"Has Network APIs              : {sum(1 for r in results if r['has_network'])}")
    print(f"Has Identity API              : {sum(1 for r in results if r['has_identity'])}")
    print(f"Has Scripting / Injection     : {sum(1 for r in results if r['has_injection'])}")
    print(f"Has High Privilege            : {sum(1 for r in results if r['has_high_privilege'])}")
    print(f"Has Media Capture             : {sum(1 for r in results if r['has_media'])}")
    print(f"Has Settings APIs             : {sum(1 for r in results if r['has_settings'])}")
    print(f"Has Device APIs               : {sum(1 for r in results if r['has_device'])}")
    print("=" * 70)


if __name__ == "__main__":
    main()