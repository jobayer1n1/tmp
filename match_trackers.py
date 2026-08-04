import re
import json
import csv
from pathlib import Path
from typing import Set, Dict, List
from concurrent.futures import ThreadPoolExecutor, as_completed
from threading import Lock
import tldextract
import warnings

warnings.filterwarnings("ignore", category=UserWarning, module="requests")

# ============================================================
# Config
# ============================================================
MAX_WORKERS = 8
print_lock = Lock()

# ============================================================
# Tracking Intelligence Data
# ============================================================
STRICT_TRACKERS = {
    "google-analytics.com", "googletagmanager.com", "googleadservices.com",
    "googlesyndication.com", "doubleclick.net", "2mdn.net", "googletagservices.com",
    "scorecardresearch.com", "hotjar.com", "mixpanel.com", "amplitude.com",
    "segment.com", "segment.io", "newrelic.com", "nr-data.net", "sentry.io",
    "bugsnag.com", "fullstory.com", "mouseflow.com", "crazyegg.com",
    "optimizely.com", "chartbeat.com", "parse.ly", "parsely.com",
    "quantserve.com", "outbrain.com", "taboola.com", "criteo.com",
    "adsrvr.org", "adsafeprotected.com", "moatads.com", "openx.net",
    "pubmatic.com", "rubiconproject.com", "casalemedia.com", "adnxs.com",
    "advertising.com", "adform.net", "bidswitch.net", "smartadserver.com",
    "liadm.com", "rlcdn.com", "bluekai.com", "exelator.com", "krxd.net",
    "demdex.net", "omtrdc.net", "everesttech.net", "ads-twitter.com",
    "twitter.com", "bing.com", "amazon-adsystem.com",
    "media.net", "contextweb.com", "spotxchange.com", "stickyadstv.com",
    "sharethrough.com", "teads.tv", "triplelift.com", "yieldmo.com",
    "sonobi.com", "openx.com", "indexww.com", "districtm.io",
    "appnexus.com", "conversantmedia.com", "adcolony.com", "unity3d.com",
    "vungle.com", "chartboost.com", "ironsrc.com", "supersonicads.com",
    "tapjoy.com", "adjust.com", "appsflyer.com", "branch.io",
    "kochava.com", "tenjin.io", "singular.net", "heap.io",
    "heapanalytics.com", "kissmetrics.com", "clicktale.net", "clicktale.com",
    "logrocket.com", "rollbar.com", "raygun.io", "trackjs.com", "datadoghq.com"
}

ECOSYSTEM_DOMAINS = {
    "google.com", "googleapis.com", "gstatic.com", "ggpht.com",
    "facebook.com", "facebook.net", "fbcdn.net", "instagram.com",
    "linkedin.com", "licdn.com", "yahoo.com", "yahoo.net",
    "amazon.com", "yandex.ru", "yandex.com", "yandex.net", "vk.com", "t.co"
}

NETWORK_TRIGGERS = re.compile(
    r'\b(fetch|xmlhttprequest|xhr|ajax|\.open\(|sendbeacon|websocket|ws\s*=|connect|postmessage|\.src\s*=|\[\s*["\'\s]*src["\'\s]*\]\s*=|\.createelement|\.appendchild|\.insertbefore)\b',
    re.IGNORECASE
)


def load_extra_trackers(file_path: Path) -> Set[str]:
    extra = set()
    if file_path.exists():
        with open(file_path, encoding="utf-8") as f:
            for line in f:
                line = line.strip().lower()
                if line and not line.startswith("#"):
                    extra.add(line)
    return extra


def scan_declarative_net_request(ext_dir: Path, target_domain: str) -> bool:
    manifest_path = ext_dir / "manifest.json"
    if not manifest_path.exists():
        return False

    try:
        with open(manifest_path, "r", encoding="utf-8", errors="ignore") as f:
            manifest = json.load(f)

        dnr = manifest.get("declarative_net_request", {})
        rulesets = dnr.get("rule_resources", [])

        for resource in rulesets:
            rule_file_path = ext_dir / resource.get("path", "")
            if rule_file_path.exists() and rule_file_path.suffix.lower() == ".json":
                with open(rule_file_path, "r", encoding="utf-8", errors="ignore") as rf:
                    rules_data = json.load(rf)
                    rules_str = json.dumps(rules_data).lower()
                    if target_domain in rules_str:
                        for rule in rules_data:
                            action_type = rule.get("action", {}).get("type", "")
                            if action_type in ("redirect", "modifyHeaders"):
                                rule_dump = json.dumps(rule).lower()
                                if target_domain in rule_dump:
                                    return True
    except Exception:
        pass
    return False


def inspect_code_context(ext_dir: Path, target_domain: str) -> str:
    if scan_declarative_net_request(ext_dir, target_domain):
        return "active"

    extensions_to_scan = {".js", ".html", ".htm", ".json", ".css"}
    for file_path in ext_dir.rglob("*"):
        if not file_path.is_file() or file_path.suffix.lower() not in extensions_to_scan:
            continue
        try:
            if file_path.name == "manifest.json":
                continue
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    if target_domain in line.lower():
                        if NETWORK_TRIGGERS.search(line):
                            return "active"
        except Exception:
            continue
    return "passive"


def match_and_classify_domains(ext_dir: Path, domains: List[str],
                               strict_set: Set[str], ecosystem_set: Set[str]) -> Dict[str, List[str]]:
    active_strict = set()
    passive_strict = set()
    active_ecosystem = set()
    passive_ecosystem = set()

    for domain in domains:
        domain_lower = domain.lower()
        matched_tracker = None
        is_strict = False

        if domain_lower in strict_set:
            matched_tracker = domain_lower
            is_strict = True
        elif domain_lower in ecosystem_set:
            matched_tracker = domain_lower
        else:
            try:
                ext = tldextract.extract(f"http://{domain_lower}")
                if ext.domain and ext.suffix:
                    reg_dom = f"{ext.domain}.{ext.suffix}"
                    if reg_dom in strict_set:
                        matched_tracker = reg_dom
                        is_strict = True
                    elif reg_dom in ecosystem_set:
                        matched_tracker = reg_dom
            except Exception:
                pass

        if matched_tracker:
            context_type = inspect_code_context(ext_dir, domain_lower)

            if is_strict:
                if context_type == "active":
                    active_strict.add(domain_lower)
                else:
                    passive_strict.add(domain_lower)
            else:
                if context_type == "active":
                    active_ecosystem.add(domain_lower)
                else:
                    passive_ecosystem.add(domain_lower)

    return {
        "active_strict": sorted(list(active_strict)),
        "passive_strict": sorted(list(passive_strict)),
        "active_ecosystem": sorted(list(active_ecosystem)),
        "passive_ecosystem": sorted(list(passive_ecosystem))
    }


def process_one_extension(item: Dict, unpacked_dir: Path,
                          strict_set: Set[str], ecosystem_set: Set[str]) -> Dict:
    """Process a single extension (runs in a thread)."""
    ext_id = item["extension_id"]
    domains = item.get("domains", [])
    ext_folder_path = unpacked_dir / ext_id

    if not ext_folder_path.exists():
        return None

    report = match_and_classify_domains(ext_folder_path, domains, strict_set, ecosystem_set)

    return {
        "extension_id": ext_id,
        "total_extracted_domains": len(domains),
        "active_strict_trackers": report["active_strict"],
        "passive_strict_rules": report["passive_strict"],
        "active_ecosystem_platforms": report["active_ecosystem"],
        "passive_ecosystem_rules": report["passive_ecosystem"],
        # For summary CSV
        "_summary": {
            "extension_id": ext_id,
            "total_domains": len(domains),
            "active_strict_count": len(report["active_strict"]),
            "active_strict": " | ".join(report["active_strict"]),
            "passive_strict": " | ".join(report["passive_strict"]),
            "active_ecosystem": " | ".join(report["active_ecosystem"]),
            "passive_ecosystem": " | ".join(report["passive_ecosystem"]),
        }
    }


def main():
    base_dir = Path(r"/home/akm/Documents/Static Analysis/downloaded_crx_no_dashboard_no_link")
    unpacked_dir = base_dir / "unpacked"
    domain_results_file = Path(r"/home/akm/Documents/Static Analysis/results/domains/domain_extraction_results.json")
    extra_trackers_file = Path(r"/home/akm/Documents/Static Analysis/results/trackers/extra_trackers.txt")
    results_dir = Path(r"/home/akm/Documents/Static Analysis/results/trackers")

    results_dir.mkdir(parents=True, exist_ok=True)

    if not domain_results_file.exists():
        print(f"[ERROR] Missing: {domain_results_file}")
        return

    with open(domain_results_file, encoding="utf-8") as f:
        domain_results = json.load(f)

    strict_set = set(STRICT_TRACKERS)
    strict_set.update(load_extra_trackers(extra_trackers_file))
    ecosystem_set = set(ECOSYSTEM_DOMAINS)

    print(f"Loaded {len(strict_set)} strict tracking and {len(ecosystem_set)} ecosystem host targets.")
    print(f"Using {MAX_WORKERS} parallel workers\n")

    results = []
    summary_rows = []
    completed = 0
    total = len(domain_results)

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = {
            executor.submit(process_one_extension, item, unpacked_dir, strict_set, ecosystem_set): item
            for item in domain_results
        }

        for future in as_completed(futures):
            record = future.result()
            completed += 1

            if record is None:
                continue

            results.append({
                "extension_id": record["extension_id"],
                "total_extracted_domains": record["total_extracted_domains"],
                "active_strict_trackers": record["active_strict_trackers"],
                "passive_strict_rules": record["passive_strict_rules"],
                "active_ecosystem_platforms": record["active_ecosystem_platforms"],
                "passive_ecosystem_rules": record["passive_ecosystem_rules"],
            })
            summary_rows.append(record["_summary"])

            with print_lock:
                print(f"[{completed:05d}/{total}] {record['extension_id'][:12]}... → "
                      f"{len(record['active_strict_trackers'])} Active | "
                      f"{len(record['passive_strict_rules'])} Passive")

    # ===== Save JSON =====
    out_json = results_dir / "tracker_matching_results.json"
    with open(out_json, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)
    print(f"\n[OK] Deep validation results saved → {out_json}")

    # ===== Save CSV =====
    out_csv = results_dir / "tracker_matching_summary.csv"
    with open(out_csv, "w", newline="", encoding="utf-8-sig") as f:
        writer = csv.DictWriter(f, fieldnames=[
            "extension_id", "total_domains", "active_strict_count",
            "active_strict", "passive_strict", "active_ecosystem", "passive_ecosystem"
        ])
        writer.writeheader()
        for row in sorted(summary_rows, key=lambda x: x["active_strict_count"], reverse=True):
            writer.writerow(row)

    print(f"[OK] Summary CSV saved → {out_csv}")
    print(f"\nProcessed {len(results)} extensions successfully.")


if __name__ == "__main__":
    main()