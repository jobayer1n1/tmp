import json
import zipfile
import shutil
import csv
from pathlib import Path
from typing import Dict, Set, List, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed
from threading import Lock

# ============================================================
# Risk mapping (Improved)
# ============================================================
HIGHEST_HOST_PATTERNS = {
    "<all_urls>", "*://*/*", "http://*/*", "https://*/*",
    "*://*/*/*", "http://*/*/*", "https://*/*/*",
}

HIGH_RISK = {
    "debugger", "nativeMessaging", "history", "proxy", "tabs", "webNavigation",
    "downloads", "downloads.open", "audioCapture", "videoCapture", "tabCapture",
    "pageCapture", "privacy", "vpnProvider", "socket", "usb", "usbDevices", "hid",
    "experimental", "declarativeNetRequest", "declarativeWebRequest", "browsingData",
    "contentSettings", "content_security_policy", "copresence", "unsafe-eval",
    "web_accessible_resources", "app.window.fullscreen.overrideEsc",
    "scripting", "declarativeNetRequestWithHostAccess", "userScripts",
    "webAuthenticationProxy",
}

MEDIUM_RISK = {
    "activeTab", "bookmarks", "clipboardRead", "clipboardWrite", "contextMenus",
    "cookies", "desktopCapture", "fileSystem", "fileSystem.directory",
    "fileSystem.retainEntries", "fileSystem.write", "fileSystem.writeDirectory",
    "geolocation", "identity", "identity.email", "management", "processes",
    "sessions", "syncFileSystem", "system.storage", "topSites", "tts",
    "webRequest", "webRequestBlocking", "offscreen", "sidePanel", "favicon",
    # Newly added modern permissions
    "search", "tabGroups", "commands", "declarativeNetRequestFeedback", "windows",
}

LOW_RISK = {
    "alarms", "background", "storage", "unlimitedStorage", "notifications",
    "idle", "gcm", "declarativeContent", "fontSettings", "power",
    "accessibilityFeatures.modify", "accessibilityFeatures.read",
    "certificateProvider", "documentScan", "enterprise.deviceAttributes",
    "enterprise.hardwarePlatform", "enterprise.platformKeys",
    "externally_connectable", "fileBrowserHandler", "fileSystemProvider",
    "homepage_url", "mediaGalleries", "networking.config",
    "overrideEscFullscreen", "platformKeys", "printerProvider",
    "signedInDevices", "system.memory", "system.cpu", "system.display",
    "ttsEngine", "wallpaper", "webview", "alwaysOnTopWindows",
    "app.window.alpha", "app.window.alwaysOnTop", "app.window.fullscreen",
    "app.window.shape",
}

WEIGHTS = {
    "highest_host": 45,
    "high": 18,
    "medium": 8,
    "low": 2,
    "unknown": 7,
}

COMBINATION_BONUSES = [
    ({"tabs"}, 12, "tabs + broad host"),
    ({"cookies"}, 15, "cookies + broad host"),
    ({"scripting", "userScripts"}, 15, "scripting + broad host"),
    ({"webRequest", "webRequestBlocking"}, 12, "webRequest + broad host"),
    ({"webNavigation"}, 10, "webNavigation + broad host"),
    ({"history"}, 12, "history + broad host"),
    ({"declarativeNetRequest", "declarativeNetRequestWithHostAccess"}, 10, "DNR + broad host"),
    ({"debugger"}, 20, "debugger + broad host"),
]

EXTRA_COMBOS = [
    ({"cookies", "tabs"}, 8, "cookies + tabs + broad host"),
    ({"scripting", "tabs"}, 10, "scripting + tabs + broad host"),
    ({"scripting", "cookies"}, 10, "scripting + cookies + broad host"),
]

GENERIC_HIGH_RISK_BONUS = 8

# ============================================================
# Config
# ============================================================
MAX_WORKERS = 6
print_lock = Lock()


def is_broad_host(perm: str) -> bool:
    p = perm.lower().strip()
    if p in HIGHEST_HOST_PATTERNS:
        return True
    if p.startswith("*://") or p.startswith("http://*") or p.startswith("https://*"):
        return True
    if "<all_urls>" in p:
        return True
    return False


def is_site_specific_host(perm: str) -> bool:
    """
    Returns True for host permissions that are NOT broad
    (e.g. https://www.youtube.com/*, *://chatgpt.com/*, file:///*)
    """
    p = perm.lower().strip()
    if is_broad_host(p):
        return False
    # Looks like a host / match pattern
    if ("://" in p or p.startswith("*") or p.endswith("/*") or
        p.startswith("http") or p.startswith("file:") or p.startswith("ftp:")):
        return True
    return False


def score_manifest(manifest_path: Path, extension_id: str) -> Dict:
    data = json.loads(manifest_path.read_text(encoding="utf-8", errors="ignore"))

    perms: Set[str] = set()
    for key in ["permissions", "optional_permissions",
                "host_permissions", "optional_host_permissions"]:
        value = data.get(key)
        if isinstance(value, list):
            perms.update(str(p) for p in value)

    for cs in data.get("content_scripts", []) or []:
        for m in cs.get("matches", []) or []:
            perms.add(str(m))

    highest, high, medium, low, unknown = [], [], [], [], []
    score = 0
    has_broad_host = False

    for p in perms:
        if is_broad_host(p):
            highest.append(p)
            score += WEIGHTS["highest_host"]
            has_broad_host = True
        elif p in HIGH_RISK:
            high.append(p)
            score += WEIGHTS["high"]
        elif p in MEDIUM_RISK:
            medium.append(p)
            score += WEIGHTS["medium"]
        elif p in LOW_RISK or is_site_specific_host(p):
            # Site-specific host permissions are now treated as Low risk
            low.append(p)
            score += WEIGHTS["low"]
        else:
            unknown.append(p)
            score += WEIGHTS["unknown"]

    # Combination scoring
    combination_hits: List[str] = []
    matched_high_risk: Set[str] = set()

    if has_broad_host:
        for required, bonus, desc in COMBINATION_BONUSES:
            if required & perms:
                score += bonus
                combination_hits.append(desc)
                matched_high_risk.update(required & perms)

        for required, bonus, desc in EXTRA_COMBOS:
            if required.issubset(perms):
                score += bonus
                combination_hits.append(desc)

        remaining_high = (set(high) | (HIGH_RISK & perms)) - matched_high_risk
        for p in sorted(remaining_high):
            score += GENERIC_HIGH_RISK_BONUS
            combination_hits.append(f"{p} + broad host (generic)")

    score = min(score, 100)

    if score >= 75 or (has_broad_host and (high or "cookies" in perms or "scripting" in perms)):
        risk_label = "Critical"
    elif score >= 45:
        risk_label = "High"
    elif score >= 22:
        risk_label = "Medium"
    else:
        risk_label = "Low"

    return {
        "extension_id": extension_id,
        "manifest_version": data.get("manifest_version"),
        "score": score,
        "risk_label": risk_label,
        "has_broad_host": has_broad_host,
        "highest_host_permissions": highest,
        "high_risk": high,
        "medium_risk": medium,
        "low_risk": low,
        "unknown": unknown,
        "dangerous_combinations": combination_hits,
        "all_permissions": sorted(list(perms)),
        "has_content_scripts": bool(data.get("content_scripts")),
    }


def extract_crx(crx_path: Path, extract_to: Path) -> bool:
    try:
        with zipfile.ZipFile(crx_path, 'r') as z:
            z.extractall(extract_to)
        return True
    except zipfile.BadZipFile:
        try:
            data = crx_path.read_bytes()
            zip_start = data.find(b'PK\x03\x04')
            if zip_start == -1:
                return False
            temp_zip = extract_to.parent / f"{crx_path.stem}_temp.zip"
            temp_zip.write_bytes(data[zip_start:])
            with zipfile.ZipFile(temp_zip, 'r') as z:
                z.extractall(extract_to)
            temp_zip.unlink(missing_ok=True)
            return True
        except Exception:
            return False


def process_one_crx(crx: Path, unpack_dir: Path) -> Dict:
    ext_id = crx.stem
    target = unpack_dir / ext_id
    try:
        if target.exists():
            shutil.rmtree(target, ignore_errors=True)
        target.mkdir(exist_ok=True)

        success = extract_crx(crx, target)
        if not success:
            return {"extension_id": ext_id, "error": "Failed to extract CRX"}

        manifest = target / "manifest.json"
        if not manifest.exists():
            return {"extension_id": ext_id, "error": "No manifest.json"}

        return score_manifest(manifest, ext_id)
    except Exception as e:
        return {"extension_id": ext_id, "error": str(e)}


def main():
    # ====================== PATHS ======================
    script_dir = Path(__file__).parent
    crx_dir = script_dir / 'zip'
    unpack_dir = script_dir / 'unzip'
    results_dir = script_dir / 'results' / 'permission' 
    # crx_dir = Path(r"/home/akm/Documents/Static Analysis/downloaded_crx_no_dashboard_no_link")
    # unpack_dir = crx_dir / "unpacked"
    # results_dir = Path(r"/home/akm/Documents/Static Analysis/results_no_dashboard_no_link/permissions")
    # ===================================================

    unpack_dir.mkdir(exist_ok=True)
    results_dir.mkdir(parents=True, exist_ok=True)

    crx_files = list(crx_dir.glob("*.crx"))
    total = len(crx_files)
    print(f"Found {total} CRX files")
    print(f"Using {MAX_WORKERS} parallel workers\n")

    results = []
    completed = 0

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        future_to_crx = {
            executor.submit(process_one_crx, crx, unpack_dir): crx
            for crx in crx_files
        }

        for future in as_completed(future_to_crx):
            result = future.result()
            results.append(result)
            completed += 1

            with print_lock:
                if "error" in result:
                    print(f"[{completed:03d}/{total}] {result['extension_id']} → ERROR: {result['error']}")
                else:
                    combos = ", ".join(result.get("dangerous_combinations", []))
                    print(f"[{completed:03d}/{total}] {result['extension_id']} → "
                          f"Score: {result['score']:3d} | {result['risk_label']:8s} | "
                          f"Broad: {result['has_broad_host']}")
                    if combos:
                        print(f"           Combinations: {combos}")

    # ========== Save JSON ==========
    out_json = results_dir / "permission_risk_results.json"
    with open(out_json, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)
    print(f"\n[OK] JSON saved → {out_json}")

    # ========== Save CSV ==========
    out_csv = results_dir / "permission_risk_results.csv"
    valid_results = [r for r in results if "score" in r]

    if not valid_results:
        print("[WARNING] No valid results found. CSV will not be created.")
    else:
        fieldnames = [
            "extension_id", "manifest_version", "score", "risk_label",
            "has_broad_host", "dangerous_combinations",
            "highest_host_permissions", "high_risk", "medium_risk",
            "unknown", "has_content_scripts", "all_permissions"
        ]

        with open(out_csv, "w", newline="", encoding="utf-8-sig") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()

            for r in sorted(valid_results, key=lambda x: x["score"], reverse=True):
                row = {
                    "extension_id": r.get("extension_id", ""),
                    "manifest_version": r.get("manifest_version", ""),
                    "score": r.get("score", ""),
                    "risk_label": r.get("risk_label", ""),
                    "has_broad_host": r.get("has_broad_host", ""),
                    "dangerous_combinations": " | ".join(r.get("dangerous_combinations", [])),
                    "highest_host_permissions": " | ".join(r.get("highest_host_permissions", [])),
                    "high_risk": " | ".join(r.get("high_risk", [])),
                    "medium_risk": " | ".join(r.get("medium_risk", [])),
                    "unknown": " | ".join(r.get("unknown", [])),
                    "has_content_scripts": r.get("has_content_scripts", False),
                    "all_permissions": " | ".join(r.get("all_permissions", [])),
                }
                writer.writerow(row)

        print(f"[OK] CSV saved → {out_csv}")

    # ========== Summary ==========
    print("\n" + "=" * 100)
    print(f"{'Extension ID':<40} {'Score':>6} {'Risk':<10} {'Broad':<7} Combinations")
    print("=" * 100)

    for r in sorted(valid_results, key=lambda x: x["score"], reverse=True)[:30]:  # show top 30 only
        combos = ", ".join(r.get("dangerous_combinations", []))[:55]
        print(f"{r['extension_id']:<40} {r['score']:>6} {r['risk_label']:<10} "
              f"{str(r['has_broad_host']):<7} {combos}")

    print("=" * 100)
    print(f"\nCritical : {sum(1 for r in valid_results if r['risk_label'] == 'Critical')}")
    print(f"High     : {sum(1 for r in valid_results if r['risk_label'] == 'High')}")
    print(f"Medium   : {sum(1 for r in valid_results if r['risk_label'] == 'Medium')}")
    print(f"Low      : {sum(1 for r in valid_results if r['risk_label'] == 'Low')}")


if __name__ == "__main__":
    main()