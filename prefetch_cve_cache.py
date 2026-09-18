#!/usr/bin/env python3
"""
prefetch_cve_cache.py — CyberSentinel AI / SIH26153

Run this ONCE while your machine has internet access:

    python3 prefetch_cve_cache.py

It fetches real NVD CVE data for every MITRE technique keyword the
CVE-match agent (cybersentinel_skeleton.py) can ever look up, and saves
them to cve_cache.json. After that, nvd_cve_lookup() reads from the cache
first and never needs a live network call — so the Streamlit demo's CVE
panel keeps working even fully offline / air-gapped, satisfying SIH26153's
"the interface must run fully offline without cloud API dependencies"
requirement for the working demonstration interface.

Safe to re-run any time: already-cached keywords are skipped, so this only
ever fetches what's missing. Respects NVD's public (no API key) rate limit
of roughly 5 requests / 30 seconds with a 1.5s delay between calls — with
~38 keywords this takes about a minute.
"""
import time

from cybersentinel_skeleton import (CVE_CACHE_PATH, TECHNIQUE_NVD_KEYWORDS,
                                     _load_cve_cache, nvd_cve_lookup)


def main():
    cache = _load_cve_cache()
    keywords = sorted(set(TECHNIQUE_NVD_KEYWORDS.values()))
    already_cached = sum(1 for kw in keywords if kw in cache)

    print(f"[Prefetch] {len(keywords)} unique technique keywords "
          f"({already_cached} already cached)")
    print(f"[Prefetch] Cache file: {CVE_CACHE_PATH}\n")

    fetched, empty, skipped = 0, 0, 0
    for i, kw in enumerate(keywords, 1):
        if kw in cache:
            print(f"  [{i:2d}/{len(keywords)}] cached   : {kw}")
            skipped += 1
            continue
        results = nvd_cve_lookup(kw, max_results=3)   # caches internally on success
        if results:
            print(f"  [{i:2d}/{len(keywords)}] fetched  : {kw}  "
                  f"({len(results)} CVE{'s' if len(results) != 1 else ''})")
            fetched += 1
        else:
            print(f"  [{i:2d}/{len(keywords)}] EMPTY    : {kw}  "
                  f"(no NVD matches, or offline/rate-limited — will retry next run)")
            empty += 1
        time.sleep(1.5)

    print(f"\n[Prefetch] fetched={fetched}  already-cached={skipped}  empty/failed={empty}")
    if empty > 0:
        print("[Prefetch] Some keywords came back empty — if that's because you were")
        print("[Prefetch] offline or rate-limited (not because NVD genuinely has zero")
        print("[Prefetch] matches), just re-run this script once you have a connection;")
        print("[Prefetch] already-cached keywords are skipped so it only fills gaps.")
    print("[Prefetch] Done. The Streamlit CVE panel will now work fully offline.")


if __name__ == "__main__":
    main()
