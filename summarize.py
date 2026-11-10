"""Median of each figure across the runs in runs/*.json, printed as the table used in the paper."""
import glob
import json
import statistics

runs = [json.load(open(p)) for p in sorted(glob.glob("runs/run*.json"))]
print(f"{len(runs)} runs, {runs[0]['openssl']}, Python {runs[0]['python']}")
print(f"SHA-256 of 1 MiB image: {statistics.median(r['sha256_1MiB_us'] for r in runs) / 1000:.2f} ms")
print(f"RSA-3072 + ML-DSA-65 check incl. hash: "
      f"{statistics.median(r['dual_check_rsa3072_mldsa65_incl_hash_us'] for r in runs) / 1000:.2f} ms")
print(f"{'scheme':<20}{'pk bytes':>10}{'sig bytes':>11}{'verify ms':>11}")
for i, row in enumerate(runs[0]["rows"]):
    if "verify_us" not in row:
        continue
    t = statistics.median(r["rows"][i]["verify_us"] for r in runs) / 1000
    print(f"{row['scheme']:<20}{row['pk_bytes']:>10}{row['sig_bytes']:>11}{t:>11.2f}")
print("acceptance checks consistent across runs:",
      all(r["acceptance_checks"] == runs[0]["acceptance_checks"] for r in runs), runs[0]["acceptance_checks"])
