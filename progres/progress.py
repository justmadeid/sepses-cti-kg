#!/usr/bin/env python3
"""Print research-v3 progress from tracker.csv.

Usage:
  python3 research-v3/progress.py            # summary per phase + next actionable tasks
  python3 research-v3/progress.py --all      # also list every task
  python3 research-v3/progress.py --who Mahasiswa   # filter actionable tasks by owner

Edit tracker.csv (Excel/Numbers/VS Code) to change a task status:
TODO | IN-PROGRESS | MENUNGGU-BIMBINGAN | DONE | BLOCKED. Update `tanggal_update` when you do.
MENUNGGU-BIMBINGAN = draft sudah ada, menunggu keputusan pembimbing (gate G-2).
"""
from __future__ import annotations

import argparse
import csv
from collections import OrderedDict
from pathlib import Path

TRACKER = Path(__file__).resolve().parent / "tracker.csv"
STATUSES = ("DONE", "IN-PROGRESS", "MENUNGGU-BIMBINGAN", "TODO", "BLOCKED")


def bar(done: int, total: int, width: int = 20) -> str:
    filled = round(width * done / total) if total else 0
    return "█" * filled + "░" * (width - filled)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--all", action="store_true")
    ap.add_argument("--who", default="")
    args = ap.parse_args()

    rows = list(csv.DictReader(TRACKER.open(newline="", encoding="utf-8")))
    status = {r["id"]: r["status"].strip().upper() for r in rows}
    unknown = sorted({s for s in status.values() if s not in STATUSES})
    if unknown:
        print(f"! status tidak dikenal: {unknown} (gunakan {', '.join(STATUSES)})")

    phases: "OrderedDict[str, list[dict]]" = OrderedDict()
    for r in rows:
        phases.setdefault(r["fase"], []).append(r)

    total_done = sum(1 for s in status.values() if s == "DONE")
    print(f"research-v3 — {total_done}/{len(rows)} tugas selesai  {bar(total_done, len(rows))}\n")
    for phase, items in phases.items():
        done = sum(1 for r in items if status[r["id"]] == "DONE")
        wip = sum(1 for r in items if status[r["id"]] == "IN-PROGRESS")
        blk = sum(1 for r in items if status[r["id"]] == "BLOCKED")
        wait = sum(1 for r in items if status[r["id"]] == "MENUNGGU-BIMBINGAN")
        parts = [f"{wip} berjalan"] * bool(wip) + [f"{wait} menunggu bimbingan"] * bool(wait) + [f"{blk} terblokir"] * bool(blk)
        extra = f"  ({', '.join(parts)})" if parts else ""
        print(f"{phase:<22} {done:>2}/{len(items):<2} {bar(done, len(items), 12)}{extra}")

    def ready(r: dict) -> bool:
        deps = [d.strip() for d in r["dependensi"].split(";") if d.strip()]
        return status[r["id"]] in ("TODO", "IN-PROGRESS") and all(status.get(d) == "DONE" for d in deps)

    nxt = [r for r in rows if ready(r) and args.who.lower() in r["pelaksana"].lower()]
    print("\nBisa dikerjakan sekarang:")
    for r in nxt or []:
        gate = f"  [{r['catatan']}]" if r["catatan"].startswith("Gate") else ""
        print(f"  {r['id']:<8} {status[r['id']]:<11} {r['pelaksana']:<22} {r['tugas']}{gate}")
    if not nxt:
        print("  (tidak ada — cek tugas BLOCKED atau dependensi)")

    waiting = [r for r in rows if status[r["id"]] == "MENUNGGU-BIMBINGAN"]
    if waiting:
        print(f"\nMenunggu bimbingan (gate G-2): {', '.join(r['id'] for r in waiting)}")

    if args.all:
        print("\nSemua tugas:")
        for r in rows:
            print(f"  {r['id']:<8} {status[r['id']]:<18} {r.get('tahap_alur', ''):<16} {r['tugas']}")


if __name__ == "__main__":
    main()
