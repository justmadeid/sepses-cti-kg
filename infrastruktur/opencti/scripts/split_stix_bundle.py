#!/usr/bin/env python3
"""Sanitize and split a report-centric STIX 2.1 bundle for OpenCTI import."""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import shutil
import uuid
from collections import Counter, deque
from pathlib import Path


def stix_references(obj: dict) -> set[str]:
    references: set[str] = set()
    for key, value in obj.items():
        if key.endswith("_ref") and isinstance(value, str) and "--" in value:
            references.add(value)
        elif key.endswith("_refs") and isinstance(value, list):
            references.update(
                item for item in value if isinstance(item, str) and "--" in item
            )
    return references


def dependency_closure(seed_ids: set[str], objects_by_id: dict[str, dict]) -> set[str]:
    closure: set[str] = set()
    pending = deque(seed_ids)
    while pending:
        object_id = pending.popleft()
        if object_id in closure or object_id not in objects_by_id:
            continue
        closure.add(object_id)
        pending.extend(stix_references(objects_by_id[object_id]) - closure)
    return closure


def serialized_size(obj: dict) -> int:
    return len(json.dumps(obj, ensure_ascii=False, separators=(",", ":")).encode("utf-8"))


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("source", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--target-mib", type=int, default=48)
    parser.add_argument("--force", action="store_true")
    args = parser.parse_args()

    if args.output.exists():
        if not args.force:
            raise SystemExit(f"Output already exists: {args.output}")
        shutil.rmtree(args.output)
    args.output.mkdir(parents=True)

    source_sha256 = hashlib.sha256()
    with args.source.open("rb") as stream:
        while block := stream.read(1024 * 1024):
            source_sha256.update(block)

    with args.source.open(encoding="utf-8-sig") as stream:
        bundle = json.load(stream)
    if bundle.get("type") != "bundle" or not isinstance(bundle.get("objects"), list):
        raise SystemExit("Source is not a STIX bundle")

    objects = bundle["objects"]
    objects_by_id = {obj["id"]: obj for obj in objects}
    all_ids = set(objects_by_id)
    broken_relationships = {
        obj["id"]
        for obj in objects
        if obj.get("type") == "relationship"
        and (obj.get("source_ref") not in all_ids or obj.get("target_ref") not in all_ids)
    }

    sanitized_by_id: dict[str, dict] = {}
    for object_id, obj in objects_by_id.items():
        if object_id in broken_relationships:
            continue
        if obj.get("type") == "report" and broken_relationships.intersection(obj.get("object_refs", [])):
            obj = copy.deepcopy(obj)
            obj["object_refs"] = [
                ref for ref in obj.get("object_refs", []) if ref not in broken_relationships
            ]
        sanitized_by_id[object_id] = obj

    reports = sorted(
        (obj for obj in sanitized_by_id.values() if obj.get("type") == "report"),
        key=lambda obj: (obj.get("published", ""), obj["id"]),
    )
    target_bytes = args.target_mib * 1024 * 1024
    object_sizes = {object_id: serialized_size(obj) for object_id, obj in sanitized_by_id.items()}

    chunks: list[tuple[list[str], set[str]]] = []
    chunk_reports: list[str] = []
    chunk_objects: set[str] = set()
    for report in reports:
        report_ids = dependency_closure({report["id"]}, sanitized_by_id)
        added_size = sum(object_sizes[item] for item in report_ids - chunk_objects)
        current_size = sum(object_sizes[item] for item in chunk_objects)
        if chunk_reports and current_size + added_size > target_bytes:
            chunks.append((chunk_reports, chunk_objects))
            chunk_reports = []
            chunk_objects = set()
        chunk_reports.append(report["id"])
        chunk_objects.update(report_ids)
    if chunk_reports:
        chunks.append((chunk_reports, chunk_objects))

    manifest = {
        "source": str(args.source),
        "source_sha256": source_sha256.hexdigest(),
        "source_object_count": len(objects),
        "report_count": len(reports),
        "removed_broken_relationships": len(broken_relationships),
        "target_mib": args.target_mib,
        "chunks": [],
    }
    for number, (report_ids, object_ids) in enumerate(chunks, start=1):
        ordered_ids = sorted(object_ids, key=lambda item: (sanitized_by_id[item].get("type", ""), item))
        chunk = {
            "type": "bundle",
            "id": f"bundle--{uuid.uuid5(uuid.NAMESPACE_URL, '|'.join(report_ids))}",
            "objects": [sanitized_by_id[item] for item in ordered_ids],
        }
        filename = f"alienvault-2025-{number:03d}.json"
        path = args.output / filename
        with path.open("w", encoding="utf-8") as stream:
            json.dump(chunk, stream, ensure_ascii=False, separators=(",", ":"))
        type_counts = Counter(sanitized_by_id[item].get("type", "unknown") for item in object_ids)
        manifest["chunks"].append(
            {
                "file": filename,
                "bytes": path.stat().st_size,
                "reports": len(report_ids),
                "objects": len(object_ids),
                "types": dict(sorted(type_counts.items())),
            }
        )

    with (args.output / "manifest.json").open("w", encoding="utf-8") as stream:
        json.dump(manifest, stream, ensure_ascii=False, indent=2)
        stream.write("\n")
    print(json.dumps(manifest, indent=2))


if __name__ == "__main__":
    main()
