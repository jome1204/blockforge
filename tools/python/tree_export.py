#!/usr/bin/env python3
"""Export a safe logical tree manifest from a BlockForge filesystem image."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import sys
from pathlib import Path
from typing import Iterable, TextIO

from blockforge_inspect import FormatError, parse_image
from image_diff import Node, build_tree

TYPE_NAMES = {1: "file", 2: "directory", 3: "symlink"}


def manifest(path: Path) -> dict[str, object]:
    image = parse_image(path)
    tree = build_tree(image)
    nodes = []
    for logical_path, node in sorted(tree.items()):
        nodes.append(
            {
                "path": logical_path,
                "inode": node.inode,
                "type": TYPE_NAMES.get(node.type, "unknown"),
                "mode": f"{node.mode:04o}",
                "links": node.links,
                "logical_bytes": node.size,
                "allocated_bytes": node.allocated_bytes,
                "generation": node.generation,
                "symlink_target": node.symlink_target,
                "extent_count": len(node.extents),
                "sparse": node.allocated_bytes < node.size,
                "fragmented": sum(not extent[3] for extent in node.extents) > 1,
                "attributes": [
                    {
                        "name": name,
                        "bytes": length,
                        "sha256": digest,
                    }
                    for name, length, digest in node.attributes
                ],
            }
        )
    return {
        "format": "BlockForge tree manifest",
        "version": 1,
        "source": str(path),
        "image_sha256": image.sha256,
        "image_bytes": image.bytes,
        "block_size": image.header.block_size,
        "block_count": image.header.block_count,
        "root_inode": image.header.root_inode,
        "generation": image.header.generation,
        "node_count": len(nodes),
        "file_count": sum(node.type == 1 for node in tree.values()),
        "directory_count": sum(node.type == 2 for node in tree.values()),
        "symlink_count": sum(node.type == 3 for node in tree.values()),
        "logical_file_bytes": sum(
            node.size for node in tree.values() if node.type == 1
        ),
        "allocated_file_bytes": sum(
            node.allocated_bytes for node in tree.values() if node.type == 1
        ),
        "nodes": nodes,
    }


def write_csv(value: dict[str, object], output: TextIO) -> None:
    fields = [
        "path",
        "inode",
        "type",
        "mode",
        "links",
        "logical_bytes",
        "allocated_bytes",
        "generation",
        "symlink_target",
        "extent_count",
        "sparse",
        "fragmented",
        "attribute_count",
    ]
    writer = csv.DictWriter(output, fieldnames=fields)
    writer.writeheader()
    for node in value["nodes"]:  # type: ignore[assignment]
        writer.writerow(
            {
                **{field: node.get(field, "") for field in fields},
                "attribute_count": len(node["attributes"]),
            }
        )


def write_paths(value: dict[str, object], output: TextIO) -> None:
    for node in value["nodes"]:  # type: ignore[assignment]
        marker = {"file": "-", "directory": "d", "symlink": "l"}.get(
            node["type"], "?"
        )
        output.write(
            f"{marker} {node['mode']} {node['links']:4} "
            f"{node['logical_bytes']:10} {node['path']}"
        )
        if node["symlink_target"]:
            output.write(f" -> {node['symlink_target']}")
        output.write("\n")


def verify_manifest(value: dict[str, object]) -> list[str]:
    issues: list[str] = []
    nodes = value.get("nodes")
    if not isinstance(nodes, list):
        return ["nodes field is absent or not an array"]
    paths: set[str] = set()
    inodes: dict[int, int] = {}
    for index, node in enumerate(nodes):
        if not isinstance(node, dict):
            issues.append(f"node {index} is not an object")
            continue
        path = node.get("path")
        inode = node.get("inode")
        if not isinstance(path, str) or not path.startswith("/"):
            issues.append(f"node {index} has an invalid path")
        elif path in paths:
            issues.append(f"duplicate path {path}")
        else:
            paths.add(path)
        if not isinstance(inode, int) or inode <= 0:
            issues.append(f"node {index} has an invalid inode")
        else:
            inodes[inode] = inodes.get(inode, 0) + 1
        if node.get("type") not in {"file", "directory", "symlink"}:
            issues.append(f"node {index} has an invalid type")
        if not isinstance(node.get("logical_bytes"), int):
            issues.append(f"node {index} has an invalid logical size")
    if "/" not in paths:
        issues.append("manifest lacks root path")
    if value.get("node_count") != len(nodes):
        issues.append("node_count does not match nodes array")
    return issues


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    export = subparsers.add_parser("export")
    export.add_argument("image", type=Path)
    export.add_argument("--format", choices=("json", "csv", "paths"),
                        default="json")
    export.add_argument("--output", type=Path)
    verify = subparsers.add_parser("verify")
    verify.add_argument("manifest", type=Path)
    return parser


def main(argv: Iterable[str] | None = None) -> int:
    arguments = _parser().parse_args(argv)
    try:
        if arguments.command == "verify":
            value = json.loads(arguments.manifest.read_text(encoding="utf-8"))
            issues = verify_manifest(value)
            if issues:
                for issue in issues:
                    print(f"ERROR: {issue}", file=sys.stderr)
                return 1
            encoded = arguments.manifest.read_bytes()
            print(
                f"OK {arguments.manifest}: {value['node_count']} nodes, "
                f"SHA-256 {hashlib.sha256(encoded).hexdigest()}"
            )
            return 0
        value = manifest(arguments.image)
        output: TextIO
        should_close = arguments.output is not None
        if arguments.output:
            arguments.output.parent.mkdir(parents=True, exist_ok=True)
            output = arguments.output.open("w", encoding="utf-8", newline="")
        else:
            output = sys.stdout
        try:
            if arguments.format == "json":
                json.dump(value, output, indent=2, ensure_ascii=False)
                output.write("\n")
            elif arguments.format == "csv":
                write_csv(value, output)
            else:
                write_paths(value, output)
        finally:
            if should_close:
                output.close()
        return 0
    except (OSError, UnicodeError, ValueError, FormatError) as error:
        print(f"tree_export: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
