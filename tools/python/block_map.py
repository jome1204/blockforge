#!/usr/bin/env python3
"""Report ownership, fragmentation, holes, and allocation leaks by block."""

from __future__ import annotations

import argparse
import dataclasses
import json
import sys
from pathlib import Path
from typing import Iterable

from blockforge_inspect import FormatError, Image, parse_image
from image_diff import build_tree


@dataclasses.dataclass(frozen=True)
class BlockOwner:
    block: int
    inode: int
    logical_block: int
    path: str


@dataclasses.dataclass(frozen=True)
class Finding:
    severity: str
    code: str
    block: int
    inode: int
    detail: str


def bitmap_blocks(image: Image, raw: bytes) -> set[int]:
    start = 112
    bitmap = raw[start : start + image.header.bitmap_bytes]
    output: set[int] = set()
    for block in range(image.header.block_count):
        if bitmap[block // 8] & (1 << (block % 8)):
            output.add(block)
    return output


def analyze(image: Image, raw: bytes) -> dict[str, object]:
    tree = build_tree(image)
    inode_paths: dict[int, list[str]] = {}
    for path, node in tree.items():
        inode_paths.setdefault(node.inode, []).append(path)
    owners: dict[int, list[BlockOwner]] = {}
    holes = 0
    extent_count = 0
    for inode in image.inodes:
        paths = inode_paths.get(inode.identifier, [f"<inode:{inode.identifier}>"])
        canonical = sorted(paths)[0]
        for extent in inode.extents:
            extent_count += 1
            if extent.sparse:
                holes += extent.block_count
                continue
            for relative in range(extent.block_count):
                block = extent.physical_block + relative
                owner = BlockOwner(
                    block,
                    inode.identifier,
                    extent.logical_block + relative,
                    canonical,
                )
                owners.setdefault(block, []).append(owner)
    allocated = bitmap_blocks(image, raw)
    findings: list[Finding] = []
    referenced = set(owners)
    for block, block_owners in sorted(owners.items()):
        if block >= image.header.block_count:
            for owner in block_owners:
                findings.append(
                    Finding(
                        "error",
                        "out_of_range",
                        block,
                        owner.inode,
                        f"{owner.path} references a block outside the image",
                    )
                )
            continue
        if len(block_owners) > 1:
            findings.append(
                Finding(
                    "fatal",
                    "duplicate_owner",
                    block,
                    block_owners[0].inode,
                    "block is shared by "
                    + ", ".join(
                        f"{owner.path}(inode {owner.inode})"
                        for owner in block_owners
                    ),
                )
            )
        if block not in allocated:
            findings.append(
                Finding(
                    "error",
                    "referenced_free",
                    block,
                    block_owners[0].inode,
                    "referenced block is marked free in the bitmap",
                )
            )
    for block in sorted(allocated - referenced - {0}):
        findings.append(
            Finding(
                "warning",
                "allocation_leak",
                block,
                0,
                "allocated block has no inode owner",
            )
        )
    files = []
    for inode in image.inodes:
        if inode.type != 1:
            continue
        physical_extents = sum(not extent.sparse for extent in inode.extents)
        files.append(
            {
                "inode": inode.identifier,
                "paths": inode_paths.get(inode.identifier, []),
                "logical_bytes": inode.size,
                "allocated_bytes": inode.allocated_bytes,
                "extent_count": len(inode.extents),
                "physical_extents": physical_extents,
                "sparse_blocks": sum(
                    extent.block_count
                    for extent in inode.extents
                    if extent.sparse
                ),
                "fragmented": physical_extents > 1,
            }
        )
    return {
        "image": image.path,
        "block_size": image.header.block_size,
        "block_count": image.header.block_count,
        "allocated_blocks": len(allocated),
        "referenced_blocks": len(referenced),
        "unreferenced_allocated_blocks": len(allocated - referenced - {0}),
        "sparse_blocks": holes,
        "extent_count": extent_count,
        "duplicate_blocks": sum(len(value) > 1 for value in owners.values()),
        "findings": [dataclasses.asdict(finding) for finding in findings],
        "files": files,
        "owners": [
            dataclasses.asdict(owner)
            for block_owners in owners.values()
            for owner in block_owners
        ],
    }


def render_text(report: dict[str, object], verbose: bool) -> str:
    lines = [
        f"{report['image']}:",
        f"  blocks: {report['block_count']} x {report['block_size']} bytes",
        f"  allocated: {report['allocated_blocks']}",
        f"  referenced: {report['referenced_blocks']}",
        f"  allocation leaks: {report['unreferenced_allocated_blocks']}",
        f"  sparse logical blocks: {report['sparse_blocks']}",
        f"  extents: {report['extent_count']}",
        f"  duplicate-owned blocks: {report['duplicate_blocks']}",
    ]
    findings = report["findings"]
    if findings:
        lines.append("  findings:")
        for finding in findings:  # type: ignore[assignment]
            lines.append(
                f"    [{finding['severity']}] {finding['code']} "
                f"block={finding['block']} inode={finding['inode']}: "
                f"{finding['detail']}"
            )
    if verbose:
        lines.append("  files:")
        for file in report["files"]:  # type: ignore[assignment]
            lines.append(
                f"    inode={file['inode']} size={file['logical_bytes']} "
                f"allocated={file['allocated_bytes']} "
                f"extents={file['extent_count']} "
                f"paths={','.join(file['paths'])}"
            )
    return "\n".join(lines)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("images", type=Path, nargs="+")
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--verbose", action="store_true")
    return parser


def main(argv: Iterable[str] | None = None) -> int:
    arguments = _parser().parse_args(argv)
    try:
        reports = []
        for path in arguments.images:
            raw = path.read_bytes()
            reports.append(analyze(parse_image(path), raw))
        if arguments.json:
            print(json.dumps(reports, indent=2, ensure_ascii=False))
        else:
            print(
                "\n\n".join(
                    render_text(report, arguments.verbose)
                    for report in reports
                )
            )
        has_error = any(
            finding["severity"] in {"error", "fatal"}
            for report in reports
            for finding in report["findings"]  # type: ignore[index]
        )
        return 1 if has_error else 0
    except (OSError, UnicodeError, FormatError) as error:
        print(f"block_map: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
