#!/usr/bin/env python3
"""Compare the logical metadata of two BlockForge filesystem images."""

from __future__ import annotations

import argparse
import dataclasses
import json
import sys
from collections import Counter, deque
from pathlib import Path
from typing import Any, Iterable

from blockforge_inspect import FormatError, Image, Inode, parse_image


@dataclasses.dataclass(frozen=True)
class Node:
    path: str
    inode: int
    type: int
    size: int
    allocated_bytes: int
    links: int
    mode: int
    generation: int
    symlink_target: str
    extents: tuple[tuple[int, int, int, bool], ...]
    attributes: tuple[tuple[str, int, str], ...]


@dataclasses.dataclass(frozen=True)
class Change:
    kind: str
    path: str
    detail: str
    left: Any = None
    right: Any = None


def _node(path: str, inode: Inode) -> Node:
    return Node(
        path,
        inode.identifier,
        inode.type,
        inode.size,
        inode.allocated_bytes,
        inode.links,
        inode.mode,
        inode.generation,
        inode.symlink_target,
        tuple(
            (
                extent.logical_block,
                extent.physical_block,
                extent.block_count,
                extent.sparse,
            )
            for extent in inode.extents
        ),
        tuple(
            (attribute.name, attribute.value_bytes, attribute.sha256)
            for attribute in inode.attributes
        ),
    )


def build_tree(image: Image) -> dict[str, Node]:
    inodes = {inode.identifier: inode for inode in image.inodes}
    directories = {
        directory.inode: directory for directory in image.directories
    }
    root = image.header.root_inode
    if root not in inodes:
        raise FormatError("image root inode does not exist")
    output: dict[str, Node] = {"/": _node("/", inodes[root])}
    pending: deque[tuple[int, str, tuple[int, ...]]] = deque(
        [(root, "/", ())]
    )
    visited_directories: set[int] = set()
    while pending:
        identifier, path, ancestors = pending.popleft()
        inode = inodes.get(identifier)
        if inode is None or inode.type != 2:
            continue
        if identifier in ancestors:
            raise FormatError(f"directory cycle at {path}")
        if identifier in visited_directories:
            continue
        visited_directories.add(identifier)
        directory = directories.get(identifier)
        if directory is None:
            raise FormatError(f"missing directory table for inode {identifier}")
        for entry in directory.entries:
            if entry.deleted or entry.name in {".", ".."}:
                continue
            target = inodes.get(entry.inode)
            if target is None:
                raise FormatError(
                    f"directory {path} refers to missing inode {entry.inode}"
                )
            child_path = (
                "/" + entry.name if path == "/" else path + "/" + entry.name
            )
            if child_path in output:
                raise FormatError(f"duplicate logical path {child_path}")
            output[child_path] = _node(child_path, target)
            if target.type == 2:
                pending.append(
                    (target.identifier, child_path, ancestors + (identifier,))
                )
            if len(output) > 1_000_000:
                raise FormatError("logical tree exceeds resource limit")
    return output


def compare(left: Image, right: Image) -> list[Change]:
    left_tree = build_tree(left)
    right_tree = build_tree(right)
    changes: list[Change] = []
    for path in sorted(left_tree.keys() - right_tree.keys()):
        changes.append(
            Change("removed", path, "path exists only in left image",
                   dataclasses.asdict(left_tree[path]), None)
        )
    for path in sorted(right_tree.keys() - left_tree.keys()):
        changes.append(
            Change("added", path, "path exists only in right image",
                   None, dataclasses.asdict(right_tree[path]))
        )
    for path in sorted(left_tree.keys() & right_tree.keys()):
        before = left_tree[path]
        after = right_tree[path]
        if before.type != after.type:
            changes.append(
                Change(
                    "type",
                    path,
                    f"type changed from {before.type} to {after.type}",
                    before.type,
                    after.type,
                )
            )
            continue
        if (
            before.size != after.size
            or before.allocated_bytes != after.allocated_bytes
            or before.extents != after.extents
        ):
            changes.append(
                Change(
                    "content",
                    path,
                    f"size {before.size}->{after.size}, allocated "
                    f"{before.allocated_bytes}->{after.allocated_bytes}",
                    {
                        "size": before.size,
                        "allocated": before.allocated_bytes,
                        "extents": before.extents,
                    },
                    {
                        "size": after.size,
                        "allocated": after.allocated_bytes,
                        "extents": after.extents,
                    },
                )
            )
        if (
            before.mode != after.mode
            or before.links != after.links
            or before.attributes != after.attributes
            or before.symlink_target != after.symlink_target
        ):
            changes.append(
                Change(
                    "metadata",
                    path,
                    "mode, links, attributes, or symlink target changed",
                    {
                        "mode": before.mode,
                        "links": before.links,
                        "attributes": before.attributes,
                        "symlink": before.symlink_target,
                    },
                    {
                        "mode": after.mode,
                        "links": after.links,
                        "attributes": after.attributes,
                        "symlink": after.symlink_target,
                    },
                )
            )
    if left.header.block_size != right.header.block_size:
        changes.insert(
            0,
            Change(
                "geometry",
                "/",
                f"block size changed from {left.header.block_size} "
                f"to {right.header.block_size}",
                left.header.block_size,
                right.header.block_size,
            ),
        )
    return changes


def render_text(changes: list[Change]) -> str:
    if not changes:
        return "Images are logically equal"
    markers = {
        "added": "+",
        "removed": "-",
        "type": "T",
        "content": "C",
        "metadata": "M",
        "geometry": "G",
    }
    counts = Counter(change.kind for change in changes)
    lines = [
        f"Changes: {len(changes)}",
        "Summary: " + ", ".join(
            f"{kind}={count}" for kind, count in sorted(counts.items())
        ),
    ]
    lines.extend(
        f"{markers.get(change.kind, '?')} {change.path}: {change.detail}"
        for change in changes
    )
    return "\n".join(lines)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("left", type=Path)
    parser.add_argument("right", type=Path)
    parser.add_argument("--json", action="store_true")
    return parser


def main(argv: Iterable[str] | None = None) -> int:
    arguments = _parser().parse_args(argv)
    try:
        changes = compare(
            parse_image(arguments.left), parse_image(arguments.right)
        )
        if arguments.json:
            print(
                json.dumps(
                    [dataclasses.asdict(change) for change in changes],
                    indent=2,
                    ensure_ascii=False,
                )
            )
        else:
            print(render_text(changes))
        return 0 if not changes else 1
    except (OSError, UnicodeError, FormatError) as error:
        print(f"image_diff: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
