#!/usr/bin/env python3
"""Decode, generate, and compare BlockForge operation-fuzzer sequences."""

from __future__ import annotations

import argparse
import dataclasses
import json
import random
import sys
from collections import Counter
from pathlib import Path
from typing import Iterable

MAX_OPERATIONS = 4096

OPERATIONS = (
    "mkdir",
    "create",
    "write",
    "append",
    "read",
    "remove",
    "rename",
    "hard-link",
    "symlink",
    "list",
    "walk",
    "begin",
    "rollback",
    "commit",
    "checkpoint",
    "set-xattr",
    "get-xattr",
    "remove-xattr",
    "serialize-reopen",
    "stat",
    "recursive-remove",
)


@dataclasses.dataclass(frozen=True)
class Operation:
    ordinal: int
    opcode: int
    name: str
    slot: int
    value: int
    transaction_depth: int


def decode(data: bytes) -> tuple[list[Operation], list[str]]:
    operations: list[Operation] = []
    warnings: list[str] = []
    depth = 0
    count = min(len(data), MAX_OPERATIONS)
    for index, byte in enumerate(data[:count]):
        opcode = byte % len(OPERATIONS)
        name = OPERATIONS[opcode]
        if name == "begin":
            if depth:
                warnings.append(f"operation {index}: nested transaction")
            depth += 1
        elif name in {"rollback", "commit"}:
            if not depth:
                warnings.append(
                    f"operation {index}: {name} without transaction"
                )
            else:
                depth -= 1
        operations.append(
            Operation(
                ordinal=index,
                opcode=opcode,
                name=name,
                slot=(byte >> 3) & 31,
                value=(byte * 257 + index * 17) & 0xFFFF,
                transaction_depth=depth,
            )
        )
    if len(data) > MAX_OPERATIONS:
        warnings.append(
            f"{len(data) - MAX_OPERATIONS} operations omitted by limit"
        )
    if depth:
        warnings.append(f"sequence ends with {depth} active transaction(s)")
    return operations, warnings


def report(path: Path) -> dict[str, object]:
    data = path.read_bytes()
    operations, warnings = decode(data)
    counts = Counter(operation.name for operation in operations)
    maximum_depth = max(
        (operation.transaction_depth for operation in operations), default=0
    )
    mutating = {
        "mkdir",
        "create",
        "write",
        "append",
        "remove",
        "rename",
        "hard-link",
        "symlink",
        "recursive-remove",
        "set-xattr",
        "remove-xattr",
    }
    return {
        "path": str(path),
        "bytes": len(data),
        "operations": len(operations),
        "mutations": sum(operation.name in mutating for operation in operations),
        "reads": sum(
            operation.name
            in {"read", "list", "walk", "get-xattr", "stat"}
            for operation in operations
        ),
        "maximum_transaction_depth": maximum_depth,
        "counts": dict(sorted(counts.items())),
        "warnings": warnings,
        "trace": [dataclasses.asdict(operation) for operation in operations],
    }


def render_text(value: dict[str, object], verbose: bool) -> str:
    lines = [
        f"{value['path']}:",
        f"  bytes: {value['bytes']}",
        f"  operations: {value['operations']}",
        f"  mutations: {value['mutations']}",
        f"  reads: {value['reads']}",
        f"  maximum transaction depth: {value['maximum_transaction_depth']}",
        "  operation counts:",
    ]
    for name, count in value["counts"].items():  # type: ignore[union-attr]
        lines.append(f"    {name}: {count}")
    warnings = value["warnings"]
    if warnings:
        lines.append("  warnings:")
        lines.extend(f"    {warning}" for warning in warnings)  # type: ignore[arg-type]
    if verbose:
        lines.append("  trace:")
        for operation in value["trace"]:  # type: ignore[assignment]
            lines.append(
                f"    {operation['ordinal']:4} {operation['name']:<18} "
                f"slot={operation['slot']:<2} value={operation['value']:<5} "
                f"tx-depth={operation['transaction_depth']}"
            )
    return "\n".join(lines)


def generate(length: int, seed: int) -> bytes:
    if length < 0 or length > MAX_OPERATIONS:
        raise ValueError(f"length must be between 0 and {MAX_OPERATIONS}")
    generator = random.Random(seed)
    output = bytearray()
    transaction = False
    for index in range(length):
        if index % 31 == 0 and not transaction:
            opcode = OPERATIONS.index("begin")
            transaction = True
        elif index % 31 == 30 and transaction:
            opcode = generator.choice(
                (OPERATIONS.index("commit"), OPERATIONS.index("rollback"))
            )
            transaction = False
        else:
            opcode = generator.randrange(len(OPERATIONS))
            if transaction and OPERATIONS[opcode] == "begin":
                opcode = OPERATIONS.index("write")
            if not transaction and OPERATIONS[opcode] in {"commit", "rollback"}:
                opcode = OPERATIONS.index("read")
        upper = generator.randrange(0, 256 // len(OPERATIONS) + 1)
        output.append((opcode + upper * len(OPERATIONS)) & 0xFF)
    if transaction and output:
        output[-1] = OPERATIONS.index("rollback")
    return bytes(output)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    inspect = subparsers.add_parser("inspect")
    inspect.add_argument("seeds", type=Path, nargs="+")
    inspect.add_argument("--json", action="store_true")
    inspect.add_argument("--verbose", action="store_true")
    create = subparsers.add_parser("generate")
    create.add_argument("output", type=Path)
    create.add_argument("--length", type=int, default=256)
    create.add_argument("--seed", type=int, default=1)
    return parser


def main(argv: Iterable[str] | None = None) -> int:
    arguments = _parser().parse_args(argv)
    try:
        if arguments.command == "generate":
            arguments.output.parent.mkdir(parents=True, exist_ok=True)
            arguments.output.write_bytes(
                generate(arguments.length, arguments.seed)
            )
            print(f"wrote {arguments.output}")
            return 0
        reports = [report(path) for path in arguments.seeds]
        if arguments.json:
            print(json.dumps(reports, indent=2))
        else:
            print(
                "\n\n".join(
                    render_text(value, arguments.verbose)
                    for value in reports
                )
            )
        return 0
    except (OSError, ValueError) as error:
        print(f"operation_trace: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
