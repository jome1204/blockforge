#!/usr/bin/env python3
"""Audit transaction lifecycles and mutation targets in BlockForge journals."""

from __future__ import annotations

import argparse
import dataclasses
import json
import sys
from collections import Counter, defaultdict
from pathlib import Path
from typing import Iterable

from blockforge_inspect import FormatError, JournalRecord, parse_image

TYPE_NAMES = {
    1: "begin",
    2: "allocate_inode",
    3: "free_inode",
    4: "allocate_block",
    5: "free_block",
    6: "write_inode",
    7: "write_directory",
    8: "write_data",
    9: "rename_entry",
    10: "commit",
    11: "rollback",
    12: "checkpoint",
}


@dataclasses.dataclass
class Transaction:
    identifier: int
    first_sequence: int = 0
    last_sequence: int = 0
    outcome: str = "incomplete"
    mutations: int = 0
    payload_bytes: int = 0
    targets: set[int] = dataclasses.field(default_factory=set)
    record_types: Counter[str] = dataclasses.field(default_factory=Counter)
    warnings: list[str] = dataclasses.field(default_factory=list)

    def accept(self, record: JournalRecord) -> None:
        if not self.first_sequence:
            self.first_sequence = record.sequence
        self.last_sequence = record.sequence
        name = TYPE_NAMES.get(record.type, f"unknown_{record.type}")
        self.record_types[name] += 1
        self.payload_bytes += record.payload_bytes
        if record.target:
            self.targets.add(record.target)
        if record.type not in {1, 10, 11, 12}:
            self.mutations += 1
        if record.type == 10:
            if self.outcome != "incomplete":
                self.warnings.append("transaction completes more than once")
            self.outcome = "committed"
        elif record.type == 11:
            if self.outcome != "incomplete":
                self.warnings.append("transaction completes more than once")
            self.outcome = "rolled_back"


def audit(records: tuple[JournalRecord, ...]) -> dict[str, object]:
    transactions: dict[int, Transaction] = {}
    warnings: list[str] = []
    active: set[int] = set()
    previous = 0
    checkpoints: list[int] = []
    type_counts: Counter[str] = Counter()
    target_counts: Counter[int] = Counter()
    for record in records:
        name = TYPE_NAMES.get(record.type, f"unknown_{record.type}")
        type_counts[name] += 1
        if record.sequence <= previous:
            warnings.append(
                f"sequence {record.sequence} is not greater than {previous}"
            )
        previous = record.sequence
        if record.type == 12:
            checkpoints.append(record.sequence)
            if active:
                warnings.append(
                    f"checkpoint {record.sequence} occurs with active "
                    f"transactions {sorted(active)}"
                )
            if record.transaction:
                warnings.append(
                    f"checkpoint {record.sequence} has transaction "
                    f"{record.transaction}"
                )
            continue
        transaction = transactions.setdefault(
            record.transaction, Transaction(record.transaction)
        )
        if record.type == 1:
            if record.transaction == 0:
                transaction.warnings.append("BEGIN has transaction zero")
            if record.transaction in active:
                transaction.warnings.append("transaction begins twice")
            active.add(record.transaction)
        elif record.type in {10, 11}:
            if record.transaction not in active:
                transaction.warnings.append(
                    f"{name} has no matching active BEGIN"
                )
            active.discard(record.transaction)
        elif record.transaction not in active:
            transaction.warnings.append(
                f"{name} mutation occurs outside active transaction"
            )
        if record.target:
            target_counts[record.target] += 1
        transaction.accept(record)
    for identifier in sorted(active):
        transactions[identifier].warnings.append(
            "transaction is incomplete at end of journal"
        )
    transaction_values = []
    for transaction in transactions.values():
        transaction_values.append(
            {
                "identifier": transaction.identifier,
                "first_sequence": transaction.first_sequence,
                "last_sequence": transaction.last_sequence,
                "outcome": transaction.outcome,
                "mutations": transaction.mutations,
                "payload_bytes": transaction.payload_bytes,
                "targets": sorted(transaction.targets),
                "record_types": dict(sorted(transaction.record_types.items())),
                "warnings": transaction.warnings,
            }
        )
    all_warnings = warnings + [
        f"transaction {transaction.identifier}: {warning}"
        for transaction in transactions.values()
        for warning in transaction.warnings
    ]
    return {
        "records": len(records),
        "transactions": len(transactions),
        "committed": sum(
            transaction.outcome == "committed"
            for transaction in transactions.values()
        ),
        "rolled_back": sum(
            transaction.outcome == "rolled_back"
            for transaction in transactions.values()
        ),
        "incomplete": sum(
            transaction.outcome == "incomplete"
            for transaction in transactions.values()
        ),
        "payload_bytes": sum(record.payload_bytes for record in records),
        "checkpoints": checkpoints,
        "type_counts": dict(sorted(type_counts.items())),
        "hot_targets": [
            {"target": target, "records": count}
            for target, count in target_counts.most_common(20)
        ],
        "transaction_details": transaction_values,
        "warnings": all_warnings,
        "valid": not all_warnings,
    }


def render_text(path: Path, report: dict[str, object], verbose: bool) -> str:
    lines = [
        f"{path}:",
        f"  records: {report['records']}",
        f"  transactions: {report['transactions']}",
        f"  committed: {report['committed']}",
        f"  rolled back: {report['rolled_back']}",
        f"  incomplete: {report['incomplete']}",
        f"  payload bytes: {report['payload_bytes']}",
        f"  checkpoints: {len(report['checkpoints'])}",  # type: ignore[arg-type]
        f"  status: {'valid' if report['valid'] else 'warnings'}",
        "  record types:",
    ]
    for name, count in report["type_counts"].items():  # type: ignore[union-attr]
        lines.append(f"    {name}: {count}")
    if report["warnings"]:
        lines.append("  warnings:")
        lines.extend(
            f"    {warning}" for warning in report["warnings"]  # type: ignore[union-attr]
        )
    if verbose:
        lines.append("  transactions:")
        for transaction in report["transaction_details"]:  # type: ignore[assignment]
            lines.append(
                f"    tx={transaction['identifier']} "
                f"seq={transaction['first_sequence']}.."
                f"{transaction['last_sequence']} "
                f"outcome={transaction['outcome']} "
                f"mutations={transaction['mutations']} "
                f"targets={transaction['targets']}"
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
        values = [
            (path, audit(parse_image(path).journal))
            for path in arguments.images
        ]
        if arguments.json:
            print(
                json.dumps(
                    {str(path): report for path, report in values},
                    indent=2,
                )
            )
        else:
            print(
                "\n\n".join(
                    render_text(path, report, arguments.verbose)
                    for path, report in values
                )
            )
        return 0 if all(report["valid"] for _, report in values) else 1
    except (OSError, UnicodeError, FormatError) as error:
        print(f"journal_audit: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
