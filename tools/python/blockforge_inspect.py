#!/usr/bin/env python3
"""Inspect and validate BlockForge filesystem images without dependencies."""

from __future__ import annotations

import argparse
import dataclasses
import hashlib
import json
import struct
import sys
import zlib
from pathlib import Path
from typing import Any, Iterable

SIGNATURE = b"BFIMG1\x00\x00"
HEADER_SIZE = 112
MAX_IMAGE = 256 * 1024 * 1024
MAX_INODES = 1_000_000
MAX_RECORD = 64 * 1024 * 1024
MAX_NAME = 255
MAX_PATH = 4096


class FormatError(ValueError):
    pass


class Reader:
    def __init__(self, data: bytes, origin: int = 0):
        self.data = data
        self.position = 0
        self.origin = origin

    @property
    def remaining(self) -> int:
        return len(self.data) - self.position

    @property
    def offset(self) -> int:
        return self.origin + self.position

    def take(self, count: int, label: str) -> bytes:
        if count < 0 or count > self.remaining:
            raise FormatError(
                f"{label} at offset {self.offset} needs {count} bytes; "
                f"{self.remaining} remain"
            )
        result = self.data[self.position : self.position + count]
        self.position += count
        return result

    def u8(self, label: str) -> int:
        return self.take(1, label)[0]

    def u16(self, label: str) -> int:
        return struct.unpack("<H", self.take(2, label))[0]

    def u32(self, label: str) -> int:
        return struct.unpack("<I", self.take(4, label))[0]

    def u64(self, label: str) -> int:
        return struct.unpack("<Q", self.take(8, label))[0]

    def string(self, maximum: int, label: str) -> str:
        length = self.u32(f"{label} length")
        if length > maximum:
            raise FormatError(f"{label} exceeds {maximum} bytes")
        return self.take(length, label).decode("utf-8", errors="strict")

    def subreader(self, count: int, label: str) -> "Reader":
        origin = self.offset
        return Reader(self.take(count, label), origin)


@dataclasses.dataclass(frozen=True)
class Header:
    version: int
    block_size: int
    block_count: int
    inode_count: int
    root_inode: int
    generation: int
    bitmap_bytes: int
    inode_bytes: int
    directory_bytes: int
    journal_bytes: int
    device_bytes: int
    next_inode: int
    checksum: int
    dirty: bool


@dataclasses.dataclass(frozen=True)
class Extent:
    logical_block: int
    physical_block: int
    block_count: int
    sparse: bool


@dataclasses.dataclass(frozen=True)
class Attribute:
    name: str
    value_bytes: int
    sha256: str


@dataclasses.dataclass(frozen=True)
class Inode:
    identifier: int
    type: int
    mode: int
    owner: int
    group: int
    links: int
    size: int
    allocated_bytes: int
    generation: int
    deleted: bool
    symlink_target: str
    extents: tuple[Extent, ...]
    attributes: tuple[Attribute, ...]


@dataclasses.dataclass(frozen=True)
class DirectoryEntry:
    inode: int
    type: int
    name: str
    record_length: int
    deleted: bool


@dataclasses.dataclass(frozen=True)
class Directory:
    inode: int
    entries: tuple[DirectoryEntry, ...]


@dataclasses.dataclass(frozen=True)
class JournalRecord:
    type: int
    sequence: int
    transaction: int
    target: int
    generation: int
    payload_bytes: int


@dataclasses.dataclass(frozen=True)
class Image:
    path: str
    bytes: int
    sha256: str
    header: Header
    allocated_blocks: int
    inodes: tuple[Inode, ...]
    directories: tuple[Directory, ...]
    journal: tuple[JournalRecord, ...]
    device_sha256: str


def _power_of_two(value: int) -> bool:
    return value > 0 and (value & (value - 1)) == 0


def parse_header(data: bytes) -> Header:
    if len(data) < HEADER_SIZE:
        raise FormatError("filesystem header is truncated")
    if data[:8] != SIGNATURE:
        raise FormatError("filesystem signature is invalid")
    version, block_size = struct.unpack_from("<II", data, 8)
    fields = struct.unpack_from("<10Q", data, 16)
    block_count, inode_count, root_inode, generation = fields[:4]
    bitmap_bytes, inode_bytes, directory_bytes, journal_bytes = fields[4:8]
    device_bytes, next_inode = fields[8:10]
    checksum, flags = struct.unpack_from("<II", data, 96)
    if version != 1:
        raise FormatError(f"unsupported filesystem version {version}")
    if not 512 <= block_size <= 65536 or not _power_of_two(block_size):
        raise FormatError(f"invalid block size {block_size}")
    if block_count == 0 or block_count > 4_000_000:
        raise FormatError("block count exceeds resource limit")
    if inode_count > MAX_INODES or root_inode == 0:
        raise FormatError("inode count or root inode is invalid")
    if bitmap_bytes != (block_count + 7) // 8:
        raise FormatError("allocation bitmap size is inconsistent")
    if device_bytes != block_count * block_size:
        raise FormatError("device byte count is inconsistent")
    if flags & ~1:
        raise FormatError("unknown filesystem header flags")
    expected = HEADER_SIZE + sum(
        (bitmap_bytes, inode_bytes, directory_bytes, journal_bytes, device_bytes)
    )
    if expected != len(data):
        raise FormatError(
            f"section sizes describe {expected} bytes, image has {len(data)}"
        )
    actual_checksum = zlib.crc32(data[HEADER_SIZE:]) & 0xFFFFFFFF
    if checksum != actual_checksum:
        raise FormatError(
            f"body checksum mismatch: {checksum:08x} != {actual_checksum:08x}"
        )
    return Header(
        version,
        block_size,
        block_count,
        inode_count,
        root_inode,
        generation,
        bitmap_bytes,
        inode_bytes,
        directory_bytes,
        journal_bytes,
        device_bytes,
        next_inode,
        checksum,
        bool(flags & 1),
    )


def _parse_inode(record: Reader, header: Header) -> Inode:
    raw = record.data
    if len(raw) < 91 or raw[:4] != b"BFIN":
        raise FormatError(f"invalid inode signature at offset {record.origin}")
    stored = struct.unpack_from("<I", raw, len(raw) - 4)[0]
    actual = zlib.crc32(raw[:-4]) & 0xFFFFFFFF
    if stored != actual:
        raise FormatError(f"inode checksum mismatch at offset {record.origin}")
    reader = Reader(raw[4:-4], record.origin + 4)
    identifier = reader.u64("inode identifier")
    inode_type = reader.u8("inode type")
    mode = reader.u16("inode mode")
    owner = reader.u32("inode owner")
    group = reader.u32("inode group")
    links = reader.u32("inode link count")
    size = reader.u64("inode size")
    allocated_bytes = reader.u64("inode allocated bytes")
    reader.u64("inode creation time")
    reader.u64("inode modification time")
    reader.u64("inode change time")
    generation = reader.u64("inode generation")
    deleted = reader.u8("inode deletion flag")
    extent_count = reader.u32("inode extent count")
    attribute_count = reader.u32("inode attribute count")
    symlink = reader.string(MAX_PATH, "symbolic-link target")
    if identifier == 0 or not 1 <= inode_type <= 3 or links == 0:
        raise FormatError(f"invalid inode fields at offset {record.origin}")
    if size > 64 * 1024 * 1024 or allocated_bytes > 64 * 1024 * 1024:
        raise FormatError("inode sizes exceed resource limit")
    if deleted > 1 or extent_count > 65536:
        raise FormatError("inode flags or extent count are invalid")

    extents: list[Extent] = []
    previous_end = 0
    physical_blocks = 0
    for index in range(extent_count):
        logical = reader.u64("extent logical block")
        physical = reader.u64("extent physical block")
        count = reader.u32("extent block count")
        sparse = reader.u8("extent sparse flag")
        if count == 0 or sparse > 1:
            raise FormatError(f"invalid extent {index} in inode {identifier}")
        if logical < previous_end or logical + count > (1 << 64) - 1:
            raise FormatError(f"overlapping extent in inode {identifier}")
        if not sparse and physical + count > header.block_count:
            raise FormatError(f"out-of-range extent in inode {identifier}")
        previous_end = logical + count
        if not sparse:
            physical_blocks += count
        extents.append(Extent(logical, physical, count, bool(sparse)))
    if physical_blocks * header.block_size != allocated_bytes:
        raise FormatError(f"allocated byte mismatch in inode {identifier}")

    attributes: list[Attribute] = []
    attribute_names: set[str] = set()
    attribute_bytes = 0
    for _ in range(attribute_count):
        name = reader.string(MAX_NAME, "attribute name")
        length = reader.u32("attribute value length")
        if length > 4 * 1024 * 1024:
            raise FormatError("attribute value exceeds resource limit")
        value = reader.take(length, "attribute value")
        attribute_bytes += len(name.encode()) + length
        if not name or name in attribute_names:
            raise FormatError(f"invalid attribute name in inode {identifier}")
        attribute_names.add(name)
        attributes.append(
            Attribute(name, length, hashlib.sha256(value).hexdigest())
        )
    if attribute_bytes > 4 * 1024 * 1024 or reader.remaining:
        raise FormatError(f"invalid attribute area in inode {identifier}")
    return Inode(
        identifier,
        inode_type,
        mode,
        owner,
        group,
        links,
        size,
        allocated_bytes,
        generation,
        bool(deleted),
        symlink,
        tuple(extents),
        tuple(attributes),
    )


def parse_inodes(data: bytes, header: Header, origin: int) -> tuple[Inode, ...]:
    reader = Reader(data, origin)
    count = reader.u32("inode section count")
    if count != header.inode_count:
        raise FormatError("inode section count differs from header")
    output: list[Inode] = []
    identifiers: set[int] = set()
    for _ in range(count):
        length = reader.u32("inode record length")
        if length > MAX_RECORD:
            raise FormatError("inode record length exceeds resource limit")
        inode = _parse_inode(reader.subreader(length, "inode record"), header)
        if inode.identifier in identifiers:
            raise FormatError(f"duplicate inode {inode.identifier}")
        identifiers.add(inode.identifier)
        output.append(inode)
    if reader.remaining:
        raise FormatError("inode section has trailing bytes")
    if header.root_inode not in identifiers:
        raise FormatError("root inode is absent")
    return tuple(output)


def _parse_directory_record(record: Reader) -> tuple[DirectoryEntry, ...]:
    raw = record.data
    if len(raw) < 12 or raw[:4] != b"BFDR":
        raise FormatError("directory record signature is invalid")
    stored = struct.unpack_from("<I", raw, len(raw) - 4)[0]
    if zlib.crc32(raw[:-4]) & 0xFFFFFFFF != stored:
        raise FormatError("directory record checksum mismatch")
    reader = Reader(raw[4:-4], record.origin + 4)
    count = reader.u32("directory entry count")
    if count > 1_000_000:
        raise FormatError("directory entry count exceeds resource limit")
    entries: list[DirectoryEntry] = []
    active_names: set[str] = set()
    for _ in range(count):
        start = reader.position
        record_length = reader.u32("directory entry record length")
        inode = reader.u64("directory entry inode")
        entry_type = reader.u8("directory entry type")
        deleted = reader.u8("directory entry deleted flag")
        name_length = reader.u16("directory entry name length")
        if record_length < 16 or record_length % 8:
            raise FormatError("directory entry record length is invalid")
        if name_length > MAX_NAME or name_length > record_length - 16:
            raise FormatError("directory entry name length is invalid")
        name = reader.take(name_length, "directory entry name").decode(
            "utf-8", errors="strict"
        )
        consumed = reader.position - start
        reader.take(record_length - consumed, "directory entry padding")
        if inode == 0 or not 1 <= entry_type <= 3 or deleted > 1:
            raise FormatError("directory entry fields are invalid")
        if not name or "/" in name or "\x00" in name:
            raise FormatError("directory entry name is invalid")
        folded = name.casefold()
        if not deleted and folded in active_names:
            raise FormatError("duplicate active directory entry name")
        if not deleted:
            active_names.add(folded)
        entries.append(
            DirectoryEntry(inode, entry_type, name, record_length, bool(deleted))
        )
    if reader.remaining:
        raise FormatError("directory record has trailing bytes")
    return tuple(entries)


def parse_directories(
    data: bytes, inode_ids: set[int], origin: int
) -> tuple[Directory, ...]:
    reader = Reader(data, origin)
    count = reader.u32("directory count")
    if count > len(inode_ids):
        raise FormatError("directory count exceeds inode count")
    output: list[Directory] = []
    identifiers: set[int] = set()
    for _ in range(count):
        identifier = reader.u64("directory inode")
        length = reader.u32("directory record length")
        if identifier not in inode_ids or identifier in identifiers:
            raise FormatError("directory inode is invalid or duplicated")
        entries = _parse_directory_record(
            reader.subreader(length, "directory record")
        )
        if not any(entry.name == "." and entry.inode == identifier
                   for entry in entries if not entry.deleted):
            raise FormatError(f"directory {identifier} lacks self entry")
        identifiers.add(identifier)
        output.append(Directory(identifier, entries))
    if reader.remaining:
        raise FormatError("directory section has trailing bytes")
    return tuple(output)


def parse_journal(data: bytes, origin: int) -> tuple[JournalRecord, ...]:
    if len(data) < 16 or data[:8] != b"BFJNL1\x00\x00":
        raise FormatError("journal header is invalid")
    version, count = struct.unpack_from("<II", data, 8)
    if version != 1 or count > 1_000_000:
        raise FormatError("journal version or count is invalid")
    reader = Reader(data[16:], origin + 16)
    records: list[JournalRecord] = []
    previous = 0
    for _ in range(count):
        start = reader.position
        length = reader.u32("journal record length")
        if length < 48 or length > reader.remaining + 4:
            raise FormatError("journal record length is invalid")
        record_type = reader.u16("journal record type")
        flags = reader.u16("journal record flags")
        sequence = reader.u64("journal sequence")
        transaction = reader.u64("journal transaction")
        target = reader.u64("journal target")
        generation = reader.u64("journal generation")
        payload_length = reader.u32("journal payload length")
        if payload_length != length - 48:
            raise FormatError("journal payload length is inconsistent")
        payload = reader.take(payload_length, "journal payload")
        checksum = reader.u32("journal checksum")
        encoded = data[16 + start + 4 : 16 + start + length - 4]
        if zlib.crc32(encoded) & 0xFFFFFFFF != checksum:
            raise FormatError("journal record checksum mismatch")
        if not 1 <= record_type <= 12 or flags or sequence <= previous:
            raise FormatError("journal record fields are invalid")
        records.append(
            JournalRecord(
                record_type,
                sequence,
                transaction,
                target,
                generation,
                len(payload),
            )
        )
        previous = sequence
    if reader.remaining:
        raise FormatError("journal has trailing bytes")
    return tuple(records)


def parse_image(path: Path) -> Image:
    if path.stat().st_size > MAX_IMAGE:
        raise FormatError(f"{path}: image exceeds resource limit")
    data = path.read_bytes()
    header = parse_header(data)
    position = HEADER_SIZE
    bitmap = data[position : position + header.bitmap_bytes]
    position += header.bitmap_bytes
    inode_origin = position
    inode_data = data[position : position + header.inode_bytes]
    position += header.inode_bytes
    directory_origin = position
    directory_data = data[position : position + header.directory_bytes]
    position += header.directory_bytes
    journal_origin = position
    journal_data = data[position : position + header.journal_bytes]
    position += header.journal_bytes
    device = data[position : position + header.device_bytes]
    allocated = sum(byte.bit_count() for byte in bitmap)
    inodes = parse_inodes(inode_data, header, inode_origin)
    inode_ids = {inode.identifier for inode in inodes}
    directories = parse_directories(directory_data, inode_ids, directory_origin)
    journal = parse_journal(journal_data, journal_origin)
    return Image(
        str(path),
        len(data),
        hashlib.sha256(data).hexdigest(),
        header,
        allocated,
        inodes,
        directories,
        journal,
        hashlib.sha256(device).hexdigest(),
    )


def summary(image: Image) -> dict[str, Any]:
    type_counts = {"regular": 0, "directory": 0, "symlink": 0}
    logical_bytes = 0
    physical_bytes = 0
    deleted_entries = 0
    for inode in image.inodes:
        type_counts[("regular", "directory", "symlink")[inode.type - 1]] += 1
        if inode.type == 1:
            logical_bytes += inode.size
            physical_bytes += inode.allocated_bytes
    for directory in image.directories:
        deleted_entries += sum(entry.deleted for entry in directory.entries)
    return {
        "path": image.path,
        "bytes": image.bytes,
        "sha256": image.sha256,
        "version": image.header.version,
        "block_size": image.header.block_size,
        "block_count": image.header.block_count,
        "allocated_blocks": image.allocated_blocks,
        "free_blocks": image.header.block_count - image.allocated_blocks,
        "inode_count": len(image.inodes),
        "root_inode": image.header.root_inode,
        "generation": image.header.generation,
        "dirty": image.header.dirty,
        "types": type_counts,
        "logical_file_bytes": logical_bytes,
        "physical_file_bytes": physical_bytes,
        "directory_count": len(image.directories),
        "deleted_directory_entries": deleted_entries,
        "journal_records": len(image.journal),
        "device_sha256": image.device_sha256,
        "inodes": [dataclasses.asdict(inode) for inode in image.inodes],
        "directories": [
            dataclasses.asdict(directory) for directory in image.directories
        ],
        "journal": [dataclasses.asdict(record) for record in image.journal],
    }


def render_text(report: dict[str, Any], verbose: bool) -> str:
    lines = [
        f"{report['path']}:",
        f"  image bytes: {report['bytes']}",
        f"  SHA-256: {report['sha256']}",
        f"  blocks: {report['allocated_blocks']} allocated, "
        f"{report['free_blocks']} free, {report['block_size']} bytes each",
        f"  inodes: {report['inode_count']} "
        f"({report['types']['regular']} files, "
        f"{report['types']['directory']} directories, "
        f"{report['types']['symlink']} symlinks)",
        f"  file bytes: {report['logical_file_bytes']} logical, "
        f"{report['physical_file_bytes']} allocated",
        f"  journal records: {report['journal_records']}",
        f"  status: {'dirty' if report['dirty'] else 'clean'}",
    ]
    if verbose:
        lines.append("  inode table:")
        for inode in report["inodes"]:
            lines.append(
                f"    {inode['identifier']:6} type={inode['type']} "
                f"size={inode['size']} blocks={len(inode['extents'])} "
                f"links={inode['links']}"
            )
        lines.append("  directories:")
        for directory in report["directories"]:
            lines.append(f"    inode {directory['inode']}:")
            for entry in directory["entries"]:
                marker = "deleted " if entry["deleted"] else ""
                lines.append(
                    f"      {marker}{entry['name']} -> {entry['inode']}"
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
        reports = [summary(parse_image(path)) for path in arguments.images]
        if arguments.json:
            print(json.dumps(reports, indent=2, ensure_ascii=False))
        else:
            print(
                "\n\n".join(
                    render_text(report, arguments.verbose)
                    for report in reports
                )
            )
        return 0
    except (OSError, UnicodeError, FormatError) as error:
        print(f"blockforge_inspect: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
