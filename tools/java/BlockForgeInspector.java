package blockforge.tools;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.zip.CRC32;

/** Independent, allocation-bounded BlockForge image inspector. */
public final class BlockForgeInspector {
    private static final byte[] SIGNATURE = {
        'B', 'F', 'I', 'M', 'G', '1', 0, 0
    };
    private static final int HEADER_SIZE = 112;
    private static final long MAX_IMAGE = 256L * 1024L * 1024L;
    private static final int MAX_INODES = 1_000_000;
    private static final int MAX_NAME = 255;
    private static final int MAX_PATH = 4096;
    private static final int MAX_RECORD = 64 * 1024 * 1024;

    private BlockForgeInspector() {
    }

    public static final class FormatException extends Exception {
        private final long offset;

        FormatException(String message, long offset) {
            super(message + " at offset " + offset);
            this.offset = offset;
        }

        public long offset() {
            return offset;
        }
    }

    public record Header(
        int version,
        int blockSize,
        long blockCount,
        long inodeCount,
        long rootInode,
        long generation,
        long bitmapBytes,
        long inodeBytes,
        long directoryBytes,
        long journalBytes,
        long deviceBytes,
        long nextInode,
        long checksum,
        boolean dirty
    ) {
    }

    public record Extent(
        long logicalBlock,
        long physicalBlock,
        long blockCount,
        boolean sparse
    ) {
    }

    public record Inode(
        long identifier,
        int type,
        int mode,
        long links,
        long size,
        long allocatedBytes,
        long generation,
        boolean deleted,
        String symlink,
        List<Extent> extents,
        int attributeCount
    ) {
        Inode {
            extents = List.copyOf(extents);
        }
    }

    public record DirectoryEntry(
        long inode,
        int type,
        String name,
        int recordLength,
        boolean deleted
    ) {
    }

    public record Directory(long inode, List<DirectoryEntry> entries) {
        Directory {
            entries = List.copyOf(entries);
        }
    }

    public record JournalRecord(
        int type,
        long sequence,
        long transaction,
        long target,
        long generation,
        int payloadBytes
    ) {
    }

    public record Image(
        Header header,
        List<Inode> inodes,
        List<Directory> directories,
        List<JournalRecord> journal,
        long allocatedBlocks,
        String sha256
    ) {
        Image {
            inodes = List.copyOf(inodes);
            directories = List.copyOf(directories);
            journal = List.copyOf(journal);
        }
    }

    private static final class Reader {
        private final ByteBuffer buffer;
        private final long origin;

        Reader(byte[] data) {
            this(data, 0);
        }

        Reader(byte[] data, long origin) {
            buffer = ByteBuffer.wrap(data).order(ByteOrder.LITTLE_ENDIAN);
            this.origin = origin;
        }

        long offset() {
            return origin + buffer.position();
        }

        int remaining() {
            return buffer.remaining();
        }

        void require(int count, String label) throws FormatException {
            if (count < 0 || count > buffer.remaining()) {
                throw new FormatException(
                    label + " is truncated; need " + count
                        + " bytes, have " + buffer.remaining(),
                    offset()
                );
            }
        }

        byte[] bytes(int count, String label) throws FormatException {
            require(count, label);
            byte[] output = new byte[count];
            buffer.get(output);
            return output;
        }

        int u8(String label) throws FormatException {
            require(1, label);
            return buffer.get() & 0xff;
        }

        int u16(String label) throws FormatException {
            require(2, label);
            return buffer.getShort() & 0xffff;
        }

        long u32(String label) throws FormatException {
            require(4, label);
            return Integer.toUnsignedLong(buffer.getInt());
        }

        long u64(String label) throws FormatException {
            require(8, label);
            return buffer.getLong();
        }

        String text(int maximum, String label) throws FormatException {
            long length = u32(label + " length");
            if (length > maximum) {
                throw new FormatException(
                    label + " exceeds resource limit",
                    offset() - 4
                );
            }
            byte[] encoded = bytes((int) length, label);
            try {
                return StandardCharsets.UTF_8.newDecoder()
                    .onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT)
                    .decode(ByteBuffer.wrap(encoded))
                    .toString();
            } catch (CharacterCodingException error) {
                throw new FormatException(
                    label + " is not valid UTF-8",
                    offset() - length
                );
            }
        }

        Reader subreader(int count, String label) throws FormatException {
            long start = offset();
            return new Reader(bytes(count, label), start);
        }
    }

    private static boolean powerOfTwo(int value) {
        return value > 0 && (value & (value - 1)) == 0;
    }

    private static long checkedAdd(long left, long right, long offset)
        throws FormatException {
        if (left < 0 || right < 0 || left > Long.MAX_VALUE - right) {
            throw new FormatException("integer addition overflows", offset);
        }
        return left + right;
    }

    private static long checkedMultiply(long left, long right, long offset)
        throws FormatException {
        if (left < 0 || right < 0
            || (left != 0 && right > Long.MAX_VALUE / left)) {
            throw new FormatException(
                "integer multiplication overflows",
                offset
            );
        }
        return left * right;
    }

    private static long readUnsignedInt(byte[] data, int offset) {
        return Integer.toUnsignedLong(
            ByteBuffer.wrap(data, offset, 4)
                .order(ByteOrder.LITTLE_ENDIAN)
                .getInt()
        );
    }

    private static long crc32(byte[] data, int offset, int length) {
        CRC32 crc = new CRC32();
        crc.update(data, offset, length);
        return crc.getValue();
    }

    private static Header parseHeader(byte[] data) throws FormatException {
        if (data.length < HEADER_SIZE) {
            throw new FormatException("filesystem header is truncated", 0);
        }
        if (!java.util.Arrays.equals(
                java.util.Arrays.copyOfRange(data, 0, 8),
                SIGNATURE)) {
            throw new FormatException("filesystem signature is invalid", 0);
        }
        Reader reader = new Reader(data);
        reader.bytes(8, "signature");
        int version = (int) reader.u32("version");
        int blockSize = (int) reader.u32("block size");
        long blockCount = reader.u64("block count");
        long inodeCount = reader.u64("inode count");
        long rootInode = reader.u64("root inode");
        long generation = reader.u64("generation");
        long bitmapBytes = reader.u64("bitmap bytes");
        long inodeBytes = reader.u64("inode bytes");
        long directoryBytes = reader.u64("directory bytes");
        long journalBytes = reader.u64("journal bytes");
        long deviceBytes = reader.u64("device bytes");
        long nextInode = reader.u64("next inode");
        long checksum = reader.u32("checksum");
        long flags = reader.u32("flags");
        reader.bytes(8, "reserved header");
        if (version != 1) {
            throw new FormatException("unsupported filesystem version", 8);
        }
        if (blockSize < 512 || blockSize > 65536
            || !powerOfTwo(blockSize)) {
            throw new FormatException("block size is invalid", 12);
        }
        if (blockCount <= 0 || blockCount > 4_000_000L
            || inodeCount < 0 || inodeCount > MAX_INODES
            || rootInode <= 0) {
            throw new FormatException(
                "filesystem counts exceed resource limit",
                16
            );
        }
        if (bitmapBytes != (blockCount + 7) / 8) {
            throw new FormatException("bitmap length is inconsistent", 48);
        }
        if (deviceBytes != checkedMultiply(blockCount, blockSize, 80)) {
            throw new FormatException("device length is inconsistent", 80);
        }
        if ((flags & ~1L) != 0) {
            throw new FormatException("unknown filesystem flags", 100);
        }
        long total = HEADER_SIZE;
        for (long length : new long[] {
            bitmapBytes, inodeBytes, directoryBytes, journalBytes, deviceBytes
        }) {
            total = checkedAdd(total, length, 48);
        }
        if (total != data.length) {
            throw new FormatException(
                "section sizes do not match image length",
                48
            );
        }
        if (checksum != crc32(data, HEADER_SIZE, data.length - HEADER_SIZE)) {
            throw new FormatException("filesystem checksum mismatch", 96);
        }
        return new Header(
            version,
            blockSize,
            blockCount,
            inodeCount,
            rootInode,
            generation,
            bitmapBytes,
            inodeBytes,
            directoryBytes,
            journalBytes,
            deviceBytes,
            nextInode,
            checksum,
            (flags & 1) != 0
        );
    }

    private static Inode parseInode(Reader record, Header header)
        throws FormatException {
        byte[] raw = record.buffer.array();
        if (raw.length < 91
            || raw[0] != 'B' || raw[1] != 'F'
            || raw[2] != 'I' || raw[3] != 'N') {
            throw new FormatException(
                "inode signature is invalid",
                record.origin
            );
        }
        long stored = readUnsignedInt(raw, raw.length - 4);
        if (stored != crc32(raw, 0, raw.length - 4)) {
            throw new FormatException(
                "inode checksum mismatch",
                record.origin + raw.length - 4
            );
        }
        Reader reader = new Reader(
            java.util.Arrays.copyOfRange(raw, 4, raw.length - 4),
            record.origin + 4
        );
        long identifier = reader.u64("inode identifier");
        int type = reader.u8("inode type");
        int mode = reader.u16("inode mode");
        reader.u32("inode owner");
        reader.u32("inode group");
        long links = reader.u32("inode link count");
        long size = reader.u64("inode size");
        long allocatedBytes = reader.u64("inode allocated bytes");
        reader.u64("created time");
        reader.u64("modified time");
        reader.u64("changed time");
        long generation = reader.u64("inode generation");
        int deleted = reader.u8("inode deletion flag");
        long extentCount = reader.u32("extent count");
        long attributeCount = reader.u32("attribute count");
        String symlink = reader.text(MAX_PATH, "symbolic-link target");
        if (identifier <= 0 || type < 1 || type > 3 || links <= 0
            || size < 0 || size > 64L * 1024L * 1024L
            || allocatedBytes < 0
            || allocatedBytes > 64L * 1024L * 1024L
            || deleted > 1 || extentCount > 65536
            || attributeCount > 1_000_000) {
            throw new FormatException("inode fields are invalid", record.origin);
        }
        List<Extent> extents = new ArrayList<>();
        long previousEnd = 0;
        long physicalBlocks = 0;
        for (int index = 0; index < extentCount; index++) {
            long logical = reader.u64("extent logical block");
            long physical = reader.u64("extent physical block");
            long count = reader.u32("extent block count");
            int sparse = reader.u8("extent sparse flag");
            if (count <= 0 || sparse > 1 || logical < previousEnd) {
                throw new FormatException(
                    "extent is empty, overlapping, or malformed",
                    reader.offset()
                );
            }
            long logicalEnd = checkedAdd(logical, count, reader.offset());
            if (sparse == 0) {
                long physicalEnd =
                    checkedAdd(physical, count, reader.offset());
                if (physicalEnd > header.blockCount()) {
                    throw new FormatException(
                        "extent exceeds filesystem",
                        reader.offset()
                    );
                }
                physicalBlocks =
                    checkedAdd(physicalBlocks, count, reader.offset());
            }
            previousEnd = logicalEnd;
            extents.add(new Extent(logical, physical, count, sparse != 0));
        }
        if (checkedMultiply(
                physicalBlocks,
                header.blockSize(),
                reader.offset()) != allocatedBytes) {
            throw new FormatException(
                "allocated byte count differs from extents",
                record.origin
            );
        }
        Set<String> attributeNames = new HashSet<>();
        long attributeBytes = 0;
        for (int index = 0; index < attributeCount; index++) {
            String name = reader.text(MAX_NAME, "attribute name");
            long length = reader.u32("attribute value length");
            if (length > 4L * 1024L * 1024L) {
                throw new FormatException(
                    "attribute exceeds resource limit",
                    reader.offset()
                );
            }
            reader.bytes((int) length, "attribute value");
            if (name.isEmpty() || !attributeNames.add(name)) {
                throw new FormatException(
                    "attribute name is empty or duplicated",
                    reader.offset()
                );
            }
            attributeBytes = checkedAdd(
                attributeBytes,
                name.length() + length,
                reader.offset()
            );
            if (attributeBytes > 4L * 1024L * 1024L) {
                throw new FormatException(
                    "attribute area exceeds resource limit",
                    reader.offset()
                );
            }
        }
        if (reader.remaining() != 0) {
            throw new FormatException(
                "inode has trailing bytes",
                reader.offset()
            );
        }
        return new Inode(
            identifier,
            type,
            mode,
            links,
            size,
            allocatedBytes,
            generation,
            deleted != 0,
            symlink,
            extents,
            (int) attributeCount
        );
    }

    private static List<Inode> parseInodes(
        Reader section,
        Header header
    ) throws FormatException {
        long count = section.u32("inode count");
        if (count != header.inodeCount()) {
            throw new FormatException(
                "inode section count differs from header",
                section.offset() - 4
            );
        }
        List<Inode> output = new ArrayList<>();
        Set<Long> identifiers = new HashSet<>();
        for (int index = 0; index < count; index++) {
            long length = section.u32("inode record length");
            if (length > MAX_RECORD) {
                throw new FormatException(
                    "inode record exceeds resource limit",
                    section.offset() - 4
                );
            }
            Inode inode =
                parseInode(section.subreader((int) length, "inode"), header);
            if (!identifiers.add(inode.identifier())) {
                throw new FormatException(
                    "duplicate inode identifier",
                    section.offset()
                );
            }
            output.add(inode);
        }
        if (section.remaining() != 0
            || !identifiers.contains(header.rootInode())) {
            throw new FormatException(
                "inode section has trailing bytes or lacks root",
                section.offset()
            );
        }
        return output;
    }

    private static List<DirectoryEntry> parseDirectoryRecord(
        Reader record
    ) throws FormatException {
        byte[] raw = record.buffer.array();
        if (raw.length < 12
            || raw[0] != 'B' || raw[1] != 'F'
            || raw[2] != 'D' || raw[3] != 'R') {
            throw new FormatException(
                "directory signature is invalid",
                record.origin
            );
        }
        long stored = readUnsignedInt(raw, raw.length - 4);
        if (stored != crc32(raw, 0, raw.length - 4)) {
            throw new FormatException(
                "directory checksum mismatch",
                record.origin + raw.length - 4
            );
        }
        Reader reader = new Reader(
            java.util.Arrays.copyOfRange(raw, 4, raw.length - 4),
            record.origin + 4
        );
        long count = reader.u32("directory entry count");
        if (count > 1_000_000) {
            throw new FormatException(
                "directory entry count exceeds limit",
                reader.offset() - 4
            );
        }
        List<DirectoryEntry> output = new ArrayList<>();
        Set<String> names = new HashSet<>();
        for (int index = 0; index < count; index++) {
            long start = reader.offset();
            long recordLength = reader.u32("entry record length");
            long inode = reader.u64("entry inode");
            int type = reader.u8("entry type");
            int deleted = reader.u8("entry deletion flag");
            int nameLength = reader.u16("entry name length");
            if (recordLength < 16 || (recordLength & 7) != 0
                || recordLength > reader.remaining() + 16L
                || nameLength > MAX_NAME
                || nameLength > recordLength - 16
                || inode <= 0 || type < 1 || type > 3 || deleted > 1) {
                throw new FormatException(
                    "directory entry fields are invalid",
                    start
                );
            }
            byte[] nameBytes = reader.bytes(nameLength, "entry name");
            String name;
            try {
                name = StandardCharsets.UTF_8.newDecoder()
                    .onMalformedInput(CodingErrorAction.REPORT)
                    .decode(ByteBuffer.wrap(nameBytes))
                    .toString();
            } catch (CharacterCodingException error) {
                throw new FormatException("entry name is not UTF-8", start);
            }
            int consumed = (int) (reader.offset() - start);
            reader.bytes(
                (int) recordLength - consumed,
                "directory entry padding"
            );
            if (name.isEmpty() || name.indexOf('/') >= 0
                || (!deleted
                    && !names.add(name.toLowerCase(Locale.ROOT)))) {
                throw new FormatException(
                    "entry name is invalid or duplicated",
                    start
                );
            }
            output.add(
                new DirectoryEntry(
                    inode,
                    type,
                    name,
                    (int) recordLength,
                    deleted != 0
                )
            );
        }
        if (reader.remaining() != 0) {
            throw new FormatException(
                "directory record has trailing bytes",
                reader.offset()
            );
        }
        return output;
    }

    private static List<Directory> parseDirectories(
        Reader section,
        Set<Long> inodeIdentifiers
    ) throws FormatException {
        long count = section.u32("directory count");
        if (count > inodeIdentifiers.size()) {
            throw new FormatException(
                "directory count exceeds inode count",
                section.offset() - 4
            );
        }
        List<Directory> output = new ArrayList<>();
        Set<Long> identifiers = new HashSet<>();
        for (int index = 0; index < count; index++) {
            long identifier = section.u64("directory inode");
            long length = section.u32("directory record length");
            if (!inodeIdentifiers.contains(identifier)
                || !identifiers.add(identifier)
                || length > MAX_RECORD) {
                throw new FormatException(
                    "directory identifier or length is invalid",
                    section.offset()
                );
            }
            List<DirectoryEntry> entries = parseDirectoryRecord(
                section.subreader((int) length, "directory record")
            );
            boolean self = entries.stream().anyMatch(
                entry -> !entry.deleted()
                    && entry.name().equals(".")
                    && entry.inode() == identifier
            );
            if (!self) {
                throw new FormatException(
                    "directory lacks self entry",
                    section.offset()
                );
            }
            output.add(new Directory(identifier, entries));
        }
        if (section.remaining() != 0) {
            throw new FormatException(
                "directory section has trailing bytes",
                section.offset()
            );
        }
        return output;
    }

    private static List<JournalRecord> parseJournal(Reader section)
        throws FormatException {
        byte[] signature = section.bytes(8, "journal signature");
        byte[] expected = {'B', 'F', 'J', 'N', 'L', '1', 0, 0};
        if (!java.util.Arrays.equals(signature, expected)
            || section.u32("journal version") != 1) {
            throw new FormatException(
                "journal signature or version is invalid",
                section.origin
            );
        }
        long count = section.u32("journal record count");
        if (count > 1_000_000) {
            throw new FormatException(
                "journal record count exceeds limit",
                section.offset() - 4
            );
        }
        List<JournalRecord> output = new ArrayList<>();
        long previous = 0;
        for (int index = 0; index < count; index++) {
            long start = section.offset();
            long length = section.u32("journal record length");
            if (length < 48 || length > section.remaining() + 4L) {
                throw new FormatException(
                    "journal record length is invalid",
                    start
                );
            }
            int type = section.u16("journal type");
            int flags = section.u16("journal flags");
            long sequence = section.u64("journal sequence");
            long transaction = section.u64("journal transaction");
            long target = section.u64("journal target");
            long generation = section.u64("journal generation");
            long payloadLength = section.u32("journal payload length");
            if (payloadLength != length - 48 || payloadLength > MAX_RECORD) {
                throw new FormatException(
                    "journal payload length is inconsistent",
                    section.offset() - 4
                );
            }
            byte[] payload = section.bytes(
                (int) payloadLength,
                "journal payload"
            );
            long stored = section.u32("journal checksum");
            int encodedOffset = (int) (start - section.origin + 4);
            int encodedLength = (int) length - 8;
            if (stored != crc32(
                    section.buffer.array(),
                    encodedOffset,
                    encodedLength)
                || type < 1 || type > 12 || flags != 0
                || sequence <= previous) {
                throw new FormatException(
                    "journal checksum or fields are invalid",
                    start
                );
            }
            output.add(
                new JournalRecord(
                    type,
                    sequence,
                    transaction,
                    target,
                    generation,
                    payload.length
                )
            );
            previous = sequence;
        }
        if (section.remaining() != 0) {
            throw new FormatException(
                "journal has trailing bytes",
                section.offset()
            );
        }
        return output;
    }

    public static Image read(Path path)
        throws IOException, FormatException {
        long fileSize = Files.size(path);
        if (fileSize > MAX_IMAGE) {
            throw new FormatException(
                "filesystem image exceeds resource limit",
                0
            );
        }
        byte[] data = Files.readAllBytes(path);
        Header header = parseHeader(data);
        Reader reader = new Reader(data);
        reader.bytes(HEADER_SIZE, "filesystem header");
        byte[] bitmap = reader.bytes(
            (int) header.bitmapBytes(),
            "allocation bitmap"
        );
        Reader inodeSection = reader.subreader(
            (int) header.inodeBytes(),
            "inode section"
        );
        Reader directorySection = reader.subreader(
            (int) header.directoryBytes(),
            "directory section"
        );
        Reader journalSection = reader.subreader(
            (int) header.journalBytes(),
            "journal section"
        );
        reader.bytes((int) header.deviceBytes(), "block device");
        if (reader.remaining() != 0) {
            throw new FormatException(
                "filesystem has trailing bytes",
                reader.offset()
            );
        }
        long allocated = 0;
        for (byte value : bitmap) {
            allocated += Integer.bitCount(value & 0xff);
        }
        List<Inode> inodes = parseInodes(inodeSection, header);
        Set<Long> identifiers = new HashSet<>();
        for (Inode inode : inodes) {
            identifiers.add(inode.identifier());
        }
        List<Directory> directories = parseDirectories(
            directorySection,
            identifiers
        );
        List<JournalRecord> journal = parseJournal(journalSection);
        return new Image(
            header,
            inodes,
            directories,
            journal,
            allocated,
            sha256(data)
        );
    }

    private static String sha256(byte[] data) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            StringBuilder output = new StringBuilder();
            for (byte value : digest.digest(data)) {
                output.append(
                    String.format(Locale.ROOT, "%02x", value & 0xff)
                );
            }
            return output.toString();
        } catch (NoSuchAlgorithmException impossible) {
            throw new AssertionError(impossible);
        }
    }

    private static String typeName(int type) {
        return switch (type) {
            case 1 -> "file";
            case 2 -> "directory";
            case 3 -> "symlink";
            default -> "unknown";
        };
    }

    private static void print(Path path, Image image, boolean verbose) {
        long files = image.inodes().stream()
            .filter(inode -> inode.type() == 1)
            .count();
        long directories = image.inodes().stream()
            .filter(inode -> inode.type() == 2)
            .count();
        long symlinks = image.inodes().stream()
            .filter(inode -> inode.type() == 3)
            .count();
        long logicalBytes = image.inodes().stream()
            .filter(inode -> inode.type() == 1)
            .mapToLong(Inode::size)
            .sum();
        System.out.printf(
            Locale.ROOT,
            "%s: blocks=%d/%d inodes=%d files=%d directories=%d "
                + "symlinks=%d logical-bytes=%d journal=%d dirty=%s%n",
            path,
            image.allocatedBlocks(),
            image.header().blockCount(),
            image.inodes().size(),
            files,
            directories,
            symlinks,
            logicalBytes,
            image.journal().size(),
            image.header().dirty()
        );
        System.out.println("  SHA-256: " + image.sha256());
        if (!verbose) {
            return;
        }
        for (Inode inode : image.inodes()) {
            System.out.printf(
                Locale.ROOT,
                "  inode=%d type=%s mode=%04o links=%d size=%d "
                    + "allocated=%d extents=%d attributes=%d%n",
                inode.identifier(),
                typeName(inode.type()),
                inode.mode(),
                inode.links(),
                inode.size(),
                inode.allocatedBytes(),
                inode.extents().size(),
                inode.attributeCount()
            );
            if (!inode.symlink().isEmpty()) {
                System.out.println("    -> " + inode.symlink());
            }
        }
        for (Directory directory : image.directories()) {
            System.out.println("  directory inode=" + directory.inode());
            for (DirectoryEntry entry : directory.entries()) {
                System.out.printf(
                    Locale.ROOT,
                    "    %s%-20s -> %-8d %s%n",
                    entry.deleted() ? "(deleted) " : "",
                    entry.name(),
                    entry.inode(),
                    typeName(entry.type())
                );
            }
        }
    }

    private static void usage() {
        System.err.println(
            "Usage: BlockForgeInspector [--verbose] IMAGE..."
        );
    }

    public static void main(String[] arguments) {
        boolean verbose = false;
        List<Path> paths = new ArrayList<>();
        for (String argument : arguments) {
            if (argument.equals("--verbose")) {
                verbose = true;
            } else if (argument.startsWith("-")) {
                usage();
                System.exit(2);
            } else {
                paths.add(Path.of(argument));
            }
        }
        if (paths.isEmpty()) {
            usage();
            System.exit(2);
        }
        try {
            for (Path path : paths) {
                print(path, read(path), verbose);
            }
        } catch (IOException | FormatException error) {
            System.err.println("BlockForgeInspector: " + error.getMessage());
            System.exit(1);
        }
    }
}
