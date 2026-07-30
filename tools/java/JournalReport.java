package blockforge.tools;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.EnumMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.zip.CRC32;

/** Standalone transaction lifecycle analyzer for BlockForge journal sections. */
public final class JournalReport {
    private static final int IMAGE_HEADER_BYTES = 112;
    private static final byte[] IMAGE_SIGNATURE = {
        'B', 'F', 'I', 'M', 'G', '1', 0, 0
    };
    private static final byte[] JOURNAL_SIGNATURE = {
        'B', 'F', 'J', 'N', 'L', '1', 0, 0
    };

    private JournalReport() {
    }

    public enum Type {
        BEGIN,
        ALLOCATE_INODE,
        FREE_INODE,
        ALLOCATE_BLOCK,
        FREE_BLOCK,
        WRITE_INODE,
        WRITE_DIRECTORY,
        WRITE_DATA,
        RENAME_ENTRY,
        COMMIT,
        ROLLBACK,
        CHECKPOINT;

        static Type fromCode(int code) throws FormatException {
            if (code < 1 || code > values().length) {
                throw new FormatException("invalid journal type " + code);
            }
            return values()[code - 1];
        }
    }

    public static final class FormatException extends Exception {
        FormatException(String message) {
            super(message);
        }
    }

    public record Record(
        Type type,
        long sequence,
        long transaction,
        long target,
        long generation,
        int payloadBytes
    ) {
    }

    private static final class Transaction {
        final long identifier;
        long firstSequence;
        long lastSequence;
        int mutations;
        long payloadBytes;
        String outcome = "incomplete";
        final List<String> warnings = new ArrayList<>();

        Transaction(long identifier) {
            this.identifier = identifier;
        }

        void accept(Record record) {
            if (firstSequence == 0) {
                firstSequence = record.sequence();
            }
            lastSequence = record.sequence();
            payloadBytes += record.payloadBytes();
            if (record.type() != Type.BEGIN
                && record.type() != Type.COMMIT
                && record.type() != Type.ROLLBACK) {
                mutations++;
            }
            if (record.type() == Type.COMMIT) {
                if (!outcome.equals("incomplete")) {
                    warnings.add("transaction completes more than once");
                }
                outcome = "committed";
            } else if (record.type() == Type.ROLLBACK) {
                if (!outcome.equals("incomplete")) {
                    warnings.add("transaction completes more than once");
                }
                outcome = "rolled_back";
            }
        }
    }

    private static long u32(byte[] data, int offset) {
        return Integer.toUnsignedLong(
            ByteBuffer.wrap(data, offset, 4)
                .order(ByteOrder.LITTLE_ENDIAN)
                .getInt()
        );
    }

    private static long u64(byte[] data, int offset) {
        return ByteBuffer.wrap(data, offset, 8)
            .order(ByteOrder.LITTLE_ENDIAN)
            .getLong();
    }

    private static boolean signature(
        byte[] data,
        int offset,
        byte[] expected
    ) {
        if (offset < 0 || expected.length > data.length - offset) {
            return false;
        }
        for (int index = 0; index < expected.length; index++) {
            if (data[offset + index] != expected[index]) {
                return false;
            }
        }
        return true;
    }

    public static List<Record> read(Path path)
        throws IOException, FormatException {
        byte[] image = Files.readAllBytes(path);
        if (image.length < IMAGE_HEADER_BYTES
            || !signature(image, 0, IMAGE_SIGNATURE)) {
            throw new FormatException("filesystem image header is invalid");
        }
        long bitmapBytes = u64(image, 48);
        long inodeBytes = u64(image, 56);
        long directoryBytes = u64(image, 64);
        long journalBytes = u64(image, 72);
        long journalOffset = IMAGE_HEADER_BYTES;
        for (long length : new long[] {
            bitmapBytes, inodeBytes, directoryBytes
        }) {
            if (length < 0 || journalOffset > Long.MAX_VALUE - length) {
                throw new FormatException("section offset overflows");
            }
            journalOffset += length;
        }
        if (journalOffset > Integer.MAX_VALUE
            || journalBytes < 16
            || journalBytes > image.length - journalOffset
            || !signature(image, (int) journalOffset, JOURNAL_SIGNATURE)) {
            throw new FormatException("journal section is invalid");
        }
        int offset = (int) journalOffset;
        long version = u32(image, offset + 8);
        long count = u32(image, offset + 12);
        if (version != 1 || count > 1_000_000) {
            throw new FormatException("journal version or count is invalid");
        }
        int position = offset + 16;
        int end = (int) (journalOffset + journalBytes);
        long previous = 0;
        List<Record> records = new ArrayList<>();
        for (int index = 0; index < count; index++) {
            if (end - position < 48) {
                throw new FormatException("journal record is truncated");
            }
            long length = u32(image, position);
            if (length < 48 || length > end - position) {
                throw new FormatException("journal record length is invalid");
            }
            int typeCode = Byte.toUnsignedInt(image[position + 4])
                | (Byte.toUnsignedInt(image[position + 5]) << 8);
            int flags = Byte.toUnsignedInt(image[position + 6])
                | (Byte.toUnsignedInt(image[position + 7]) << 8);
            long sequence = u64(image, position + 8);
            long transaction = u64(image, position + 16);
            long target = u64(image, position + 24);
            long generation = u64(image, position + 32);
            long payloadBytes = u32(image, position + 40);
            if (flags != 0 || payloadBytes != length - 48
                || sequence <= previous) {
                throw new FormatException(
                    "journal record fields are inconsistent"
                );
            }
            long stored = u32(image, position + (int) length - 4);
            CRC32 crc = new CRC32();
            crc.update(image, position + 4, (int) length - 8);
            if (stored != crc.getValue()) {
                throw new FormatException("journal record checksum mismatch");
            }
            records.add(
                new Record(
                    Type.fromCode(typeCode),
                    sequence,
                    transaction,
                    target,
                    generation,
                    (int) payloadBytes
                )
            );
            previous = sequence;
            position += (int) length;
        }
        if (position != end) {
            throw new FormatException("journal section has trailing bytes");
        }
        return records;
    }

    private static void report(Path path, List<Record> records) {
        Map<Long, Transaction> transactions = new LinkedHashMap<>();
        EnumMap<Type, Integer> counts = new EnumMap<>(Type.class);
        List<String> warnings = new ArrayList<>();
        long active = 0;
        int checkpoints = 0;
        for (Record record : records) {
            counts.merge(record.type(), 1, Integer::sum);
            if (record.type() == Type.CHECKPOINT) {
                checkpoints++;
                if (active != 0) {
                    warnings.add(
                        "checkpoint " + record.sequence()
                            + " occurs inside transaction " + active
                    );
                }
                continue;
            }
            Transaction transaction = transactions.computeIfAbsent(
                record.transaction(),
                Transaction::new
            );
            if (record.type() == Type.BEGIN) {
                if (active != 0) {
                    transaction.warnings.add("nested transaction");
                }
                active = record.transaction();
            } else if (record.type() == Type.COMMIT
                       || record.type() == Type.ROLLBACK) {
                if (active != record.transaction()) {
                    transaction.warnings.add(
                        "completion has no matching active transaction"
                    );
                }
                active = 0;
            } else if (active != record.transaction()) {
                transaction.warnings.add(
                    "mutation occurs outside matching transaction"
                );
            }
            transaction.accept(record);
        }
        if (active != 0) {
            warnings.add("journal ends inside transaction " + active);
        }
        System.out.printf(
            Locale.ROOT,
            "%s: records=%d transactions=%d checkpoints=%d warnings=%d%n",
            path,
            records.size(),
            transactions.size(),
            checkpoints,
            warnings.size()
        );
        for (Type type : Type.values()) {
            int count = counts.getOrDefault(type, 0);
            if (count != 0) {
                System.out.printf(
                    Locale.ROOT,
                    "  %-18s %d%n",
                    type,
                    count
                );
            }
        }
        for (Transaction transaction : transactions.values()) {
            System.out.printf(
                Locale.ROOT,
                "  tx=%d seq=%d..%d outcome=%s mutations=%d payload=%d%n",
                transaction.identifier,
                transaction.firstSequence,
                transaction.lastSequence,
                transaction.outcome,
                transaction.mutations,
                transaction.payloadBytes
            );
            for (String warning : transaction.warnings) {
                System.out.println("    warning: " + warning);
            }
        }
        for (String warning : warnings) {
            System.out.println("  warning: " + warning);
        }
    }

    private static void usage() {
        System.err.println("Usage: JournalReport IMAGE...");
    }

    public static void main(String[] arguments) {
        if (arguments.length == 0) {
            usage();
            System.exit(2);
        }
        try {
            for (String argument : arguments) {
                report(Path.of(argument), read(Path.of(argument)));
            }
        } catch (IOException | FormatException error) {
            System.err.println("JournalReport: " + error.getMessage());
            System.exit(1);
        }
    }
}
