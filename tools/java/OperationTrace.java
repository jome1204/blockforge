package blockforge.tools;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.EnumMap;
import java.util.List;
import java.util.Locale;

/** Decoder and validator for filesystem_operation_fuzzer byte sequences. */
public final class OperationTrace {
    private static final int MAX_OPERATIONS = 4096;

    private OperationTrace() {
    }

    public enum Kind {
        MKDIR,
        CREATE,
        WRITE,
        APPEND,
        READ,
        REMOVE,
        RENAME,
        HARD_LINK,
        SYMLINK,
        LIST,
        WALK,
        BEGIN,
        ROLLBACK,
        COMMIT,
        CHECKPOINT,
        SET_XATTR,
        GET_XATTR,
        REMOVE_XATTR,
        SERIALIZE_REOPEN,
        STAT,
        RECURSIVE_REMOVE;

        static Kind fromByte(int value) {
            return values()[value % values().length];
        }

        boolean mutates() {
            return switch (this) {
                case MKDIR, CREATE, WRITE, APPEND, REMOVE, RENAME,
                     HARD_LINK, SYMLINK, SET_XATTR, REMOVE_XATTR,
                     RECURSIVE_REMOVE -> true;
                default -> false;
            };
        }

        boolean reads() {
            return switch (this) {
                case READ, LIST, WALK, GET_XATTR, STAT -> true;
                default -> false;
            };
        }
    }

    public record Operation(
        int ordinal,
        int raw,
        Kind kind,
        int slot,
        int value,
        int transactionDepth
    ) {
    }

    public record Report(
        Path path,
        int bytes,
        List<Operation> operations,
        List<String> warnings,
        int maximumTransactionDepth
    ) {
        Report {
            operations = List.copyOf(operations);
            warnings = List.copyOf(warnings);
        }

        long mutationCount() {
            return operations.stream()
                .filter(operation -> operation.kind().mutates())
                .count();
        }

        long readCount() {
            return operations.stream()
                .filter(operation -> operation.kind().reads())
                .count();
        }

        EnumMap<Kind, Integer> counts() {
            EnumMap<Kind, Integer> result = new EnumMap<>(Kind.class);
            for (Operation operation : operations) {
                result.merge(operation.kind(), 1, Integer::sum);
            }
            return result;
        }
    }

    public static Report decode(Path path) throws IOException {
        byte[] data = Files.readAllBytes(path);
        int count = Math.min(data.length, MAX_OPERATIONS);
        List<Operation> operations = new ArrayList<>(count);
        List<String> warnings = new ArrayList<>();
        int transactionDepth = 0;
        int maximumDepth = 0;
        for (int index = 0; index < count; index++) {
            int raw = data[index] & 0xff;
            Kind kind = Kind.fromByte(raw);
            if (kind == Kind.BEGIN) {
                if (transactionDepth != 0) {
                    warnings.add(
                        "operation " + index + ": nested BEGIN"
                    );
                }
                transactionDepth++;
                maximumDepth = Math.max(maximumDepth, transactionDepth);
            } else if (kind == Kind.COMMIT || kind == Kind.ROLLBACK) {
                if (transactionDepth == 0) {
                    warnings.add(
                        "operation " + index + ": " + kind
                            + " without BEGIN"
                    );
                } else {
                    transactionDepth--;
                }
            } else if (kind == Kind.CHECKPOINT && transactionDepth != 0) {
                warnings.add(
                    "operation " + index
                        + ": CHECKPOINT inside transaction"
                );
            }
            operations.add(
                new Operation(
                    index,
                    raw,
                    kind,
                    (raw >>> 3) & 31,
                    (raw * 257 + index * 17) & 0xffff,
                    transactionDepth
                )
            );
        }
        if (data.length > MAX_OPERATIONS) {
            warnings.add(
                (data.length - MAX_OPERATIONS)
                    + " operations omitted by resource limit"
            );
        }
        if (transactionDepth != 0) {
            warnings.add(
                "sequence ends with " + transactionDepth
                    + " active transaction(s)"
            );
        }
        return new Report(
            path,
            data.length,
            operations,
            warnings,
            maximumDepth
        );
    }

    private static void print(Report report, boolean verbose) {
        System.out.printf(
            Locale.ROOT,
            "%s: bytes=%d operations=%d mutations=%d reads=%d "
                + "maximum-transaction-depth=%d%n",
            report.path(),
            report.bytes(),
            report.operations().size(),
            report.mutationCount(),
            report.readCount(),
            report.maximumTransactionDepth()
        );
        for (Kind kind : Kind.values()) {
            int count = report.counts().getOrDefault(kind, 0);
            if (count != 0) {
                System.out.printf(
                    Locale.ROOT,
                    "  %-20s %d%n",
                    kind,
                    count
                );
            }
        }
        for (String warning : report.warnings()) {
            System.out.println("  warning: " + warning);
        }
        if (verbose) {
            for (Operation operation : report.operations()) {
                System.out.printf(
                    Locale.ROOT,
                    "  %4d raw=%3d %-20s slot=%2d value=%5d tx=%d%n",
                    operation.ordinal(),
                    operation.raw(),
                    operation.kind(),
                    operation.slot(),
                    operation.value(),
                    operation.transactionDepth()
                );
            }
        }
    }

    private static void usage() {
        System.err.println("Usage: OperationTrace [--verbose] SEED...");
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
                print(decode(path), verbose);
            }
        } catch (IOException error) {
            System.err.println("OperationTrace: " + error.getMessage());
            System.exit(1);
        }
    }
}
