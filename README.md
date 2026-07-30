# BlockForge

BlockForge is an original C++17 userspace filesystem-image implementation for
bounded processing of hostile images. It implements a block device, allocation
bitmap, typed inodes, directory records, sparse and fragmented extents, bounded
path and symbolic-link resolution, journal records, transactional operations,
portable image serialization, consistency analysis, and repair planning.

The core has no third-party dependencies and builds completely offline.
Independent C, Python, and Java tools inspect the portable image format.

Five libFuzzer harnesses are provided:

- `filesystem_mount_fuzzer`
- `filesystem_walk_fuzzer`
- `filesystem_read_fuzzer`
- `filesystem_repair_fuzzer`
- `filesystem_operation_fuzzer`

Each harness has its own structured seed corpus under `fuzz/corpus/`.

Copyright (c) 2026. All rights reserved. This private repository may not be
redistributed or published.
