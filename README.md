# Data Extractor Pro

A disk-image data-recovery tool in the spirit of DMDE / R-Studio: open a raw
disk image, browse its filesystems in a tree, preview files, and export them —
including reconstructing **Intel Optane Memory (H10/H20)** volumes from a
paired QLC-NAND image and Optane-cache image.

Status:
- **NTFS** open → browse → export — working (Qt5 GUI + CLI).
- **Intel Optane reconstruction (span merge)** — working: merges a QLC + Optane
  image into the reconstructed disk. An oracle-backed coverage study (see
  `src/optane/FORMAT_NOTES.md §3b`) showed this span+QLC reconstruction is
  **~99.9 % correct** — the linear span is authoritative for the volume start,
  and QLC is authoritative beyond it. Rare recently-written deep files can live
  in the Optane's hashed NV-cache (undecoded); these are a < 0.2 % residual not
  currently recovered.
- **BitLocker decryption** — working: recovery password → VMK → FVEK →
  AES-XTS-128, browse/extract the decrypted NTFS. Validated byte-for-byte
  against UFS Explorer on a real Optane H10 case.

HFS+ and ext4 are on the roadmap below.

## Optane + BitLocker workflow (CLI)

```sh
# reconstruct the disk from the two images and scan partitions
de-cli merge  <qlc.img> <optane.img> <cacheHintSector>
# parse the BitLocker key protectors on the reconstructed volume
de-cli bde    <qlc.img> <optane.img> <cacheHintSector>
# unlock with the 48-digit recovery key and decrypt a test sector
de-cli unlock <qlc.img> <optane.img> <cacheHintSector> <recovery-key> [offset]
# full pipeline: reconstruct + unlock + browse the decrypted NTFS
de-cli browse <qlc.img> <optane.img> <cacheHintSector> <recovery-key> [cat <recno>]
```
`cacheHintSector` is the Intel Cache region start (skips a slow device scan);
find it with `de-cli imsm <optane.img>` if unknown.

## Building

Requires a C++20 compiler, CMake ≥ 3.16, and Qt5 Widgets.

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=RelWithDebInfo
cmake --build build -j
```

Produces `build/data-extractor` (GUI) and `build/de-cli` (headless).

## Using the CLI

```sh
de-cli disk.img                     # list partitions + detected filesystems
de-cli disk.img ls 1                # list the root of partition 1
de-cli disk.img ls 1 65             # list a directory by its MFT record number
de-cli disk.img cat 1 64            # dump a file's data to stdout
de-cli disk.img extract 1 67 out.bin
```

## Architecture

The engine (`libde_engine`, pure C++/no Qt) is layered so each concern is
independently testable and the hard Optane work slots in without touching the
filesystem parsers.

```
┌─────────────────────────────────────────────┐
│ GUI (Qt5)              CLI (de-cli)           │  front-ends
├─────────────────────────────────────────────┤
│ Filesystem: NTFS  [HFS+]  [ext4]              │  fs/ — browse + read
├─────────────────────────────────────────────┤
│ Partition scan: MBR / GPT                     │  partition/
├─────────────────────────────────────────────┤
│ ImageSource: Raw │ SubImage │ [OptaneMerge]   │  core/ — the key seam
└─────────────────────────────────────────────┘
```

The pivot is **`ImageSource`** (`src/core/image_source.h`): a raw image, a
single-partition window, and the future merged Optane view are all just byte
sources. The filesystem parsers only ever see "a volume of bytes," so Optane
reconstruction becomes *a new `ImageSource`, not a change to NTFS/HFS+/ext4*.

### What NTFS support does today (`src/fs/ntfs/`)
- Boot-sector geometry (sector/cluster size, MFT location, record size)
- MFT record reads with update-sequence (**fixup**) verification
- Resident and non-resident attribute parsing; signed, variable-width
  **data-run** decoding, including sparse (hole) runs
- Bootstraps from `$MFT`'s own `$DATA` runs, so a **fragmented MFT** is handled
- Directory enumeration via the `$INDEX_ROOT` + `$INDEX_ALLOCATION` B-tree,
  collapsing DOS 8.3 aliases and preserving Unicode names
- Full-file read/export honouring the real data size

Verified end-to-end against `mkntfs`-generated images (resident files,
multi-run 3 MB file extracted byte-for-byte, subdirectories, Unicode, and an
NTFS-in-GPT-partition layout).

## Roadmap

### Near term
- **ext4** — superblock, inode + extent tree (and legacy block maps), HTree
  directories. Signature detection already stubbed in `fs_detect.cpp`.
- **HFS+/HFSX** — volume header, catalog + extents B-trees. Also stubbed.
- **Deleted-file recovery** — scavenge unallocated MFT records / inodes and
  `FsNode::isDeleted` is already plumbed through the model.
- NTFS gaps: LZNT1-**compressed** streams, named/alternate data streams,
  `$Bitmap`-aware allocation. (Compressed streams are detected and flagged.)
- GUI: recursive folder export, hash-on-export, streaming reads for huge files.

### The headline feature — Intel Optane reconstruction
Optane Memory H10/H20 puts a 3D-XPoint (Optane) cache and a QLC-NAND SSD behind
one M.2 connector, fronted by the Intel RST driver. Recent writes can live only
in the Optane cache, so imaging the QLC alone yields a **stale, inconsistent**
volume. Recovery needs *both* images merged at the correct LBAs.

Planned design — a new `OptaneMergeSource : ImageSource`:
1. Take two child `ImageSource`s: the **QLC** image and the **Optane** image.
2. Parse the **Intel RST cache-mapping metadata** (the pinned/dirty-block
   tables that record which LBA ranges are resident in the cache) to build an
   LBA → {QLC | Optane} translation map.
3. On `readAt(lba)`, serve each block from whichever medium holds its current
   version, transparently presenting a single coherent volume.
4. Everything above — partition scan and the NTFS/ext4/HFS+ parsers — then runs
   unmodified on the merged source.

Because the merge is *just another `ImageSource`*, the entire browse/export
stack works over reconstructed Optane volumes with no parser changes. The open
research task is the exact on-media layout of the RST cache metadata across
driver versions; that reverse-engineering will land in `src/optane/`.

## Layout
```
src/core/        ImageSource, byte-reader helpers
src/partition/   MBR + GPT scanning
src/fs/          Filesystem interface, detector, ntfs/
src/gui/         Qt5 main window + hex view
src/cli/         headless driver
```
