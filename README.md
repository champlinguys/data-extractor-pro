# Data Extractor Pro

A disk-image data-recovery tool in the spirit of DMDE / R-Studio: open a raw
disk image, browse its filesystems in a tree, preview files, and export them - including reconstructing **Intel Optane Memory (H10/H20)** volumes from a
paired QLC-NAND image and Optane-cache image.

> **Recovering data from an Optane laptop?** Follow the plain-English,
> step-by-step guide in **[RECOVERY.md](RECOVERY.md)** - from making a boot USB
> to exporting the files.

## Download
Prebuilt Linux binaries are on the [Releases](../../releases) page - no building
required. The latest version is **v0.4.0**.

**GUI** (Qt and OpenSSL are bundled in, so there are no dependencies to install):
```sh
wget https://github.com/champlinguys/data-extractor-pro/releases/download/v0.4.0/DataExtractorPro-x86_64.AppImage
chmod +x DataExtractorPro-x86_64.AppImage
./DataExtractorPro-x86_64.AppImage
```

**Headless CLI**:
```sh
wget https://github.com/champlinguys/data-extractor-pro/releases/download/v0.4.0/de-cli-linux-x86_64.tar.gz
tar xzf de-cli-linux-x86_64.tar.gz
./de-cli
```

Prefer to build from source? See [Building](#building) below.

Status:
- **NTFS** open -> browse -> export - working (Qt5 GUI + CLI).
- **Intel Optane reconstruction (span merge)** - working: merges a QLC + Optane
  image into the reconstructed disk. An oracle-backed coverage study (see
  `src/optane/FORMAT_NOTES.md section 3b`) showed this span+QLC reconstruction is
  **~99.9 % correct** - the linear span is authoritative for the volume start,
  and QLC is authoritative beyond it. Rare recently-written deep files can live
  in the Optane's hashed NV-cache (undecoded); these are a < 0.2 % residual not
  currently recovered.
- **BitLocker decryption** - working: recovery password -> VMK -> FVEK, then
  AES-XTS-128/256 or AES-CBC-128/256 sector decryption, browse/extract the
  decrypted NTFS. Enter the recovery key up front (Open Optane Set) or
  right-click a locked BitLocker partition to unlock it in place. The AES-XTS
  path is validated byte-for-byte against a reference recovery tool on a real
  Optane H10 case; the Elephant-diffuser CBC variants are not yet supported.
- **FileVault 2 / CoreStorage decryption** - working, given the volume key:
  AES-XTS decryption of the CoreStorage logical volume, then browse/extract the
  HFS+ inside. Right-click a locked FileVault 2 partition to unlock it in place,
  or pass `--volume-key <hex>` to the CLI. The logical volume's start is found
  by trial-decrypting the HFS+ header rather than assumed, so a key that
  verifies has proved the offset with it. Validated byte-for-byte against
  libfvde on a real 12.73 TiB FileVault 2 case (20/20 exact 4 KiB matches from
  1 KiB to 928 GiB), and - unlike libfvde, which refuses every read past 1 TiB -
  it reads the whole volume: files at 1.25-1.54 TiB extract intact.
  Deriving the volume key from the user's passphrase is not implemented yet;
  the key is supplied ready-made.

- **Classic HFS (pre-HFS+)** - working: the 1985-1998 Macintosh filesystem
  found on old Mac floppies and small disks, which mainstream tools (Sleuth
  Kit, DMDE) refuse to open. Parses the Master Directory Block, reassembles
  the Catalog and Extents-Overflow B-trees (including fragmented catalogs),
  walks the full directory tree, and exports both data and resource forks
  (resource forks as `<name>.rsrc` sidecars). Validated byte-for-byte against
  a reference Python implementation on two real 1.44 MB customer floppies,
  including heavily fragmented forks.

- **HFS+ / HFSX** - working: Mac OS Extended, the filesystem on most Mac
  external drives formatted before APFS. Volume header, catalog and
  extents-overflow B-trees walked lazily (nothing is loaded up front, so a
  multi-terabyte volume opens instantly), fragmented files via the
  extents-overflow tree, hard links, resource forks, and transparently
  compressed files. Verified byte-for-byte against filesystems created and
  populated by Linux's own `mkfs.hfsplus`/`hfsplus` driver, including a
  60-extent fragmented file and a 4000-entry directory (`tools/verify_hfsplus.sh`).

- **RAID / multi-drive sets** - working: present two or more drives as one
  disk - RAID 0 (striped), concatenated/JBOD, or RAID 1 (mirrored, with reads
  falling back to the other member when one drive has bad sectors). If you do
  not know how the set was configured, it works the geometry out and *verifies*
  it (see below). Verified end-to-end on striped sets at four stripe sizes and
  on a concatenated set, in each case recovering the geometry with no hints and
  reading every file back byte-for-byte (`tools/verify_raid.sh`).

- **APFS** - working: containers and their volumes, the object map and
  filesystem B-trees, sparse and multi-extent files, extended attributes, and
  Fusion (two-device) containers. FileVault-encrypted volumes are identified
  and reported, not decrypted. Verified against synthetic containers built by
  `tools/mkapfs.py`, including a multi-level B-tree.

- **exFAT** - working: the filesystem on essentially every large removable
  drive - external USB disks over 32 GB, SDXC cards, and anything that has to
  be readable on both Windows and macOS. Boot sector (with a fall back to the
  backup boot region at sector 12 when the primary is damaged), FAT chains,
  contiguous `NoFatChain` allocations, directory entry sets, UTF-16 long names
  and the local-time-plus-UTC-offset timestamps. **Deleted files are listed and
  recoverable**: deleting on exFAT only clears an in-use bit, so the entry set -
  name, size and starting cluster included - usually survives intact. Verified
  byte-for-byte against the kernel driver on a 954 GB customer drive and on
  synthetic volumes covering fragmented, nested, Unicode-named and deleted
  files.

- **Apple transparent compression (decmpfs)** - working for both HFS+ and
  APFS: zlib and LZVN, stored in either the attribute or the resource fork.
  Without this a large share of the files on a Mac volume export as zero bytes.
  The LZVN decoder is checked against Apple's own reference encoder from the
  LZFSE project. LZFSE-compressed files are reported as unsupported rather than
  exported as corrupt.

ext4 is on the roadmap below.

## Recovering a two-drive RAID set (e.g. an OWC Gemini)

Add both drives; the geometry is worked out and checked for you:

```sh
# analyse a set: shows every geometry tried, best first, with the evidence
de-cli raid /dev/sdc /dev/sdd

# then use it - any command takes a RAID set in place of an image
de-cli 'raid:auto:/dev/sdc,/dev/sdd'                    # list partitions
de-cli 'raid:auto:/dev/sdc,/dev/sdd' ls 2               # browse the volume
de-cli 'raid:auto:/dev/sdc,/dev/sdd' export 2 28 /mnt/dest/StormySky
```

If you already know the geometry, state it and skip the search:

```sh
de-cli 'raid:stripe:128k:/dev/sdc,/dev/sdd'   # RAID 0, 128 KiB stripe
de-cli 'raid:concat:/dev/sdc,/dev/sdd'        # spanned / JBOD
de-cli 'raid:mirror:/dev/sdc,/dev/sdd'        # RAID 1
```

Where a set writes a descriptor of its own (the OWC Gemini keeps one in the
last sector of each drive), the member order, set name and set size are read
straight out of it; the rest is worked out and, either way, the result is
checked before you rely on it. In the GUI it is
**File -> Open RAID Set** (Ctrl+R), or pass the same spec on the command line:
`data-extractor 'raid:auto:/dev/sdc,/dev/sdd'`. Reading raw drives needs root.

`export` writes a whole folder recursively and preserves dates, which is the
workflow when the destination is smaller than the source: browse, pick the
folders you need, take only those.

## Finding things, and listing the whole volume

Deciding what to recover first means seeing what is there. Search every name
on the volume, or write the entire listing to a file you can keep and search
yourself:

```sh
de-cli disk.img find 2 osage wetland      # case-insensitive, prints full paths
de-cli disk.img tree 2 listing.txt        # every object: size, date, full path
de-cli disk.img tree 2 listing.html       # same, with a search box
de-cli disk.img tree 2 listing.txt listing.html --dirs-only
```

Both formats come from a single pass over the catalog, so asking for both
costs no more than asking for one - worth knowing on a volume where the walk
takes minutes. The HTML page is self-contained (no network, no external
files): folders expand on click, and typing filters every path on the volume,
plain substring or regular expression. It holds the listing as data and
renders only what is on screen, so half a million files stays responsive.

On a 32 TB volume with 617,509 files the walk takes about ten minutes and
produces a 62 MB text listing or a 29 MB HTML page.

### How the geometry is worked out

Guessing wrong is worse than failing, because a wrong stripe size yields a
volume that mounts, lists files, and hands back shredded data. So each
candidate (member order x level x stripe size) is assembled and then judged on
evidence, and contradictions count against it rather than merely failing to
count for it:

- The **backup GPT** in the last sector and the **backup HFS+ volume header**
  at the end of the volume: these only appear if the total size and member
  order are right.
- Whether the volume's own recorded size **fits the space it sits in** - this
  is what catches a stripe read as a mirror.
- A **catalog walk** compared against the file and folder counts the volume
  header records.
- Decisively, **the files themselves**: a sample of files whose names promise a
  known format (`.NEF`, `.JPG`, `.MOV`, ...) must actually start with that
  format's signature. Metadata can survive a wrong geometry - half the address
  space still maps correctly when the guessed stripe is a multiple of the real
  one - but a hundred photo headers cannot.

A geometry that no filesystem confirms is reported as *not* solved, with the
best attempt shown, rather than being offered as an answer.

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

## FileVault 2 (CoreStorage) workflow (CLI)

```sh
# identify the CoreStorage volume and check whether a key unlocks it
de-cli <image> cs 2 --volume-key <hex>
# browse, search and export the HFS+ volume inside
de-cli <image> ls      2         --volume-key <hex>
de-cli <image> find    2 <word>  --volume-key <hex>
de-cli <image> export  2 <recno> <outdir> --volume-key <hex>
```
The volume key is the AES-XTS key pair (cipher key followed by tweak key)
as hex: 64 characters for AES-XTS-128, 128 for AES-XTS-256. `--volume-key`
may appear anywhere on the command line.

## Building

Requires a C++20 compiler, CMake >= 3.16, and Qt5 Widgets.

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=RelWithDebInfo
cmake --build build -j
```

Produces `build/data-extractor` (GUI) and `build/de-cli` (headless).

## Tests

The tricky parsers are checked against filesystems and streams produced by
*other* implementations wherever one exists, rather than only against
themselves:

```sh
tools/verify_hfsplus.sh    # HFS+: mkfs.hfsplus + the kernel driver create it,
                           # we read it back (needs sudo for the loop mount)
tools/verify_raid.sh       # RAID: split a real disk image into members at a
                           # stripe size the detector is not told, then check
                           # it recovers the geometry and every file
python3 tools/verify_apfs.py   # APFS: synthetic containers from tools/mkapfs.py
```

## Using the CLI

```sh
de-cli disk.img                     # list partitions + detected filesystems
de-cli disk.img ls 1                # list the root of partition 1
de-cli disk.img ls 1 65             # list a directory by its MFT record number
de-cli disk.img cat 1 64            # dump a file's data to stdout
de-cli disk.img extract 1 67 out.bin # write one file
de-cli disk.img export 1 65 outdir/  # recursively export a folder, with dates
```

Any of these takes a RAID set in place of `disk.img` - see above.

## Architecture

The engine (`libde_engine`, pure C++/no Qt) is layered so each concern is
independently testable and the hard Optane work slots in without touching the
filesystem parsers.

```
+-----------------------------------------------------+
| GUI (Qt5)              CLI (de-cli)                  |  front-ends
+-----------------------------------------------------+
| Filesystem: NTFS HFS HFS+ APFS exFAT [ext4]         |  fs/ - browse + read
+-----------------------------------------------------+
| Partition scan: MBR / GPT                           |  partition/
+-----------------------------------------------------+
| ImageSource: Raw | SubImage | OptaneMerge |         |  core/ - the key seam
|              BitLocker | RAID (stripe/concat/mirror) |
+-----------------------------------------------------+
```

The pivot is **`ImageSource`** (`src/core/image_source.h`): a raw image, a
single-partition window, the merged Optane volume, and a decrypt-on-read
BitLocker volume are all just byte sources. The filesystem parsers only ever see
"a volume of bytes," so Optane reconstruction, BitLocker decryption and RAID
reassembly are each *a new `ImageSource`, not a change to NTFS/HFS+/APFS/exFAT*.

### What NTFS support does today (`src/fs/ntfs/`)
- Boot-sector geometry (sector/cluster size, MFT location, record size)
- MFT record reads with update-sequence (**fixup**) verification
- Resident and non-resident attribute parsing; signed, variable-width
  **data-run** decoding, including sparse (hole) runs
- Bootstraps from `$MFT`'s own `$DATA` runs, so a **fragmented MFT** is handled
- Directory enumeration via the `$INDEX_ROOT` + `$INDEX_ALLOCATION` B-tree,
  collapsing DOS 8.3 aliases and preserving Unicode names
- Full-file read/export honouring the real data size
- `$STANDARD_INFORMATION` timestamps, so exports keep the dates the files had
  on the original volume (see [Timestamps on export](#timestamps-on-export))

Verified end-to-end against `mkntfs`-generated images (resident files,
multi-run 3 MB file extracted byte-for-byte, subdirectories, Unicode, and an
NTFS-in-GPT-partition layout).

### What classic-HFS support does today (`src/fs/hfs/`)
- Master Directory Block parsing (`BD` signature at sector 2) - allocation
  geometry, volume name (MacRoman -> UTF-8), Catalog/Extents-Overflow extents
- Reassembles the special files by following their extent records, so a
  **fragmented Catalog** (the case that defeats naive readers) works
- Generic classic-HFS B-tree reader: header node, reversed per-node offset
  tables, leaf-chain walk with a scan-all-nodes fallback for damaged headers
- Full tree enumeration with Mac type/creator codes and HFS-epoch timestamps
- Fork reads consult the **Extents-Overflow B-tree** when the three inline
  extents don't cover the logical length (heavily fragmented files)
- Exports **both forks**: data fork as the file, resource fork as a
  `<name>.rsrc` sidecar (via `Filesystem::readResourceFork`, default-empty
  for filesystems without forks)

### Timestamps on export

Exported files and folders are given the **modified and accessed dates recorded
on the source volume** instead of the time of extraction, so a recovery keeps a
sane timeline when the customer uploads it to cloud storage. On by default;
turn it off under *Preferences -> Export -> Timestamps*.

- **NTFS** reads `$STANDARD_INFORMATION` per exported object - the same values
  Explorer and timeline tools show. (The `$FILE_NAME` copy in the directory
  index is cheaper and is what the browser shows, but it goes stale after a
  rename, so it is not what gets written out.)
- **Classic HFS** uses the catalog's modification date. These are whole seconds
  in the Mac's *local* time with no stored UTC offset, so they are carried
  across as-is. HFS records no access time; the modification time is used for
  both.
- Directories are stamped **after** their contents, since writing children
  bumps a directory's own mtime.
- **Creation dates are not restored**: Linux has no portable syscall to set a
  birth time. They are parsed and carried through the model, so a future
  Windows build or a sidecar manifest can use them.
- A file whose source timestamp is missing (0) is left with its extraction
  date rather than being stamped with 1970.

## Roadmap

- **ext4** - superblock, inode + extent tree (and legacy block maps), HTree
  directories. Signature detection already stubbed in `fs_detect.cpp`.
- **LZFSE decmpfs** - compression types 11/12. Currently reported as
  unsupported rather than exported as corrupt.
- **FileVault (encrypted APFS)** - the keybag, and AES-XTS volume decryption.
  Encrypted volumes are already identified and reported.
- **RAID 5/6** - parity sets. Only striping, concatenation and mirroring are
  handled today.
- **RAID descriptors** - the enclosure descriptor in the last sector of each
  member is read for the member order, set name and set size; the stripe size
  and level within it are not decoded yet, so those still come from the
  geometry search. SoftRAID's own format is not published either. The search
  verifies its answer, so these are speed issues rather than correctness ones.
- **Deleted-file recovery** - scavenge unallocated MFT records / inodes;
  `FsNode::isDeleted` is already plumbed through the model.
- NTFS gaps: LZNT1-**compressed** streams and named/alternate data streams.
  (Compressed streams are detected and flagged.)
- **Full Optane reconstruction**: decode the Intel RST hashed NV-cache index to
  recover the last <0.2% of blocks (rare, recently-written data) that the span
  merge does not yet cover. See `src/optane/FORMAT_NOTES.md`.

### How Intel Optane reconstruction works
Optane Memory H10/H20 puts a 3D-XPoint (Optane) cache and a QLC-NAND SSD behind
one M.2 connector, managed by the Intel RST driver. Recent writes can live only
in the Optane cache, so imaging the QLC alone yields a stale, inconsistent
volume; you need both images merged.

`OptaneMergeSource` takes the QLC and Optane images and serves each block from
whichever medium holds its current version, presenting one coherent volume.
Everything above it (partition scanning and the filesystem parsers) runs
unchanged, and a BitLocker partition is handled the same way by an `ImageSource`
that decrypts on read. An oracle-backed coverage study
(`src/optane/FORMAT_NOTES.md`) put the current span+QLC merge at ~99.9% correct;
decoding the RST hashed NV-cache index for the remaining fraction is the one open
item above.

## Layout
```
src/core/        ImageSource, byte-reader helpers
src/partition/   MBR + GPT scanning
src/fs/          Filesystem interface, detector, ntfs/ hfs/ hfsplus/ apfs/ exfat/
src/fs/compression/  Apple decmpfs (zlib, LZVN) shared by HFS+ and APFS
src/raid/        multi-drive assembly + geometry detection
src/gui/         Qt5 main window + hex view
src/cli/         headless driver
tools/           test-image builders and verification scripts
```

## License
Data Extractor Pro is released under the **GNU General Public License v3.0** - see [LICENSE](LICENSE).
