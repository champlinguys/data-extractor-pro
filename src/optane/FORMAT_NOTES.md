# Intel Optane Memory (RST) reconstruction - reverse-engineering notes

Working notes from analysing a real Intel Optane Memory **H10** module
(two NVMe namespaces: QLC = `/dev/nvme0n1`, Optane = `/dev/nvme1n1`), imaged
with ddrescue as `qlc.img` (512 GB) and `optane.img` (27.25 GB).

**These are read-only forensic images. Never write to them.**

## 0. Why reconstruction is mandatory (proven empirically)

The QLC alone gives a **stale, pre-BitLocker** view. At volume sector 567296
(start of partition 3):

| Source | Bytes at 0x03 | Meaning |
|--------|---------------|---------|
| QLC `qlc.img` | `NTFS    ` | old NTFS boot sector (stale) |
| Optane `optane.img` | `-FVE-FS-` | current BitLocker header |

When BitLocker was enabled, the new headers/data were written into the Optane
write-cache and never flushed back to the QLC. Imaging the QLC by itself loses
them. The merged view is what a reference recovery tool shows as `IntelCache::<device-serial-redacted>`,
whose partition 3 is BitLocker (not NTFS).

## 1. Media geometry

```
QLC   qlc.img    512,110,190,592 B = 1,000,215,216 sectors (476.9 GiB)
Optane optane.img 29,260,513,280 B =    57,149,440 sectors (27.25 GiB)
```

A reference tool's interpretation of the Optane device:
- **Span component partition** - sector 0, 7.25 GB   (holds cached DATA blocks)
- **Intel Cache partition** - sector **15206656** (byte 7,785,807,872), 20 GB
  (holds the RST/NV-cache **metadata**, incl. the mapping table)

The Optane image has **no valid GPT** - the leading bytes are RST data, not a
partition table (sector 0 is actually a cached BitLocker/FAT32-style header).

## 2. Metadata signatures (in the Intel Cache region, from sector 15206656)

Two structures, interleaved and stored in **redundant 8 KiB-strided copies**:

| Offset in cache region | Signature (ASCII) | What it is |
|---|---|---|
| `0x0000` | `Intel IMSM NV Cache Cfg. Sig.   ` | Optane NV-cache config (the caching extension) |
| `0x1E00` | `Intel Raid ISM Cfg Sig. 1.4.01`   | standard **IMSM** RAID metadata (mdadm-compatible) |
| `0x2000` | (NV Cache Cfg copy)               | redundant copy |
| `0x3E00` | (IMSM copy)                       | redundant copy |

Device serial / volume name throughout: `<device-serial-redacted>`. RST version `17.0`.

### 2a. IMSM RAID super (`Intel Raid ISM Cfg Sig.`) - DOCUMENTED

This is the same on-disk format Linux `mdadm` implements (`super-intel.c`,
`struct imsm_super`). Parsed values from this module:

```
mpb_size            428
family_num          0xc2f0f054
generation_num      1,060,296
num_disks           1
num_raid_devs       1
disk[0].serial      "<device-serial-redacted>"
disk[0].total_blocks 1,000,215,216   == exact QLC image size  <- the cached disk
dev.volume          "<device-serial-redacted>"
dev.size            1,000,210,695     <- reconstructed logical volume size
```

Field offsets (from mdadm), relative to the signature start:
```
0x00 u8[32] sig            0x38 u8  num_disks       0x50 u64 creation_time
0x20 u32 check_sum         0x39 u8  num_raid_devs   0xD8 imsm_disk[num_disks]
0x24 u32 mpb_size          0x3A u8  error_log_pos   (each imsm_disk = 48 bytes:
0x28 u32 family_num        0x3C u32 cache_size        0x00 u8[16] serial
0x2C u32 generation_num    0x40 u32 orig_family_num   0x10 u32 total_blocks_lo
0x30 u32 error_log_size    0x44 u32 pwr_cycle_count   0x14 u32 scsi_id
0x34 u32 attributes        0x48 u32 bbm_log_size      0x18 u32 status ...)
```
`imsm_dev` (RAID volume) follows the disk array; `total_blocks` = lo | (hi<<32).

**Conclusion:** the IMSM super gives us the logical volume geometry and confirms
the QLC is the backing disk. This part we can parse today (see `imsm.h`).

### 2b. NV Cache Cfg (`Intel IMSM NV Cache Cfg. Sig.`) - the Optane extension

Header (relative to signature start):
```
0x00 u8[32] "Intel IMSM NV Cache Cfg. Sig.   "
0x20 u32 = 0x00aa0006      0x2c u32 = 0xe7000000     0x38 u32 = 0x00030000
0x24 u32 = 0x0000014a(330) 0x30 u32 = 0x0000027f(639)
0x28 u32 = 0x00010001      0x34 u32 = 0
```
Field meanings not yet confirmed (version/counts/flags). The device serial and
`Stat17.0` string also appear in this block.

## 2c. The "span component" is a LINEAR copy of the volume start (CONFIRMED)

The Optane device's first **7.25 GB** (the reference tool's "span component", Optane sectors
0 .. 15206656) is a **linear, sector-for-sector image of the BitLocker volume
starting at its beginning**. Optane byte 0 = BitLocker-partition byte 0.

Proof (self-consistent, three independent oracles): the volume header at Optane
byte 0 lists its FVE metadata copies at partition-relative byte offsets
`0x837b4000`, `0x837c4000`, `0xb2d1c000`. Reading the Optane at *those exact
byte offsets* yields valid `-FVE-FS-` FVE-metadata-block headers whose own
copy-pointer arrays read back the same three offsets. The QLC has only zeros /
stale NTFS at those offsets.

Consequence: for the covered range, reconstruction is trivial - take the bytes
from the Optane span, not the QLC. Crucially this range contains the **BitLocker
FVE metadata**, i.e. everything the decryption layer needs.

Open: the exact end of the linear region and whether it is contiguous or itself
governed by the mapping table (section 3). Confirmed linear at least through 0xb2d1c000
(~2.79 GB).

## 3. The mapping table (partially decoded - the crux, still OPEN)

Located deep in the cache region (~64-72 MiB past the metadata anchor in this
module). It is a **sparse / hashed table of 16-byte records**, NOT a flat sorted
array - records with unrelated keys sit adjacent, so entries are bucketed by a
hash of the key, with mostly-zero slots between.

Record layout (observed):
```
struct nvc_entry {          // 16 bytes
    u32 key;                // a volume LBA (appears in 512B-granular table)
    u32 value;              // a second LBA-sized field
    u64 tail;               // usually 0 - chain pointer / flags / LRU?
};
```

There appear to be **two tables at different granularities**:
- a **512-byte-granular** table (keys are raw volume sectors), and
- a **4 KiB-granular** table (keys are volume sectors >> 3).

Anchor we located (volume sector 567296 = 0x8a800, the BitLocker header):
```
512B table  record: key=0x0008a800  value=0x0008ba40  tail=0
4KiB table  record: 0x000114ef      0x00011500(=567296/8)
```

Reconciliation puzzle: the anchor record `(key=567296, val=571968)` does NOT
say "optane sector 571968" for the header (that reads as encrypted data), yet we
proved the header is physically at Optane byte 0 via the linear span. So either
(a) the record columns are `(start_lba, end_lba)` of a cached extent and the
data location is implied by the linear span offset `(key - partition_start)`, or
(b) there are two independent mechanisms (linear span for a pinned prefix, hash
map for the rest). Keys seen span the whole disk (e.g. 4761, 991558, ...), which a
single span-relative scheme can't cover - pointing at (b). Resolving this is the
remaining crux.

### Structures found so far (corrected)
The cache-metadata region holds at least three distinct structures:
1. **Header block** (`0x0000`, NV Cache Cfg) + IMSM super (`0x1E00`), 8 KiB copies.
2. **Flat sorted u32 index array** at `0x4000`: strictly increasing values
   `1803, 4761, 10693, 991558, 999826, 1006964, ...` (verified authoritative).
   These are NOT (key,val) pairs - a single sorted sequence, ~disk-LBA
   magnitude, entries ~7-8 K sectors apart after an initial jump. Almost
   certainly a **binary-search index of cached disk LBAs / extent starts**. The
   matching Optane locations must live in a *parallel* array (i-th location for
   i-th sorted LBA) - not yet located.
3. **16-byte records** `[u32 a][u32 b][u64 0]` deep in the region (~72 MiB in),
   e.g. `(567296, 571968)` for the BitLocker header sector.

### Hypotheses tested and DISPROVEN (do not retry these)
- `b` (or `val`) is the Optane sector/byte of key's data - reading it gives
  encrypted data, not the `-FVE-FS-` header the anchor must resolve to.
- Reverse map `Optane[a] == Optane[b-partStart]` (span oracle) - no matches.
- 0x4000 as interleaved `(disk_lba, optane_lba)` pairs - the array is a single
  strictly-sorted sequence, so any pairing is an artifact.

### It is a multi-level index (B-tree/hash), not keys+parallel-values
Chasing the "parallel value array" showed the `0x4000` region is a **fixed
16 KiB node**: `[header @0x4000][2543 sorted u32 keys @0x4008..0x67c4]
[0xFFFFFFFF padding to 0x8000]`, then zeros. Critically, the sorted keys span
the **entire 32-bit range** (4761 ... ~0xFFD2C455), far beyond the ~1e9-sector
disk - so they are **hashes / separator keys, not disk LBAs**.

Model that now fits all evidence: a **B-tree (or hashed) index** whose root/
internal node is this 16 KiB block of 2543 separator keys, pointing to leaf
nodes that hold the ~396 K `[u32 a][u32 b][u64 0]` records (~156 records/leaf).
Lookup is: hash(disk_lba) -> binary-search separators -> leaf -> record -> Optane
location. The word `1803` at `0x4004` is not the key count (2543 keys observed);
likely a generation/counter.

Implication: closing this needs a proper index walk (decode the node header +
child pointers + leaf entry semantics), and is best validated with an external
per-sector oracle (a reference tool's reconstructed volume) rather than more
hex-pattern guessing. The three disproven hypotheses above were flat-structure
assumptions that this multi-level model explains away.

### Open questions (what the next session must resolve)
1. **Which column is the Optane location, and in what units + base offset?**
   The value `0x8ba40` read directly as an Optane sector is high-entropy
   (encrypted) data, not the `-FVE-FS-` header - so `value` is **not** a raw
   Optane sector, or the cache-data area has a non-zero base and/or 4 KiB units.
2. **How is the cache-data region addressed?** The reference tool shows a 7.25 GB "span
   component" at Optane sector 0 that likely holds the cached data blocks.
   Need the base offset + granularity that turns a `value` into a byte offset.
3. **Hash/tree structure:** how to look up an arbitrary volume LBA (bucket
   function, collision chaining via `tail`, or a tree we walk).
4. **QLC vs Optane precedence:** presumably "present in cache map => read Optane,
   else read QLC", but confirm dirty vs clean flags in `tail`.

### How to resolve them (method that works here)
We have **ground truth**: for many sectors we can compare QLC (stale) vs the
correct answer. Procedure:
1. Extract the entire mapping table region to a file.
2. Enumerate all non-zero 16-byte records; build candidate `key->value` maps for
   each granularity/units hypothesis.
3. For each hypothesis, reconstruct a few hundred sectors and score them: a
   correct mapping makes partition 3 parse as a coherent BitLocker volume and
   makes the FVE metadata copies (offsets 0x837b4000 / 0x837c4000 / 0xb2d1c000
   from the header) self-consistent. The hypothesis that maximises coherence
   wins.

## 3b. COVERAGE FINDINGS (re-encryption oracle, decisive)

Using the recovered FVEK + a decrypted ground-truth image, we measured, per
volume offset, whether each source holds the correct data. This reframed the
whole problem:

- **Linear span [0, ~7.25 GB) is authoritative.** Sampling 1468 populated
  offsets across the *entire* span range: **99.93 % correct** (decrypt(Optane
  span) == `.dsk`). The only failures are a **~3 MB sliver at the very end**
  (7.422-7.425 GiB): last-200 MB dense sample = 1.5 % wrong, all in the last
  ~3 MB. So the span is a fully linear, correct copy except its tail.
- **Beyond the span, QLC is ~99.8 % authoritative.** High-offset sample
  [8 GB..476 GB]: 494/495 correct. Deep-volume files (the ones the GUI flags as
  possibly stale) are almost always already correct from QLC - **that flag is
  mostly a false alarm.**
- **But beyond-span caching is real, not noise.** Around 386 GiB there is a
  **contiguous 331-block (~170 KB) stale cluster** (a recently-written file);
  its correct data physically exists in the Optane at offset 9,634,217,984,
  i.e. inside the 20 GB **Intel Cache region**, not the span. disk_lba
  810069515 and that location do **not** appear as raw u32 in the metadata head,
  so these blocks are addressed by the **hashed index** (section 3), which remains
  undecoded.

### Consequence for the tool
The current **span + QLC reconstruction is already ~99.9 % correct** and matches
the reference tool for the vast majority of populated data. Residual defects are < 0.1-0.2 %:
(a) the ~3 MB span-tail sliver, and (b) rare beyond-span cached clusters
(recently-written deep files) that live in the Intel Cache region and need the
hashed index to locate. The records enumerated at the region head (section 3) are
dominated by **linear** entries (2956/2956 sampled populated records had their
data at the span offset), confirming the span *is* the cache's linear data
store; they do not reveal the beyond-span/relocated location encoding.

### Records: structure recap (from oracle-backed sampling)
- 396 K `[u32 a][u32 b][u64 0]` records; unique keys 287 ... 41,943,041.
- `a` = a cached disk LBA. Sampled records are 100 % linear
  (data at `(a-PART_START)*512` in the span). `b` ~ `a` +/- small (extent
  bookkeeping / run length), NOT a relocated location for the linear majority.
- The relocated/beyond-span minority is addressed by the hashed index whose
  leaf-location encoding is still not cracked.

## 4. Target reconstruction algorithm

Implement as `OptaneMergeSource : ImageSource` (fits the existing engine seam):
```
readAt(volume_off, len):
    for each block in [volume_off, volume_off+len):
        vlba = block >> 9
        if mapping.lookup(vlba) -> optane_loc:   read Optane at optane_loc
        else:                                     read QLC at vlba
```
Everything above (partition scan, NTFS/etc.) then runs unchanged on the merged
source. After that, partition 3 is BitLocker -> hand the volume to the BitLocker
layer (see `../bitlocker/fve.h`) with the user's recovery key.

## 5. Reproducing the analysis
The reverse-engineering was done with small Python scripts (a re-encryption
oracle plus IMSM/NV-cache parsers) run against a sector-aligned extract of the
cache metadata region:
`dd if=optane.img bs=512 skip=<cache-region-sector> count=262144 of=cache.bin`
These case-specific scripts are not included in this repository. The structural
findings above (IMSM layout, the linear span, and the 16-byte record format) are
device-independent and sufficient to re-derive them.

---

# Variant B: a module with NO linear span (second unit analysed)

A second Optane set (HP Envy, same H10 geometry: QLC 512,110,190,592 B /
1,000,215,216 sectors, Optane 29,260,513,280 B) turned out to use a
**completely different on-media layout**. Everything above describes what is
now "variant A". Do not assume a new module matches it.

## What is NOT there

- **No linear span.** Optane byte 0 is not a boot record - the first ~7 MiB are
  zero apart from four bytes at 0x1B8. `makeSpanMerge()` therefore (correctly)
  declines; the tool now falls back to the QLC with a warning instead of
  refusing to open the case.
- **No `Intel Raid ISM Cfg Sig.` and no `Intel IMSM NV Cache Cfg. Sig.` anywhere
  in the 29 GB Optane image** (verified by a full-image byte scan). This is why
  third-party tools report "no Optane cache found" on such a unit - there is no
  signature for them to anchor on.
- The 28 `-FVE-FS-` hits in the Optane image are all **cached file data** (they
  sit inside a Windows binary's string table, next to `PBKDF2_HMAC_SHA256`,
  `ReFS`, `EXFAT`, `NTFS`), not cached volume headers.

## What IS there

- **The IMSM super lives on the QLC, at `size - 1024`** (i.e. the second-to-last
  sector), not on the Optane - and its first signature byte is zeroed, so it
  reads as `\0ntel Raid ISM Cfg Sig. 1.0.00`. `num_disks` and `num_raid_devs`
  read 0 as well, though `mpb_size` = 264 = 0xD8 + 48 accounts for exactly one
  disk. The structure is otherwise intact and parses at the documented offsets:
  disk[0] serial `PG144401R0512A-1`, `total_blocks` = 1,000,215,216 (the QLC),
  and the `imsm_dev` that follows at 0xD8+48 gives size 1,000,210,695. The
  string `Cache_Volume` appears later in the same block (offset 0x1A0, past
  `mpb_size`); which field owns it is not yet pinned down. RST version string is
  **1.0.00**, not 1.4.01.
- **A mapping/journal region at roughly 0x680000 .. 0x10000000**, then cached
  data (high entropy) beyond it, with large zero holes further in.
- Each 512-byte block of that region starts `[u32 0x0338][u32 count][u32 0]`
  followed by **variable-length records whose length is chosen by a leading
  tag**: tag `0x00008200` introduces a 12-byte record `[tag][u32 a][u32 b]`
  where `a` steps like a disk LBA and `b` is a strictly incrementing
  Optane-side counter; tags such as `0x0180FFFF`, `0x0100FFFF`, `0x00020000`
  introduce 8-byte records `[tag][u32 lba]`. It reads as an **operation log**,
  not a flat table - which fits an append-only write-back cache.
- **A structure at the far end of the device** (from ~`0x6CFE00000`) with magic
  `0xCAFE1150`, holding pairs `[u32 a][u32 ~a]` (the two words always sum to
  0xFFFFFFFF), `a` ascending - most likely a free/erase list with a complement
  check, not a mapping.

## Practical consequence (this unit)

Unlike variant A, **the QLC alone is very nearly complete**: partition 3 already
holds the current `-FVE-FS-` BitLocker header, and both FVE metadata copies
named by that header (partition-relative `0x504B0000` and `0x86854000`) are
present and valid on the QLC. Reconstruction is not required to unlock.

The one thing genuinely missing from the QLC is the **primary GPT header at
LBA 1, which is all zeros** while the entry array at LBA 2 is intact and
current - the classic signature of a block that was written into the cache and
never flushed. The backup GPT at the last sector survives but its entry array is
stale (it still describes a 78 GB partition 3) and partly overwritten by the
RST metadata that shares those sectors. `scanPartitions()` now recovers from
this: geometry from whichever header survives, entries from whichever candidate
array (LBA 2 or the header's) yields more in-range entries, preferring LBA 2.
