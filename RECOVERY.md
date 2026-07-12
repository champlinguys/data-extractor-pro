# Recovering data from an Intel Optane laptop — step-by-step

This guide walks you through pulling the data off a laptop that uses **Intel
Optane Memory (H10/H20)** — the setup where a single M.2 slot holds *two* drives
(a big QLC SSD and a small Optane cache). You have to image **both** and merge
them, because recent files can live only in the Optane cache.

You do **not** need to be an expert, but you will be typing a few commands
exactly as shown. Read each step fully before running it.

> ⚠️ **Golden rule:** we only ever *read* from the laptop's drives. Never let any
> command write to them. The one dangerous mistake is swapping the order of the
> `ddrescue` command — double-check it every time (Step 4).

---

## What you'll need
- The **laptop** (or its Optane M.2 module in a compatible machine).
- A **USB stick** (≥ 2 GB) to make a boot drive.
- An **external drive**, formatted **exFAT**, big enough for **both** images —
  for a 512 GB laptop that's about **550 GB**, so a **1 TB** external is safe.
- A second computer running **Ubuntu** (or similar Linux) to run the recovery
  tool afterward.
- The **BitLocker recovery key** if the laptop's data drive is encrypted (most
  Windows laptops are). It's a 48-digit number; the owner can get it from
  https://account.microsoft.com/devices/recoverykey.

---

## Step 1 — Make a SystemRescue boot USB
SystemRescue is a small Linux that boots from USB and includes `ddrescue`.

1. On any computer, download the SystemRescue ISO from
   https://www.system-rescue.org/Download/.
2. Write it to your USB stick. The easiest tool is **balenaEtcher**
   (https://etcher.balena.io/): open it, pick the ISO, pick the USB stick,
   click **Flash**.
3. When it finishes, you have a bootable SystemRescue USB.

## Step 2 — Boot the laptop from the USB, plug in the external drive
1. Insert the SystemRescue USB into the laptop.
2. Power on and open the boot menu (usually tapping **F12**, **F9**, or **Esc**
   right after powering on — it varies by brand). Choose the USB stick.
3. At the SystemRescue menu, press **Enter** to boot to the default option.
   After a minute you'll get a text command prompt.
4. Now plug your **exFAT external drive** into a USB port on the laptop.

## Step 3 — Identify the two Optane drives
At the prompt, type:

```sh
lsblk -d -o NAME,SIZE,MODEL
```

You'll see a list of drives. The Optane laptop shows **two NVMe devices**, for
example:

```
NAME      SIZE  MODEL
nvme0n1   476G  ...            <- the LARGER one = QLC  (the main SSD)
nvme1n1    27G  ...            <- the SMALLER one = Optane (the cache)
sda       931G  My exFAT Disk  <- your external drive
```

**Write these down.** The rule is simple:
- **Larger** NVMe (hundreds of GB) = **QLC** → we'll call its image `qlc.img`.
- **Smaller** NVMe (~16–32 GB) = **Optane** → we'll call its image `optane.img`.
- The **external drive** is usually `sda` (or `sdb`). Confirm by its size/label.

Now mount your external drive so we can save the images to it:

```sh
mkdir -p /mnt/backup
mount /dev/sda1 /mnt/backup        # <- use YOUR external drive's name + "1"
```

(If `sda1` gives an error, run `lsblk -f` and use the partition that shows an
`exfat` filesystem, e.g. `sdb1`.)

## Step 4 — Image both drives with ddrescue
Run these **two** commands, one at a time. Each reads an entire drive into a file
on your external disk. **Do not swap the order of the arguments** — the `/dev/...`
device comes **first** (the source we read), the `/mnt/backup/...` file comes
**second** (where we save it).

```sh
# Image the QLC (the LARGER NVMe). Replace nvme0n1 with YOUR larger device.
ddrescue -f -n -d /dev/nvme0n1 /mnt/backup/qlc.img /mnt/backup/qlc.log

# Image the Optane (the SMALLER NVMe). Replace nvme1n1 with YOUR smaller device.
ddrescue -f -n -d /dev/nvme1n1 /mnt/backup/optane.img /mnt/backup/optane.log
```

What the options mean: `-f` allow writing the image file, `-n` fast pass (no slow
scraping — good for a first copy), `-d` read the drive directly. The `.log` file
lets ddrescue resume if it's interrupted, so don't delete it.

The QLC can take a while (hundreds of GB). When both finish, flush and power off:

```sh
sync
umount /mnt/backup
poweroff
```

Unplug the external drive.

## Step 5 — Recover the files on your Ubuntu workstation
1. Plug the external drive into your Ubuntu computer. It should mount
   automatically; note the folder (often `/media/<you>/<label>/`). You now have
   `qlc.img` and `optane.img` there.
2. Build Data Extractor Pro (once):

   ```sh
   sudo apt install build-essential cmake qtbase5-dev libssl-dev gddrescue
   cd data-extractor-pro
   cmake -S . -B build && cmake --build build -j
   ```

3. Find the Optane cache location (a number the tool needs):

   ```sh
   ./build/de-cli imsm /media/you/label/optane.img
   ```

   It prints the metadata; note the **cache region sector** it reports (also
   shown as the "Intel Cache" start). Call it `<cacheSector>`.

4. Open everything in the graphical app:

   ```sh
   ./build/data-extractor
   ```

   Then **File → Open Optane Set…**, and fill in:
   - **QLC image:** your `qlc.img`
   - **Optane image:** your `optane.img`
   - **Cache sector:** the `<cacheSector>` number from step 3
   - **Recovery key:** the 48-digit BitLocker key (leave blank if the drive
     isn't encrypted)

   Click **OK**. After a short wait, the reconstructed, decrypted drive appears.
   Expand the partitions, tick the checkboxes next to the folders/files you want,
   and use **File → Export Selected** to copy them out — the folder structure is
   preserved.

That's it — the merged Optane image plus the recovery key gives you the current,
correct files, including anything that was still sitting in the Optane cache.

---

### Prefer the command line?
The same end-to-end recovery without the GUI:

```sh
./build/de-cli browse qlc.img optane.img <cacheSector> <recovery-key>
# list a folder by its record number, or extract a whole folder:
./build/de-cli browse qlc.img optane.img <cacheSector> <recovery-key> ls <recno>
./build/de-cli browse qlc.img optane.img <cacheSector> <recovery-key> extract <recno> ./out
```

### If a drive is failing
If the laptop's SSD has bad sectors (ddrescue reports errors or slows to a
crawl), stop the fast pass and let ddrescue do a thorough retry pass by dropping
the `-n`:

```sh
ddrescue -f -d /dev/nvme0n1 /mnt/backup/qlc.img /mnt/backup/qlc.log
```

For a truly unstable drive, seek professional imaging hardware rather than
pushing it — every extra read is wear on a dying drive.
