#!/usr/bin/env python3
"""Round-trip test: build a synthetic APFS image, then read it back with de-cli.

Every file the builder put in is extracted through the C++ engine and compared
byte for byte against what was written - including the sparse file's hole, the
two-extent file, and the decmpfs-compressed ones. Run after touching anything
under src/fs/apfs.

Usage:  verify_apfs.py [--cli build/de-cli] [--files 400]
"""
import argparse
import json
import os
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)


def run(cli, *args):
    r = subprocess.run([cli] + list(args), capture_output=True)
    if r.returncode != 0:
        raise RuntimeError(f'{" ".join(args)} failed: {r.stderr.decode().strip()}')
    return r.stdout


def parse_ls(out):
    """Parse `de-cli ls` output into (id, is_dir, size, name) tuples."""
    rows = []
    for line in out.decode(errors='replace').splitlines():
        parts = line.split(None, 1)
        if len(parts) != 2:
            continue
        node_id = parts[0]
        if not node_id.isdigit():
            continue
        rest = parts[1]
        is_dir = rest.startswith('<DIR>')
        rest = rest[5:] if is_dir else rest
        rest = rest.strip()
        size, name = rest.split(None, 1)
        rows.append((node_id, is_dir, int(size), name))
    return rows


def walk(cli, img, node_id, prefix=''):
    """Recursively collect {path: (id, size)} for every file under a node."""
    found = {}
    for nid, is_dir, size, name in parse_ls(run(cli, img, 'ls', '1', node_id)):
        path = f'{prefix}{name}'
        if is_dir:
            found.update(walk(cli, img, nid, path + '/'))
        else:
            found[path] = (nid, size)
    return found


def check(cli, img, manifest, label):
    volumes = parse_ls(run(cli, img, 'ls', '1'))
    if len(volumes) != 1:
        raise SystemExit(f'{label}: expected 1 volume, got {len(volumes)}')
    files = walk(cli, img, volumes[0][0])

    failures = []
    for path, expect_hex in manifest['files'].items():
        expect = bytes.fromhex(expect_hex)
        if path not in files:
            failures.append(f'{path}: missing from the listing')
            continue
        nid, size = files[path]
        if size != len(expect):
            failures.append(f'{path}: listed size {size}, expected {len(expect)}')
        got = run(cli, img, 'cat', '1', nid)
        if got != expect:
            failures.append(f'{path}: content differs '
                            f'({len(got)} bytes read, {len(expect)} expected)')
    for d in manifest['dirs']:
        if not any(p.startswith(d + '/') for p in files):
            failures.append(f'{d}/: directory appears empty')

    extra = set(files) - set(manifest['files'])
    if extra:
        failures.append(f'unexpected entries: {sorted(extra)[:5]}')

    print(f'{label}: {len(manifest["files"])} files checked, '
          f'{len(failures)} failure(s)')
    for f in failures:
        print('  FAIL ' + f)
    return not failures


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--cli', default=os.path.join(ROOT, 'build', 'de-cli'))
    ap.add_argument('--files', type=int, default=400,
                    help='file count for the multi-level B-tree case')
    args = ap.parse_args()
    if not os.path.exists(args.cli):
        raise SystemExit(f'{args.cli} not found - build it first')

    ok = True
    with tempfile.TemporaryDirectory() as tmp:
        for label, extra in (('single-node tree', 0),
                             ('multi-level tree', args.files)):
            img = os.path.join(tmp, f'apfs{extra}.img')
            subprocess.run([sys.executable, os.path.join(HERE, 'mkapfs.py'), img,
                            '--files', str(extra)], check=True,
                           stdout=subprocess.DEVNULL)
            with open(img + '.manifest.json') as f:
                manifest = json.load(f)
            ok &= check(args.cli, img, manifest, label)
    print('OK' if ok else 'FAILED')
    return 0 if ok else 1


if __name__ == '__main__':
    sys.exit(main())
