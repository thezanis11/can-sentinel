"""HTTP-range ZIP reader: fetch selected original files, verify member CRCs.

Avoids downloading the full 1.5 GB archive. The source ZIP MD5 is recorded but
cannot be verified for a partial transfer; each member's CRC32 and local SHA256
are recorded instead. No rehosted copy or credentials are needed.
"""
import argparse
import hashlib
import io
import json
from pathlib import Path
import re
import time
import zipfile
import zlib

import requests

ROOT = Path(__file__).resolve().parents[1]
API = 'https://api.figshare.com/v2/articles/24805533'


class RemoteZip(io.RawIOBase):
    def __init__(self, url, size):
        self.url, self.size, self.position = url, size, 0
        self.cache_start, self.cache = 0, b''
        self.transferred = 0
        self.session = requests.Session()

    def seekable(self):
        return True

    def readable(self):
        return True

    def tell(self):
        return self.position

    def seek(self, offset, whence=0):
        self.position = offset if whence == 0 else (self.position if whence == 1 else self.size) + offset
        if self.position < 0:
            raise ValueError('Negative seek')
        return self.position

    def read(self, size=-1):
        if size < 0:
            size = self.size - self.position
        size = min(size, self.size - self.position)
        if size <= 0:
            return b''
        start, end = self.position, self.position + size
        if not (self.cache_start <= start and end <= self.cache_start + len(self.cache)):
            request_end = min(self.size, max(end, start + 1024 * 1024))
            for attempt in range(3):
                try:
                    response = self.session.get(self.url, headers={'Range': f'bytes={start}-{request_end-1}'}, timeout=120)
                    response.raise_for_status()
                    if response.status_code != 206 or not response.headers.get('Content-Range', '').startswith(f'bytes {start}-'):
                        raise ValueError('Server did not honor the byte range')
                    if len(response.content) != request_end - start:
                        raise ValueError('Incomplete HTTP range')
                    # Figshare's redirected signed URL expires after seconds;
                    # obtain a fresh redirect from the stable public URL each time.
                    self.cache_start, self.cache = start, response.content
                    self.transferred += len(self.cache)
                    break
                except (requests.RequestException, ValueError):
                    if attempt == 2:
                        raise
                    time.sleep(1)
        data = self.cache[start-self.cache_start:end-self.cache_start]
        self.position = end
        return data


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--list', action='store_true')
    parser.add_argument('--set', default='set_01')
    parser.add_argument('--per-family', type=int, default=1,
                        help='Test captures per attack family per official folder; retain all training files')
    args = parser.parse_args()
    response = requests.get(API, timeout=90)
    response.raise_for_status()
    record = response.json()
    item = next(f for f in record['files'] if f['name'] == 'can-train-and-test.zip')
    remote = RemoteZip(item['download_url'], item['size'])
    with zipfile.ZipFile(remote) as archive:
        names = archive.namelist()
        if args.list:
            print('\n'.join(names[:150]))
            for name in names:
                if name.lower().endswith(('.md', '.txt')):
                    print(name, archive.read(name).decode('utf-8', errors='replace')[:18000])
            candidates = [n for n in names if args.set in n and n.endswith('.csv')]
            for name in candidates[:2]:
                with archive.open(name) as source:
                    print('SAMPLE', name, [source.readline().decode() for _ in range(4)])
            print('transferred', remote.transferred)
            return
        folders = {}
        for name in sorted(names):
            if args.set in name.split('/') and name.endswith('.csv') and not name.startswith('__MACOSX'):
                folders.setdefault(str(Path(name).parent), []).append(name)
        selected = []
        for folder, members in folders.items():
            if Path(folder).name == 'train_01':
                selected.extend(members)
                continue
            families = {}
            for name in members:
                family = re.sub(r'-\d+$', '', Path(name).stem)
                families.setdefault(family, []).append(name)
            for members_of_family in families.values():
                selected.extend(members_of_family[:args.per_family])
        if not selected:
            raise ValueError('No files selected; inspect --list first')
        target = ROOT / 'data/raw/ctt_subset'
        target.mkdir(parents=True, exist_ok=True)
        entries = []
        for index, name in enumerate(selected):
            destination = (target / name).resolve()
            if not destination.is_relative_to(target.resolve()):
                raise ValueError('Unsafe archive path')
            info = archive.getinfo(name)
            if not destination.exists() or destination.stat().st_size != info.file_size:
                destination.parent.mkdir(parents=True, exist_ok=True)
                partial = destination.with_suffix('.csv.part')
                with archive.open(name) as source, partial.open('wb') as output:
                    while block := source.read(1024 * 1024):
                        output.write(block)
                partial.replace(destination)
            sha = hashlib.sha256()
            crc = 0
            with destination.open('rb') as source:
                while block := source.read(1024 * 1024):
                    sha.update(block)
                    crc = zlib.crc32(block, crc)
            digest = sha.hexdigest()
            if crc != info.CRC:
                raise ValueError(f'Local member CRC mismatch: {name}')
            entries.append(dict(member=name, bytes=info.file_size, zip_crc32=f'{info.CRC:08x}', sha256=digest))
            print(f'[{index+1}/{len(selected)}] {name} ({info.file_size/1e6:.1f} MB)', flush=True)
        manifest = dict(api=API, doi=record['doi'], license=record['license'],
                        selection=f'{args.set}: all training files; first {args.per_family} test capture(s) per attack family per official folder, lexicographic order; selection fixed before test evaluation',
                        source_archive_bytes=item['size'], source_archive_md5=item['computed_md5'],
                        integrity='ZIP member CRC32 checked on download; SHA256 recorded; entire-archive MD5 not verified for partial transfer',
                        transferred_bytes=remote.transferred, files=entries)
        (target / 'manifest.json').write_text(json.dumps(manifest, indent=2), encoding='utf-8')
        print(f'Done; transferred {remote.transferred/1e6:.1f} MB.', flush=True)


if __name__ == '__main__':
    main()
