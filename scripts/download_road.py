"""Download the original ROAD archive, check its checksum, retain provenance."""
import hashlib
import json
from pathlib import Path
import time
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
RECORD = 'https://zenodo.org/api/records/10462796'


def main():
    target = ROOT / 'data' / 'raw'
    target.mkdir(parents=True, exist_ok=True)
    with urllib.request.urlopen(RECORD, timeout=90) as response:
        record = json.load(response)
    item = next(f for f in record['files'] if f['key'] == 'road.zip')
    path = target / 'road.zip'
    expected = item['checksum'].split(':', 1)[1]
    if not path.exists() or path.stat().st_size != item['size']:
        partial = path.with_suffix('.zip.part')
        started = time.monotonic()
        with urllib.request.urlopen(item['links']['self'], timeout=180) as response, partial.open('wb') as out:
            received = 0
            last = 0
            while block := response.read(1024 * 1024):
                out.write(block)
                received += len(block)
                if received - last >= 50 * 1024 * 1024:
                    print(f'{received / 1e6:.0f}/{item["size"] / 1e6:.0f} MB, {time.monotonic() - started:.0f}s', flush=True)
                    last = received
        if partial.stat().st_size != item['size']:
            raise ValueError('Incomplete download')
        partial.replace(path)
    with path.open('rb') as stream:
        actual = hashlib.file_digest(stream, 'md5').hexdigest()
    if actual != expected:
        raise ValueError(f'Checksum mismatch: {actual} != {expected}')
    manifest = {
        'record': RECORD, 'doi': record['metadata'].get('doi'),
        'license': record['metadata'].get('license'), 'file': item['key'],
        'bytes': item['size'], 'checksum': item['checksum'],
        'download_url': item['links']['self'],
    }
    (target / 'road-provenance.json').write_text(json.dumps(manifest, indent=2), encoding='utf-8')
    print('ROAD downloaded and checksum verified.', flush=True)


if __name__ == '__main__':
    main()
