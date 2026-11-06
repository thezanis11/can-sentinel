"""Download the authors' public, licensed second dataset with MD5 verification."""
import hashlib
import json
from pathlib import Path
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
API = 'https://api.figshare.com/v2/articles/24805533'


def main():
    folder = ROOT / 'data/raw'
    folder.mkdir(parents=True, exist_ok=True)
    with urllib.request.urlopen(API, timeout=90) as response:
        record = json.load(response)
    item = next(f for f in record['files'] if f['name'] == 'can-train-and-test.zip')
    path = folder / item['name']
    if not path.exists() or path.stat().st_size != item['size']:
        partial = path.with_suffix('.zip.part')
        with urllib.request.urlopen(item['download_url'], timeout=180) as response, partial.open('wb') as output:
            count = last = 0
            while block := response.read(1024 * 1024):
                output.write(block)
                count += len(block)
                if count - last >= 150 * 1024 * 1024:
                    print(f'{count/1e6:.0f}/{item["size"]/1e6:.0f} MB', flush=True)
                    last = count
        if partial.stat().st_size != item['size']:
            raise ValueError('Incomplete download')
        partial.replace(path)
    with path.open('rb') as source:
        digest = hashlib.file_digest(source, 'md5').hexdigest()
    if digest != item['computed_md5']:
        raise ValueError('Checksum mismatch')
    manifest = dict(api=API, doi=record['doi'], license=record['license'],
                    file=item['name'], bytes=item['size'], md5=digest,
                    download_url=item['download_url'])
    (folder / 'can-train-and-test-provenance.json').write_text(json.dumps(manifest, indent=2), encoding='utf-8')
    print('can-train-and-test downloaded and verified.', flush=True)


if __name__ == '__main__':
    main()
