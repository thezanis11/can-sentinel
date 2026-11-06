"""Package tracked deliverables only; datasets, environments and models stay local."""
from pathlib import Path
import subprocess
import zipfile

ROOT = Path(__file__).resolve().parents[1]


def main():
    files = subprocess.check_output(['git', 'ls-files', '-z'], cwd=ROOT).decode('utf-8').split('\0')
    destination = ROOT.parent / 'CAN-Sentinel-portfolio.zip'
    with zipfile.ZipFile(destination, 'w', compression=zipfile.ZIP_DEFLATED) as archive:
        for name in files:
            if not name:
                continue
            path = ROOT / name
            if not path.resolve().is_relative_to(ROOT.resolve()):
                raise ValueError('Unexpected path outside project')
            archive.write(path, f'can-sentinel/{name}')
    print(f'{destination} ({destination.stat().st_size / 1e6:.2f} MB)')


if __name__ == '__main__':
    main()
