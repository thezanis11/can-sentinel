"""Run local inference on an original held-out ROAD capture, without a vehicle."""
from pathlib import Path
import sys
import zipfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from can_sentinel.benchmark import detect


def main():
    target = ROOT / 'data/raw/demo-correlated-signal.log'
    with zipfile.ZipFile(ROOT / 'data/raw/road.zip') as archive:
        target.write_bytes(archive.read('road/attacks/correlated_signal_attack_3.log'))
    detect(target, ROOT / 'models/champion.joblib', ROOT / 'reports/demo_detection.csv')


if __name__ == '__main__':
    main()
