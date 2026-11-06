"""Rebuild ROAD presentation from frozen predictions, without retraining."""
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import pandas as pd
from can_sentinel.report import build_report, build_ctt_report


def main():
    folder = ROOT / 'reports'
    manifest = json.loads((folder / 'experiment.json').read_text(encoding='utf-8'))
    frame = pd.read_csv(folder / 'test_predictions.csv')
    traces = {r['model']: frame[r['model'].lower().replace(' ', '_') + '_score'].to_numpy()
              for r in manifest['results']}
    importance = pd.read_csv(folder / 'feature_importance.csv')
    build_report(manifest, frame, traces, importance, folder)
    ctt = folder / 'ctt'
    if (ctt / 'experiment.json').exists():
        build_ctt_report(json.loads((ctt / 'experiment.json').read_text(encoding='utf-8')), ctt)


if __name__ == '__main__':
    main()
