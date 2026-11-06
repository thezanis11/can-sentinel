"""Adapter for the authors' labeled can-train-and-test CSV format."""
import json
from pathlib import Path
import re

import joblib
import numpy as np
import pandas as pd

from .data import CHUNK_SIZE, WINDOW_SECONDS, aggregate_windows


def features_from_csv(path, chunk_size=CHUNK_SIZE):
    outputs = []
    carry = pd.DataFrame()
    origin = previous = None
    raw_rows = 0
    # Original attack captures can have tiny timestamp reversals where injected
    # messages were merged. Stable global per-capture sorting is necessary;
    # independently sorting chunks would leave cross-chunk order incorrect.
    whole = pd.read_csv(path, dtype={'arbitration_id': 'str', 'data_field': 'str'}, keep_default_na=False)
    required = {'timestamp', 'arbitration_id', 'data_field', 'attack'}
    if set(whole.columns) != required:
        raise ValueError(f'Unexpected CSV columns: {list(whole.columns)}')
    timestamps = whole.timestamp.to_numpy(dtype=float)
    if not np.isfinite(timestamps).all():
        raise ValueError('Non-finite timestamp')
    backwards = int((np.diff(timestamps) < 0).sum())
    whole = whole.sort_values('timestamp', kind='stable').reset_index(drop=True)
    for offset in range(0, len(whole), chunk_size):
        raw = whole.iloc[offset:offset+chunk_size]
        required = {'timestamp', 'arbitration_id', 'data_field', 'attack'}
        if set(raw.columns) != required:
            raise ValueError(f'Unexpected CSV columns: {list(raw.columns)}')
        stamp = raw.timestamp.to_numpy(dtype=float)
        if not np.isfinite(stamp).all() or np.any(np.diff(stamp) < 0) or (previous is not None and stamp[0] < previous):
            raise ValueError('Invalid timestamp sequence')
        previous = stamp[-1]
        if origin is None:
            origin = stamp[0]
        payload = raw.data_field.str.upper()
        if not payload.str.fullmatch(r'(?:[0-9A-F]{2}){0,8}').all():
            raise ValueError('Invalid classic CAN payload')
        if not raw.arbitration_id.str.fullmatch(r'[0-9A-Fa-f]{1,8}').all():
            raise ValueError('Invalid CAN identifier')
        if not raw.attack.isin([0, 1]).all():
            raise ValueError('Expected binary attack labels')
        labels = raw.attack.to_numpy(dtype=int)
        data = np.frombuffer(bytes.fromhex(''.join(payload.str.pad(16, side='right', fillchar='0'))),
                             dtype=np.uint8).reshape(-1, 8)
        frame = pd.DataFrame(data, columns=[f'b{i}' for i in range(8)])
        frame['t'] = stamp - origin
        frame['id'] = raw.arbitration_id.map(lambda s: int(s, 16)).to_numpy(dtype=np.int32)
        frame['window'] = np.floor((frame.t.to_numpy() + 1e-7) / WINDOW_SECONDS).astype(np.int64)
        frame['label'] = labels
        raw_rows += len(raw)
        block = pd.concat([carry, frame], ignore_index=True)
        last = block.window.iloc[-1]
        carry = block.loc[block.window == last].copy()
        complete = block.loc[block.window != last]
        if not complete.empty:
            outputs.append(aggregate_windows(complete))
    if not carry.empty:
        outputs.append(aggregate_windows(carry))
    if not outputs:
        raise ValueError('No CSV frames')
    result = pd.concat(outputs, ignore_index=True).fillna(0)
    return result, dict(raw_rows=raw_rows, filler_rows=0, kept_rows=raw_rows,
                        windows=len(result), positive_windows=int(result.label.sum()),
                        timestamp_backward_steps=backwards, feature_version=2)


def prepare_ctt(source: Path, out: Path):
    manifest = json.loads((source / 'manifest.json').read_text(encoding='utf-8'))
    out.mkdir(parents=True, exist_ok=True)
    inventory = []
    hashes = {}
    for index, item in enumerate(manifest['files']):
        member = item['member']
        path = source / member
        stem = path.stem
        folder = path.parent.name
        split = ('validation' if stem.endswith('-2') else 'train') if folder == 'train_01' else 'test'
        family = re.sub(r'-\d+$', '', stem)
        if family in {'accessory', 'attack-free'}:
            family = 'benign'
        if item['sha256'] in hashes and hashes[item['sha256']] != split:
            raise ValueError('An identical capture occurs across splits')
        hashes[item['sha256']] = split
        name = f'{folder}__{stem}'
        destination = out / f'{name}.pkl'
        stats_path = destination.with_suffix('.json')
        cached = json.loads(stats_path.read_text(encoding='utf-8')) if stats_path.exists() else {}
        if destination.exists() and cached.get('feature_version') == 2:
            stats = cached
        else:
            features, stats = features_from_csv(path)
            features.astype({c: 'float32' for c in features.columns if c != 'label'}).to_pickle(destination)
            stats_path.write_text(json.dumps(stats, indent=2), encoding='utf-8')
        inventory.append(dict(capture=name, member=member, group=name, family=family,
                              split=split, scenario=folder, dataset='can-train-and-test subset', **stats))
        print(f'[{index+1}/{len(manifest["files"])}] {name}: {stats}', flush=True)
    (out / 'inventory.json').write_text(json.dumps(inventory, indent=2), encoding='utf-8')
    (out / 'provenance.json').write_text(json.dumps(manifest, indent=2), encoding='utf-8')


def evaluate_transfer(data: Path, model_path: Path, out: Path):
    from .benchmark import anomaly_scores, feature_matrix, load_frames, metrics
    inventory = json.loads((data / 'inventory.json').read_text(encoding='utf-8'))
    artifact = joblib.load(model_path)
    frame = load_frames(data, inventory, columns=artifact['columns'])
    test = frame.loc[frame.split == 'test'].reset_index(drop=True)
    x = feature_matrix(test, artifact['columns'])
    scores = anomaly_scores(artifact['model'], x)
    result = dict(source_model=str(model_path.name), source_dataset='ROAD',
                  target_dataset='can-train-and-test set_01 documented subset',
                  threshold=artifact['threshold'], adaptation='none; source model and threshold unchanged',
                  metrics=metrics(test.label, scores, artifact['threshold']),
                  mean_unknown_id_fraction=float(x[:, -1].mean()))
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(result, indent=2), encoding='utf-8')
    print(json.dumps(result, indent=2), flush=True)
    return result
