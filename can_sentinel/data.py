"""ROAD adapter. Labels are reconstructed, never passed into feature extraction."""
from __future__ import annotations

import json
from pathlib import Path
import re
import zipfile

import numpy as np
import pandas as pd

WINDOW_SECONDS = 0.5
CHUNK_SIZE = 200_000
FILLER_ID = 0xFFF


def capture_group(name: str) -> str:
    """Original and postprocessed masquerade variants share a source capture."""
    return name.removesuffix('_masquerade')


def family_of(name: str) -> str:
    if name.startswith('ambient'):
        return 'benign'
    return re.sub(r'_\d+$', '', capture_group(name)).removesuffix('_attack')


def split_for(name: str) -> str:
    if name.startswith('accelerator'):
        return 'unlabeled'
    if name.startswith('ambient'):
        if name in {'ambient_dyno_drive_radio_infotainment', 'ambient_dyno_reverse'}:
            return 'validation'
        if name in {'ambient_dyno_drive_benign_anomaly', 'ambient_dyno_drive_winter',
                    'ambient_highway_street_driving_diagnostics'}:
            return 'test'
        return 'train'
    base = capture_group(name)
    if base.endswith('_1'):
        return 'train'
    if base.endswith('_2'):
        return 'validation'
    # Third repetitions and singleton coolant attack are genuinely held out.
    return 'test'


def read_inventory(archive: Path) -> list[dict]:
    inventory = []
    with zipfile.ZipFile(archive) as z:
        for kind in ('ambient', 'attacks'):
            metadata = json.loads(z.read(f'road/{kind}/capture_metadata.json'))
            for name, info in sorted(metadata.items()):
                member = f'road/{kind}/{name}.log'
                if member not in z.namelist():
                    raise ValueError(f'Missing archive member {member}')
                inventory.append(dict(capture=name, member=member, group=capture_group(name),
                                      family=family_of(name), split=split_for(name), **info))
    return inventory


def reconstruct_labels(time, ids, payload, metadata: dict) -> np.ndarray:
    """Weak frame labels: elapsed interval AND ID AND wildcard payload match.

    Accelerator captures have no injected-frame ground truth and receive -1.
    Matching a legitimate frame is possible; this limitation is documented.
    """
    if metadata.get('capture', '').startswith('accelerator'):
        return np.full(len(time), -1, dtype=np.int8)
    interval = metadata.get('injection_interval')
    if not interval:
        return np.zeros(len(time), dtype=np.int8)
    mask = (np.asarray(time) >= interval[0] - 1e-6) & (np.asarray(time) <= interval[1] + 1e-6)
    target = metadata.get('injection_id')
    if target and not set(target.upper()) <= {'X'}:
        mask &= np.asarray(ids) == int(target, 16)
    pattern = metadata.get('injection_data_str')
    if pattern:
        regex = '^' + ''.join('[0-9A-F]' if c == 'X' else re.escape(c) for c in pattern.upper()) + '$'
        mask &= pd.Series(np.asarray(payload), dtype='str').str.fullmatch(regex).to_numpy()
    return mask.astype(np.int8)


def iter_frames(stream, metadata: dict, chunk_size=CHUNK_SIZE):
    """Parse candump chunks with strict validation and monotonic elapsed times."""
    origin = None
    previous = None
    reader = pd.read_csv(stream, sep=r'\s+', names=['stamp', 'channel', 'message'],
                         dtype='str', chunksize=chunk_size, on_bad_lines='error')
    for raw in reader:
        if raw.isna().any().any():
            raise ValueError('Incomplete candump row')
        stamp = raw.stamp.str.strip('()').astype(float).to_numpy()
        if not np.isfinite(stamp).all() or np.any(np.diff(stamp) < 0):
            raise ValueError('Non-finite or unordered timestamps')
        if previous is not None and stamp[0] < previous:
            raise ValueError('Timestamps go backwards between chunks')
        previous = stamp[-1]
        if origin is None:
            origin = stamp[0]
        parts = raw.message.str.split('#', n=1, expand=True)
        if parts.shape[1] != 2 or not parts[0].str.fullmatch(r'[0-9a-fA-F]{1,8}').all():
            raise ValueError('Expected classic candump ID#DATA format')
        payload = parts[1].str.upper()
        # ROAD pads all classic-CAN payloads to eight bytes. Reject CAN FD / RTR.
        if not payload.str.fullmatch(r'[0-9A-F]{16}').all():
            raise ValueError('Expected exactly eight data bytes per frame')
        ids = parts[0].map(lambda v: int(v, 16)).to_numpy(dtype=np.int32)
        elapsed = stamp - origin
        labels = reconstruct_labels(elapsed, ids, payload.to_numpy(), metadata)
        data = np.frombuffer(bytes.fromhex(''.join(payload)), dtype=np.uint8).reshape(-1, 8)
        frame = pd.DataFrame(data, columns=[f'b{i}' for i in range(8)])
        frame['t'] = elapsed
        frame['id'] = ids
        frame['window'] = np.floor((elapsed + 1e-7) / WINDOW_SECONDS).astype(np.int64)
        frame['label'] = labels
        # This is an anonymization placeholder, not a physical CAN arbitration ID.
        yield frame.loc[frame.id != FILLER_ID].reset_index(drop=True), len(raw), int((ids == FILLER_ID).sum())


def aggregate_windows(frames: pd.DataFrame) -> pd.DataFrame:
    """Features use only messages from the current, nonoverlapping window.

    Capture names, labels, absolute/elapsed time, and injection metadata are
    explicitly excluded. Window time is output separately as report metadata.
    """
    if frames.empty:
        return pd.DataFrame()
    values = frames.copy()
    keys = ['window', 'id']
    values['same_id_dt'] = values.groupby(keys, sort=False).t.diff()
    grouped = values.groupby(keys, sort=True)
    spec = {'count': ('t', 'size'), 'dt_mean': ('same_id_dt', 'mean'),
            'dt_min': ('same_id_dt', 'min'), 'dt_std': ('same_id_dt', 'std')}
    for i in range(8):
        spec[f'b{i}_mean'] = (f'b{i}', 'mean')
        spec[f'b{i}_std'] = (f'b{i}', 'std')
    per_id = grouped.agg(**spec).fillna(0)
    wide = per_id.unstack('id', fill_value=0)
    wide.columns = [f'id_{int(aid):03X}_{stat}' for stat, aid in wide.columns]
    by_window = values.groupby('window', sort=True)
    wide['frame_count'] = by_window.size()
    wide['unique_ids'] = by_window.id.nunique()
    proportions = per_id['count'] / per_id['count'].groupby(level=0).transform('sum')
    wide['id_entropy'] = (-proportions * np.log2(proportions)).groupby(level=0).sum()
    wide['dominant_share'] = proportions.groupby(level=0).max()
    wide['label'] = by_window.label.max()
    wide['start_seconds'] = wide.index.to_numpy() * WINDOW_SECONDS
    return wide.fillna(0).reset_index(drop=True)


def features_from_stream(stream, metadata: dict, chunk_size=CHUNK_SIZE):
    outputs = []
    carry = pd.DataFrame()
    raw_rows = filler_rows = kept_rows = 0
    for chunk, n, filler in iter_frames(stream, metadata, chunk_size):
        raw_rows += n
        filler_rows += filler
        kept_rows += len(chunk)
        block = pd.concat([carry, chunk], ignore_index=True)
        if block.empty:
            continue
        final_window = block.window.iloc[-1]
        carry = block.loc[block.window == final_window].copy()
        complete = block.loc[block.window != final_window]
        if not complete.empty:
            outputs.append(aggregate_windows(complete))
    if not carry.empty:
        outputs.append(aggregate_windows(carry))
    if not outputs:
        raise ValueError('Capture contains no usable frames')
    result = pd.concat(outputs, ignore_index=True).fillna(0)
    return result, dict(raw_rows=raw_rows, filler_rows=filler_rows, kept_rows=kept_rows,
                        windows=len(result), positive_windows=int((result.label == 1).sum()))


def prepare(archive: Path, out: Path):
    out.mkdir(parents=True, exist_ok=True)
    inventory = read_inventory(archive)
    with zipfile.ZipFile(archive) as z:
        for index, item in enumerate(inventory):
            destination = out / f'{item["capture"]}.pkl'
            stats_path = destination.with_suffix('.json')
            if destination.exists() and stats_path.exists():
                item.update(json.loads(stats_path.read_text(encoding='utf-8')))
                print(f'[{index+1}/{len(inventory)}] cached {item["capture"]}', flush=True)
                continue
            with z.open(item['member']) as source:
                features, stats = features_from_stream(source, item)
            features.astype({c: 'float32' for c in features.columns if c != 'label'}).to_pickle(destination)
            stats_path.write_text(json.dumps(stats, indent=2), encoding='utf-8')
            item.update(stats)
            print(f'[{index+1}/{len(inventory)}] {item["capture"]}: {stats}', flush=True)
    (out / 'inventory.json').write_text(json.dumps(inventory, indent=2), encoding='utf-8')
    return inventory
