"""Capture-separated benchmark; validation chooses thresholds and champion."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import platform
import time

import joblib
import numpy as np
import pandas as pd
import sklearn
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.metrics import (average_precision_score, confusion_matrix,
                             f1_score, precision_recall_curve, precision_score,
                             recall_score, roc_auc_score)

from .data import WINDOW_SECONDS, features_from_stream

SEED = 42
FPR_BUDGET = 0.01
EXCLUDED = {'label', 'start_seconds', 'capture', 'family', 'split', 'group'}


def feature_matrix(frame: pd.DataFrame, columns: list[str]) -> np.ndarray:
    """Training defines the schema; unseen IDs become an explicit fraction."""
    result = frame.reindex(columns=columns, fill_value=0).fillna(0).copy()
    known_counts = {c for c in columns if c.startswith('id_') and c.endswith('_count')}
    other_counts = [c for c in frame.columns if c.startswith('id_') and c.endswith('_count') and c not in known_counts]
    if 'unknown_id_fraction' in frame:
        unknown_fraction = frame.unknown_id_fraction.to_numpy()
    else:
        unknown = frame[other_counts].sum(axis=1).to_numpy() if other_counts else np.zeros(len(frame))
        unknown_fraction = unknown / np.maximum(frame.frame_count.to_numpy(), 1)
    result['unknown_id_fraction'] = unknown_fraction
    return result.to_numpy(dtype=np.float32)


class RobustProfile:
    """Explainable robust deviation from benign per-ID rate/payload statistics."""
    def fit(self, x):
        self.center_ = np.median(x, axis=0)
        q05, q95 = np.quantile(x, [0.05, 0.95], axis=0)
        # Quantile span with a nonzero floor prevents division by zero on counters.
        self.scale_ = np.maximum(q95 - q05, 0.01)
        return self

    def score_samples(self, x):
        deviations = np.abs(x - self.center_) / self.scale_
        # A few changed CAN fields should remain visible among many unchanged IDs.
        return np.partition(deviations, -3, axis=1)[:, -3:].mean(axis=1)


def anomaly_scores(model, x):
    if isinstance(model, IsolationForest):
        return -model.score_samples(x)
    if isinstance(model, RandomForestClassifier):
        positive = int(np.flatnonzero(model.classes_ == 1)[0])
        return model.predict_proba(x)[:, positive]
    return model.score_samples(x)


def calibrate_threshold(y, scores, supervised=False, budget=FPR_BUDGET):
    """Validation only. Return a threshold respecting the empirical benign FPR."""
    y = np.asarray(y)
    scores = np.asarray(scores)
    benign = scores[y == 0]
    if not len(benign) or not np.isfinite(scores).all():
        raise ValueError('Finite scores and benign validation samples required')
    floor = (float(np.nextafter(scores.min(), -np.inf)) if budget == 1.0
             else float(np.quantile(benign, 1 - budget, method='higher')))
    # Strict > resolves ties conservatively; the finite-sample budget is explicit.
    if not supervised:
        return floor
    candidates = np.unique(np.r_[floor, np.quantile(scores, np.linspace(0, 1, 301))])
    best = (float('-inf'), floor)
    for threshold in candidates[candidates >= floor]:
        predicted = scores > threshold
        fpr = predicted[y == 0].mean()
        if fpr <= budget:
            value = f1_score(y, predicted, zero_division=0)
            if value > best[0]:
                best = (value, float(threshold))
    return best[1]


def metrics(y, scores, threshold):
    y = np.asarray(y, dtype=int)
    predicted = np.asarray(scores) > threshold
    tn, fp, fn, tp = confusion_matrix(y, predicted, labels=[0, 1]).ravel()
    both_classes = len(np.unique(y)) == 2
    return dict(windows=len(y), positive_windows=int(y.sum()),
                precision=float(precision_score(y, predicted, zero_division=0)),
                recall=float(recall_score(y, predicted, zero_division=0)),
                f1=float(f1_score(y, predicted, zero_division=0)),
                pr_auc=float(average_precision_score(y, scores)) if both_classes else None,
                roc_auc=float(roc_auc_score(y, scores)) if both_classes else None,
                false_positive_rate=float(fp / (fp + tn)) if fp + tn else None,
                false_positive_windows=int(fp), true_negative_windows=int(tn),
                missed_attack_windows=int(fn), detected_attack_windows=int(tp))


def grouped_bootstrap(frame, scores, threshold, iterations=400):
    """Resample source captures, preserving dependencies between derived variants."""
    groups = frame.group.unique()
    positions = [np.flatnonzero(frame.group.to_numpy() == g) for g in groups]
    rng = np.random.default_rng(SEED)
    estimates = []
    y = frame.label.to_numpy()
    for _ in range(iterations):
        idx = np.concatenate([positions[i] for i in rng.integers(0, len(groups), len(groups))])
        if len(np.unique(y[idx])) == 2:
            estimates.append(f1_score(y[idx], scores[idx] > threshold, zero_division=0))
    if not estimates:
        return None
    return [float(v) for v in np.quantile(estimates, [0.025, 0.975])]


def load_frames(data: Path, inventory, columns=None):
    # Fuzzing can introduce thousands of IDs. Do not concatenate a dense union
    # of every test-only ID's 20 statistics across every capture. Reduce each
    # capture to the frozen benign-training schema before concatenation.
    if columns is None:
        normal = [pd.read_pickle(data / f'{i["capture"]}.pkl') for i in inventory
                  if i['split'] == 'train' and i['family'] == 'benign']
        columns = sorted(set().union(*(set(b.columns) for b in normal)) - EXCLUDED)
    known_counts = {c for c in columns if c.startswith('id_') and c.endswith('_count')}
    blocks = []
    for item in inventory:
        raw = pd.read_pickle(data / f'{item["capture"]}.pkl')
        unseen_counts = [c for c in raw.columns if c.startswith('id_') and c.endswith('_count') and c not in known_counts]
        unknown = raw[unseen_counts].sum(axis=1).to_numpy() if unseen_counts else np.zeros(len(raw))
        part = raw.reindex(columns=columns + ['label', 'start_seconds'], fill_value=0).fillna(0).copy()
        part['unknown_id_fraction'] = unknown / np.maximum(raw.frame_count.to_numpy(), 1)
        for column in ('capture', 'family', 'split', 'group'):
            part[column] = item[column]
        blocks.append(part)
    return pd.concat(blocks, ignore_index=True).fillna(0)


def benchmark(data: Path, out: Path, models_path: Path):
    out.mkdir(parents=True, exist_ok=True)
    models_path.mkdir(parents=True, exist_ok=True)
    inventory = json.loads((data / 'inventory.json').read_text(encoding='utf-8'))
    frame = load_frames(data, inventory)
    train = frame.loc[frame.split == 'train'].reset_index(drop=True)
    val = frame.loc[frame.split == 'validation'].reset_index(drop=True)
    test = frame.loc[frame.split == 'test'].reset_index(drop=True)
    for left, right in ((train, val), (train, test), (val, test)):
        if set(left.group) & set(right.group):
            raise ValueError('Source capture leakage detected')
    benign_train = train.loc[train.family == 'benign']
    # Features discovered exclusively in genuine benign training captures.
    benign_blocks = [pd.read_pickle(data / f'{i["capture"]}.pkl') for i in inventory
                     if i['split'] == 'train' and i['family'] == 'benign']
    columns = sorted(set().union(*(set(b.columns) for b in benign_blocks)) - EXCLUDED)
    x_train, x_val, x_test = [feature_matrix(s, columns) for s in (train, val, test)]
    x_benign = feature_matrix(benign_train, columns)
    names = columns + ['unknown_id_fraction']
    y_train, y_val, y_test = [s.label.to_numpy(dtype=int) for s in (train, val, test)]
    specifications = {
        'Robust profile': RobustProfile(),
        'Isolation Forest': IsolationForest(n_estimators=160, max_samples=min(4096, len(x_benign)),
                                          random_state=SEED, n_jobs=2),
        'Random Forest': RandomForestClassifier(n_estimators=160, min_samples_leaf=3,
                                               max_features='sqrt', class_weight='balanced_subsample',
                                               random_state=SEED, n_jobs=2),
    }
    results = []
    predictions = test[['capture', 'family', 'group', 'start_seconds', 'label']].copy()
    traces = {}
    for name, model in specifications.items():
        print(f'Training {name}: train={x_train.shape}, benign={x_benign.shape}', flush=True)
        begin = time.perf_counter()
        supervised = isinstance(model, RandomForestClassifier)
        if supervised:
            model.fit(x_train, y_train)
        else:
            model.fit(x_benign)
        training_seconds = time.perf_counter() - begin
        validation_scores = anomaly_scores(model, x_val)
        strict_threshold = calibrate_threshold(y_val, validation_scores, supervised)
        # Balanced operating point: labels are used for threshold calibration,
        # including for normal-only fitted models. Kept distinct from the fully
        # normal-only protocol below and the low-FPR operating point.
        threshold = calibrate_threshold(y_val, validation_scores, supervised=True, budget=1.0)
        begin = time.perf_counter()
        scores = anomaly_scores(model, x_test)
        seconds = time.perf_counter() - begin
        result = dict(model=name, threshold=threshold, training_seconds=training_seconds,
                      test_score_seconds=seconds, windows_per_second=len(test) / max(seconds, 1e-9),
                      validation=metrics(y_val, validation_scores, threshold),
                      test=metrics(y_test, scores, threshold),
                      low_fpr_operation=dict(threshold=strict_threshold,
                                             validation=metrics(y_val, validation_scores, strict_threshold),
                                             test=metrics(y_test, scores, strict_threshold)),
                      f1_capture_bootstrap_95=grouped_bootstrap(test, scores, threshold))
        result['by_family'] = {}
        for family in sorted(test.family.unique()):
            mask = test.family == family
            result['by_family'][family] = metrics(y_test[mask], scores[mask], threshold)
        result['by_capture'] = {}
        if inventory[0].get('dataset'):
            result['by_scenario'] = {}
            for scenario in sorted({i['scenario'] for i in inventory if i['split'] == 'test'}):
                captures = {i['capture'] for i in inventory if i.get('scenario') == scenario}
                mask = test.capture.isin(captures).to_numpy()
                result['by_scenario'][scenario] = metrics(y_test[mask], scores[mask], threshold)
        for capture in test.capture.unique():
            mask = (test.capture == capture).to_numpy()
            item = metrics(y_test[mask], scores[mask], threshold)
            positives = np.flatnonzero(mask & (y_test == 1))
            detected = np.flatnonzero(mask & (y_test == 1) & (scores > threshold))
            item['first_detected_window_delay_seconds'] = (
                float(test.start_seconds.iloc[detected[0]] - test.start_seconds.iloc[positives[0]])
                if len(positives) and len(detected) else None)
            result['by_capture'][capture] = item
        artifact = dict(model=model, name=name, threshold=threshold, columns=columns,
                        window_seconds=WINDOW_SECONDS, sklearn_version=sklearn.__version__,
                        schema_version=1)
        slug = name.lower().replace(' ', '_')
        joblib.dump(artifact, models_path / f'{slug}.joblib', compress=3)
        predictions[f'{slug}_score'] = scores
        predictions[f'{slug}_alert'] = (scores > threshold).astype(int)
        traces[name] = scores
        results.append(result)
        print(f'{name}: validation F1={result["validation"]["f1"]:.3f}, test={result["test"]}', flush=True)
    # Choose the deployed model strictly from validation performance.
    champion = max(results, key=lambda r: r['validation']['f1'])
    chosen = models_path / (champion['model'].lower().replace(' ', '_') + '.joblib')
    (models_path / 'champion.joblib').write_bytes(chosen.read_bytes())
    predictions.to_csv(out / 'test_predictions.csv', index=False)
    pd.DataFrame([dict(model=r['model'], **r['test']) for r in results]).to_csv(out / 'metrics.csv', index=False)
    # Performance on all attack captures for normal-only models: no attack was
    # used for fitting or threshold calibration in this additional protocol.
    normal_val = val.loc[val.family == 'benign']
    zero_day = frame.loc[(frame.family != 'benign') & (frame.label >= 0)].reset_index(drop=True)
    zero_day_protocol = {}
    for name in ('Robust profile', 'Isolation Forest'):
        artifact = joblib.load(models_path / (name.lower().replace(' ', '_') + '.joblib'))
        normal_scores = anomaly_scores(artifact['model'], feature_matrix(normal_val, columns))
        threshold = calibrate_threshold(np.zeros(len(normal_val)), normal_scores)
        combined = pd.concat([test.loc[test.family == 'benign'], zero_day], ignore_index=True)
        scores = anomaly_scores(artifact['model'], feature_matrix(combined, columns))
        zero_day_protocol[name] = dict(threshold=threshold, metrics=metrics(combined.label, scores, threshold),
                                       attack_captures=int(zero_day.capture.nunique()))
    unlabeled = frame.loc[frame.split == 'unlabeled']
    unlabeled_summary = {}
    if not unlabeled.empty:
        artifact = joblib.load(models_path / 'champion.joblib')
        scores = anomaly_scores(artifact['model'], feature_matrix(unlabeled, columns))
        for capture in unlabeled.capture.unique():
            mask = (unlabeled.capture == capture).to_numpy()
            unlabeled_summary[capture] = dict(windows=int(mask.sum()), alert_fraction=float((scores[mask] > artifact['threshold']).mean()))
    manifest = dict(seed=SEED, window_seconds=WINDOW_SECONDS, validation_fpr_budget=FPR_BUDGET,
                    dataset=inventory[0].get('dataset', 'ROAD'),
                    primary_operating_point='maximum validation F1; attack labels used to calibrate all thresholds',
                    study_status='exploratory; test metrics inspected during development; not a blind final audit',
                    python=platform.python_version(), sklearn=sklearn.__version__,
                    training_feature_count=len(names), champion=champion['model'],
                    champion_selection='highest validation F1, never test F1',
                    raw_frames=sum(i['raw_rows'] for i in inventory),
                    filler_frames_removed=sum(i['filler_rows'] for i in inventory),
                    feature_windows=len(frame),
                    splits={s: sorted(frame.loc[frame.split == s, 'capture'].unique())
                            for s in ('train', 'validation', 'test', 'unlabeled')},
                    inventory=inventory, results=results, normal_only_protocol=zero_day_protocol,
                    unlabeled_accelerator=unlabeled_summary,
                    labeling='weak frame labels matched by elapsed interval, ID and wildcard payload; window positive if any matched frame',
                    inference_timing='feature extraction excluded; offline CPU scoring; not a real-time guarantee')
    provenance = data.parents[1] / 'raw/road-provenance.json'
    if provenance.exists():
        manifest['dataset_provenance'] = json.loads(provenance.read_text(encoding='utf-8'))
    if (data / 'provenance.json').exists():
        manifest['dataset_provenance'] = json.loads((data / 'provenance.json').read_text(encoding='utf-8'))
        manifest['labeling'] = 'author-provided binary frame labels; window positive if any attack frame'
        manifest['study_status'] = 'exploratory documented subset; subset and method fixed before initial CTT test evaluation'
    manifest['inventory_sha256'] = hashlib.sha256((data / 'inventory.json').read_bytes()).hexdigest()
    (out / 'experiment.json').write_text(json.dumps(manifest, indent=2, allow_nan=False), encoding='utf-8')
    # Impurity importance is descriptive only, never model selection.
    rf = specifications['Random Forest']
    importance = pd.DataFrame(dict(feature=names, importance=rf.feature_importances_)).sort_values('importance', ascending=False)
    importance.to_csv(out / 'feature_importance.csv', index=False)
    from .report import build_report
    build_report(manifest, predictions, traces, importance, out)
    print(f'Complete. Validation-selected champion: {champion["model"]}. Report: {out / "index.html"}', flush=True)
    return manifest


def detect(capture: Path, model_path: Path, out: Path):
    # Load only locally produced, trusted model artifacts (pickle-based format).
    artifact = joblib.load(model_path)
    with capture.open('rb') as source:
        frame, stats = features_from_stream(source, {})
    stats.pop('positive_windows', None)
    stats['ground_truth'] = 'not supplied; alerts are model predictions only'
    x = feature_matrix(frame, artifact['columns'])
    scores = anomaly_scores(artifact['model'], x)
    result = frame[['start_seconds', 'frame_count']].copy()
    result['score'] = scores
    result['threshold'] = artifact['threshold']
    result['alert'] = scores > artifact['threshold']
    out.parent.mkdir(parents=True, exist_ok=True)
    result.to_csv(out, index=False)
    print(json.dumps(dict(model=artifact['name'], **stats, alert_windows=int(result.alert.sum()), output=str(out)), indent=2))
