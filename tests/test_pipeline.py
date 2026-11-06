import io
from pathlib import Path
import unittest
from unittest.mock import patch

import numpy as np
import pandas as pd

from can_sentinel.benchmark import (RobustProfile, calibrate_threshold,
                                    feature_matrix, load_frames, metrics)
from can_sentinel.data import (aggregate_windows, capture_group,
                               features_from_stream, reconstruct_labels,
                               split_for)


class LabelTests(unittest.TestCase):
    def test_id_payload_interval_must_all_match(self):
        meta = dict(injection_id='0x123', injection_data_str='XXFFXXXXXXXXXXXX',
                    injection_interval=[1, 2])
        y = reconstruct_labels(np.array([0.9, 1.1, 1.5, 2.1, 1.8]),
                               np.array([0x123, 0x123, 0x124, 0x123, 0x123]),
                               ['00FF000000000000', '12FF345678901234', '00FF000000000000',
                                '00FF000000000000', '0000000000000000'], meta)
        np.testing.assert_array_equal(y, [0, 1, 0, 0, 0])

    def test_fuzzing_wildcard_and_unlabeled_accelerator(self):
        y = reconstruct_labels([1], [0x22], ['FFFFFFFFFFFFFFFF'],
                               dict(injection_id='XXX', injection_data_str='FFFFFFFFFFFFFFFF',
                                    injection_interval=[0, 2]))
        self.assertEqual(y.tolist(), [1])
        y = reconstruct_labels([1], [1], ['0000000000000000'], {'capture': 'accelerator_attack_drive_1'})
        self.assertEqual(y.tolist(), [-1])

    def test_source_variants_never_cross_splits(self):
        for family in ('correlated_signal', 'max_speedometer', 'reverse_light_on', 'reverse_light_off'):
            for index in (1, 2, 3):
                name = f'{family}_attack_{index}'
                self.assertEqual(capture_group(name), capture_group(name + '_masquerade'))
                self.assertEqual(split_for(name), split_for(name + '_masquerade'))
        self.assertEqual(split_for('max_engine_coolant_temp_attack'), 'test')


class FeatureTests(unittest.TestCase):
    DATA = b'''(1000.000000) can0 123#0102030405060708
(1000.100000) can0 123#0202030405060708
(1000.200000) can0 FFF#0000000000000000
(1000.400000) can0 456#FFFFFFFFFFFFFFFF
(1000.500000) can0 123#0302030405060708
(1000.800000) can0 456#0101010101010101
(1001.000000) can0 123#0402030405060708
'''

    def test_chunk_boundaries_do_not_change_features(self):
        a, stats = features_from_stream(io.BytesIO(self.DATA), {}, chunk_size=2)
        b, _ = features_from_stream(io.BytesIO(self.DATA), {}, chunk_size=100)
        pd.testing.assert_frame_equal(a.sort_index(axis=1), b.sort_index(axis=1), check_dtype=False)
        self.assertEqual(stats['raw_rows'], 7)
        self.assertEqual(stats['filler_rows'], 1)
        self.assertEqual(a.frame_count.tolist(), [3, 2, 1])
        self.assertEqual(a.start_seconds.tolist(), [0, 0.5, 1])

    def test_labels_cannot_affect_features(self):
        a, _ = features_from_stream(io.BytesIO(self.DATA), {})
        b, _ = features_from_stream(io.BytesIO(self.DATA),
                                    dict(injection_id='123', injection_data_str='XXXXXXXXXXXXXXXX',
                                         injection_interval=[0, 100]))
        pd.testing.assert_frame_equal(a.drop(columns='label'), b.drop(columns='label'))
        self.assertNotEqual(a.label.sum(), b.label.sum())

    def test_future_messages_do_not_change_previous_window(self):
        prefix = b'\n'.join(self.DATA.splitlines()[:4]) + b'\n'
        a, _ = features_from_stream(io.BytesIO(prefix), {})
        b, _ = features_from_stream(io.BytesIO(self.DATA), {})
        pd.testing.assert_series_equal(a.iloc[0].sort_index(), b.iloc[0].sort_index(), check_names=False)

    def test_malformed_capture_is_rejected(self):
        with self.assertRaises(ValueError):
            features_from_stream(io.BytesIO(b'(0) can0 123#BAD\n'), {})
        with self.assertRaises(ValueError):
            features_from_stream(io.BytesIO(b'(2) can0 123#0000000000000000\n(1) can0 123#0000000000000000\n'), {})

    def test_unseen_ids_are_not_new_model_columns(self):
        frame = pd.DataFrame({'id_123_count': [5], 'id_456_count': [5], 'frame_count': [10], 'label': [1]})
        x = feature_matrix(frame, ['frame_count', 'id_123_count'])
        self.assertEqual(x.shape, (1, 3))
        np.testing.assert_array_equal(x, [[10, 5, 0.5]])

    def test_compact_capture_loading_preserves_unknown_id_scores(self):
        raw = pd.DataFrame({'id_123_count': [5, 8], 'id_456_count': [5, 2],
                            'id_456_b0_mean': [20, 30], 'frame_count': [10, 10],
                            'label': [0, 1], 'start_seconds': [0, 0.5]})
        columns = ['frame_count', 'id_123_count']
        inventory = [dict(capture='sample', group='sample', family='attack', split='test')]
        with patch('can_sentinel.benchmark.pd.read_pickle', return_value=raw):
            compact = load_frames(Path('.'), inventory, columns=columns)
        np.testing.assert_array_equal(feature_matrix(raw, columns), feature_matrix(compact, columns))
        self.assertNotIn('id_456_b0_mean', compact.columns)


class EvaluationTests(unittest.TestCase):
    def test_validation_false_positive_budget_and_ties(self):
        y = np.r_[np.zeros(100), np.ones(10)]
        scores = np.r_[np.arange(100), np.full(10, 200)]
        threshold = calibrate_threshold(y, scores)
        self.assertLessEqual(np.mean(scores[y == 0] > threshold), 0.01)
        threshold = calibrate_threshold(y, np.ones(110), supervised=True)
        self.assertEqual(threshold, 1)

    def test_confusion_counts(self):
        m = metrics([0, 0, 1, 1], [0.1, 0.8, 0.7, 0.2], 0.5)
        self.assertEqual(m['false_positive_windows'], 1)
        self.assertEqual(m['missed_attack_windows'], 1)
        self.assertEqual(m['f1'], 0.5)

    def test_robust_profile_handles_constant_columns(self):
        model = RobustProfile().fit(np.zeros((8, 4)))
        self.assertTrue(np.isfinite(model.score_samples(np.ones((2, 4)))).all())


if __name__ == '__main__':
    unittest.main()
