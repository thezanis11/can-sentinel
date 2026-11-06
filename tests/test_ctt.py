import io
import unittest
from unittest.mock import patch

import pandas as pd

from can_sentinel.ctt import features_from_csv
from scripts.fetch_ctt_subset import RemoteZip


class CTTTests(unittest.TestCase):
    DATA = b'''timestamp,arbitration_id,data_field,attack
1000.0,123,01,0
1000.1,123,0203,1
1000.5,456,FFFFFFFFFFFFFFFF,0
1000.9,456,FFFFFFFFFFFFFFFF,1
1001.0,123,00,0
'''

    def test_labels_padding_and_chunk_invariance(self):
        a, stats = features_from_csv(io.BytesIO(self.DATA), chunk_size=2)
        b, _ = features_from_csv(io.BytesIO(self.DATA), chunk_size=100)
        pd.testing.assert_frame_equal(a.sort_index(axis=1), b.sort_index(axis=1), check_dtype=False)
        self.assertEqual(stats['raw_rows'], 5)
        self.assertEqual(a.label.tolist(), [1, 1, 0])
        self.assertEqual(a.iloc[0]['id_123_b7_mean'], 0)

    def test_invalid_labels_and_payloads_are_rejected(self):
        with self.assertRaises(ValueError):
            features_from_csv(io.BytesIO(self.DATA.replace(b',1\n', b',2\n')))
        with self.assertRaises(ValueError):
            features_from_csv(io.BytesIO(self.DATA.replace(b',1\n', b',0.5\n')))
        with self.assertRaises(ValueError):
            features_from_csv(io.BytesIO(self.DATA.replace(b'0203', b'BAD')))

    def test_timestamp_reversals_are_stably_sorted_and_counted(self):
        lines = self.DATA.splitlines()
        unsorted = b'\n'.join([lines[0], lines[2], lines[1], *lines[3:]]) + b'\n'
        a, stats = features_from_csv(io.BytesIO(unsorted), chunk_size=2)
        b, _ = features_from_csv(io.BytesIO(self.DATA), chunk_size=100)
        pd.testing.assert_frame_equal(a.sort_index(axis=1), b.sort_index(axis=1), check_dtype=False)
        self.assertEqual(stats['timestamp_backward_steps'], 1)

    def test_remote_reader_respects_seek_and_ranges(self):
        payload = b'0123456789' * 200_000

        class Response:
            status_code = 206

            def __init__(self, start, end):
                self.headers = {'Content-Range': f'bytes {start}-{end}/{len(payload)}'}
                self.content = payload[start:end+1]

            def raise_for_status(self):
                pass

        calls = []

        def get(url, headers, timeout):
            calls.append(url)
            start, end = map(int, headers['Range'].removeprefix('bytes=').split('-'))
            return Response(start, end)

        reader = RemoteZip('https://example.org/stable', len(payload))
        with patch.object(reader.session, 'get', side_effect=get):
            self.assertEqual(reader.read(25), payload[:25])
            reader.seek(-20, 2)
            self.assertEqual(reader.read(), payload[-20:])
            reader.seek(1)
            self.assertEqual(reader.read(11), payload[1:12])
        self.assertTrue(all(url == 'https://example.org/stable' for url in calls))


if __name__ == '__main__':
    unittest.main()
