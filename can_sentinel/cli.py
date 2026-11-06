"""Entry points kept small so the benchmark can be inspected and reproduced."""
import argparse
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser(description='CAN Sentinel — offline automotive intrusion detection')
    commands = parser.add_subparsers(dest='command', required=True)
    prep = commands.add_parser('prepare', help='Validate and extract ROAD features')
    prep.add_argument('--archive', type=Path, default=ROOT / 'data/raw/road.zip')
    prep.add_argument('--out', type=Path, default=ROOT / 'data/processed/road')
    ctt = commands.add_parser('prepare-ctt', help='Extract features from the documented second-dataset subset')
    ctt.add_argument('--source', type=Path, default=ROOT / 'data/raw/ctt_subset')
    ctt.add_argument('--out', type=Path, default=ROOT / 'data/processed/ctt')
    bench = commands.add_parser('benchmark', help='Train, calibrate and evaluate all models')
    bench.add_argument('--data', type=Path, default=ROOT / 'data/processed/road')
    bench.add_argument('--out', type=Path, default=ROOT / 'reports')
    bench.add_argument('--models', type=Path, default=ROOT / 'models')
    detect = commands.add_parser('detect', help='Analyze a classic CAN candump capture with a local model')
    detect.add_argument('capture', type=Path)
    detect.add_argument('--model', type=Path, default=ROOT / 'models/champion.joblib')
    detect.add_argument('--out', type=Path, default=ROOT / 'reports/detection.csv')
    transfer = commands.add_parser('transfer', help='Evaluate the frozen ROAD model on CTT without adaptation')
    transfer.add_argument('--data', type=Path, default=ROOT / 'data/processed/ctt')
    transfer.add_argument('--model', type=Path, default=ROOT / 'models/champion.joblib')
    transfer.add_argument('--out', type=Path, default=ROOT / 'reports/ctt/road_transfer.json')
    args = parser.parse_args()
    if args.command == 'prepare':
        from .data import prepare
        prepare(args.archive, args.out)
    elif args.command == 'benchmark':
        from .benchmark import benchmark
        benchmark(args.data, args.out, args.models)
    elif args.command == 'detect':
        from .benchmark import detect
        detect(args.capture, args.model, args.out)
    elif args.command == 'prepare-ctt':
        from .ctt import prepare_ctt
        prepare_ctt(args.source, args.out)
    elif args.command == 'transfer':
        from .ctt import evaluate_transfer
        evaluate_transfer(args.data, args.model, args.out)


if __name__ == '__main__':
    main()
