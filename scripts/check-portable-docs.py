#!/usr/bin/env python3
from __future__ import annotations

from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
PATHS = [ROOT / 'README.md', ROOT / 'docs', ROOT / '.github', ROOT / 'scripts', ROOT / 'Makefile']
BLOCKED = ('/' + 'Users/', 'A' + 'egis' + 'AI', 'Arg' + 'us' + 'AI', 'Documents/' + 'Projects')
TEXT_SUFFIXES = {'.md', '.yml', '.yaml', '.sh', '.py', '.json'}

def iter_files(path: Path):
    if path.is_file():
        yield path
        return
    for item in path.rglob('*'):
        if item.is_file() and item.suffix.lower() in TEXT_SUFFIXES:
            yield item

def main() -> int:
    failures = []
    for path in PATHS:
        if not path.exists():
            continue
        for item in iter_files(path):
            if item == Path(__file__).resolve():
                continue
            text = item.read_text(encoding='utf-8')
            for token in BLOCKED:
                if token in text:
                    failures.append(f'{item.relative_to(ROOT)} contains {token!r}')
    if failures:
        print('Portable docs check failed:', file=sys.stderr)
        for failure in failures:
            print(f'  - {failure}', file=sys.stderr)
        return 1
    print('Portable docs check passed.')
    return 0

if __name__ == '__main__':
    raise SystemExit(main())
