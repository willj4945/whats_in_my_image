"""Re-align every Markdown pipe table in the given files: padded cells, |----| separators, equal row widths.

Usage: python3 .claude/skills/docs-sync/align_tables.py FILE [FILE ...]

Escaped pipes (\\|) inside cells are kept. Tables inside fenced code blocks are left alone.
"""

from __future__ import annotations

import re
import sys

SEPARATOR = re.compile(r"^\s*\|[\s:|-]+\|\s*$")


def split_row(line: str) -> list[str]:
    body = line.strip()[1:-1]
    cells, cur, i = [], "", 0
    while i < len(body):
        if body[i] == "\\" and i + 1 < len(body):
            cur += body[i : i + 2]
            i += 2
            continue
        if body[i] == "|":
            cells.append(cur.strip())
            cur = ""
        else:
            cur += body[i]
        i += 1
    cells.append(cur.strip())
    return cells


def align(text: str) -> str:
    lines = text.split("\n")
    out: list[str] = []
    i, fenced = 0, False
    while i < len(lines):
        line = lines[i]
        if line.lstrip().startswith(("```", "~~~")):
            fenced = not fenced
        is_table = not fenced and line.lstrip().startswith("|") and i + 1 < len(lines) and SEPARATOR.match(lines[i + 1])
        if not is_table:
            out.append(line)
            i += 1
            continue
        j = i
        while j < len(lines) and lines[j].lstrip().startswith("|"):
            j += 1
        indent = line[: len(line) - len(line.lstrip())]
        rows = [split_row(row) for k, row in enumerate(lines[i:j]) if k != 1]
        n = max(len(r) for r in rows)
        rows = [r + [""] * (n - len(r)) for r in rows]
        widths = [max(3, *(len(r[c]) for r in rows)) for c in range(n)]

        def fmt(r: list[str], widths: list[int] = widths, n: int = n, indent: str = indent) -> str:
            return indent + "| " + " | ".join(r[c].ljust(widths[c]) for c in range(n)) + " |"

        out.append(fmt(rows[0]))
        out.append(indent + "|" + "|".join("-" * (w + 2) for w in widths) + "|")
        out.extend(fmt(r) for r in rows[1:])
        i = j
    return "\n".join(out)


def main(paths: list[str]) -> int:
    if not paths:
        print(__doc__.strip(), file=sys.stderr)
        return 2
    for path in paths:
        with open(path, encoding="utf-8") as f:
            text = f.read()
        new = align(text)
        if new != text:
            with open(path, "w", encoding="utf-8") as f:
                f.write(new)
            print(f"aligned {path}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
