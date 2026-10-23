"""A QR code, made here: byte mode, error correction M, versions 1 to 10.

The first-run setup page (relay/firstrun.py) shows the new device's link as a
QR code, and that link carries a token. So the code is drawn on the bouncer,
as an inline SVG, rather than by a chart API or a script from somewhere else:
the token goes to nobody. It is the web page's own encoder (web/index.html,
"a QR code") written out again in Python, step for step, and checked against
the same reference codes (tests/fixtures/qr.json, made by CoreImage).

ISO/IEC 18004, the plain way: the bytes with a mode and a length in front,
padded to the version's capacity, split into blocks, each given its
Reed-Solomon remainder, interleaved, laid into the grid in the zigzag round
the fixed patterns, and masked with whichever of the eight masks scores best.
"""

from __future__ import annotations

from dataclasses import dataclass

# Per version at level M: error-correction bytes per block, then the blocks
# as (how many, data bytes each) for the one or two sizes there are.
BLOCKS = [None,
          (10, (1, 16)), (16, (1, 28)), (26, (1, 44)), (18, (2, 32)), (24, (2, 43)),
          (16, (4, 27)), (18, (4, 31)), (22, (2, 38), (2, 39)), (22, (3, 36), (2, 37)),
          (26, (4, 43), (1, 44))]
# Where the alignment patterns' centres go, per version.
ALIGN = [None, [], [6, 18], [6, 22], [6, 26], [6, 30], [6, 34],
         [6, 22, 38], [6, 24, 42], [6, 26, 46], [6, 28, 50]]
MAX_VERSION = 10


def _field() -> tuple[list[int], list[int]]:
    """GF(256) with the QR polynomial x^8+x^4+x^3+x^2+1, as exp and log
    tables; exp twice as long as it need be, so two logs add without wrapping."""
    exp, log = [0] * 512, [0] * 256
    x = 1
    for i in range(255):
        exp[i], log[x] = x, i
        x <<= 1
        if x & 0x100:
            x ^= 0x11D
    for i in range(255, 512):
        exp[i] = exp[i - 255]
    return exp, log


_EXP, _LOG = _field()


def _mul(a: int, b: int) -> int:
    return _EXP[_LOG[a] + _LOG[b]] if a and b else 0


def _remainder(data: list[int], count: int) -> list[int]:
    """The Reed-Solomon remainder of `data`: `count` error-correction bytes."""
    gen = [0] * count
    gen[-1] = 1
    root = 1
    for _ in range(count):
        for j in range(count):
            gen[j] = _mul(gen[j], root) ^ (gen[j + 1] if j + 1 < count else 0)
        root = _mul(root, 2)
    rem = [0] * count
    for byte in data:
        factor = byte ^ rem[0]
        rem = rem[1:] + [0]
        for j in range(count):
            rem[j] ^= _mul(gen[j], factor)
    return rem


def _codewords(data_bytes: bytes, version: int) -> list[int] | None:
    """The data and error-correction bytes of a version's symbol, in the
    order they are laid down. None when the bytes do not fit."""
    ec_len, *groups = BLOCKS[version]
    capacity = sum(n * size for n, size in groups)
    length_bits = 8 if version < 10 else 16
    if 4 + length_bits + len(data_bytes) * 8 > capacity * 8:
        return None
    bits: list[int] = []

    def put(value: int, n: int) -> None:
        bits.extend((value >> i) & 1 for i in range(n - 1, -1, -1))

    put(4, 4)                                    # byte mode
    put(len(data_bytes), length_bits)
    for b in data_bytes:
        put(b, 8)
    put(0, min(4, capacity * 8 - len(bits)))     # the terminator, as much as fits
    while len(bits) % 8:
        bits.append(0)
    data = [int("".join(map(str, bits[i:i + 8])), 2) for i in range(0, len(bits), 8)]
    pad = 0xEC
    while len(data) < capacity:
        data.append(pad)
        pad ^= 0xEC ^ 0x11
    blocks = []
    at = 0
    for n, size in groups:
        for _ in range(n):
            block = data[at:at + size]
            at += size
            blocks.append((block, _remainder(block, ec_len)))
    # Interleaved: the first byte of every block, then the second, and so on;
    # the longer blocks' last bytes follow on their own.
    out = []
    for i in range(max(len(b) for b, _ in blocks)):
        out.extend(b[i] for b, _ in blocks if i < len(b))
    for i in range(ec_len):
        out.extend(ec[i] for _, ec in blocks)
    return out


MASKS = [
    lambda x, y: (x + y) % 2 == 0,
    lambda x, y: y % 2 == 0,
    lambda x, y: x % 3 == 0,
    lambda x, y: (x + y) % 3 == 0,
    lambda x, y: (x // 3 + y // 2) % 2 == 0,
    lambda x, y: (x * y) % 2 + (x * y) % 3 == 0,
    lambda x, y: ((x * y) % 2 + (x * y) % 3) % 2 == 0,
    lambda x, y: ((x + y) % 2 + (x * y) % 3) % 2 == 0,
]


def penalty(rows: list[list[int]]) -> int:
    """How bad a finished grid is to scan, by the standard's four rules: long
    runs of one colour, 2x2 blocks of one colour, anything that looks like a
    finder pattern, and an uneven share of dark. Lower is better."""
    size = len(rows)
    score = 0

    def line(get) -> None:
        nonlocal score
        run, bits = 1, get(0)
        for i in range(1, size):
            if get(i) == get(i - 1):
                run += 1
            else:
                if run >= 5:
                    score += run - 2
                run = 1
            bits = ((bits << 1) | get(i)) & 0x7FF
            # 1011101 with four light modules before or after it.
            if i >= 10 and bits in (0x05D, 0x5D0):
                score += 40
        if run >= 5:
            score += run - 2

    for y in range(size):
        line(lambda x: rows[y][x])
    for x in range(size):
        line(lambda y: rows[y][x])
    dark = 0
    for y in range(size):
        for x in range(size):
            v = rows[y][x]
            dark += v
            if (x + 1 < size and y + 1 < size and v == rows[y][x + 1] == rows[y + 1][x]
                    == rows[y + 1][x + 1]):
                score += 3
    score += abs(dark * 20 - size * size * 10) // (size * size) * 10
    return score


@dataclass
class QRCode:
    version: int
    size: int
    mask: int
    rows: list[list[int]]          # 1 dark, 0 light


def encode(text: str, force_mask: int | None = None) -> QRCode | None:
    """`text` as a QR code, or None when it is too long for version 10.
    `force_mask` is for the tests, which compare against a known mask."""
    data_bytes = text.encode("utf-8")
    codewords = None
    version = 1
    for version in range(1, MAX_VERSION + 1):
        codewords = _codewords(data_bytes, version)
        if codewords:
            break
    if not codewords:
        return None
    size = version * 4 + 17
    rows = [[0] * size for _ in range(size)]
    fixed = [[0] * size for _ in range(size)]

    def put(x: int, y: int, dark: bool) -> None:
        rows[y][x] = 1 if dark else 0
        fixed[y][x] = 1

    # Timing, the three finders with their light border, the alignment
    # patterns, and room for the format and version bits.
    for i in range(size):
        put(6, i, i % 2 == 0)
        put(i, 6, i % 2 == 0)
    for cx, cy in ((3, 3), (size - 4, 3), (3, size - 4)):
        for dy in range(-4, 5):
            for dx in range(-4, 5):
                x, y = cx + dx, cy + dy
                if 0 <= x < size and 0 <= y < size:
                    ring = max(abs(dx), abs(dy))
                    put(x, y, ring not in (2, 4))
    centres = ALIGN[version]
    last = len(centres) - 1
    for i, cx in enumerate(centres):
        for j, cy in enumerate(centres):
            if (i, j) in ((0, 0), (0, last), (last, 0)):
                continue
            for dy in range(-2, 3):
                for dx in range(-2, 3):
                    put(cx + dx, cy + dy, max(abs(dx), abs(dy)) != 1)

    def format_bits(mask: int) -> None:
        # Level M is 00, then the mask; ten check bits; the fixed scramble.
        rem = mask
        for _ in range(10):
            rem = (rem << 1) ^ ((rem >> 9) * 0x537)
        bits = ((mask << 10) | rem) ^ 0x5412

        def bit(i: int) -> bool:
            return (bits >> i) & 1 == 1

        for i in range(6):
            put(8, i, bit(i))
        put(8, 7, bit(6))
        put(8, 8, bit(7))
        put(7, 8, bit(8))
        for i in range(9, 15):
            put(14 - i, 8, bit(i))
        for i in range(8):
            put(size - 1 - i, 8, bit(i))
        for i in range(8, 15):
            put(8, size - 15 + i, bit(i))
        put(8, size - 8, True)                   # always dark

    format_bits(0)
    if version >= 7:
        rem = version
        for _ in range(12):
            rem = (rem << 1) ^ ((rem >> 11) * 0x1F25)
        bits = (version << 12) | rem
        for i in range(18):
            dark = (bits >> i) & 1 == 1
            a, b = size - 11 + i % 3, i // 3
            put(a, b, dark)
            put(b, a, dark)

    # The bytes, most significant bit first, up and down in two-module
    # columns from the bottom right, stepping over the vertical timing line.
    n = 0
    right = size - 1
    while right >= 1:
        if right == 6:
            right = 5
        upward = ((right + 1) & 2) == 0
        for step in range(size):
            y = size - 1 - step if upward else step
            for j in range(2):
                x = right - j
                if fixed[y][x] or n >= len(codewords) * 8:
                    continue
                rows[y][x] = (codewords[n >> 3] >> (7 - (n & 7))) & 1
                n += 1
        right -= 2

    def flip(mask: int) -> None:
        test = MASKS[mask]
        for y in range(size):
            for x in range(size):
                if not fixed[y][x] and test(x, y):
                    rows[y][x] ^= 1

    best = force_mask
    if best is None:
        best_score = None
        for mask in range(8):
            flip(mask)
            format_bits(mask)
            score = penalty(rows)
            if best_score is None or score < best_score:
                best, best_score = mask, score
            flip(mask)                           # and back: a mask is its own undo
    flip(best)
    format_bits(best)
    return QRCode(version, size, best, rows)


def svg(code: QRCode, label: str = "QR code") -> str:
    """The code as an SVG: dark squares on a white ground four modules deep
    all round, the quiet zone a reader needs. Black on white in every theme."""
    from html import escape

    quiet = 4
    side = code.size + quiet * 2
    dots = []
    for y, row in enumerate(code.rows):
        x = 0
        while x < code.size:
            if not row[x]:
                x += 1
                continue
            # A run of dark modules is one rectangle.
            w = 1
            while x + w < code.size and row[x + w]:
                w += 1
            dots.append(f"M{x + quiet} {y + quiet}h{w}v1h-{w}z")
            x += w
    return (f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {side} {side}" '
            f'shape-rendering="crispEdges" role="img" aria-label="{escape(label)}">'
            f'<rect width="{side}" height="{side}" fill="#fff"/>'
            f'<path d="{"".join(dots)}" fill="#000"/></svg>')
