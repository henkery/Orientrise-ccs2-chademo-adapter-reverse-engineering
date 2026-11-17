import math, collections, sys

data = open(sys.argv[1], 'rb').read()
print(f"size: {len(data)} (0x{len(data):x})")

def entropy(b):
    if not b: return 0
    c = collections.Counter(b)
    n = len(b)
    return -sum(v/n * math.log2(v/n) for v in c.values())

# entropy map, 2KB blocks
print("\n== entropy per 2KB block ==")
BS = 2048
regions = []
for i in range(0, len(data), BS):
    blk = data[i:i+BS]
    e = entropy(blk)
    regions.append((i, e))
# print compact: group consecutive blocks by entropy class
prev = None
for i, e in regions:
    cls = 'LOW ' if e < 5.0 else ('MED ' if e < 7.0 else 'HIGH')
    if cls != prev:
        print(f"0x{i:06x}: {cls} (H={e:.2f})")
        prev = cls

# autocorrelation on header region and tail region
def autocorr(buf, maxshift=256):
    scores = []
    for s in range(1, maxshift+1):
        n = min(len(buf)-s, 4096)
        if n <= 0: break
        match = sum(1 for i in range(n) if buf[i] == buf[i+s])
        scores.append((match/n, s))
    scores.sort(reverse=True)
    return scores[:12]

print("\n== autocorr header[0:0x58] ==")
for r, s in autocorr(data[:0x58]):
    print(f"shift {s:3d} (0x{s:02x}): {r:.3f}")

print("\n== autocorr tail[-4096:] ==")
for r, s in autocorr(data[-4096:]):
    print(f"shift {s:3d} (0x{s:02x}): {r:.3f}")

print("\n== autocorr whole file (sampled) ==")
for r, s in autocorr(data[::4]):
    print(f"shift {s*4:4d} (0x{s*4:03x}): {r:.3f}")

# byte histogram of header
print("\n== header bytes ==")
print(data[:0x60].hex(' '))