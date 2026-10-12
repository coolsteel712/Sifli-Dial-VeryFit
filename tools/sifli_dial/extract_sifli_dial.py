#!/usr/bin/env python3
"""extract_sifli_dial.py - unpack, decode and repack IDO/SiFli .watch watch-face files.

Needs Python 3 and Pillow (pip install pillow).

Usage:
  extract_sifli_dial.py extract FACE.watch [-o OUTDIR]   unpack files AND decode images to PNG (default command)
  extract_sifli_dial.py unpack  FACE.watch [-o OUTDIR]   unpack files only
  extract_sifli_dial.py decode  INPUT [-o OUTDIR]        decode image .bin / folder of .bin / .watch to PNG
  extract_sifli_dial.py pack    OUTDIR FACE.watch        rebuild a .watch from an unpacked OUTDIR

Output layout of extract/unpack:
  OUTDIR/raw/...        the embedded files, exactly as stored (device paths preserved)
  OUTDIR/manifest.json  container fields needed to repack byte-identically
  OUTDIR/png/           decoded images (extract/decode)

VERIFIED on wf_w62.watch:
  * Container (from ido_app_custom_dial_make.c): 32-byte head_t, names, 16-byte file_head_t entries, data.
    CRC-16/MODBUS over the header body and over each file; unpack -> pack is byte-identical.
  * Image .bin, cf 5: raw RGB565+A8 pointer image.
  * Image .bin, cf 1/2: a single ezip frame (also used by thumbnails); cf 31: multi-frame container; each frame uses the shared-Huffman "legacy" ezip layout
    (layout taken from the OpenEZIP tool); every decoded frame's Adler-32 matched.
NOT handled: 8-bit palette-indexed ezip (ctrl 0x43, seen on wf_f82: layout partly understood, colors
unresolved), the standard raw-DEFLATE ezip variant, and per-block raw DEFLATE (ported
from OpenEZIP but UNTESTED, no sample available). Other faces/devices are untested.

TESTED DEVICES:
DR03: Passed
BF300P: Passed
GTX26: Passed
"""
import argparse
import json
import os
import struct
import sys
import zlib

MAGIC = 0xA1B2C8D9

# ---------------------------------------------------------------- .watch container


def crc16(data):
    """CRC-16/MODBUS (poly 0xA001, init 0xFFFF); equals the table-driven CRC16 in the C packer."""
    crc = 0xFFFF
    for b in data:
        crc ^= b
        for _ in range(8):
            crc = (crc >> 1) ^ 0xA001 if crc & 1 else crc >> 1
    return crc


def parse_watch(d):
    """Return (manifest_fields, [(name, data, reserve), ...]); verifies every checksum."""
    magic, size, proj, cnt, ck, dsz, nsz = struct.unpack_from('<IHHHHII', d, 0)
    if magic != MAGIC:
        raise ValueError('not a .watch file (bad magic)')
    if crc16(d[size:size + dsz]) != ck:
        raise ValueError('header checksum mismatch')
    files = []
    for i in range(cnt):
        no, fs, c, res, off = struct.unpack_from('<IIHHI', d, size + nsz + 16 * i)
        name = d[size + no:d.index(b'\0', size + no)].decode()
        real = off + nsz + 16 * cnt
        data = d[real:real + fs]
        if crc16(data) != c:
            raise ValueError('crc mismatch for ' + name)
        files.append((name, data, res))
    man = dict(project_no=proj, head_size=size, head_reserve=d[20:32].hex())
    return man, files


def unpack(path, outdir):
    with open(path, 'rb') as fh:
        d = fh.read()
    man, files = parse_watch(d)
    man['files'] = []
    for name, data, res in files:
        p = os.path.join(outdir, 'raw', name.lstrip('/'))
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, 'wb') as fh:
            fh.write(data)
        man['files'].append(dict(name=name, reserve=res))
    with open(os.path.join(outdir, 'manifest.json'), 'w') as fh:
        json.dump(man, fh, indent=1)
    return len(files)


def pack(srcdir, path):
    with open(os.path.join(srcdir, 'manifest.json')) as fh:
        man = json.load(fh)
    names = b''
    heads = b''
    blobs = b''
    noffs = []
    for f in man['files']:
        noffs.append(len(names))
        names += f['name'].encode() + b'\0'
    for f, no in zip(man['files'], noffs):
        with open(os.path.join(srcdir, 'raw', f['name'].lstrip('/')), 'rb') as fh:
            data = fh.read()
        heads += struct.pack('<IIHHI', no, len(data), crc16(data), f['reserve'], len(blobs) + 32)
        blobs += data
    body = names + heads + blobs
    hdr = struct.pack('<IHHHHII', MAGIC, man['head_size'], man['project_no'], len(man['files']),
                      crc16(body), len(body), len(names)) + bytes.fromhex(man['head_reserve'])
    with open(path, 'wb') as fh:
        fh.write(hdr + body)


# ---------------------------------------------------------------- ezip shared-Huffman decoder

LENGTHBASE = [3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31, 35, 43, 51, 59, 67, 83, 99, 115,
              131, 163, 195, 227, 258]
LENGTHEXTRA = [0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0]
DISTBASE = [1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193, 257, 385, 513, 769, 1025, 1537,
            2049, 3073, 4097, 6145, 8193, 12289, 16385, 24577]
DISTEXTRA = [0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13, 13]
CLCL_ORDER = [16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15]


class BitStream:
    def __init__(self, data):
        self.data = data
        self.bp = 0
        self.length = len(data) * 8

    def bit(self):
        if self.bp >= self.length:
            raise EOFError('end of ezip stream')
        b = (self.data[self.bp >> 3] >> (self.bp & 7)) & 1
        self.bp += 1
        return b

    def bits(self, n):
        v = 0
        for i in range(n):
            v |= self.bit() << i
        return v

    def align4(self):
        self.bp = ((((self.bp + 7) >> 3) + 3) & ~3) * 8


def make_tree(lengths):
    max_len = max(lengths) if lengths else 0
    bl = [0] * (max_len + 1)
    for l in lengths:
        if l:
            bl[l] += 1
    nxt = [0] * (max_len + 1)
    code = 0
    for b in range(1, max_len + 1):
        code = (code + bl[b - 1]) << 1
        nxt[b] = code
    tree = {}
    for i, l in enumerate(lengths):
        if l:
            tree[(l, nxt[l])] = i
            nxt[l] += 1
    return tree


def decode_symbol(s, tree):
    code = 0
    length = 0
    while True:
        code = (code << 1) | s.bit()
        length += 1
        if (length, code) in tree:
            return tree[(length, code)]
        if length > 15:
            raise ValueError('invalid Huffman sequence')


def decode_shared_huffman(data):
    """Decode an ezip stream whose blocks share one Huffman table (no BFINAL/BTYPE before the table)."""
    s = BitStream(data)
    hlit = s.bits(5) + 257
    hdist = s.bits(5) + 1
    hclen = s.bits(4) + 4
    cl = [0] * 19
    for i in range(hclen):
        cl[CLCL_ORDER[i]] = s.bits(3)
    cl_tree = make_tree(cl)
    lengths = []
    while len(lengths) < hlit + hdist:
        sym = decode_symbol(s, cl_tree)
        if sym <= 15:
            lengths.append(sym)
        elif sym == 16:
            lengths.extend([lengths[-1]] * (s.bits(2) + 3))
        elif sym == 17:
            lengths.extend([0] * (s.bits(3) + 3))
        else:
            lengths.extend([0] * (s.bits(7) + 11))
    t_ll = make_tree(lengths[:hlit])
    t_d = make_tree(lengths[hlit:])
    s.align4()
    out = bytearray()
    while True:
        final = s.bit()
        btype = s.bits(2)
        if btype == 0:
            s.bp = (s.bp + 7) & ~7
            i = s.bp >> 3
            n = data[i] | (data[i + 1] << 8)
            i += 4
            out.extend(data[i:i + n])
            s.bp = (i + n) * 8
        elif btype in (1, 2):
            while True:
                sym = decode_symbol(s, t_ll)
                if sym < 256:
                    out.append(sym)
                elif sym == 256:
                    break
                else:
                    k = sym - 257
                    ln = LENGTHBASE[k] + s.bits(LENGTHEXTRA[k])
                    ds = decode_symbol(s, t_d)
                    dist = DISTBASE[ds] + s.bits(DISTEXTRA[ds])
                    for _ in range(ln):
                        out.append(out[-dist])
        else:
            raise ValueError('invalid block type')
        s.align4()
        if final:
            break
    return out


def _paeth(a, b, c):
    p = a + b - c
    pa, pb, pc = abs(p - a), abs(p - b), abs(p - c)
    return a if pa <= pb and pa <= pc else (b if pb <= pc else c)


def unfilter(data, w, h, bpp, block_rows):
    """Reverse PNG row filters; the 'previous row' resets at each block of block_rows rows."""
    stride = w * bpp
    if len(data) != h * (stride + 1):
        raise ValueError('decoded size %d != expected %d' % (len(data), h * (stride + 1)))
    out = bytearray(stride * h)
    for y in range(h):
        r = y * (stride + 1)
        ft = data[r]
        if ft > 4:
            raise ValueError('bad filter type %d on row %d' % (ft, y))
        first = y % block_rows == 0
        for x in range(stride):
            raw = data[r + 1 + x]
            left = out[y * stride + x - bpp] if x >= bpp else 0
            up = 0 if first else out[(y - 1) * stride + x]
            ul = 0 if first or x < bpp else out[(y - 1) * stride + x - bpp]
            v = (raw, raw + left, raw + up, raw + (left + up) // 2, raw + _paeth(left, up, ul))[ft]
            out[y * stride + x] = v & 255
    return out


# ---------------------------------------------------------------- image decoding


def _pillow():
    try:
        from PIL import Image
        return Image
    except ImportError:
        sys.exit('Pillow is required: pip install pillow')


def header(d):
    """4-byte LE bitfield: bits 0-4 format, 10-20 width, 21-31 height."""
    v = struct.unpack_from('<I', d, 0)[0]
    return v & 0x1F, (v >> 10) & 0x7FF, (v >> 21) & 0x7FF


def rgb565_image(px, w, h, alpha):
    Image = _pillow()
    n = 3 if alpha else 2
    im = Image.new('RGBA', (w, h))
    pix = im.load()
    for i in range(w * h):
        c = px[n * i] | (px[n * i + 1] << 8)
        pix[i % w, i // w] = (((c >> 11) & 31) * 255 // 31, ((c >> 5) & 63) * 255 // 63,
                              (c & 31) * 255 // 31, px[n * i + 2] if alpha else 255)
    return im


def decode_frame(f):
    """Decode one ezip frame (4-byte resource header + stream). Verifies the Adler-32 trailer."""
    _, w, h = header(f)
    if f[9] == 8:  # stream bit depth 8 (ctrl 0x43): palette-indexed variant
        raise ValueError('8-bit palette variant (ctrl 0x%02x) not supported yet' % f[8])
    size = struct.unpack_from('>I', f, 4)[0]
    ctrl = f[8]
    filters = (f[16] & 15) != 1
    comp = f[20:]
    rows, nblk = struct.unpack_from('>HH', comp, 0)
    table = 4 * (nblk + 1)
    raw = comp[table:]
    if (ctrl >> 4) > 2 and (ctrl >> 4) != 5:
        lz = decode_shared_huffman(raw)
    else:  # per-block raw DEFLATE, ported from OpenEZIP, UNTESTED
        offs = [struct.unpack_from('>I', comp, 4 + 4 * i)[0] for i in range(nblk)]
        offs[0] &= 0xFFFFFF
        offs.append(len(raw) + table + 16)
        lz = bytearray()
        for i in range(nblk):
            lz += zlib.decompress(raw[offs[i] - 16 - table:offs[i + 1] - 16 - table], -15)
    want = struct.unpack_from('>I', f, 4 + size - 4)[0]
    if zlib.adler32(bytes(lz)) & 0xFFFFFFFF != want:
        raise ValueError('Adler-32 mismatch')
    bpp = (len(lz) - (h if filters else 0)) // (w * h)
    if bpp not in (2, 3):
        raise ValueError('unsupported bytes/pixel %d' % bpp)
    px = unfilter(lz, w, h, bpp, rows) if filters else lz
    return rgb565_image(px, w, h, bpp == 3)


def decode_image(d):
    """Return a list of PIL images (one per frame) for an image .bin."""
    fmt, w, h = header(d)
    if fmt == 5:  # raw RGB565 + alpha
        need = 4 + w * h * 3
        if len(d) not in (need, need + 4):
            raise ValueError('size %d does not fit %dx%d raw image' % (len(d), w, h))
        return [rgb565_image(d[4:need], w, h, True)]
    if fmt in (1, 2):  # single ezip frame: 1 = RGB565, 2 = RGB565+alpha
        return [decode_frame(d)]
    if fmt == 0x1F:  # multi-frame container
        n, _ = struct.unpack_from('<II', d, 4)
        frames = []
        for o in struct.unpack_from('<%dI' % n, d, 0x10):
            s = struct.unpack_from('<I', d, o + 4)[0]
            frames.append(decode_frame(d[o + 8:o + 8 + s]))
        return frames
    raise ValueError('image format %d not supported' % fmt)


def iter_images(path):
    """Yield (name, bytes) for each image .bin in a file, folder or .watch."""
    if os.path.isdir(path):
        for root, _, fs in os.walk(path):
            for f in sorted(fs):
                if f.endswith('.bin'):
                    with open(os.path.join(root, f), 'rb') as fh:
                        yield f, fh.read()
        return
    with open(path, 'rb') as fh:
        d = fh.read()
    if struct.unpack_from('<I', d, 0)[0] == MAGIC:
        _, files = parse_watch(d)
        for name, data, _ in files:
            if name.endswith('.bin'):
                yield os.path.basename(name), data
    else:
        yield os.path.basename(path), d


def decode_all(path, outdir):
    os.makedirs(outdir, exist_ok=True)
    ok = bad = 0
    for name, data in iter_images(path):
        try:
            frames = decode_image(data)
            stem = os.path.splitext(name)[0]
            for i, im in enumerate(frames):
                im.save(os.path.join(outdir, stem + ('_f%d' % i if len(frames) > 1 else '') + '.png'))
            print('  %-40s OK    %d frame(s) %dx%d' % (name, len(frames), *frames[0].size))
            ok += 1
        except Exception as e:  # report and keep going
            print('  %-40s SKIP  %s' % (name, e))
            bad += 1
    print('images: %d decoded, %d skipped' % (ok, bad))
    return ok


# ---------------------------------------------------------------- command line


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest='cmd')
    for name in ('extract', 'unpack', 'decode'):
        p = sub.add_parser(name)
        p.add_argument('input')
        p.add_argument('-o', '--outdir')
    p = sub.add_parser('pack')
    p.add_argument('srcdir')
    p.add_argument('output')
    args = ap.parse_args()
    if args.cmd is None:
        ap.print_help()
        return 1
    if args.cmd == 'pack':
        pack(args.srcdir, args.output)
        print('wrote', args.output)
        return 0
    out = args.outdir or os.path.splitext(os.path.basename(args.input))[0] + '_out'
    if args.cmd in ('extract', 'unpack'):
        print('unpacked %d files -> %s' % (unpack(args.input, out), os.path.join(out, 'raw')))
    if args.cmd in ('extract', 'decode'):
        decode_all(args.input, os.path.join(out, 'png'))
    return 0


if __name__ == '__main__':
    sys.exit(main())