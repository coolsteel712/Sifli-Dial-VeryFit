# SiFli `.watch` dial format

Reverse-engineering notes on the `.watch` watch-face container used by IDO / VeryFit watches built on SiFli
(思澈) SoCs, and on the image resources inside it.

---

## 1. Overview

A `.watch` file is a flat archive of the files a watch needs to install one watch face:

```
.watch
├── /dynamic_app/watchface/installer/<name>.dsc        descriptor (see §4)
├── /dynamic_app/watchface/installer/<name>.so         face logic, compiled ARM ELF (see §5)
├── /dynamic_app/watchface/installer/<name>_res.so     resource module, compiled ARM ELF
└── /dynamic_app/watchface/<name>/ezip/*.bin           images, including the thumbnail <name>_tn.bin
```

`<name>` is e.g. `wf_w62` or `wf_f82`. Every file is stored under its absolute **device path**. **VERIFIED** on both samples.

Pipeline context (**SOURCE**, from the IDO Watch Face designer): the designer exports a project zip containing
`iwf.json`, `font.json` and source images; the C source for the face is generated server-side from `iwf.json`; the
images are converted to the ezip format and the face is compiled to ELF inside the SiFli SCons build. A pure-Python
tool can therefore read and repack `.watch` files, but cannot produce the compiled `.so` modules.

---

## 2. Container layout

All integers are **little-endian**. **VERIFIED** (every header and per-file checksum matched on both samples; unpack →
repack reproduced `wf_w62.watch` byte for byte). Layout is **SOURCE**: `ido_app_custom_dial_make.c`.

```
offset                      size   content
0x00                        32     head_t
0x20                        N      name table (N = name_size): NUL-terminated device paths
0x20 + N                    16*C   file table (C = file_count): C × file_head_t
0x20 + N + 16*C             ...    file data, concatenated, no padding
```

### 2.1 `head_t` (32 bytes)

| Offset | Size | Field | Notes |
|---|---|---|---|
| 0x00 | u32 | `magic` | `0xA1B2C8D9`, i.e. bytes `D9 C8 B2 A1` |
| 0x04 | u16 | `size` | Header size; `32` in both samples. Name table starts at this offset. |
| 0x06 | u16 | `project_no` | `13` in both samples. Meaning **UNKNOWN**. |
| 0x08 | u16 | `file_count` | 9 (`wf_w62`), 50 (`wf_f82`) |
| 0x0A | u16 | `checksum` | CRC-16 (§2.3) over everything after the header: `file[size : size + data_size]` |
| 0x0C | u32 | `data_size` | Bytes after the header (= file length − 32) |
| 0x10 | u32 | `name_size` | Length of the name table: 505 (`wf_w62`), 3227 (`wf_f82`) |
| 0x14 | 12 | `reserve` | All zero in both samples. Preserved verbatim when repacking. |

Example, `wf_w62.watch`:
`d9 c8 b2 a1 | 20 00 | 0d 00 | 09 00 | c8 ba | 85 de 01 00 | f9 01 00 00 | 00…`

### 2.2 `file_head_t` (16 bytes, one per file)

| Offset | Size | Field | Notes |
|---|---|---|---|
| 0x00 | u32 | `name_off` | Offset of the file's path, relative to the end of `head_t` (i.e. from `size`) |
| 0x04 | u32 | `file_size` | Bytes of file data |
| 0x08 | u16 | `crc16` | CRC-16 (§2.3) of the file data |
| 0x0A | u16 | `reserve` | 0 in both samples. Preserved when repacking. |
| 0x0C | u32 | `offset` | **Stored value = (offset of the data within the data area) + 32** |

Resolving a file:

```
name       = NUL-terminated string at  size + name_off
data_start = offset + name_size + 16 * file_count          # = 32 + name_size + 16*C + data_offset
data       = file[data_start : data_start + file_size]
```

Files are stored back to back; in both samples the last file ends exactly at the end of the `.watch`.
The index order is: `.dsc`, `.so`, `_res.so`, thumbnail `_tn.bin`, then the remaining images in name order.
(**OBSERVED**; order is not required by the parser logic seen.)

### 2.3 Checksum: CRC-16/MODBUS

Polynomial `0xA001` (reflected `0x8005`), initial value `0xFFFF`, no final XOR. This is the table-driven `CRC16`
(`CRC16Hi`/`CRC16Lo`) in the vendor C code. **VERIFIED**: matches the header checksum and all per-file checksums on both
samples.

```python
def crc16(data):
    crc = 0xFFFF
    for b in data:
        crc ^= b
        for _ in range(8):
            crc = (crc >> 1) ^ 0xA001 if crc & 1 else crc >> 1
    return crc
```

### 2.4 Minimal reader

```python
import struct

def read_watch(d):
    magic, size, proj, cnt, ck, dsz, nsz = struct.unpack_from('<IHHHHII', d, 0)
    assert magic == 0xA1B2C8D9 and crc16(d[size:size + dsz]) == ck
    for i in range(cnt):
        no, fs, c, res, off = struct.unpack_from('<IIHHI', d, size + nsz + 16 * i)
        name = d[size + no:d.index(b'\0', size + no)].decode()
        start = off + nsz + 16 * cnt
        data = d[start:start + fs]
        assert crc16(data) == c
        yield name, data
```

---

## 3. File inventory and naming

Both samples have the same shape (**OBSERVED**):

| Sample | Files | `.dsc` | `.so` | images |
|---|---|---|---|---|
| `wf_w62.watch` | 9 | 1 | 2 | 6 (`_tn` + 5) |
| `wf_f82.watch` | 50 | 1 | 2 | 47 (`_tn` + 46) |

Image file names follow `wf_<face>_<widget>_<content>_<font>_<index>.bin`, mirroring the designer's export names
(**SOURCE**: `ProtocolUtilSiChe.js`). Examples:

| File | Widget / role |
|---|---|
| `wf_w62_picture_dialBg.bin`, `wf_f82_picture_dialBg_0.bin` | Background picture |
| `wf_w62_time_1_dialPointer_1..3.bin` | Hour / minute / second hands |
| `wf_f82_time_0_dialClock_0..10.bin` | Digit images for a digital clock |
| `wf_w62_week_0_dialDate.bin` | Weekday labels (7 frames in one file) |
| `wf_f82_week_2_dialDate_0..6.bin` | Weekday labels (one file per day) |
| `wf_f82_date_1_dialDate_0..10.bin`, `wf_f82_temprature_3_dialData_0..12.bin` | Digit/symbol images (11 and 13 files) |
| `<name>_tn.bin` | Thumbnail shown in the watch-face picker |

Hands are stored uncompressed (§6.2); the designer places them in a separate `no_ezip` folder (**SOURCE**).
How multi-frame widgets are split differs between the two samples (one 7-frame file vs. seven files).
Why is **UNKNOWN**.

---

## 4. The `.dsc` descriptor

Small (68 bytes in both samples), a list of `type, length, NUL-terminated string` entries followed by a trailer.
Hex dump of `wf_w62.dsc`:

```
06 07 'wf_w62\0'   0a 07 'wf_w62\0'   08 0a 'wf_w62.so\0'
09 0e 'wf_w62_tn.bin\0'   07 0e 'wf_w62_res.so\0'   00 00   30 f7 e4 6a
```

- Entry = 1-byte type, 1-byte length (string length + 1, includes the NUL), then the string. **VERIFIED** (parses both samples).
- Types seen: `0x06` and `0x0A` carry the face name (meaning of each **UNKNOWN**), `0x08` the face module, `0x09` the
  thumbnail, `0x07` the resource module. The role names are inferred from the strings; the code values are **OBSERVED**.
- After the entries: `00 00`, then a 4-byte value (`30 f7 e4 6a` / `c6 62 de 24`). Algorithm **UNKNOWN**; it is not plain
  CRC-32 of the preceding bytes.

---

## 5. The `.so` modules

`<name>.so` and `<name>_res.so` are 32-bit ARM ELF shared objects (**OBSERVED**, both samples):

| Property | Value |
|---|---|
| Class / type | `ELFCLASS32`, `ET_DYN` (3) |
| Machine | `EM_ARM` (40) |
| `e_flags` | `0x05000400` (EABI version 5, hard-float flag) |
| Sizes | `wf_w62.so` 4632 B, `wf_f82.so` 10248 B, `*_res.so` 2472 B (both) |

The face module imports LVGL (v7-style) functions such as `lv_img_create` and `lv_img_set_angle`, and its source is
generated from the designer's layout (**SOURCE**: the generated `wf_sifliTest.c`; clock-hand angles use tenths of a degree,
with the hand rotated about a per-hand pivot). Each `.so` file ends in a 4-byte value (e.g. `6e 3c 8f 8f` on `wf_w62.so`) whose meaning is **UNKNOWN**
(it is not plain CRC-32 of the preceding bytes).

---

## 6. Image `.bin` files

### 6.1 Resource header (first 4 bytes, little-endian u32, LVGL-style bitfield)

| Bits | Field |
|---|---|
| 0–4 | `format` |
| 10–20 | `width` |
| 21–31 | `height` |

**VERIFIED**: yields the correct size for every decoded image. Other bits are **UNKNOWN**.

| `format` | Meaning | Status |
|---|---|---|
| 5 | Raw RGB565 + alpha, uncompressed (§6.2) | VERIFIED |
| 1 | ezip frame, RGB565, no alpha (§6.3) | VERIFIED |
| 2 | ezip frame, RGB565 + alpha (§6.3) | VERIFIED |
| 0x1F (31) | Multi-frame container of ezip frames (§6.4) | VERIFIED (`wf_w62` only) |

### 6.2 Raw images (`format` 5)

After the 4-byte header: `width × height` pixels, 3 bytes each: RGB565 (u16 LE) then alpha (u8, straight alpha),
row-major. Then a 4-byte trailer (**UNKNOWN**). **VERIFIED**: file size is exactly `4 + w·h·3` + 4. Used for
clock hands (`wf_w62`: 26×88, 26×106, 26×106; `wf_f82`: 34×220 ×3).

RGB565 → 8-bit: `r = (c>>11 & 31)·255//31`, `g = (c>>5 & 63)·255//63`, `b = (c & 31)·255//31`.

### 6.3 ezip frame (`format` 1 or 2)

The compression is performed in hardware by the SiFli EZIP block on the watch (**SOURCE**: `bf0_hal_ezip.c` only configures
that block; it contains no bitstream). The layout below was worked out against the **OpenEZIP** decoder and checked on real
files. File offsets, starting from the 4-byte resource header:

| File offset | Size | Endian | Field |
|---|---|---|---|
| 0 | 4 | LE | Resource header (§6.1) |
| 4 | 4 | BE | `size`: length of the stream below, **including** the Adler-32 |
| 8 | 1 | | `ctrl` (see below) |
| 9 | 1 | | `depth`: bits per pixel of the decoded data (16, 24 or 8) |
| 10 | 1 | | `block_rows`: rows per block (32 in all samples) |
| 11 | 1 | | flags (0 in all samples) |
| 12 | 2+2 | BE | width, height (repeat the resource header) |
| 16 | 1 | | low nibble = filter mode: `1` = no row filters, otherwise PNG-style filters present (0 in all samples) |
| 17–19 | 3 | | `00 00 00` for RGB565 variants; byte 17 = palette count − 1 in the palette variant (§6.6) |
| 20 | 2 | BE | `rows` (see below) |
| 22 | 2 | BE | `nblk`: number of blocks |
| 24 | 4·`nblk` | BE | Block table (§6.3.1) |
| 24 + 4·`nblk` | … | | Compressed data |
| 4 + `size` − 4 | 4 | BE | **Adler-32** of the *decoded* (still filtered) data |

The file can be longer than `4 + size` by a few bytes (4–7 observed on `wf_f82`; purpose **UNKNOWN**, possibly padding).

**`ctrl`**: `0x4C` for 24-bit (format 2) images, `0x48` for 16-bit (format 1) images, `0x43` for 8-bit palette images
(**OBSERVED** correlation). The high nibble selects the entropy coder: `>2` and `!=5` → shared Huffman (§6.3.2, seen: 4);
otherwise per-block raw DEFLATE (from OpenEZIP, **UNTESTED**: no sample uses it).

**`rows`** equals `min(height, 32)` in every sample (26 for the 60×26 weekday frames, 20 for the 12×20 digits,
32 for the larger images), i.e. the number of rows per block. **OBSERVED.** OpenEZIP's shared-Huffman path uses this value
as the block size for the filter reset in §6.3.3, and so does `extract_sifli_dial.py`; the `block_rows` byte at offset 10 is
32 in all samples and is not used by that path.

#### 6.3.1 Block table

`nblk` big-endian u32 values, `ceil(height / block_rows)` blocks (1 for 60×26, 10 for 172×320, 12 for 360×360).
For the shared-Huffman coder the table is **not needed to decode**; the whole block stream is decoded sequentially.
What the entries contain is **UNKNOWN** (they may be block offsets; OpenEZIP masks the first one with `0x00FFFFFF`
in its per-block-DEFLATE path, reason unknown).

#### 6.3.2 Shared-Huffman stream (`ctrl >> 4 == 4`) — VERIFIED

A DEFLATE-style bit stream (bits LSB-first) with one Huffman table shared by all blocks:

1. **Table header**, with *no* leading BFINAL/BTYPE bits: `HLIT` (5 bits, +257), `HDIST` (5 bits, +1), `HCLEN` (4 bits, +4).
2. Code-length code lengths: `HCLEN` × 3 bits, in the standard order `16,17,18,0,8,7,9,6,10,5,11,4,12,3,13,2,14,1,15`.
3. Literal/length and distance code lengths, decoded with symbols 0–15 (length), 16 (repeat previous 3–6),
   17 (zeros 3–10), 18 (zeros 11–138), exactly as in DEFLATE. Canonical Huffman code assignment as in DEFLATE.
4. **Align to the next 4-byte boundary.**
5. Then one or more **blocks**, each: `BFINAL` (1 bit), `BTYPE` (2 bits): `0` = stored, `1` or `2` = compressed with the
   shared tables from step 3 (no per-block tables). Stored blocks: 16-bit length, then skip 4 bytes (LEN and NLEN),
   then raw bytes. Compressed blocks use standard DEFLATE length/distance symbols and extra bits; symbol 256 ends the block.
6. **Align to a 4-byte boundary after every block**; stop after the block with `BFINAL = 1`.

Decoded size equals `height × (width × bytes_per_pixel + 1)`, where the `+1` is the filter-type byte per row.
`bytes_per_pixel = depth / 8`. The Adler-32 of that buffer must match the trailer: **it did for every RGB565 / RGB565+alpha
frame decoded from both samples** (23 ezip image files, including both backgrounds and both thumbnails; the 6 raw
hand images have no checksum).

#### 6.3.3 PNG-style row filters

Each row is preceded by a filter-type byte (0 None, 1 Sub, 2 Up, 3 Average, 4 Paeth), exactly as in PNG with
`bpp` = bytes per pixel. **The "previous row" is treated as all zero at the first row of each block** (row index
`y % rows == 0`, `rows` from file offset 20), so blocks are independently decodable.

#### 6.3.4 Pixel formats after unfiltering

| `format` | `depth` | Bytes/pixel | Pixel |
|---|---|---|---|
| 1 | 16 | 2 | RGB565, little-endian |
| 2 | 24 | 3 | RGB565 little-endian, then alpha byte (straight alpha) |

### 6.4 Multi-frame container (`format` 0x1F) — VERIFIED on `wf_w62` only

| File offset | Size | Endian | Field |
|---|---|---|---|
| 0 | 4 | LE | Resource header (`format` = 0x1F, width, height of one frame) |
| 4 | 4 | LE | Frame count `n` |
| 8 | 4 | LE | Second count/limit (**UNKNOWN** meaning) |
| 0x10 | 4·`n` | LE | Offsets `o[i]`, measured from file offset 4 |
| `o[i] + 4` | 4 | LE | Frame size `s[i]` |
| `o[i] + 8` | `s[i]` | | A complete ezip frame (§6.3), with its own 4-byte resource header |

`wf_w62_picture_dialBg.bin` is a container with one frame (172×320, format 1); `wf_w62_week_0_dialDate.bin` has 7 frames
(60×26, format 2, SUN..SAT). `wf_f82` has no `0x1F` files; its images are single frames (§6.3).

### 6.5 Thumbnail

`<name>_tn.bin` is a normal single ezip frame (`wf_w62`: 136×252, `wf_f82`: 270×270). **VERIFIED**.

### 6.6 8-bit palette variant (`ctrl` 0x43) — PARTLY UNDERSTOOD, not decodable yet

On `wf_f82`, 24 of 47 images (clock digits, weekday labels, some date/temperature digits) use `format` 1 with `depth` 8 and
`ctrl` 0x43.

- Byte 17 holds a count (e.g. 0x43 = 67 for `wf_f82_date_1_dialDate_10.bin`, 10×20), and the file has a table of
  4-byte entries beginning at file offset 24.
- On that one file, shared-Huffman data starts at `24 + 4·(count + 1)` = 296 and decodes to exactly `10×20 + 20` bytes with
  a matching Adler-32. **VERIFIED for this file only.** The same rule fails on larger files (e.g. `wf_f82_time_0_dialClock_0.bin`).
- After unfiltering (1 byte/pixel), the index map is clearly an image (a diagonal glyph), with indices numbered in
  first-appearance order. So the stream is a palette-index image.
- **UNKNOWN:** how the 4-byte table entries map to color and alpha (tried RGBA, ARGB, BGRA and RGB-opaque byte orders; none
  gives a clean image), and how the data offset is derived on larger files.

---

## 7. Sources

- `ido_app_custom_dial_make.c`: vendor packer for the container (`head_t`, `file_head_t`, CRC-16).
- OpenEZIP (SiFli ezip decoder tool, `ezip_decoder.py` / `sifli_header.py`): ezip stream layouts and shared-Huffman decoder.
- `bf0_hal_ezip.c`: SiFli EZIP hardware driver (decode modes EZIP / GZIP / LZ4, error flags); no bitstream.
- Designer JS (`WatchService.js`, `ProtocolUtilSiChe.js`): export zip layout, image naming, `ezip` / `no_ezip` split.
- `wf_sifliTest.c`: example generated LVGL face source (hand pivots and angle formulas).
- Sample faces: `wf_w62.watch`, `wf_f82.watch`.
