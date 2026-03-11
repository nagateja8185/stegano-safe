"""
SteganoSafe — Hybrid Steganography Module
==========================================
Implements two steganographic embedding strategies:

Strategy 1 — Multi-bit LSB (VERSION 2):
    - For small payloads that fit within pixel data
    - Payload is zlib-compressed, then embedded in N LSBs per channel
    - Minimal visual impact (uses fewest bits possible)

Strategy 2 — IEND-append (VERSION 3):
    - For large payloads (1 MB – 50 MB+)
    - The cover image is NOT modified at all (zero quality loss)
    - Compressed payload is appended after the PNG IEND chunk
    - PNG viewers/browsers ignore data after IEND
    - The file still opens as a normal PNG image

The system auto-selects the best strategy based on capacity.

Security:
- Embedded data is already AES-256-GCM encrypted
- CRC32 integrity check on extraction
- Tamper detection via extraction failure
"""

import struct
import zlib


class Steganography:
    """
    Hybrid steganography engine for hiding data in PNG images.

    Auto-selects between:
    - Multi-bit LSB (VERSION 2) — small payloads, pixel-level hiding
    - IEND-append (VERSION 3) — large payloads, zero image degradation
    """

    MAGIC = b'STEG'
    VERSION_LSB = 2
    VERSION_APPEND = 3
    MAX_BPC = 6
    MIN_BPC = 1

    # ─── Capacity ────────────────────────────────────────────────

    def _lsb_capacity(self, num_pixels: int, bpc: int) -> int:
        """Byte capacity for LSB mode (excluding 14-byte header)."""
        total_bits = num_pixels * 3 * bpc
        header_bits = 14 * 8  # MAGIC(4)+VER(1)+BPC(1)+LEN(4)+CRC(4)
        return max(0, (total_bits - header_bits) // 8)

    def _best_bpc(self, num_pixels: int, payload_size: int):
        """Find minimum bits-per-channel that fits, or None."""
        for bpc in range(self.MIN_BPC, self.MAX_BPC + 1):
            if self._lsb_capacity(num_pixels, bpc) >= payload_size:
                return bpc
        return None

    # ─── PNG Chunk Helper ────────────────────────────────────────

    @staticmethod
    def _chunk(chunk_type: bytes, data: bytes) -> bytes:
        """Build a single PNG chunk."""
        body = chunk_type + data
        crc = struct.pack('>I', zlib.crc32(body) & 0xFFFFFFFF)
        return struct.pack('>I', len(data)) + body + crc

    # ─── PNG Parser ──────────────────────────────────────────────

    def _parse_png(self, png_data: bytes):
        """
        Parse PNG into flat pixel list of [r, g, b] values.
        Returns (pixels, width, height).
        """
        if len(png_data) < 8 or png_data[:8] != b'\x89PNG\r\n\x1a\n':  # type: ignore[index]
            raise ValueError("Not a valid PNG file")

        pos: int = 8
        w: int = 0
        h: int = 0
        bpp: int = 3
        color_type: int = 2
        idat = bytearray()
        got_ihdr = False

        while pos + 12 <= len(png_data):
            clen = struct.unpack('>I', png_data[pos:pos + 4])[0]  # type: ignore[arg-type]
            ctype = png_data[pos + 4:pos + 8]  # type: ignore[index]
            cdata = png_data[pos + 8:pos + 8 + clen]  # type: ignore[index]
            pos += 12 + clen

            if ctype == b'IHDR':
                w, h = struct.unpack('>II', cdata[:8])  # type: ignore[arg-type]
                bd = cdata[8]
                color_type = cdata[9]
                if bd != 8:
                    raise ValueError(f"Only 8-bit depth supported, got {bd}-bit")
                got_ihdr = True
                if color_type == 2:
                    bpp = 3
                elif color_type == 6:
                    bpp = 4
                elif color_type == 0:
                    bpp = 1
                elif color_type == 4:
                    bpp = 2
                else:
                    raise ValueError(f"Unsupported color type: {color_type}")
            elif ctype == b'IDAT':
                idat.extend(cdata)
            elif ctype == b'IEND':
                break

        if not got_ihdr:
            raise ValueError("Missing IHDR chunk")

        raw = zlib.decompress(bytes(idat))
        w = int(w)
        h = int(h)
        bpp = int(bpp)
        row_len = 1 + w * bpp
        pixels: list = []

        previous_row = bytearray(w * bpp)
        for y in range(h):
            rs = y * row_len
            ft = raw[rs]
            rd = bytearray(raw[rs + 1: rs + 1 + w * bpp])  # type: ignore[index]

            # Reconstruct filters
            if ft == 1:  # Sub
                for i in range(bpp, len(rd)):
                    rd[i] = (rd[i] + rd[i - bpp]) & 0xFF
            elif ft == 2:  # Up
                for i in range(len(rd)):
                    rd[i] = (rd[i] + previous_row[i]) & 0xFF
            elif ft == 3:  # Average
                for i in range(len(rd)):
                    left = rd[i - bpp] if i >= bpp else 0
                    up = previous_row[i]
                    rd[i] = (rd[i] + (left + up) // 2) & 0xFF
            elif ft == 4:  # Paeth
                for i in range(len(rd)):
                    left = rd[i - bpp] if i >= bpp else 0
                    up = previous_row[i]
                    ul = previous_row[i - bpp] if i >= bpp else 0
                    p = left + up - ul
                    pa, pb, pc = abs(p - left), abs(p - up), abs(p - ul)
                    if pa <= pb and pa <= pc:
                        pv = left
                    elif pb <= pc:
                        pv = up
                    else:
                        pv = ul
                    rd[i] = (rd[i] + pv) & 0xFF
                    
            previous_row = rd

            # Convert to RGB
            for x in range(w):
                idx = x * bpp
                if color_type in (0, 4):  # Grayscale
                    v = rd[idx]
                    pixels.append([v, v, v])
                else:  # RGB or RGBA
                    pixels.append([rd[idx], rd[idx + 1], rd[idx + 2]])

        return pixels, w, h

    # ─── PNG Builder ─────────────────────────────────────────────

    def _build_png(self, pixels: list, w: int, h: int) -> bytes:
        """Create a minimal PNG from a 2D pixel list."""
        sig = b'\x89PNG\r\n\x1a\n'
        ihdr = self._chunk(b'IHDR', struct.pack('>IIBBBBB', w, h, 8, 2, 0, 0, 0))

        row_size = 1 + w * 3
        raw = bytearray(row_size * h)
        for y in range(h):
            off = y * row_size
            raw[off] = 0  # Filter: None
            for x in range(w):
                p = pixels[y * w + x]
                i = off + 1 + x * 3
                raw[i] = p[0]
                raw[i + 1] = p[1]
                raw[i + 2] = p[2]

        idat = self._chunk(b'IDAT', zlib.compress(bytes(raw)))
        iend = self._chunk(b'IEND', b'')
        return sig + ihdr + idat + iend

    # ─── IEND offset finder ──────────────────────────────────────

    def _find_iend_end(self, png_data: bytes) -> int:
        """Return byte offset right after the IEND chunk."""
        pos: int = 8
        while pos + 12 <= len(png_data):
            clen = struct.unpack('>I', png_data[pos:pos + 4])[0]  # type: ignore[arg-type]
            ctype = png_data[pos + 4:pos + 8]  # type: ignore[index]
            end = pos + 12 + clen
            if ctype == b'IEND':
                return end
            pos = end
        raise ValueError("IEND chunk not found in PNG")

    # ─── Copy original PNG up to IEND ────────────────────────────

    def _copy_png_to_iend(self, png_data: bytes) -> bytes:
        """
        Copy original PNG bytes exactly up to (and including) the IEND chunk.
        This preserves the image PERFECTLY — no re-encoding, no pixel changes.
        """
        iend_end = self._find_iend_end(png_data)
        return png_data[:iend_end]  # type: ignore[index]

    # ═══════════════════════════════════════════════════════════════
    # ─── EMBED ────────────────────────────────────────────────────
    # ═══════════════════════════════════════════════════════════════

    def embed(self, carrier_data: bytes, payload: bytes) -> bytes:
        """
        Embed payload into cover image.

        Automatically selects strategy:
        - LSB mode (v2): if compressed payload fits in pixel data with ≤2 bpc
        - IEND-append (v3): for everything else (preserves image perfectly)

        Args:
            carrier_data: PNG cover image bytes
            payload: Data to hide (will be compressed)

        Returns:
            Stego PNG image bytes
        """
        compressed = zlib.compress(payload, 9)

        # Check if LSB mode is feasible with minimal quality loss
        pixels, width, height = self._parse_png(carrier_data)
        bpc = self._best_bpc(len(pixels), len(compressed))

        if bpc is not None and bpc <= 2:
            # LSB mode — only if we need ≤2 bits per channel (barely visible)
            return self._embed_lsb(pixels, width, height, compressed, bpc)
        else:
            # IEND-append — preserves cover image EXACTLY as-is
            return self._embed_append(carrier_data, compressed)

    def _embed_lsb(self, pixels: list, w: int, h: int,
                   compressed: bytes, bpc: int) -> bytes:
        """Embed via multi-bit LSB into pixel data (VERSION 2)."""
        crc = struct.pack('>I', zlib.crc32(compressed) & 0xFFFFFFFF)
        header = (self.MAGIC
                  + struct.pack('B', self.VERSION_LSB)
                  + struct.pack('B', bpc)
                  + struct.pack('>I', len(compressed))
                  + crc)
        full = header + compressed

        # Convert to bits
        bits: list = []
        for bv in full:
            for bp in range(7, -1, -1):
                bits.append((bv >> bp) & 1)

        mask = 0xFF & ~((1 << bpc) - 1)
        bi: int = 0
        for px in range(len(pixels)):
            if bi >= len(bits):
                break
            for ch in range(3):
                if bi >= len(bits):
                    break
                val: int = 0
                for _ in range(bpc):
                    if bi < len(bits):
                        val = (val << 1) | bits[bi]  # type: ignore[arg-type]
                        bi += 1  # type: ignore[operator]
                    else:
                        val <<= 1
                pixels[px][ch] = (pixels[px][ch] & mask) | val  # type: ignore[index]

        return self._build_png(pixels, w, h)

    def _embed_append(self, carrier_data: bytes, compressed: bytes) -> bytes:
        """
        Embed via IEND-append (VERSION 3).

        The cover image is NOT modified at all — we simply copy it
        byte-for-byte and append the hidden data after the IEND chunk.

        Structure after IEND:
            [8B marker: 'STEGDATA']
            [1B version: 3]
            [4B compressed length]
            [4B CRC32 of compressed data]
            [compressed payload bytes]
        """
        # Copy original PNG exactly (preserves image perfectly)
        clean_png = self._copy_png_to_iend(carrier_data)

        # Build append header
        crc = struct.pack('>I', zlib.crc32(compressed) & 0xFFFFFFFF)
        append_header = (b'STEGDATA'
                         + struct.pack('B', self.VERSION_APPEND)
                         + struct.pack('>I', len(compressed))
                         + crc)

        return clean_png + append_header + compressed

    # ═══════════════════════════════════════════════════════════════
    # ─── EXTRACT ──────────────────────────────────────────────────
    # ═══════════════════════════════════════════════════════════════

    def extract(self, stego_data: bytes) -> bytes:
        """
        Extract hidden payload from a stego image.
        Auto-detects the embedding strategy.

        Returns:
            Original payload bytes (decompressed)
        """
        # ── First: check for IEND-append (VERSION 3) ──
        # This is fast — just look for the STEGDATA marker after IEND
        try:
            iend_end = self._find_iend_end(stego_data)
            if iend_end + 8 <= len(stego_data):
                marker = stego_data[iend_end:iend_end + 8]  # type: ignore[index]
                if marker == b'STEGDATA':
                    return self._extract_append(stego_data, iend_end)
        except ValueError:
            pass

        # ── Second: try LSB extraction (VERSION 2 / legacy v1) ──
        pixels, w, h = self._parse_png(stego_data)
        num_px = len(pixels)

        # Read first 6 bytes via 1-bit LSB to check magic + version
        hdr_bits = self._extract_1bpc(pixels, 48)
        hdr_bytes = self._to_bytes(hdr_bits)

        if hdr_bytes[:4] != self.MAGIC:  # type: ignore[index]
            raise ValueError(
                "No steganographic data found in this image. "
                "The image may not contain hidden data or has been modified."
            )

        version = hdr_bytes[4]

        if version == self.VERSION_LSB:
            return self._extract_lsb_v2(pixels, num_px)
        else:
            return self._extract_lsb_v1(pixels, num_px)

    def _extract_append(self, stego_data: bytes, iend_end: int) -> bytes:
        """Extract from IEND-append format (VERSION 3)."""
        # Parse header after STEGDATA marker
        hdr_start = iend_end + 8  # skip 'STEGDATA'
        ver = stego_data[hdr_start]
        if ver != self.VERSION_APPEND:
            raise ValueError(f"Unknown append version: {ver}")

        comp_len = struct.unpack('>I', stego_data[hdr_start + 1:hdr_start + 5])[0]  # type: ignore[arg-type]
        stored_crc = stego_data[hdr_start + 5:hdr_start + 9]

        data_start = hdr_start + 9
        compressed = stego_data[data_start:data_start + comp_len]  # type: ignore[index]

        if len(compressed) != comp_len:
            raise ValueError(
                f"Truncated data: expected {comp_len} bytes, got {len(compressed)}"
            )

        # Verify CRC
        computed_crc = struct.pack('>I', zlib.crc32(compressed) & 0xFFFFFFFF)
        if computed_crc != stored_crc:
            raise ValueError("CRC32 mismatch — data may be corrupted or tampered.")

        try:
            return zlib.decompress(compressed)
        except zlib.error:
            raise ValueError("Decompression failed — data may be corrupted.")

    def _extract_lsb_v2(self, pixels: list, num_px: int) -> bytes:
        """Extract from multi-bit LSB format (VERSION 2)."""
        # Read BPC from byte 5 of header (via 1-bit LSB)
        hdr6 = self._to_bytes(self._extract_1bpc(pixels, 48))
        bpc: int = hdr6[5]
        if bpc < 1 or bpc > 6:
            raise ValueError(f"Invalid bits-per-channel: {bpc}")

        # Re-extract full 14-byte header with correct BPC
        hdr_bits = self._extract_nbpc(pixels, num_px, 14 * 8, bpc)
        hdr = self._to_bytes(hdr_bits)

        comp_len = struct.unpack('>I', hdr[6:10])[0]  # type: ignore[arg-type]
        stored_crc = hdr[10:14]

        total_bits = (14 + comp_len) * 8
        if total_bits > num_px * 3 * bpc:
            raise ValueError("Invalid payload length.")

        all_bits = self._extract_nbpc(pixels, num_px, total_bits, bpc)
        all_data = self._to_bytes(all_bits)
        compressed = all_data[14:14 + comp_len]  # type: ignore[index]

        computed_crc = struct.pack('>I', zlib.crc32(compressed) & 0xFFFFFFFF)
        if computed_crc != stored_crc:
            raise ValueError("CRC32 mismatch.")

        try:
            return zlib.decompress(compressed)
        except zlib.error:
            raise ValueError("Decompression failed.")

    def _extract_lsb_v1(self, pixels: list, num_px: int) -> bytes:
        """Extract from legacy v1 format (1-bit LSB, no compression)."""
        hdr_bits = self._extract_1bpc(pixels, 96)
        hdr = self._to_bytes(hdr_bits)

        payload_len = struct.unpack('>I', hdr[4:8])[0]  # type: ignore[arg-type]
        stored_crc = hdr[8:12]

        total_bits = (12 + payload_len) * 8
        if total_bits > num_px * 3:
            raise ValueError("Invalid payload length.")

        all_bits = self._extract_1bpc(pixels, total_bits)
        all_data = self._to_bytes(all_bits)
        payload = all_data[12:12 + payload_len]  # type: ignore[index]

        computed_crc = struct.pack('>I', zlib.crc32(payload) & 0xFFFFFFFF)
        if computed_crc != stored_crc:
            raise ValueError("CRC32 mismatch.")

        return payload

    # ─── Bit extraction helpers ──────────────────────────────────

    def _extract_1bpc(self, pixels: list, count: int) -> list:
        """Extract `count` bits using 1-bit-per-channel LSB."""
        bits: list = []
        for px in pixels:
            if len(bits) >= count:
                break
            for ch in range(3):
                if len(bits) >= count:
                    break
                bits.append(px[ch] & 1)
        return bits

    def _extract_nbpc(self, pixels: list, num_px: int,
                      count: int, bpc: int) -> list:
        """Extract `count` bits using N-bit-per-channel LSB."""
        bits: list = []
        lsb_mask = (1 << bpc) - 1
        for px_idx in range(num_px):
            if len(bits) >= count:
                break
            for ch in range(3):
                if len(bits) >= count:
                    break
                val = pixels[px_idx][ch] & lsb_mask  # type: ignore[index]
                for bi in range(bpc - 1, -1, -1):
                    if len(bits) >= count:
                        break
                    bits.append((val >> bi) & 1)
        return bits

    def _to_bytes(self, bits: list) -> bytes:
        """Convert bit list to bytes."""
        result = bytearray()
        for i in range(0, len(bits), 8):
            bv: int = 0
            for j in range(8):
                if i + j < len(bits):
                    bv = (bv << 1) | bits[i + j]  # type: ignore[arg-type]
                else:
                    bv <<= 1
            result.append(bv)
        return bytes(result)
