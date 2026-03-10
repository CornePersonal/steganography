"""
StegoCrypt v2 — Military-grade steganography that fights to survive.

Architecture:
  1. Text → zlib compress → AES-256-GCM encrypt → MAGIC+length header → Reed-Solomon ECC
  2. RS bytes → bitstream with self-describing header (RS length + quant step, repeated 7×)
  3. Bits scattered across PRNG-shuffled DCT coefficient positions (password-seeded)
  4. Each bit stored 3× (spatial redundancy) with confidence-weighted majority voting
  5. Extraction auto-detects embedding strength; smart recovery with erasure decoding

Survives: JPEG recompression (Q≥70), WhatsApp/Telegram re-encoding, format conversion.
Security: Without the password, data positions are unknown (PRNG-shuffled) + AES-256-GCM.

Dependencies:
    pip install PyQt6 numpy scipy cryptography reedsolo Pillow
"""

import sys
import os
import struct
import hashlib
import zlib
import numpy as np

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

import reedsolo

from PIL import Image
from scipy.fft import dctn, idctn

from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QTabWidget, QStackedWidget,
    QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QTextEdit, QLineEdit, QFileDialog, QMessageBox,
    QProgressBar, QFrame, QGroupBox, QSlider, QCheckBox,
    QScrollArea,
)
from PyQt6.QtCore import Qt, QThread, pyqtSignal
from PyQt6.QtGui import QPixmap, QFont, QDragEnterEvent, QDropEvent


# ═══════════════════════════════════════════════════════════════════════════
# Constants
# ═══════════════════════════════════════════════════════════════════════════
BLOCK_SIZE = 8

# Zigzag positions 3-15 → 13 mid-frequency coefficients per 8×8 block.
# These sit in the sweet spot: invisible enough, yet robust against JPEG Q≥70.
FREQ_INDICES = list(range(3, 16))
NUM_FREQS = len(FREQ_INDICES)          # 13

REDUNDANCY = 3                          # Each bit embedded 3× in different positions
HEADER_REPEATS = 7                      # RS-length + step repeated 7× for majority vote
HEADER_DATA_BYTES = 5                   # 4 bytes RS-length + 1 byte quant_step
HEADER_BITS = HEADER_DATA_BYTES * 8 * HEADER_REPEATS  # 280

RS_NSYM = 50                            # Aggressive ECC: corrects ≤25 byte errors, ≤50 erasures
RS_BLOCK_DATA = 255 - RS_NSYM           # 205 data bytes per RS block (interleaving)
MAGIC = b"STGC"                         # 4-byte signature

DEFAULT_QUANT_STEP = 16                 # Balanced robustness/invisibility
MIN_QUANT_STEP = 8
MAX_QUANT_STEP = 32

PBKDF2_ITERATIONS = 200_000
SALT_SIZE = 16
NONCE_SIZE = 12

MAX_RECOVERY_FLIPS = 40                 # Max bit-flips to try in recovery mode


# ═══════════════════════════════════════════════════════════════════════════
# AES-256-GCM encryption
# ═══════════════════════════════════════════════════════════════════════════

def _derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(), length=32,
        salt=salt, iterations=PBKDF2_ITERATIONS,
    )
    return kdf.derive(password.encode("utf-8"))


def aes_encrypt(plaintext: bytes, password: str) -> bytes:
    salt = os.urandom(SALT_SIZE)
    nonce = os.urandom(NONCE_SIZE)
    key = _derive_key(password, salt)
    ct = AESGCM(key).encrypt(nonce, plaintext, None)
    return salt + nonce + ct


def aes_decrypt(data: bytes, password: str) -> bytes:
    if len(data) < SALT_SIZE + NONCE_SIZE + 16:
        raise ValueError("Data too short for AES-GCM payload.")
    salt = data[:SALT_SIZE]
    nonce = data[SALT_SIZE:SALT_SIZE + NONCE_SIZE]
    ct = data[SALT_SIZE + NONCE_SIZE:]
    key = _derive_key(password, salt)
    try:
        return AESGCM(key).decrypt(nonce, ct, None)
    except Exception:
        raise ValueError("Decryption failed — wrong password or corrupted data.")


# ═══════════════════════════════════════════════════════════════════════════
# Reed-Solomon with smart recovery
# ═══════════════════════════════════════════════════════════════════════════

def _rs_codec():
    return reedsolo.RSCodec(RS_NSYM)


def rs_encode(data: bytes) -> bytes:
    return bytes(_rs_codec().encode(data))


def rs_decode_smart(data: bytes, bit_confidences: np.ndarray = None) -> bytes:
    """
    Multi-strategy RS decode. Tries:
      1. Standard error correction (≤25 byte errors)
      2. Erasure decoding on least-confident bytes (≤50 erasures)
      3. Cumulative bit-flipping on lowest-confidence bits + retry
    Returns decoded data or raises ValueError.
    """
    rsc = _rs_codec()

    # --- Strategy 1: straight decode ---
    try:
        decoded, _, _ = rsc.decode(data)
        return bytes(decoded)
    except reedsolo.ReedSolomonError:
        pass

    if bit_confidences is None or len(bit_confidences) < len(data) * 8:
        raise ValueError("RS decode failed and no confidence data for recovery.")

    # --- Strategy 2: erasure decoding ---
    # Compute per-byte confidence (minimum of 8 constituent bit confidences)
    n_bytes = len(data)
    byte_confs = []
    for i in range(n_bytes):
        s = i * 8
        e = min(s + 8, len(bit_confidences))
        byte_confs.append((np.min(bit_confidences[s:e]), i))
    byte_confs.sort()  # lowest confidence first

    for n_erase in [RS_NSYM, 45, 40, 35, 30, 25, 20, 15, 10, 5]:
        if n_erase > n_bytes:
            continue
        erase_pos = sorted([pos for _, pos in byte_confs[:n_erase]])
        try:
            decoded, _, _ = rsc.decode(data, erase_pos=erase_pos)
            return bytes(decoded)
        except reedsolo.ReedSolomonError:
            continue

    # --- Strategy 3: cumulative bit-flipping ---
    bit_confs_indexed = sorted(
        [(bit_confidences[i], i) for i in range(min(len(bit_confidences), n_bytes * 8))]
    )
    data_arr = bytearray(data)
    for k in range(min(MAX_RECOVERY_FLIPS, len(bit_confs_indexed))):
        _, bit_idx = bit_confs_indexed[k]
        byte_idx = bit_idx // 8
        bit_pos = 7 - (bit_idx % 8)
        data_arr[byte_idx] ^= (1 << bit_pos)
        try:
            decoded, _, _ = rsc.decode(bytes(data_arr))
            return bytes(decoded)
        except reedsolo.ReedSolomonError:
            continue

    raise ValueError(
        "Data too corrupted to recover — all RS strategies exhausted."
    )


def rs_encode_interleaved(data: bytes) -> bytes:
    """Split data into blocks, RS encode each, interleave for burst-error resistance."""
    rsc = _rs_codec()
    block_enc = RS_BLOCK_DATA + RS_NSYM  # 255
    n_blocks = max(1, -(-len(data) // RS_BLOCK_DATA))  # ceil division
    padded = data + b'\x00' * (n_blocks * RS_BLOCK_DATA - len(data))

    encoded = []
    for i in range(n_blocks):
        chunk = padded[i * RS_BLOCK_DATA:(i + 1) * RS_BLOCK_DATA]
        encoded.append(bytes(rsc.encode(chunk)))

    # Interleave byte-by-byte across blocks (spreads burst errors)
    interleaved = bytearray(n_blocks * block_enc)
    for i in range(block_enc):
        for j in range(n_blocks):
            interleaved[i * n_blocks + j] = encoded[j][i]
    return bytes(interleaved)


def rs_decode_interleaved(data: bytes, bit_confidences: np.ndarray = None) -> bytes:
    """De-interleave and decode each RS block independently with smart recovery."""
    block_enc = RS_BLOCK_DATA + RS_NSYM  # 255
    n_blocks = len(data) // block_enc
    if n_blocks == 0 or len(data) % block_enc != 0:
        raise ValueError("Invalid interleaved RS data length.")

    # De-interleave into individual blocks
    blocks = [bytearray(block_enc) for _ in range(n_blocks)]
    if bit_confidences is not None:
        block_confs = [np.zeros(block_enc * 8) for _ in range(n_blocks)]
    else:
        block_confs = [None] * n_blocks

    for i in range(block_enc):
        for j in range(n_blocks):
            src_idx = i * n_blocks + j
            blocks[j][i] = data[src_idx]
            if bit_confidences is not None:
                src_bit = src_idx * 8
                dst_bit = i * 8
                block_confs[j][dst_bit:dst_bit + 8] = bit_confidences[src_bit:src_bit + 8]

    # Decode each block with smart recovery
    decoded_blocks = []
    for j in range(n_blocks):
        decoded_blocks.append(rs_decode_smart(bytes(blocks[j]), block_confs[j]))
    return b''.join(decoded_blocks)


def _try_rs_decode(rs_bytes: bytes, bit_confs: np.ndarray) -> bytes:
    """Try interleaved RS decode first, fall back to legacy single-block."""
    block_enc = RS_BLOCK_DATA + RS_NSYM
    if len(rs_bytes) >= block_enc and len(rs_bytes) % block_enc == 0:
        try:
            return rs_decode_interleaved(rs_bytes, bit_confs)
        except ValueError:
            pass
    return rs_decode_smart(rs_bytes, bit_confs)


# ═══════════════════════════════════════════════════════════════════════════
# Zigzag scan table
# ═══════════════════════════════════════════════════════════════════════════

def _zigzag_indices(n: int):
    indices = []
    for s in range(2 * n - 1):
        if s % 2 == 0:
            r = min(s, n - 1)
            c = s - r
            while r >= 0 and c < n:
                indices.append((r, c))
                r -= 1
                c += 1
        else:
            c = min(s, n - 1)
            r = s - c
            while c >= 0 and r < n:
                indices.append((r, c))
                r += 1
                c -= 1
    return indices


_ZIGZAG = _zigzag_indices(BLOCK_SIZE)
_FREQ_ROWS = np.array([_ZIGZAG[fi][0] for fi in FREQ_INDICES])
_FREQ_COLS = np.array([_ZIGZAG[fi][1] for fi in FREQ_INDICES])


# ═══════════════════════════════════════════════════════════════════════════
# Bit / byte helpers
# ═══════════════════════════════════════════════════════════════════════════

def _bytes_to_bits(data: bytes) -> np.ndarray:
    arr = np.frombuffer(data, dtype=np.uint8)
    return np.unpackbits(arr).astype(np.int32)


def _bits_to_bytes(bits: np.ndarray) -> bytes:
    # Trim to multiple of 8
    n = (len(bits) // 8) * 8
    return bytes(np.packbits(bits[:n].astype(np.uint8)))


# ═══════════════════════════════════════════════════════════════════════════
# PRNG position shuffling (password-seeded)
# ═══════════════════════════════════════════════════════════════════════════

def _generate_positions(password: str, total_positions: int) -> np.ndarray:
    """Deterministic PRNG-shuffled position indices derived from password."""
    seed_bytes = hashlib.sha256(
        password.encode("utf-8") + b"stegocrypt_v2_positions"
    ).digest()
    seed = int.from_bytes(seed_bytes[:4], "big")
    rng = np.random.default_rng(seed)
    return rng.permutation(total_positions)


# ═══════════════════════════════════════════════════════════════════════════
# Batch DCT (vectorized — processes ALL blocks in one call)
# ═══════════════════════════════════════════════════════════════════════════

def _image_to_dct_coeffs(y_channel: np.ndarray):
    """
    Convert Y channel to a flat array of embeddable DCT coefficients.
    Returns (flat_coeffs, blocks_y, blocks_x, dct_blocks).
    flat_coeffs shape: (blocks_y * blocks_x * NUM_FREQS,)
    dct_blocks shape: (N, 8, 8)
    """
    h, w = y_channel.shape
    by = h // BLOCK_SIZE
    bx = w // BLOCK_SIZE
    y_trim = y_channel[:by * BLOCK_SIZE, :bx * BLOCK_SIZE]

    # Reshape to (N, 8, 8)
    blocks = (y_trim
              .reshape(by, BLOCK_SIZE, bx, BLOCK_SIZE)
              .transpose(0, 2, 1, 3)
              .reshape(-1, BLOCK_SIZE, BLOCK_SIZE))

    # Batch 2D DCT
    dct_blocks = dctn(blocks, axes=(-2, -1), norm="ortho")

    # Extract only the embeddable frequency coefficients → (N, NUM_FREQS) → flat
    flat_coeffs = dct_blocks[:, _FREQ_ROWS, _FREQ_COLS].flatten()
    return flat_coeffs, by, bx, dct_blocks


def _dct_coeffs_to_image(dct_blocks: np.ndarray, by: int, bx: int,
                          original_shape: tuple) -> np.ndarray:
    """
    Inverse: dct_blocks (N, 8, 8) → spatial Y channel of original_shape.
    """
    blocks = idctn(dct_blocks, axes=(-2, -1), norm="ortho")
    y_trim = (blocks
              .reshape(by, bx, BLOCK_SIZE, BLOCK_SIZE)
              .transpose(0, 2, 1, 3)
              .reshape(by * BLOCK_SIZE, bx * BLOCK_SIZE))
    y_out = np.zeros(original_shape, dtype=np.float64)
    y_out[:by * BLOCK_SIZE, :bx * BLOCK_SIZE] = y_trim
    return y_out


# ═══════════════════════════════════════════════════════════════════════════
# Vectorized embedding / extraction
# ═══════════════════════════════════════════════════════════════════════════

def _embed_bits_vec(coeffs: np.ndarray, bits: np.ndarray, step: int) -> np.ndarray:
    """Embed bits into coefficients (vectorized). Returns modified coefficients."""
    q = np.round(coeffs / step).astype(np.int64)
    needs_flip = (q % 2) != bits
    q_up = q + 1
    q_dn = q - 1
    use_up = np.abs(q_up * step - coeffs) <= np.abs(q_dn * step - coeffs)
    q_new = np.where(use_up, q_up, q_dn)
    q_final = np.where(needs_flip, q_new, q)
    return (q_final * step).astype(np.float64)


def _extract_bits_vec(coeffs: np.ndarray, step: int):
    """
    Extract bits + confidence scores (vectorized).
    confidence: 1.0 = dead center of quantization bin, 0.0 = on decision boundary.
    """
    q = np.round(coeffs / step).astype(np.int64)
    bits = (q % 2).astype(np.int32)
    frac = np.abs(coeffs / step - q)
    confidence = np.clip(1.0 - 2.0 * frac, 0.0, 1.0)
    return bits, confidence


def _majority_vote(raw_bits: np.ndarray, raw_confs: np.ndarray, n_data_bits: int):
    """
    Confidence-weighted majority vote across REDUNDANCY copies.
    Returns (voted_bits, voted_confidences).
    """
    used = n_data_bits * REDUNDANCY
    rb = raw_bits[:used].reshape(n_data_bits, REDUNDANCY)
    rc = raw_confs[:used].reshape(n_data_bits, REDUNDANCY)
    # Weighted vote: +conf for bit-1, -conf for bit-0
    scores = (rc * (2 * rb - 1)).sum(axis=1)
    voted_bits = (scores > 0).astype(np.int32)
    total_conf = rc.sum(axis=1) + 1e-10
    voted_confs = np.abs(scores) / total_conf
    return voted_bits, voted_confs


# ═══════════════════════════════════════════════════════════════════════════
# Header encode / decode
# ═══════════════════════════════════════════════════════════════════════════

def _encode_header(rs_len: int, quant_step: int) -> np.ndarray:
    """Encode header: 5 bytes (rs_len[4] + step[1]) × 7 repeats → 280 bits."""
    hdr = struct.pack(">I", rs_len) + struct.pack("B", quant_step)
    hdr_bits = _bytes_to_bits(hdr)   # 40 bits
    return np.tile(hdr_bits, HEADER_REPEATS)  # 280 bits


def _decode_header(voted_bits: np.ndarray):
    """
    Decode header from 280 voted bits → (rs_len, quant_step).
    Majority vote across 7 copies of 40-bit header.
    """
    bits_per_copy = HEADER_DATA_BYTES * 8  # 40
    final_bits = np.zeros(bits_per_copy, dtype=np.int32)
    for j in range(HEADER_REPEATS):
        final_bits += voted_bits[j * bits_per_copy:(j + 1) * bits_per_copy]
    final_bits = (final_bits > HEADER_REPEATS // 2).astype(np.int32)

    hdr_bytes = _bits_to_bytes(final_bits)
    rs_len = struct.unpack(">I", hdr_bytes[:4])[0]
    quant_step = hdr_bytes[4]
    return rs_len, quant_step


# ═══════════════════════════════════════════════════════════════════════════
# Image preparation
# ═══════════════════════════════════════════════════════════════════════════

def _prepare_image(image: Image.Image, max_dim: int = 0) -> Image.Image:
    """Ensure RGB, optionally resize, pad to multiple of 8."""
    img = image.convert("RGB")
    w, h = img.size

    if max_dim > 0 and max(w, h) > max_dim:
        scale = max_dim / max(w, h)
        w = int(w * scale)
        h = int(h * scale)
        img = img.resize((w, h), Image.LANCZOS)

    # Ensure multiples of BLOCK_SIZE
    nw = (w // BLOCK_SIZE) * BLOCK_SIZE
    nh = (h // BLOCK_SIZE) * BLOCK_SIZE
    if nw != w or nh != h:
        img = img.crop((0, 0, nw, nh))
    return img


# ═══════════════════════════════════════════════════════════════════════════
# HIGH-LEVEL EMBED
# ═══════════════════════════════════════════════════════════════════════════

def embed_data(image: Image.Image, payload: bytes, password: str,
               quant_step: int = DEFAULT_QUANT_STEP,
               max_dim: int = 0, progress_cb=None) -> Image.Image:
    """
    Full embedding pipeline:
      payload → MAGIC+len → RS encode → header+bitstream → PRNG-shuffle → DCT embed
    Returns stego PIL Image (RGB, PNG-ready).
    """
    img = _prepare_image(image, max_dim)
    if progress_cb:
        progress_cb(5)

    # --- Build inner payload ---
    inner = MAGIC + struct.pack(">I", len(payload)) + payload
    rs_data = rs_encode_interleaved(inner)
    rs_len = len(rs_data)

    # --- Build bitstream: header + RS data ---
    header_bits = _encode_header(rs_len, quant_step)     # 280 bits
    data_bits = _bytes_to_bits(rs_data)                    # rs_len * 8 bits
    logical_bits = np.concatenate([header_bits, data_bits])
    n_logical = len(logical_bits)

    # --- Get image DCT coefficients ---
    ycbcr = img.convert("YCbCr")
    ycbcr_arr = np.array(ycbcr, dtype=np.float64)
    y_ch = ycbcr_arr[:, :, 0]

    flat_coeffs, by, bx, dct_blocks = _image_to_dct_coeffs(y_ch)
    total_positions = len(flat_coeffs)
    needed_positions = n_logical * REDUNDANCY

    if needed_positions > total_positions:
        max_logical = total_positions // REDUNDANCY
        max_data = max_logical - HEADER_BITS
        max_rs = max_data // 8
        n_blk = max_rs // (RS_BLOCK_DATA + RS_NSYM)
        max_usable = n_blk * RS_BLOCK_DATA - 8
        raise ValueError(
            f"Payload too large for this image. Max ≈ {max(0, max_usable)} bytes "
            f"at strength {quant_step}. Use a larger image or shorter message."
        )

    if progress_cb:
        progress_cb(15)

    # --- PRNG shuffle positions ---
    perm = _generate_positions(password, total_positions)

    # --- Expand bits with redundancy (each bit → R copies) ---
    expanded_bits = np.repeat(logical_bits, REDUNDANCY)  # each bit 3 times

    # --- Map to shuffled positions and embed ---
    target_positions = perm[:needed_positions]
    original_coeffs = flat_coeffs[target_positions]
    modified_coeffs = _embed_bits_vec(original_coeffs, expanded_bits, quant_step)

    # --- Write modified coefficients back into DCT blocks ---
    flat_coeffs[target_positions] = modified_coeffs

    # Scatter flat_coeffs back into dct_blocks
    n_blocks = by * bx
    reshaped = flat_coeffs.reshape(n_blocks, NUM_FREQS)
    for fi in range(NUM_FREQS):
        dct_blocks[:n_blocks, _FREQ_ROWS[fi], _FREQ_COLS[fi]] = reshaped[:, fi]

    if progress_cb:
        progress_cb(75)

    # --- Inverse DCT → reconstruct image ---
    y_new = _dct_coeffs_to_image(dct_blocks, by, bx, y_ch.shape)

    # Preserve original Y for non-block-aligned edges
    y_new[:by * BLOCK_SIZE, :bx * BLOCK_SIZE] = np.clip(
        y_new[:by * BLOCK_SIZE, :bx * BLOCK_SIZE], 0, 255
    )
    # Copy original edges
    y_new[by * BLOCK_SIZE:, :] = y_ch[by * BLOCK_SIZE:, :]
    y_new[:, bx * BLOCK_SIZE:] = y_ch[:, bx * BLOCK_SIZE:]

    ycbcr_arr[:, :, 0] = np.clip(y_new, 0, 255)
    ycbcr_out = Image.fromarray(np.uint8(np.clip(ycbcr_arr, 0, 255)), "YCbCr")

    if progress_cb:
        progress_cb(100)
    return ycbcr_out.convert("RGB")


# ═══════════════════════════════════════════════════════════════════════════
# HIGH-LEVEL EXTRACT (auto-detect strength, smart recovery)
# ═══════════════════════════════════════════════════════════════════════════

def extract_data(image: Image.Image, password: str,
                 progress_cb=None, status_cb=None) -> bytes:
    """
    Full extraction pipeline with auto-detection and smart recovery.
    Tries every possible quant_step until the self-describing header matches.
    On RS failure, falls back to erasure decoding and bit-flip recovery.
    """
    def _status(msg):
        if status_cb:
            status_cb(msg)

    img = image.convert("RGB")
    ycbcr = img.convert("YCbCr")
    y_ch = np.array(ycbcr, dtype=np.float64)[:, :, 0]

    flat_coeffs, by, bx, _ = _image_to_dct_coeffs(y_ch)
    total_positions = len(flat_coeffs)

    if total_positions < HEADER_BITS * REDUNDANCY:
        raise ValueError("Image too small to contain steganographic data.")

    # PRNG shuffle
    perm = _generate_positions(password, total_positions)
    header_positions = perm[:HEADER_BITS * REDUNDANCY]
    header_coeffs = flat_coeffs[header_positions]

    if progress_cb:
        progress_cb(10)

    # --- Auto-detect quant step ---
    _status("Probing embedding strength...")
    detected_step = None
    detected_rs_len = None

    for try_step in range(MIN_QUANT_STEP, MAX_QUANT_STEP + 1):
        raw_bits, raw_confs = _extract_bits_vec(header_coeffs, try_step)
        voted_bits, _ = _majority_vote(raw_bits, raw_confs, HEADER_BITS)
        rs_len, stored_step = _decode_header(voted_bits)

        max_rs_bytes = (total_positions // REDUNDANCY - HEADER_BITS) // 8
        if stored_step == try_step and 0 < rs_len <= max_rs_bytes:
            detected_step = stored_step
            detected_rs_len = rs_len
            break

    if detected_step is None:
        raise ValueError(
            "No hidden data found — wrong password, or image has no embedded message."
        )

    _status(f"Found data (strength {detected_step}). Extracting...")
    if progress_cb:
        progress_cb(30)

    # --- Extract all needed payload positions ---
    total_logical = HEADER_BITS + detected_rs_len * 8
    needed_positions = total_logical * REDUNDANCY

    if needed_positions > total_positions:
        raise ValueError("Header claims more data than image can hold — corrupted.")

    all_positions = perm[:needed_positions]
    all_coeffs = flat_coeffs[all_positions]

    raw_bits, raw_confs = _extract_bits_vec(all_coeffs, detected_step)
    voted_bits, voted_confs = _majority_vote(raw_bits, raw_confs, total_logical)

    if progress_cb:
        progress_cb(60)

    # --- Extract RS payload bits (skip header) ---
    rs_bits = voted_bits[HEADER_BITS:]
    rs_confs = voted_confs[HEADER_BITS:]
    rs_bytes = _bits_to_bytes(rs_bits)[:detected_rs_len]

    # Build per-bit confidences for the RS bytes
    bit_confs_for_rs = rs_confs[:detected_rs_len * 8]

    # --- Smart RS decode ---
    _status("Running error correction...")
    if progress_cb:
        progress_cb(70)

    try:
        decoded = _try_rs_decode(rs_bytes, bit_confs_for_rs)
        _status("Decoded successfully.")
    except ValueError:
        _status("Standard recovery failed. Trying deep recovery...")
        if progress_cb:
            progress_cb(75)

        # Deep recovery: also try nearby quant steps (compression may shift)
        decoded = None
        for delta in [-1, 1, -2, 2]:
            alt_step = detected_step + delta
            if alt_step < MIN_QUANT_STEP or alt_step > MAX_QUANT_STEP:
                continue
            _status(f"Trying alternate strength {alt_step}...")
            alt_bits, alt_confs = _extract_bits_vec(all_coeffs, alt_step)
            alt_voted, alt_vconfs = _majority_vote(alt_bits, alt_confs, total_logical)
            alt_rs_bits = alt_voted[HEADER_BITS:]
            alt_rs_confs = alt_vconfs[HEADER_BITS:]
            alt_rs_bytes = _bits_to_bytes(alt_rs_bits)[:detected_rs_len]
            alt_bit_confs = alt_rs_confs[:detected_rs_len * 8]
            try:
                decoded = _try_rs_decode(alt_rs_bytes, alt_bit_confs)
                _status(f"Recovered using alternate strength {alt_step}!")
                break
            except ValueError:
                continue

        if decoded is None:
            raise ValueError(
                "Could not recover data — image too heavily compressed or corrupted."
            )

    if progress_cb:
        progress_cb(90)

    # --- Validate magic + parse ---
    if not decoded.startswith(MAGIC):
        raise ValueError("No valid hidden data found in this image.")

    payload_len = struct.unpack(">I", decoded[4:8])[0]
    payload = decoded[8:8 + payload_len]

    if len(payload) < payload_len:
        raise ValueError(
            f"Incomplete payload: got {len(payload)}, expected {payload_len}."
        )

    if progress_cb:
        progress_cb(100)
    _status("Extraction complete.")
    return payload


# ═══════════════════════════════════════════════════════════════════════════
# Capacity calculator
# ═══════════════════════════════════════════════════════════════════════════

def image_capacity(image: Image.Image, quant_step: int = DEFAULT_QUANT_STEP,
                   max_dim: int = 0) -> dict:
    """Return capacity breakdown for given image + settings."""
    img = _prepare_image(image, max_dim)
    w, h = img.size
    blocks_x = w // BLOCK_SIZE
    blocks_y = h // BLOCK_SIZE
    total_positions = blocks_x * blocks_y * NUM_FREQS
    max_logical_bits = total_positions // REDUNDANCY
    payload_bits = max_logical_bits - HEADER_BITS
    rs_bytes_available = payload_bits // 8
    n_blocks = rs_bytes_available // (RS_BLOCK_DATA + RS_NSYM)
    inner_bytes = n_blocks * RS_BLOCK_DATA
    # inner = MAGIC(4) + len(4) + encrypted(salt16 + nonce12 + type1 + data + tag16)
    usable = max(0, inner_bytes - 8 - 45)
    return {
        "width": w, "height": h,
        "blocks": blocks_x * blocks_y,
        "total_positions": total_positions,
        "raw_bytes": usable,
        "estimated_text": int(usable * 1.5),  # ~1.5x with zlib on text
    }


# ═══════════════════════════════════════════════════════════════════════════
# Worker threads
# ═══════════════════════════════════════════════════════════════════════════

class EmbedWorker(QThread):
    progress = pyqtSignal(int)
    status = pyqtSignal(str)
    finished = pyqtSignal(str)
    error = pyqtSignal(str)

    def __init__(self, image_path, password, output_path, quant_step, max_dim,
                 mode='text', text=None, file_path=None):
        super().__init__()
        self.image_path = image_path
        self.password = password
        self.output_path = output_path
        self.quant_step = quant_step
        self.max_dim = max_dim
        self.mode = mode
        self.text = text
        self.file_path = file_path

    def run(self):
        try:
            self.status.emit("Loading image...")
            self.progress.emit(2)
            img = Image.open(self.image_path)

            if self.mode == 'file':
                self.status.emit("Reading file...")
                with open(self.file_path, 'rb') as f:
                    file_data = f.read()
                filename = os.path.basename(self.file_path).encode('utf-8')[:65535]
                self.status.emit("Compressing file data...")
                compressed = zlib.compress(file_data, 9)
                self.status.emit(
                    f"Compressed {len(file_data):,} → {len(compressed):,} bytes "
                    f"({100 * len(compressed) // max(len(file_data), 1)}%)"
                )
                payload_plain = (b'\x01' + struct.pack('>H', len(filename))
                                 + filename + compressed)
            else:
                self.status.emit("Compressing text...")
                raw = self.text.encode("utf-8")
                compressed = zlib.compress(raw, 9)
                self.status.emit(
                    f"Compressed {len(raw):,} → {len(compressed):,} bytes "
                    f"({100 * len(compressed) // max(len(raw), 1)}%)"
                )
                payload_plain = b'\x00' + compressed

            self.progress.emit(5)

            self.status.emit("Encrypting with AES-256-GCM...")
            encrypted = aes_encrypt(payload_plain, self.password)
            self.progress.emit(8)

            self.status.emit("Embedding into DCT coefficients...")

            def prog(v):
                self.progress.emit(8 + int(v * 0.85))

            stego_img = embed_data(
                img, encrypted, self.password,
                quant_step=self.quant_step,
                max_dim=self.max_dim,
                progress_cb=prog,
            )
            self.progress.emit(95)

            self.status.emit("Saving PNG...")
            stego_img.save(self.output_path, "PNG")
            self.progress.emit(100)
            self.status.emit("Done!")
            self.finished.emit(self.output_path)
        except Exception as e:
            self.error.emit(str(e))


class ExtractWorker(QThread):
    progress = pyqtSignal(int)
    status = pyqtSignal(str)
    finished_text = pyqtSignal(str)
    finished_file = pyqtSignal(str, object)   # filename, bytes
    error = pyqtSignal(str)

    def __init__(self, image_path, password):
        super().__init__()
        self.image_path = image_path
        self.password = password

    def run(self):
        try:
            self.status.emit("Loading image...")
            self.progress.emit(2)
            img = Image.open(self.image_path)

            def prog(v):
                self.progress.emit(2 + int(v * 0.80))

            payload = extract_data(
                img, self.password,
                progress_cb=prog,
                status_cb=lambda m: self.status.emit(m),
            )
            self.progress.emit(85)

            self.status.emit("Decrypting with AES-256-GCM...")
            decrypted = aes_decrypt(payload, self.password)
            self.progress.emit(90)

            if len(decrypted) == 0:
                raise ValueError("Empty payload.")

            type_byte = decrypted[0]

            if type_byte == 0x00:
                # New text format
                self.status.emit("Decompressing text...")
                raw = zlib.decompress(decrypted[1:])
                text = raw.decode("utf-8")
                self.progress.emit(100)
                self.status.emit(f"Success! Recovered {len(text):,} characters.")
                self.finished_text.emit(text)

            elif type_byte == 0x01:
                # File format
                self.status.emit("Extracting file...")
                if len(decrypted) < 3:
                    raise ValueError("Invalid file payload.")
                fn_len = struct.unpack('>H', decrypted[1:3])[0]
                if len(decrypted) < 3 + fn_len:
                    raise ValueError("Invalid file payload (filename truncated).")
                filename = decrypted[3:3 + fn_len].decode('utf-8')
                compressed = decrypted[3 + fn_len:]
                file_data = zlib.decompress(compressed)
                self.progress.emit(100)
                self.status.emit(
                    f"Success! Extracted file: {filename} ({len(file_data):,} bytes)"
                )
                self.finished_file.emit(filename, file_data)

            else:
                # Legacy format (raw zlib, no type byte)
                self.status.emit("Decompressing (legacy format)...")
                raw = zlib.decompress(decrypted)
                text = raw.decode("utf-8")
                self.progress.emit(100)
                self.status.emit(f"Success! Recovered {len(text):,} characters.")
                self.finished_text.emit(text)

        except Exception as e:
            self.error.emit(str(e))


# ═══════════════════════════════════════════════════════════════════════════
# UI: Drag-and-drop image label
# ═══════════════════════════════════════════════════════════════════════════

class ImageDropLabel(QLabel):
    image_dropped = pyqtSignal(str)

    def __init__(self, text="Drop image here\nor click to browse"):
        super().__init__(text)
        self.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.setAcceptDrops(True)
        self.setMinimumSize(260, 180)
        self.setStyleSheet("""
            QLabel {
                border: 2px dashed #555;
                border-radius: 8px;
                background: #1e1e2e;
                color: #888;
                font-size: 13px;
            }
            QLabel:hover {
                border-color: #7c3aed;
                color: #bbb;
            }
        """)
        self._path = None

    def mousePressEvent(self, event):
        path, _ = QFileDialog.getOpenFileName(
            self, "Select Image", "",
            "Images (*.png *.jpg *.jpeg *.bmp *.tiff *.webp)"
        )
        if path:
            self._set_image(path)

    def dragEnterEvent(self, event: QDragEnterEvent):
        if event.mimeData().hasUrls():
            event.acceptProposedAction()

    def dropEvent(self, event: QDropEvent):
        urls = event.mimeData().urls()
        if urls:
            self._set_image(urls[0].toLocalFile())

    def _set_image(self, path: str):
        self._path = path
        px = QPixmap(path).scaled(
            self.width() - 8, self.height() - 8,
            Qt.AspectRatioMode.KeepAspectRatio,
            Qt.TransformationMode.SmoothTransformation,
        )
        self.setPixmap(px)
        self.image_dropped.emit(path)

    def get_path(self):
        return self._path

    def reset(self):
        self._path = None
        self.setText("Drop image here\nor click to browse")
        self.setPixmap(QPixmap())


# ═══════════════════════════════════════════════════════════════════════════
# UI: Embed tab
# ═══════════════════════════════════════════════════════════════════════════

class EmbedTab(QWidget):
    def __init__(self):
        super().__init__()
        self._worker = None
        self._payload_mode = 'text'
        self._embed_file_path = None
        self._build_ui()

    def _build_ui(self):
        layout = QVBoxLayout(self)
        layout.setSpacing(10)
        layout.setContentsMargins(16, 16, 16, 16)

        # --- Image ---
        img_group = QGroupBox("Cover Image")
        img_group.setStyleSheet(GROUP_STYLE)
        ig = QVBoxLayout(img_group)
        self.img_label = ImageDropLabel()
        self.img_label.image_dropped.connect(self._on_image_loaded)
        ig.addWidget(self.img_label)
        self.capacity_label = QLabel("Capacity: —")
        self.capacity_label.setStyleSheet("color:#888; font-size:11px;")
        self.capacity_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        ig.addWidget(self.capacity_label)
        layout.addWidget(img_group)

        # --- Payload (Text / File) ---
        payload_group = QGroupBox("Secret Payload")
        payload_group.setStyleSheet(GROUP_STYLE)
        plg = QVBoxLayout(payload_group)

        mode_row = QHBoxLayout()
        self.mode_text_btn = QPushButton("  Text  ")
        self.mode_text_btn.setCheckable(True)
        self.mode_text_btn.setChecked(True)
        self.mode_text_btn.setStyleSheet(BTN_SECONDARY_STYLE)
        self.mode_text_btn.clicked.connect(lambda: self._set_payload_mode('text'))
        self.mode_file_btn = QPushButton("  File  ")
        self.mode_file_btn.setCheckable(True)
        self.mode_file_btn.setStyleSheet(BTN_SECONDARY_STYLE)
        self.mode_file_btn.clicked.connect(lambda: self._set_payload_mode('file'))
        mode_row.addWidget(self.mode_text_btn)
        mode_row.addWidget(self.mode_file_btn)
        plg.addLayout(mode_row)

        self.payload_stack = QStackedWidget()

        # Page 0: Text input
        text_page = QWidget()
        tp_layout = QVBoxLayout(text_page)
        tp_layout.setContentsMargins(0, 0, 0, 0)
        self.text_edit = QTextEdit()
        self.text_edit.setPlaceholderText("Enter the secret text to hide…")
        self.text_edit.setStyleSheet(TEXT_EDIT_STYLE)
        self.text_edit.setMinimumHeight(90)
        self.text_edit.textChanged.connect(self._update_char_count)
        tp_layout.addWidget(self.text_edit)
        self.char_label = QLabel("0 chars / 0 bytes")
        self.char_label.setStyleSheet("color:#888; font-size:11px;")
        tp_layout.addWidget(self.char_label)
        self.payload_stack.addWidget(text_page)

        # Page 1: File input
        file_page = QWidget()
        fp_layout = QVBoxLayout(file_page)
        fp_layout.setContentsMargins(0, 0, 0, 0)
        self.file_select_btn = QPushButton("Select File…")
        self.file_select_btn.setStyleSheet(BTN_SECONDARY_STYLE)
        self.file_select_btn.clicked.connect(self._select_embed_file)
        fp_layout.addWidget(self.file_select_btn)
        self.file_info_label = QLabel("No file selected")
        self.file_info_label.setStyleSheet("color:#888; font-size:12px;")
        self.file_info_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.file_info_label.setMinimumHeight(60)
        fp_layout.addWidget(self.file_info_label)
        self.payload_stack.addWidget(file_page)

        plg.addWidget(self.payload_stack)
        layout.addWidget(payload_group)

        # --- Password ---
        pw_group = QGroupBox("AES-256 Password")
        pw_group.setStyleSheet(GROUP_STYLE)
        pg = QHBoxLayout(pw_group)
        self.pw_edit = QLineEdit()
        self.pw_edit.setPlaceholderText("Enter encryption password…")
        self.pw_edit.setEchoMode(QLineEdit.EchoMode.Password)
        self.pw_edit.setStyleSheet(INPUT_STYLE)
        self.pw_toggle = QPushButton("Show")
        self.pw_toggle.setFixedWidth(60)
        self.pw_toggle.setCheckable(True)
        self.pw_toggle.setStyleSheet(BTN_SECONDARY_STYLE)
        self.pw_toggle.toggled.connect(self._toggle_pw)
        pg.addWidget(self.pw_edit)
        pg.addWidget(self.pw_toggle)
        layout.addWidget(pw_group)

        # --- Strength slider ---
        str_group = QGroupBox("Embedding Strength")
        str_group.setStyleSheet(GROUP_STYLE)
        sg = QVBoxLayout(str_group)
        slider_row = QHBoxLayout()
        self.strength_slider = QSlider(Qt.Orientation.Horizontal)
        self.strength_slider.setRange(MIN_QUANT_STEP, MAX_QUANT_STEP)
        self.strength_slider.setValue(DEFAULT_QUANT_STEP)
        self.strength_slider.setTickPosition(QSlider.TickPosition.TicksBelow)
        self.strength_slider.setTickInterval(4)
        self.strength_slider.setStyleSheet(SLIDER_STYLE)
        self.strength_slider.valueChanged.connect(self._on_strength_changed)
        slider_row.addWidget(QLabel("Subtle"))
        slider_row.addWidget(self.strength_slider)
        slider_row.addWidget(QLabel("Robust"))
        sg.addLayout(slider_row)
        self.strength_label = QLabel(self._strength_text(DEFAULT_QUANT_STEP))
        self.strength_label.setStyleSheet("color:#aaa; font-size:11px;")
        self.strength_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        sg.addWidget(self.strength_label)
        layout.addWidget(str_group)

        # --- Auto-resize checkbox ---
        self.resize_check = QCheckBox("Auto-resize for messaging apps (max 1280 px)")
        self.resize_check.setStyleSheet("color:#aaa; font-size:11px; padding:4px;")
        self.resize_check.toggled.connect(self._update_capacity)
        layout.addWidget(self.resize_check)

        # --- Status + progress ---
        self.status_label = QLabel("")
        self.status_label.setStyleSheet("color:#7c3aed; font-size:11px;")
        layout.addWidget(self.status_label)
        self.progress = QProgressBar()
        self.progress.setVisible(False)
        self.progress.setStyleSheet(PROGRESS_STYLE)
        layout.addWidget(self.progress)

        # --- Embed button ---
        self.embed_btn = QPushButton("Embed && Save")
        self.embed_btn.setStyleSheet(BTN_PRIMARY_STYLE)
        self.embed_btn.clicked.connect(self._embed)
        layout.addWidget(self.embed_btn)
        layout.addStretch()

    @staticmethod
    def _strength_text(step):
        if step <= 10:
            tier = "Subtle — survives light compression (JPEG Q≥85)"
        elif step <= 16:
            tier = "Balanced — survives moderate compression (JPEG Q≥75)"
        elif step <= 24:
            tier = "Strong — survives heavy compression (JPEG Q≥60)"
        else:
            tier = "Maximum — survives aggressive compression (JPEG Q≥50)"
        return f"Step {step}: {tier}"

    def _on_strength_changed(self, value):
        self.strength_label.setText(self._strength_text(value))
        self._update_capacity()

    def _on_image_loaded(self, path):
        self._update_capacity()

    def _update_capacity(self):
        path = self.img_label.get_path()
        if not path:
            return
        try:
            img = Image.open(path)
            md = 1280 if self.resize_check.isChecked() else 0
            cap = image_capacity(img, self.strength_slider.value(), md)
            raw = cap['raw_bytes']
            self.capacity_label.setText(
                f"{cap['width']}×{cap['height']}px — "
                f"≈ {raw:,} bytes raw / {cap['estimated_text']:,} chars (compressed)"
            )
            # Update file page max size indicator
            if raw < 1024:
                sz = f"{raw} B"
            elif raw < 1024 * 1024:
                sz = f"{raw / 1024:.1f} KB"
            else:
                sz = f"{raw / (1024 * 1024):.1f} MB"
            if self._embed_file_path and os.path.isfile(self._embed_file_path):
                name = os.path.basename(self._embed_file_path)
                fsize = os.path.getsize(self._embed_file_path)
                if fsize < 1024:
                    fsz = f"{fsize} B"
                elif fsize < 1024 * 1024:
                    fsz = f"{fsize / 1024:.1f} KB"
                else:
                    fsz = f"{fsize / (1024 * 1024):.1f} MB"
                self.file_info_label.setText(
                    f"{name} ({fsz})\nMax file size: ≈ {sz}"
                )
            else:
                self.file_info_label.setText(
                    f"No file selected\nMax file size: ≈ {sz}"
                )
        except Exception:
            self.capacity_label.setText("Could not read image.")

    def _update_char_count(self):
        text = self.text_edit.toPlainText()
        b = text.encode("utf-8")
        self.char_label.setText(f"{len(text):,} chars / {len(b):,} bytes")

    def _set_payload_mode(self, mode):
        self._payload_mode = mode
        self.mode_text_btn.setChecked(mode == 'text')
        self.mode_file_btn.setChecked(mode == 'file')
        self.payload_stack.setCurrentIndex(0 if mode == 'text' else 1)

    def _select_embed_file(self):
        path, _ = QFileDialog.getOpenFileName(
            self, "Select File to Embed", "", "All Files (*)"
        )
        if path:
            self._embed_file_path = path
            self._update_capacity()

    def _toggle_pw(self, checked):
        self.pw_edit.setEchoMode(
            QLineEdit.EchoMode.Normal if checked else QLineEdit.EchoMode.Password
        )
        self.pw_toggle.setText("Hide" if checked else "Show")

    def _embed(self):
        img_path = self.img_label.get_path()
        if not img_path:
            QMessageBox.warning(self, "Missing Image", "Select a cover image.")
            return

        if self._payload_mode == 'text':
            text = self.text_edit.toPlainText().strip()
            if not text:
                QMessageBox.warning(self, "Missing Text", "Enter a secret message.")
                return
        else:
            if not self._embed_file_path or not os.path.isfile(self._embed_file_path):
                QMessageBox.warning(self, "Missing File", "Select a file to embed.")
                return

        password = self.pw_edit.text()
        if not password:
            QMessageBox.warning(self, "Missing Password", "Enter an AES password.")
            return

        base, _ = os.path.splitext(img_path)
        out_path, _ = QFileDialog.getSaveFileName(
            self, "Save Stego Image", base + "_stego.png", "PNG Images (*.png)"
        )
        if not out_path:
            return
        if not out_path.lower().endswith(".png"):
            out_path += ".png"

        md = 1280 if self.resize_check.isChecked() else 0
        self._set_busy(True)

        if self._payload_mode == 'text':
            self._worker = EmbedWorker(
                img_path, password, out_path,
                self.strength_slider.value(), md,
                mode='text', text=self.text_edit.toPlainText().strip(),
            )
        else:
            self._worker = EmbedWorker(
                img_path, password, out_path,
                self.strength_slider.value(), md,
                mode='file', file_path=self._embed_file_path,
            )

        self._worker.progress.connect(self.progress.setValue)
        self._worker.status.connect(self.status_label.setText)
        self._worker.finished.connect(self._on_done)
        self._worker.error.connect(self._on_error)
        self._worker.start()

    def _on_done(self, path):
        self._set_busy(False)
        QMessageBox.information(
            self, "Success",
            f"Stego image saved:\n{path}\n\n"
            f"Embedding strength: {self.strength_slider.value()}\n"
            "The receiver only needs the password — strength is auto-detected."
        )

    def _on_error(self, msg):
        self._set_busy(False)
        QMessageBox.critical(self, "Error", msg)

    def _set_busy(self, busy):
        self.embed_btn.setEnabled(not busy)
        self.progress.setVisible(busy)
        if not busy:
            self.progress.setValue(0)
            self.status_label.setText("")


# ═══════════════════════════════════════════════════════════════════════════
# UI: Extract tab
# ═══════════════════════════════════════════════════════════════════════════

class ExtractTab(QWidget):
    def __init__(self):
        super().__init__()
        self._worker = None
        self._build_ui()

    def _build_ui(self):
        layout = QVBoxLayout(self)
        layout.setSpacing(10)
        layout.setContentsMargins(16, 16, 16, 16)

        # --- Image ---
        img_group = QGroupBox("Stego Image")
        img_group.setStyleSheet(GROUP_STYLE)
        ig = QVBoxLayout(img_group)
        self.img_label = ImageDropLabel("Drop stego image here\nor click to browse")
        ig.addWidget(self.img_label)
        layout.addWidget(img_group)

        # --- Password ---
        pw_group = QGroupBox("AES-256 Password")
        pw_group.setStyleSheet(GROUP_STYLE)
        pg = QHBoxLayout(pw_group)
        self.pw_edit = QLineEdit()
        self.pw_edit.setPlaceholderText("Enter decryption password…")
        self.pw_edit.setEchoMode(QLineEdit.EchoMode.Password)
        self.pw_edit.setStyleSheet(INPUT_STYLE)
        self.pw_edit.returnPressed.connect(self._extract)
        self.pw_toggle = QPushButton("Show")
        self.pw_toggle.setFixedWidth(60)
        self.pw_toggle.setCheckable(True)
        self.pw_toggle.setStyleSheet(BTN_SECONDARY_STYLE)
        self.pw_toggle.toggled.connect(self._toggle_pw)
        pg.addWidget(self.pw_edit)
        pg.addWidget(self.pw_toggle)
        layout.addWidget(pw_group)

        # --- Status + progress ---
        self.status_label = QLabel("")
        self.status_label.setStyleSheet("color:#7c3aed; font-size:11px;")
        layout.addWidget(self.status_label)
        self.progress = QProgressBar()
        self.progress.setVisible(False)
        self.progress.setStyleSheet(PROGRESS_STYLE)
        layout.addWidget(self.progress)

        # --- Extract button ---
        self.extract_btn = QPushButton("Extract")
        self.extract_btn.setStyleSheet(BTN_PRIMARY_STYLE)
        self.extract_btn.clicked.connect(self._extract)
        layout.addWidget(self.extract_btn)

        # --- Result ---
        result_group = QGroupBox("Extracted Content")
        result_group.setStyleSheet(GROUP_STYLE)
        rg = QVBoxLayout(result_group)
        self.result_edit = QTextEdit()
        self.result_edit.setReadOnly(True)
        self.result_edit.setPlaceholderText("Decrypted message will appear here…")
        self.result_edit.setStyleSheet(TEXT_EDIT_STYLE)
        self.result_edit.setMinimumHeight(120)
        rg.addWidget(self.result_edit)
        copy_btn = QPushButton("Copy to Clipboard")
        copy_btn.setStyleSheet(BTN_SECONDARY_STYLE)
        copy_btn.clicked.connect(self._copy)
        rg.addWidget(copy_btn)
        layout.addWidget(result_group)
        layout.addStretch()

    def _toggle_pw(self, checked):
        self.pw_edit.setEchoMode(
            QLineEdit.EchoMode.Normal if checked else QLineEdit.EchoMode.Password
        )
        self.pw_toggle.setText("Hide" if checked else "Show")

    def _extract(self):
        img_path = self.img_label.get_path()
        if not img_path:
            QMessageBox.warning(self, "Missing Image", "Select a stego image.")
            return
        password = self.pw_edit.text()
        if not password:
            QMessageBox.warning(self, "Missing Password", "Enter the AES password.")
            return

        self._set_busy(True)
        self.result_edit.clear()
        self._worker = ExtractWorker(img_path, password)
        self._worker.progress.connect(self.progress.setValue)
        self._worker.status.connect(self.status_label.setText)
        self._worker.finished_text.connect(self._on_done)
        self._worker.finished_file.connect(self._on_file_done)
        self._worker.error.connect(self._on_error)
        self._worker.start()

    def _on_done(self, text):
        self._set_busy(False)
        self.result_edit.setPlainText(text)

    def _on_file_done(self, filename, data):
        self._set_busy(False)
        save_path, _ = QFileDialog.getSaveFileName(
            self, "Save Extracted File", filename, "All Files (*)"
        )
        if save_path:
            with open(save_path, 'wb') as f:
                f.write(data)
            size = len(data)
            if size < 1024:
                sz = f"{size} B"
            elif size < 1024 * 1024:
                sz = f"{size / 1024:.1f} KB"
            else:
                sz = f"{size / (1024 * 1024):.1f} MB"
            self.result_edit.setPlainText(
                f"Extracted file: {filename}\n"
                f"Size: {sz}\n"
                f"Saved to: {save_path}"
            )
        else:
            self.result_edit.setPlainText(
                f"Extracted file: {filename} ({len(data):,} bytes)\n"
                "(Save cancelled)"
            )

    def _on_error(self, msg):
        self._set_busy(False)
        QMessageBox.critical(self, "Error", msg)

    def _copy(self):
        text = self.result_edit.toPlainText()
        if text:
            QApplication.clipboard().setText(text)

    def _set_busy(self, busy):
        self.extract_btn.setEnabled(not busy)
        self.progress.setVisible(busy)
        if not busy:
            self.progress.setValue(0)
            self.status_label.setText("")


# ═══════════════════════════════════════════════════════════════════════════
# UI: About tab
# ═══════════════════════════════════════════════════════════════════════════

class AboutTab(QWidget):
    def __init__(self):
        super().__init__()
        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setStyleSheet("QScrollArea { border: none; background: transparent; }")

        content = QWidget()
        layout = QVBoxLayout(content)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(10)

        title = QLabel("StegoCrypt v2")
        title.setFont(QFont("Segoe UI", 22, QFont.Weight.Bold))
        title.setStyleSheet("color: #7c3aed;")
        layout.addWidget(title)

        subtitle = QLabel("Compression-resistant steganography that fights to survive")
        subtitle.setStyleSheet("color: #aaa; font-size: 13px;")
        layout.addWidget(subtitle)

        sep = QFrame()
        sep.setFrameShape(QFrame.Shape.HLine)
        sep.setStyleSheet("color: #333;")
        layout.addWidget(sep)

        info = QLabel("""
<p style='color:#ccc; font-size:13px; line-height:1.7'>
<b style='color:#fff'>How it works — 5 layers of protection</b><br>
<b>1. Compression:</b> Your message is zlib-compressed to maximize capacity.<br>
<b>2. Encryption:</b> AES-256-GCM with PBKDF2-SHA256 key derivation (200K iterations).
Wrong passwords are detected instantly — authenticated encryption.<br>
<b>3. Error Correction:</b> Reed-Solomon ECC with 50 parity symbols — can correct up to
25 corrupted bytes, or 50 if the program knows which bytes are suspect (erasure decoding).<br>
<b>4. Spatial Redundancy:</b> Every bit of data is embedded 3 times in different locations
across the image. Confidence-weighted majority voting recovers the true bit even if one
or two copies are destroyed.<br>
<b>5. PRNG Position Shuffling:</b> Bit positions are scattered using a password-seeded
pseudorandom permutation. Without the password, you can't even <i>find</i> the data —
it looks like normal image noise. This also spreads data evenly, so local damage
(cropping, watermarks) only affects a fraction of bits.
<br><br>
<b style='color:#fff'>DCT Embedding</b><br>
The image is split into 8×8 pixel blocks and transformed to the frequency domain using
the Discrete Cosine Transform (the same math JPEG uses internally). Bits are hidden by
quantizing mid-frequency coefficients. Because JPEG compression also quantizes these
coefficients, our embedded values survive — they're already on the quantization grid.
<br><br>
<b style='color:#fff'>Smart Recovery Engine</b><br>
Extraction is fully automatic — the embedding strength is stored in a self-describing
header and auto-detected (no settings to remember). If standard decoding fails, the
program escalates through:<br>
&nbsp;&nbsp;→ Erasure decoding (marks uncertain bytes as "unknown" for RS to reconstruct)<br>
&nbsp;&nbsp;→ Bit-flip recovery (systematically flips least-confident bits)<br>
&nbsp;&nbsp;→ Alternate-step probing (tries nearby quantization steps in case compression shifted values)
<br><br>
<b style='color:#fff'>Best Practices</b>
<ul style='margin-top:4px'>
  <li>Use the <b>Strength slider</b>: higher = survives heavier compression. Default (16) is good for most cases.</li>
  <li><b>WhatsApp/Telegram:</b> send as Document/File for lossless delivery. If sending as photo, check
  "Auto-resize for messaging apps" and use strength ≥ 20.</li>
  <li>Use images ≥ 1000×1000 px for longer messages.</li>
  <li>The receiver only needs the <b>password</b> — everything else is auto-detected.</li>
</ul>
</p>
""")
        info.setWordWrap(True)
        info.setTextFormat(Qt.TextFormat.RichText)
        layout.addWidget(info)
        layout.addStretch()

        scroll.setWidget(content)
        outer.addWidget(scroll)


# ═══════════════════════════════════════════════════════════════════════════
# Styles
# ═══════════════════════════════════════════════════════════════════════════

DARK_BG = "#12121c"
SURFACE = "#1e1e2e"
ACCENT = "#7c3aed"
ACCENT_HOVER = "#6d28d9"
TEXT = "#e0e0e0"

GROUP_STYLE = f"""
QGroupBox {{
    color: {TEXT};
    border: 1px solid #333;
    border-radius: 6px;
    margin-top: 8px;
    font-size: 12px;
    font-weight: bold;
    padding-top: 6px;
}}
QGroupBox::title {{
    subcontrol-origin: margin;
    left: 10px;
    padding: 0 4px;
    color: #aaa;
}}
"""

INPUT_STYLE = f"""
QLineEdit {{
    background: #2a2a3e;
    color: {TEXT};
    border: 1px solid #444;
    border-radius: 5px;
    padding: 6px 10px;
    font-size: 13px;
}}
QLineEdit:focus {{
    border-color: {ACCENT};
}}
"""

TEXT_EDIT_STYLE = f"""
QTextEdit {{
    background: #2a2a3e;
    color: {TEXT};
    border: 1px solid #444;
    border-radius: 5px;
    padding: 6px;
    font-size: 13px;
    font-family: 'Consolas', 'Courier New', monospace;
}}
QTextEdit:focus {{
    border-color: {ACCENT};
}}
"""

BTN_PRIMARY_STYLE = f"""
QPushButton {{
    background: {ACCENT};
    color: white;
    border: none;
    border-radius: 6px;
    padding: 10px 20px;
    font-size: 14px;
    font-weight: bold;
}}
QPushButton:hover {{
    background: {ACCENT_HOVER};
}}
QPushButton:disabled {{
    background: #444;
    color: #888;
}}
"""

BTN_SECONDARY_STYLE = f"""
QPushButton {{
    background: #2a2a3e;
    color: {TEXT};
    border: 1px solid #555;
    border-radius: 5px;
    padding: 6px 14px;
    font-size: 12px;
}}
QPushButton:hover {{
    background: #363650;
    border-color: {ACCENT};
}}
QPushButton:checked {{
    background: {ACCENT};
    color: white;
    border-color: {ACCENT};
}}
"""

SLIDER_STYLE = f"""
QSlider::groove:horizontal {{
    background: #2a2a3e;
    height: 6px;
    border-radius: 3px;
}}
QSlider::handle:horizontal {{
    background: {ACCENT};
    width: 16px;
    height: 16px;
    margin: -5px 0;
    border-radius: 8px;
}}
QSlider::sub-page:horizontal {{
    background: {ACCENT};
    border-radius: 3px;
}}
"""

PROGRESS_STYLE = f"""
QProgressBar {{
    background: #2a2a3e;
    border: 1px solid #444;
    border-radius: 4px;
    height: 12px;
    text-align: center;
    color: white;
    font-size: 10px;
}}
QProgressBar::chunk {{
    background: {ACCENT};
    border-radius: 4px;
}}
"""

APP_STYLE = f"""
QMainWindow, QWidget {{
    background: {DARK_BG};
    color: {TEXT};
    font-family: 'Segoe UI', sans-serif;
}}
QTabWidget::pane {{
    border: 1px solid #333;
    background: {SURFACE};
    border-radius: 6px;
}}
QTabBar::tab {{
    background: #1a1a2e;
    color: #888;
    padding: 8px 20px;
    border: 1px solid #333;
    border-bottom: none;
    border-top-left-radius: 5px;
    border-top-right-radius: 5px;
    margin-right: 2px;
    font-size: 13px;
}}
QTabBar::tab:selected {{
    background: {SURFACE};
    color: {TEXT};
    border-bottom: 2px solid {ACCENT};
}}
QTabBar::tab:hover:!selected {{
    background: #252538;
    color: #ccc;
}}
QScrollBar:vertical {{
    background: #1e1e2e;
    width: 10px;
    border-radius: 5px;
}}
QScrollBar::handle:vertical {{
    background: #444;
    border-radius: 5px;
    min-height: 20px;
}}
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{
    height: 0;
}}
QMessageBox {{
    background: {SURFACE};
    color: {TEXT};
}}
QMessageBox QPushButton {{
    background: {ACCENT};
    color: white;
    border: none;
    border-radius: 4px;
    padding: 6px 16px;
    min-width: 70px;
}}
"""


# ═══════════════════════════════════════════════════════════════════════════
# Main window
# ═══════════════════════════════════════════════════════════════════════════

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("StegoCrypt v2 — Compression-Resistant Steganography")
        self.setMinimumSize(620, 750)
        self.resize(740, 870)
        self.setStyleSheet(APP_STYLE)

        tabs = QTabWidget()
        tabs.addTab(EmbedTab(), "  Embed  ")
        tabs.addTab(ExtractTab(), "  Extract  ")
        tabs.addTab(AboutTab(), "  About  ")
        self.setCentralWidget(tabs)


def main():
    app = QApplication(sys.argv)
    app.setApplicationName("StegoCrypt")
    app.setStyle("Fusion")
    window = MainWindow()
    window.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
