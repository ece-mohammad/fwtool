"""
Pytest test suite for the firmware header utility.

These tests cover:
    - version parsing, packing, and validation
    - header construction with different sizes
    - header parsing and field extraction
    - header verification with pass/fail scenarios
    - header size inference
    - header size validation
    - binary splitting for attach/edit modes
    - file I/O helpers
    - subcommand handlers (attach, edit, inspect, verify)
    - end-to-end workflows
    - CLI argument validation
    - edge cases for payloads, headers, files, and modes
    - Error/exception paths (I/O failures, cleanup)
    - Handler negative tests (bad inputs, missing files)
    - User mistake scenarios (double-header, wrong mode)
    - Immutability and direct validation
    - Flag combinations
    - Property-based testing with Hypothesis
    - Permission / OS-level errors
    - Text output format verification for failure cases
    - Edge cases in resolve_header_size helpers

"""

import json
import os
import struct
from pathlib import Path
from unittest.mock import patch

import pytest
from crccheck.crc import Crc32Mpeg2
from hypothesis import given, settings
from hypothesis import strategies as st

from fwtool.cli import (
    DEFAULT_HEADER_SIZE,
    HEADER_INFO_SIZE,
    HEADER_MAGIC,
    HeaderInfo,
    VerificationResult,
    VersionInfo,
    build_header,
    build_parser,
    infer_header_size,
    main,
    parse_header,
    read_binary,
    resolve_header_size_for_build,
    resolve_header_size_for_verify,
    split_payload_from_packaged,
    validate_header_size,
    validate_input_file,
    verify_header,
    write_binary,
    write_binary_in_place,
    write_output,
)


# ---------------------------------------------------------------------------
# Test helpers
# ---------------------------------------------------------------------------


def make_packaged_binary(
    payload: bytes,
    version: str = "1.2.3",
    header_size: int = DEFAULT_HEADER_SIZE,
) -> bytes:
    """Create a packaged binary [header][payload] for tests."""
    version_info = VersionInfo.from_string(version)
    header = build_header(payload, version_info, header_size)
    return header + payload


def corrupt_byte(data: bytes, offset: int) -> bytes:
    """Flip all bits of a single byte in a bytes object."""
    mutated = bytearray(data)
    mutated[offset] ^= 0xFF
    return bytes(mutated)


def flip_bit(data: bytes, offset: int, bit: int) -> bytes:
    """Flip a single bit in a bytes object."""
    mutated = bytearray(data)
    mutated[offset] ^= 1 << bit
    return bytes(mutated)


# ===========================================================================
# 1. VersionInfo
# ===========================================================================


class TestVersionInfoFromString:
    """Tests for VersionInfo.from_string()."""

    def test_full_version(self):
        v = VersionInfo.from_string("1.2.3")
        assert v == VersionInfo(1, 2, 3)

    def test_single_component(self):
        v = VersionInfo.from_string("7")
        assert v == VersionInfo(7, 0, 0)

    def test_two_components(self):
        v = VersionInfo.from_string("7.8")
        assert v == VersionInfo(7, 8, 0)

    def test_truncates_extra_components(self):
        v = VersionInfo.from_string("1.2.3.4")
        assert v == VersionInfo(1, 2, 3)

    def test_many_extra_components(self):
        v = VersionInfo.from_string("1.2.3.4.5.6.7")
        assert v == VersionInfo(1, 2, 3)

    def test_all_zeros(self):
        v = VersionInfo.from_string("0.0.0")
        assert v == VersionInfo(0, 0, 0)

    def test_max_valid(self):
        v = VersionInfo.from_string("255.255.255")
        assert v == VersionInfo(255, 255, 255)

    def test_boundary_values(self):
        v = VersionInfo.from_string("255.0.0")
        assert v == VersionInfo(255, 0, 0)

    def test_major_out_of_range(self):
        with pytest.raises(ValueError, match="major"):
            VersionInfo.from_string("256.0.0")

    def test_minor_out_of_range(self):
        with pytest.raises(ValueError, match="minor"):
            VersionInfo.from_string("0.256.0")

    def test_patch_out_of_range(self):
        with pytest.raises(ValueError, match="patch"):
            VersionInfo.from_string("0.0.256")

    def test_negative_value(self):
        with pytest.raises(ValueError):
            VersionInfo.from_string("-1.0.0")

    def test_non_numeric(self):
        with pytest.raises(ValueError):
            VersionInfo.from_string("abc")

    def test_empty_string(self):
        with pytest.raises(ValueError):
            VersionInfo.from_string("")

    def test_whitespace_stripped(self):
        v = VersionInfo.from_string("  1.2.3  ")
        assert v == VersionInfo(1, 2, 3)

    def test_leading_zeros(self):
        v = VersionInfo.from_string("01.02.03")
        assert v == VersionInfo(1, 2, 3)

    def test_trailing_dot(self):
        v = VersionInfo.from_string("1.2.")
        assert v == VersionInfo(1, 2, 0)

    def test_leading_dot(self):
        v = VersionInfo.from_string(".1.2")
        assert v == VersionInfo(1, 2, 0)

    def test_just_dots(self):
        with pytest.raises(ValueError):
            VersionInfo.from_string("...")

    def test_double_dots(self):
        v = VersionInfo.from_string("1..3")
        assert v == VersionInfo(1, 3, 0)


class TestVersionInfoFromBytes:
    """Tests for VersionInfo.from_bytes()."""

    def test_normal(self):
        v = VersionInfo.from_bytes(b"\x00\x03\x02\x01")
        assert v == VersionInfo(1, 2, 3)

    def test_all_zeros(self):
        v = VersionInfo.from_bytes(b"\x00\x00\x00\x00")
        assert v == VersionInfo(0, 0, 0)

    def test_max_values(self):
        v = VersionInfo.from_bytes(b"\x00\xff\xff\xff")
        assert v == VersionInfo(255, 255, 255)

    def test_too_few_bytes(self):
        with pytest.raises(ValueError, match="4 bytes"):
            VersionInfo.from_bytes(b"\x00\x01\x02")

    def test_too_many_bytes(self):
        with pytest.raises(ValueError, match="4 bytes"):
            VersionInfo.from_bytes(b"\x00\x01\x02\x03\x04")

    def test_unused_byte_nonzero(self):
        v = VersionInfo.from_bytes(b"\xff\x03\x02\x01")
        assert v == VersionInfo(1, 2, 3)

    def test_single_byte(self):
        with pytest.raises(ValueError, match="4 bytes"):
            VersionInfo.from_bytes(b"\x00")

    def test_empty_bytes(self):
        with pytest.raises(ValueError, match="4 bytes"):
            VersionInfo.from_bytes(b"")


class TestVersionInfoToBytes:
    """Tests for VersionInfo.to_bytes()."""

    def test_normal(self):
        v = VersionInfo(1, 2, 3)
        assert v.to_bytes() == b"\x00\x03\x02\x01"

    def test_zeros(self):
        v = VersionInfo(0, 0, 0)
        assert v.to_bytes() == b"\x00\x00\x00\x00"

    def test_max(self):
        v = VersionInfo(255, 255, 255)
        assert v.to_bytes() == b"\x00\xff\xff\xff"

    def test_roundtrip(self):
        original = VersionInfo(10, 20, 30)
        restored = VersionInfo.from_bytes(original.to_bytes())
        assert restored == original

    def test_roundtrip_all_zeros(self):
        original = VersionInfo(0, 0, 0)
        restored = VersionInfo.from_bytes(original.to_bytes())
        assert restored == original

    def test_roundtrip_max(self):
        original = VersionInfo(255, 255, 255)
        restored = VersionInfo.from_bytes(original.to_bytes())
        assert restored == original


class TestVersionInfoToDict:
    """Tests for VersionInfo.to_dict()."""

    def test_contains_expected_keys(self):
        d = VersionInfo(1, 2, 3).to_dict()
        assert d["major"] == 1
        assert d["minor"] == 2
        assert d["patch"] == 3
        assert d["string"] == "1.2.3"

    def test_string_matches_str(self):
        v = VersionInfo(4, 5, 6)
        assert v.to_dict()["string"] == str(v)

    def test_zeros(self):
        d = VersionInfo(0, 0, 0).to_dict()
        assert d["string"] == "0.0.0"


class TestVersionInfoStr:
    """Tests for VersionInfo.__str__()."""

    def test_format(self):
        assert str(VersionInfo(1, 2, 3)) == "1.2.3"

    def test_zeros(self):
        assert str(VersionInfo(0, 0, 0)) == "0.0.0"

    def test_max(self):
        assert str(VersionInfo(255, 255, 255)) == "255.255.255"


# ===========================================================================
# 2. HeaderInfo
# ===========================================================================


class TestHeaderInfoFromBytes:
    """Tests for HeaderInfo.from_bytes()."""

    def test_valid_input(self):
        payload = b"\x01\x02\x03\x04"
        packaged = make_packaged_binary(payload)
        info = HeaderInfo.from_bytes(packaged)

        assert info.magic == HEADER_MAGIC
        assert info.version == VersionInfo(1, 2, 3)
        assert info.size == len(payload)
        assert info.crc == Crc32Mpeg2.calc(payload)

    def test_too_small(self):
        with pytest.raises(ValueError, match="at least"):
            HeaderInfo.from_bytes(b"\x00" * 10)

    def test_minimum_size(self):
        data = HEADER_MAGIC + b"\x00" * 12
        info = HeaderInfo.from_bytes(data)
        assert info.magic == HEADER_MAGIC

    def test_wrong_magic_still_parses(self):
        data = b"NOPE" + b"\x00" * 12
        info = HeaderInfo.from_bytes(data)
        assert info.magic == b"NOPE"

    def test_size_zero(self):
        data = HEADER_MAGIC + b"\x00" * 4 + struct.pack("<I", 0) + b"\x00" * 4
        info = HeaderInfo.from_bytes(data)
        assert info.size == 0

    def test_crc_zero(self):
        data = (
            HEADER_MAGIC + b"\x00" * 4 + struct.pack("<I", 100) + struct.pack("<I", 0)
        )
        info = HeaderInfo.from_bytes(data)
        assert info.crc == 0

    def test_size_max_uint32(self):
        data = HEADER_MAGIC + b"\x00" * 4 + struct.pack("<I", 0xFFFFFFFF) + b"\x00" * 4
        info = HeaderInfo.from_bytes(data)
        assert info.size == 0xFFFFFFFF

    def test_crc_max_uint32(self):
        data = HEADER_MAGIC + b"\x00" * 4 + b"\x00" * 4 + struct.pack("<I", 0xFFFFFFFF)
        info = HeaderInfo.from_bytes(data)
        assert info.crc == 0xFFFFFFFF


class TestHeaderInfoToDict:
    """Tests for HeaderInfo.to_dict()."""

    def test_contains_expected_keys(self):
        payload = b"abc"
        packaged = make_packaged_binary(payload)
        info = HeaderInfo.from_bytes(packaged)
        d = info.to_dict()

        assert d["magic_ascii"] == "XLAB"
        assert d["magic_hex"] == "584c4142"
        assert "version" in d
        assert "size" in d
        assert "crc" in d
        assert "int" in d["crc"]
        assert "hex" in d["crc"]
        assert d["crc"]["hex"].startswith("0x")

    def test_non_ascii_magic(self):
        data = b"\x80\x81\x82\x83" + b"\x00" * 12
        info = HeaderInfo.from_bytes(data)
        d = info.to_dict()
        assert "magic_ascii" in d
        assert "magic_hex" in d


# ===========================================================================
# 3. VerificationResult
# ===========================================================================


class TestVerificationResultOk:
    """Tests for VerificationResult.ok property."""

    def test_all_pass(self):
        payload = b"firmware"
        packaged = make_packaged_binary(payload)
        result = verify_header(packaged, DEFAULT_HEADER_SIZE)
        assert result.ok is True

    def test_magic_fail_only(self):
        payload = b"firmware"
        packaged = bytearray(make_packaged_binary(payload))
        packaged[:4] = b"BAD!"
        result = verify_header(bytes(packaged), DEFAULT_HEADER_SIZE)
        assert result.magic_ok is False
        assert result.size_ok is True
        assert result.crc_ok is True
        assert result.ok is False

    def test_size_fail_only(self):
        payload = b"firmware"
        packaged = bytearray(make_packaged_binary(payload))
        packaged[8:12] = struct.pack("<I", len(payload) + 1)
        result = verify_header(bytes(packaged), DEFAULT_HEADER_SIZE)
        assert result.magic_ok is True
        assert result.size_ok is False
        assert result.crc_ok is True
        assert result.ok is False

    def test_crc_fail_only(self):
        payload = b"firmware"
        packaged = make_packaged_binary(payload)
        corrupted = corrupt_byte(packaged, len(packaged) - 1)
        result = verify_header(corrupted, DEFAULT_HEADER_SIZE)
        assert result.magic_ok is True
        assert result.size_ok is True
        assert result.crc_ok is False
        assert result.ok is False

    def test_all_fail(self):
        data = b"\x00" * (DEFAULT_HEADER_SIZE + 100)
        result = verify_header(data, DEFAULT_HEADER_SIZE)
        assert result.magic_ok is False
        assert result.ok is False

    def test_size_and_crc_fail(self):
        payload = b"firmware"
        packaged = bytearray(make_packaged_binary(payload))
        packaged[8:12] = struct.pack("<I", len(payload) + 1)
        packaged[-1] ^= 0xFF
        result = verify_header(bytes(packaged), DEFAULT_HEADER_SIZE)
        assert result.magic_ok is True
        assert result.size_ok is False
        assert result.crc_ok is False
        assert result.ok is False


class TestVerificationResultToDict:
    """Tests for VerificationResult.to_dict()."""

    def test_contains_expected_keys(self):
        payload = b"abc"
        packaged = make_packaged_binary(payload)
        result = verify_header(packaged, DEFAULT_HEADER_SIZE)
        d = result.to_dict()

        assert d["ok"] is True
        assert d["magic_ok"] is True
        assert d["size_ok"] is True
        assert d["crc_ok"] is True
        assert "header_size" in d
        assert "header" in d
        assert "payload" in d
        assert "size" in d["payload"]
        assert "crc" in d["payload"]

    def test_failed_result_dict(self):
        data = b"\x00" * (DEFAULT_HEADER_SIZE + 100)
        result = verify_header(data, DEFAULT_HEADER_SIZE)
        d = result.to_dict()
        assert d["ok"] is False


# ===========================================================================
# 4. validate_header_size
# ===========================================================================


class TestValidateHeaderSize:
    """Tests for validate_header_size()."""

    @pytest.mark.parametrize(
        "size", [16, 32, 64, 128, 256, 512, 1024, 2048, 4096, 65536]
    )
    def test_valid_sizes(self, size):
        validate_header_size(size)

    def test_zero(self):
        with pytest.raises(ValueError, match="at least"):
            validate_header_size(0)

    def test_below_minimum(self):
        with pytest.raises(ValueError, match="at least"):
            validate_header_size(8)

    def test_just_below_minimum(self):
        with pytest.raises(ValueError, match="at least"):
            validate_header_size(15)

    def test_one(self):
        with pytest.raises(ValueError, match="at least"):
            validate_header_size(1)

    @pytest.mark.parametrize("size", [17, 100, 200, 255, 300, 500, 1000])
    def test_not_power_of_two(self, size):
        with pytest.raises(ValueError, match="power of 2"):
            validate_header_size(size)


# ===========================================================================
# 5. validate_input_file
# ===========================================================================


class TestValidateInputFile:
    """Tests for validate_input_file()."""

    def test_valid_file(self, tmp_path: Path):
        f = tmp_path / "test.bin"
        f.write_bytes(b"data")
        validate_input_file(f)

    def test_missing_file(self, tmp_path: Path):
        with pytest.raises(FileNotFoundError):
            validate_input_file(tmp_path / "missing.bin")

    def test_directory(self, tmp_path: Path):
        with pytest.raises(ValueError, match="not a file"):
            validate_input_file(tmp_path)

    def test_empty_file(self, tmp_path: Path):
        f = tmp_path / "empty.bin"
        f.write_bytes(b"")
        validate_input_file(f)

    def test_symlink_to_file(self, tmp_path: Path):
        real = tmp_path / "real.bin"
        real.write_bytes(b"data")
        link = tmp_path / "link.bin"
        link.symlink_to(real)
        validate_input_file(link)

    def test_symlink_to_directory(self, tmp_path: Path):
        link = tmp_path / "link"
        link.symlink_to(tmp_path)
        with pytest.raises(ValueError, match="not a file"):
            validate_input_file(link)

    def test_filename_with_spaces(self, tmp_path: Path):
        f = tmp_path / "my file.bin"
        f.write_bytes(b"data")
        validate_input_file(f)

    def test_filename_with_special_chars(self, tmp_path: Path):
        f = tmp_path / "file-name_v1.2.3 (copy).bin"
        f.write_bytes(b"data")
        validate_input_file(f)


# ===========================================================================
# 6. infer_header_size
# ===========================================================================


class TestInferHeaderSize:
    """Tests for infer_header_size()."""

    @pytest.mark.parametrize("header_size", [16, 32, 64, 128, 256, 512, 1024])
    def test_correct_inference(self, header_size):
        payload = b"test-payload"
        packaged = make_packaged_binary(payload, header_size=header_size)
        assert infer_header_size(packaged) == header_size

    def test_file_too_small(self):
        with pytest.raises(ValueError, match="too small"):
            infer_header_size(b"\x00" * 10)

    def test_stored_size_zero(self):
        data = (
            HEADER_MAGIC
            + b"\x00" * 4
            + struct.pack("<I", 0)
            + b"\x00" * 4
            + b"\xff" * 240
        )
        with pytest.raises(ValueError, match="invalid"):
            infer_header_size(data)

    def test_stored_size_larger_than_file(self):
        data = HEADER_MAGIC + b"\x00" * 4 + struct.pack("<I", 99999) + b"\x00" * 4
        with pytest.raises(ValueError, match="invalid"):
            infer_header_size(data)

    def test_inferred_size_below_minimum(self):
        payload_size = 100
        fake_stored_size = payload_size + 10
        data = (
            HEADER_MAGIC
            + b"\x00" * 4
            + struct.pack("<I", fake_stored_size)
            + b"\x00" * 4
            + b"\xff" * payload_size
        )
        with pytest.raises(ValueError):
            infer_header_size(data)

    def test_exactly_header_info_size_file(self):
        data = HEADER_MAGIC + b"\x00" * 4 + struct.pack("<I", 0) + b"\x00" * 4
        assert len(data) == HEADER_INFO_SIZE
        with pytest.raises(ValueError):
            infer_header_size(data)

    def test_stored_size_equals_file_size(self):
        file_size = 256
        data = (
            HEADER_MAGIC
            + b"\x00" * 4
            + struct.pack("<I", file_size)
            + b"\x00" * 4
            + b"\xff" * (file_size - HEADER_INFO_SIZE)
        )
        with pytest.raises(ValueError):
            infer_header_size(data)

    def test_stored_size_file_minus_one(self):
        file_size = 256
        data = (
            HEADER_MAGIC
            + b"\x00" * 4
            + struct.pack("<I", file_size - 1)
            + b"\x00" * 4
            + b"\xff" * (file_size - HEADER_INFO_SIZE)
        )
        with pytest.raises(ValueError):
            infer_header_size(data)

    def test_garbage_in_size_field(self):
        data = (
            HEADER_MAGIC
            + b"\x00" * 4
            + struct.pack("<I", 0xDEADBEEF)
            + b"\x00" * 4
            + b"\xff" * 240
        )
        with pytest.raises(ValueError):
            infer_header_size(data)

    def test_empty_payload_inference(self):
        payload = b""
        header_size = 64
        packaged = make_packaged_binary(payload, header_size=header_size)
        with pytest.raises(ValueError):
            infer_header_size(packaged)


# ===========================================================================
# 7. build_header
# ===========================================================================


class TestBuildHeader:
    """Tests for build_header()."""

    @pytest.mark.parametrize("header_size", [16, 32, 64, 128, 256, 512, 1024])
    def test_output_size(self, header_size):
        payload = b"test"
        version = VersionInfo(1, 0, 0)
        header = build_header(payload, version, header_size)
        assert len(header) == header_size

    def test_magic_field(self):
        header = build_header(b"x", VersionInfo(1, 0, 0), 512)
        assert header[:4] == HEADER_MAGIC

    def test_version_field(self):
        header = build_header(b"x", VersionInfo(1, 2, 3), 512)
        assert header[4:8] == b"\x00\x03\x02\x01"

    def test_size_field(self):
        payload = b"hello"
        header = build_header(payload, VersionInfo(1, 0, 0), 512)
        stored = struct.unpack("<I", header[8:12])[0]
        assert stored == len(payload)

    def test_crc_field(self):
        payload = b"hello"
        header = build_header(payload, VersionInfo(1, 0, 0), 512)
        stored = struct.unpack("<I", header[12:16])[0]
        assert stored == Crc32Mpeg2.calc(payload)

    def test_padding_is_ff(self):
        header = build_header(b"x", VersionInfo(1, 0, 0), 512)
        padding = header[HEADER_INFO_SIZE:]
        assert padding == b"\xff" * (512 - HEADER_INFO_SIZE)

    def test_minimum_header_size(self):
        header = build_header(b"x", VersionInfo(1, 0, 0), 16)
        assert len(header) == 16
        assert header[:4] == HEADER_MAGIC

    def test_minimum_header_no_padding(self):
        header = build_header(b"x", VersionInfo(1, 0, 0), HEADER_INFO_SIZE)
        assert len(header) == HEADER_INFO_SIZE
        assert header == (
            HEADER_MAGIC
            + VersionInfo(1, 0, 0).to_bytes()
            + struct.pack("<I", 1)
            + struct.pack("<I", Crc32Mpeg2.calc(b"x"))
        )

    def test_different_payloads_different_crcs(self):
        v = VersionInfo(1, 0, 0)
        h1 = build_header(b"aaa", v, 512)
        h2 = build_header(b"bbb", v, 512)
        crc1 = struct.unpack("<I", h1[12:16])[0]
        crc2 = struct.unpack("<I", h2[12:16])[0]
        assert crc1 != crc2

    def test_empty_payload(self):
        header = build_header(b"", VersionInfo(1, 0, 0), 512)
        assert len(header) == 512
        stored_size = struct.unpack("<I", header[8:12])[0]
        assert stored_size == 0

    def test_large_payload(self):
        payload = b"\xab" * 500_000
        header = build_header(payload, VersionInfo(1, 0, 0), 512)
        stored_size = struct.unpack("<I", header[8:12])[0]
        assert stored_size == 500_000


# ===========================================================================
# 8. parse_header
# ===========================================================================


class TestParseHeader:
    """Tests for parse_header()."""

    def test_valid_header(self):
        payload = b"\x01\x02\x03\x04"
        packaged = make_packaged_binary(payload, version="2.5.7")
        info = parse_header(packaged)

        assert info.magic == HEADER_MAGIC
        assert info.version == VersionInfo(2, 5, 7)
        assert info.size == len(payload)
        assert info.crc == Crc32Mpeg2.calc(payload)

    def test_wrong_magic(self):
        data = b"BAD!" + b"\x00" * (HEADER_INFO_SIZE - 4)
        with pytest.raises(ValueError, match="Invalid header magic"):
            parse_header(data)

    def test_too_small(self):
        with pytest.raises(ValueError, match="too small"):
            parse_header(b"\x00" * 10)

    def test_empty_file(self):
        with pytest.raises(ValueError, match="too small"):
            parse_header(b"")

    def test_just_magic(self):
        with pytest.raises(ValueError, match="too small"):
            parse_header(HEADER_MAGIC)

    def test_partial_magic(self):
        with pytest.raises(ValueError, match="too small"):
            parse_header(b"XLA")

    def test_reversed_magic(self):
        data = b"BALX" + b"\x00" * 12
        with pytest.raises(ValueError, match="Invalid header magic"):
            parse_header(data)

    def test_lowercase_magic(self):
        data = b"xlab" + b"\x00" * 12
        with pytest.raises(ValueError, match="Invalid header magic"):
            parse_header(data)

    def test_null_magic(self):
        data = b"\x00\x00\x00\x00" + b"\x00" * 12
        with pytest.raises(ValueError, match="Invalid header magic"):
            parse_header(data)

    def test_ff_magic(self):
        data = b"\xff\xff\xff\x00" + b"\x00" * 12
        with pytest.raises(ValueError, match="Invalid header magic"):
            parse_header(data)


# ===========================================================================
# 9. verify_header
# ===========================================================================


class TestVerifyHeader:
    """Tests for verify_header()."""

    @pytest.mark.parametrize("header_size", [16, 64, 128, 256, 512, 1024])
    def test_success_various_sizes(self, header_size):
        payload = b"firmware-data"
        packaged = make_packaged_binary(payload, header_size=header_size)
        result = verify_header(packaged, header_size)
        assert result.ok is True
        assert result.header_size == header_size
        assert result.payload_size == len(payload)
        assert result.payload_crc == Crc32Mpeg2.calc(payload)

    def test_corrupted_payload(self):
        payload = b"firmware-data"
        packaged = make_packaged_binary(payload)
        corrupted = corrupt_byte(packaged, len(packaged) - 1)
        result = verify_header(corrupted, DEFAULT_HEADER_SIZE)
        assert result.crc_ok is False
        assert result.size_ok is True
        assert result.ok is False

    def test_wrong_size(self):
        payload = b"firmware-data"
        packaged = bytearray(make_packaged_binary(payload))
        packaged[8:12] = struct.pack("<I", len(payload) + 99)
        result = verify_header(bytes(packaged), DEFAULT_HEADER_SIZE)
        assert result.size_ok is False
        assert result.ok is False

    def test_wrong_magic(self):
        payload = b"firmware-data"
        packaged = bytearray(make_packaged_binary(payload))
        packaged[:4] = b"NOPE"
        result = verify_header(bytes(packaged), DEFAULT_HEADER_SIZE)
        assert result.magic_ok is False
        assert result.ok is False

    def test_file_too_small(self):
        with pytest.raises(ValueError, match="too small"):
            verify_header(b"\x00" * 10, DEFAULT_HEADER_SIZE)

    def test_empty_payload(self):
        packaged = make_packaged_binary(b"")
        result = verify_header(packaged, DEFAULT_HEADER_SIZE)
        assert result.ok is True
        assert result.payload_size == 0

    def test_large_payload(self):
        payload = b"\xab" * 100_000
        packaged = make_packaged_binary(payload)
        result = verify_header(packaged, DEFAULT_HEADER_SIZE)
        assert result.ok is True

    def test_single_bit_flip_in_payload(self):
        payload = b"\x00" * 1000
        packaged = make_packaged_binary(payload)
        corrupted = flip_bit(packaged, DEFAULT_HEADER_SIZE + 500, 0)
        result = verify_header(corrupted, DEFAULT_HEADER_SIZE)
        assert result.crc_ok is False
        assert result.ok is False

    def test_single_bit_flip_in_header_crc(self):
        payload = b"firmware"
        packaged = make_packaged_binary(payload)
        corrupted = flip_bit(packaged, 12, 0)
        result = verify_header(corrupted, DEFAULT_HEADER_SIZE)
        assert result.crc_ok is False
        assert result.ok is False

    def test_swapped_crc_bytes(self):
        payload = b"firmware"
        packaged = bytearray(make_packaged_binary(payload))
        packaged[12], packaged[13] = packaged[13], packaged[12]
        result = verify_header(bytes(packaged), DEFAULT_HEADER_SIZE)
        assert result.crc_ok is False

    def test_truncated_file(self):
        payload = b"firmware" * 100
        packaged = make_packaged_binary(payload)
        truncated = packaged[:-1]
        result = verify_header(truncated, DEFAULT_HEADER_SIZE)
        assert result.size_ok is False

    def test_appended_extra_bytes(self):
        payload = b"firmware"
        packaged = make_packaged_binary(payload)
        extended = packaged + b"\x00"
        result = verify_header(extended, DEFAULT_HEADER_SIZE)
        assert result.size_ok is False

    def test_header_from_different_payload(self):
        payload_a = b"firmware-A"
        payload_b = b"firmware-B"
        header_a = build_header(payload_a, VersionInfo(1, 0, 0), DEFAULT_HEADER_SIZE)
        packaged = header_a + payload_b
        result = verify_header(packaged, DEFAULT_HEADER_SIZE)
        assert result.crc_ok is False

    def test_wrong_explicit_header_size(self):
        payload = b"firmware"
        packaged = make_packaged_binary(payload, header_size=512)
        result = verify_header(packaged, 256)
        assert result.ok is False


# ===========================================================================
# 10. split_payload_from_packaged
# ===========================================================================


class TestSplitPayloadFromPackaged:
    """Tests for split_payload_from_packaged()."""

    def test_correct_split(self):
        payload = b"raw-binary"
        packaged = make_packaged_binary(payload)
        header, extracted = split_payload_from_packaged(packaged, DEFAULT_HEADER_SIZE)
        assert len(header) == DEFAULT_HEADER_SIZE
        assert extracted == payload

    @pytest.mark.parametrize("header_size", [16, 64, 128, 256, 512, 1024])
    def test_different_header_sizes(self, header_size):
        payload = b"raw-binary"
        packaged = make_packaged_binary(payload, header_size=header_size)
        header, extracted = split_payload_from_packaged(packaged, header_size)
        assert len(header) == header_size
        assert extracted == payload

    def test_file_too_small(self):
        with pytest.raises(ValueError, match="too small"):
            split_payload_from_packaged(b"\x00" * 100, 512)

    def test_exact_header_size_no_payload(self):
        data = b"\x00" * DEFAULT_HEADER_SIZE
        header, payload = split_payload_from_packaged(data, DEFAULT_HEADER_SIZE)
        assert len(header) == DEFAULT_HEADER_SIZE
        assert payload == b""

    def test_one_byte_over_header(self):
        data = b"\x00" * (DEFAULT_HEADER_SIZE + 1)
        header, payload = split_payload_from_packaged(data, DEFAULT_HEADER_SIZE)
        assert len(header) == DEFAULT_HEADER_SIZE
        assert payload == b"\x00"


# ===========================================================================
# 11. File I/O
# ===========================================================================


class TestFileIO:
    """Tests for file reading and writing helpers."""

    def test_write_binary(self, tmp_path: Path):
        out = tmp_path / "out.bin"
        data = b"hello"
        write_binary(out, data)
        assert out.read_bytes() == data

    def test_write_binary_creates_parents(self, tmp_path: Path):
        out = tmp_path / "a" / "b" / "c" / "out.bin"
        write_binary(out, b"data")
        assert out.read_bytes() == b"data"

    def test_write_binary_in_place(self, tmp_path: Path):
        path = tmp_path / "firmware.bin"
        path.write_bytes(b"old-data")
        write_binary_in_place(path, b"new-data")
        assert path.read_bytes() == b"new-data"

    def test_write_binary_in_place_no_temp_leftover(self, tmp_path: Path):
        path = tmp_path / "firmware.bin"
        path.write_bytes(b"old")
        write_binary_in_place(path, b"new")
        temps = list(tmp_path.glob("*.tmp"))
        assert len(temps) == 0

    def test_write_binary_in_place_creates_parents(self, tmp_path: Path):
        path = tmp_path / "sub" / "dir" / "firmware.bin"
        write_binary_in_place(path, b"data")
        assert path.read_bytes() == b"data"

    def test_write_empty_file(self, tmp_path: Path):
        out = tmp_path / "empty.bin"
        write_binary(out, b"")
        assert out.read_bytes() == b""

    def test_write_large_file(self, tmp_path: Path):
        out = tmp_path / "large.bin"
        data = b"\xab" * 1_000_000
        write_binary(out, data)
        assert out.read_bytes() == data

    def test_overwrite_existing(self, tmp_path: Path):
        out = tmp_path / "out.bin"
        write_binary(out, b"first")
        write_binary(out, b"second")
        assert out.read_bytes() == b"second"


# ===========================================================================
# 12. attach subcommand
# ===========================================================================


class TestHandleAttach:
    """Tests for the attach subcommand handler."""

    def _run_attach(
        self,
        tmp_path: Path,
        payload: bytes,
        version: str = "1.2.3",
        header_size: int = DEFAULT_HEADER_SIZE,
        in_place: bool = False,
    ) -> Path:
        input_path = tmp_path / "firmware.bin"
        input_path.write_bytes(payload)

        if in_place:
            output_path = input_path
            args = build_parser().parse_args(
                [
                    "attach",
                    str(input_path),
                    version,
                    "--in-place",
                    "--header-size",
                    str(header_size),
                ]
            )
        else:
            output_path = tmp_path / "out.bin"
            args = build_parser().parse_args(
                [
                    "attach",
                    str(input_path),
                    version,
                    str(output_path),
                    "--header-size",
                    str(header_size),
                ]
            )

        args.handler(args)
        return output_path

    def test_basic_attach(self, tmp_path: Path):
        payload = b"\x01\x02\x03\x04"
        out = self._run_attach(tmp_path, payload)
        data = out.read_bytes()

        assert len(data) == DEFAULT_HEADER_SIZE + len(payload)
        assert data[:4] == HEADER_MAGIC
        assert data[DEFAULT_HEADER_SIZE:] == payload

    def test_payload_unchanged(self, tmp_path: Path):
        payload = b"\xaa\xbb\xcc\xdd" * 100
        out = self._run_attach(tmp_path, payload)
        data = out.read_bytes()
        assert data[DEFAULT_HEADER_SIZE:] == payload

    def test_header_fields_correct(self, tmp_path: Path):
        payload = b"firmware-data"
        out = self._run_attach(tmp_path, payload, version="2.5.7")
        data = out.read_bytes()

        info = HeaderInfo.from_bytes(data)
        assert info.version == VersionInfo(2, 5, 7)
        assert info.size == len(payload)
        assert info.crc == Crc32Mpeg2.calc(payload)

    @pytest.mark.parametrize("header_size", [16, 64, 128, 256, 512, 1024])
    def test_custom_header_size(self, tmp_path: Path, header_size: int):
        payload = b"test"
        out = self._run_attach(tmp_path, payload, header_size=header_size)
        data = out.read_bytes()
        assert len(data) == header_size + len(payload)

    def test_in_place(self, tmp_path: Path):
        payload = b"firmware"
        out = self._run_attach(tmp_path, payload, in_place=True)
        data = out.read_bytes()
        assert len(data) == DEFAULT_HEADER_SIZE + len(payload)
        assert data[DEFAULT_HEADER_SIZE:] == payload

    def test_attach_then_verify(self, tmp_path: Path):
        payload = b"firmware-data"
        out = self._run_attach(tmp_path, payload)
        data = out.read_bytes()
        result = verify_header(data, DEFAULT_HEADER_SIZE)
        assert result.ok is True

    def test_attach_empty_payload(self, tmp_path: Path):
        out = self._run_attach(tmp_path, b"")
        data = out.read_bytes()
        assert len(data) == DEFAULT_HEADER_SIZE
        result = verify_header(data, DEFAULT_HEADER_SIZE)
        assert result.ok is True

    def test_attach_large_payload(self, tmp_path: Path):
        payload = b"\xab" * 500_000
        out = self._run_attach(tmp_path, payload)
        data = out.read_bytes()
        result = verify_header(data, DEFAULT_HEADER_SIZE)
        assert result.ok is True

    def test_attach_one_byte_payload(self, tmp_path: Path):
        payload = b"\x42"
        out = self._run_attach(tmp_path, payload)
        data = out.read_bytes()
        result = verify_header(data, DEFAULT_HEADER_SIZE)
        assert result.ok is True
        assert result.payload_size == 1

    def test_attach_all_zeros_payload(self, tmp_path: Path):
        payload = b"\x00" * 1000
        out = self._run_attach(tmp_path, payload)
        result = verify_header(out.read_bytes(), DEFAULT_HEADER_SIZE)
        assert result.ok is True

    def test_attach_all_ff_payload(self, tmp_path: Path):
        payload = b"\xff" * 1000
        out = self._run_attach(tmp_path, payload)
        result = verify_header(out.read_bytes(), DEFAULT_HEADER_SIZE)
        assert result.ok is True

    def test_attach_payload_looks_like_header(self, tmp_path: Path):
        payload = HEADER_MAGIC + b"\x00" * 100
        out = self._run_attach(tmp_path, payload)
        data = out.read_bytes()
        result = verify_header(data, DEFAULT_HEADER_SIZE)
        assert result.ok is True
        assert result.payload_size == len(payload)

    def test_attach_payload_exactly_header_info_size(self, tmp_path: Path):
        payload = b"\x42" * HEADER_INFO_SIZE
        out = self._run_attach(tmp_path, payload)
        result = verify_header(out.read_bytes(), DEFAULT_HEADER_SIZE)
        assert result.ok is True

    def test_attach_payload_exactly_default_header_size(self, tmp_path: Path):
        payload = b"\x42" * DEFAULT_HEADER_SIZE
        out = self._run_attach(tmp_path, payload)
        result = verify_header(out.read_bytes(), DEFAULT_HEADER_SIZE)
        assert result.ok is True


# ===========================================================================
# 13. edit subcommand
# ===========================================================================


class TestHandleEdit:
    """Tests for the edit subcommand handler."""

    def _make_packaged_file(
        self,
        tmp_path: Path,
        payload: bytes,
        version: str = "1.0.0",
        header_size: int = DEFAULT_HEADER_SIZE,
    ) -> Path:
        path = tmp_path / "packaged.bin"
        path.write_bytes(make_packaged_binary(payload, version, header_size))
        return path

    def _run_edit(
        self,
        input_path: Path,
        new_version: str,
        output_path: Path | None = None,
        in_place: bool = False,
        header_size: int | None = None,
    ) -> Path:
        cmd = ["edit", str(input_path), new_version]

        if in_place:
            cmd.append("--in-place")
            result_path = input_path
        else:
            assert output_path is not None
            cmd.append(str(output_path))
            result_path = output_path

        if header_size is not None:
            cmd.extend(["--header-size", str(header_size)])

        args = build_parser().parse_args(cmd)
        args.handler(args)
        return result_path

    def test_replaces_header(self, tmp_path: Path):
        payload = b"\xaa\xbb\xcc\xdd"
        input_path = self._make_packaged_file(tmp_path, payload, version="1.0.0")
        output_path = tmp_path / "updated.bin"

        self._run_edit(input_path, "2.0.0", output_path)

        data = output_path.read_bytes()
        info = HeaderInfo.from_bytes(data)
        assert info.version == VersionInfo(2, 0, 0)

    def test_preserves_payload(self, tmp_path: Path):
        payload = b"\xaa\xbb\xcc\xdd"
        input_path = self._make_packaged_file(tmp_path, payload)
        output_path = tmp_path / "updated.bin"

        self._run_edit(input_path, "2.0.0", output_path)

        data = output_path.read_bytes()
        assert data[DEFAULT_HEADER_SIZE:] == payload

    def test_size_and_crc_match(self, tmp_path: Path):
        payload = b"firmware-data"
        input_path = self._make_packaged_file(tmp_path, payload)
        output_path = tmp_path / "updated.bin"

        self._run_edit(input_path, "3.0.0", output_path)

        data = output_path.read_bytes()
        info = HeaderInfo.from_bytes(data)
        assert info.size == len(payload)
        assert info.crc == Crc32Mpeg2.calc(payload)

    def test_infers_header_size(self, tmp_path: Path):
        payload = b"test"
        header_size = 256
        input_path = self._make_packaged_file(
            tmp_path, payload, header_size=header_size
        )
        output_path = tmp_path / "updated.bin"

        self._run_edit(input_path, "2.0.0", output_path)

        data = output_path.read_bytes()
        assert len(data) == header_size + len(payload)

    def test_explicit_header_size(self, tmp_path: Path):
        payload = b"test"
        header_size = 512
        input_path = self._make_packaged_file(
            tmp_path, payload, header_size=header_size
        )
        output_path = tmp_path / "updated.bin"

        self._run_edit(input_path, "2.0.0", output_path, header_size=header_size)

        data = output_path.read_bytes()
        assert len(data) == header_size + len(payload)

    def test_in_place(self, tmp_path: Path):
        payload = b"firmware"
        input_path = self._make_packaged_file(tmp_path, payload, version="1.0.0")

        self._run_edit(input_path, "2.0.0", in_place=True)

        data = input_path.read_bytes()
        info = HeaderInfo.from_bytes(data)
        assert info.version == VersionInfo(2, 0, 0)
        assert data[DEFAULT_HEADER_SIZE:] == payload

    def test_file_too_small(self, tmp_path: Path):
        small_file = tmp_path / "small.bin"
        small_file.write_bytes(b"\x00" * 100)

        output_path = tmp_path / "out.bin"

        with pytest.raises(ValueError, match="too small"):
            self._run_edit(
                small_file,
                "1.0.0",
                output_path,
                header_size=512,
            )

    def test_same_version(self, tmp_path: Path):
        payload = b"firmware"
        input_path = self._make_packaged_file(tmp_path, payload, version="1.0.0")
        output_path = tmp_path / "updated.bin"

        self._run_edit(input_path, "1.0.0", output_path)

        assert output_path.read_bytes() == input_path.read_bytes()

    def test_version_downgrade(self, tmp_path: Path):
        payload = b"firmware"
        input_path = self._make_packaged_file(tmp_path, payload, version="2.0.0")
        output_path = tmp_path / "updated.bin"

        self._run_edit(input_path, "1.0.0", output_path)

        info = HeaderInfo.from_bytes(output_path.read_bytes())
        assert info.version == VersionInfo(1, 0, 0)

    def test_edit_empty_payload(self, tmp_path: Path):
        payload = b""
        input_path = self._make_packaged_file(tmp_path, payload)
        output_path = tmp_path / "updated.bin"

        with pytest.raises(ValueError):
            self._run_edit(input_path, "2.0.0", output_path)

    def test_edit_then_verify(self, tmp_path: Path):
        payload = b"firmware"
        input_path = self._make_packaged_file(tmp_path, payload)
        output_path = tmp_path / "updated.bin"

        self._run_edit(input_path, "3.0.0", output_path)

        result = verify_header(output_path.read_bytes(), DEFAULT_HEADER_SIZE)
        assert result.ok is True


# ===========================================================================
# 14. inspect subcommand
# ===========================================================================


class TestHandleInspect:
    """Tests for the inspect subcommand handler."""

    def _make_packaged_file(
        self, tmp_path: Path, payload: bytes, version: str = "1.2.3"
    ) -> Path:
        path = tmp_path / "packaged.bin"
        path.write_bytes(make_packaged_binary(payload, version))
        return path

    def test_text_output(self, tmp_path: Path, capsys):
        payload = b"test"
        input_path = self._make_packaged_file(tmp_path, payload)

        args = build_parser().parse_args(["inspect", str(input_path)])
        args.handler(args)

        captured = capsys.readouterr()
        assert "XLAB" in captured.out
        assert "1.2.3" in captured.out
        assert str(len(payload)) in captured.out

    def test_json_output(self, tmp_path: Path, capsys):
        payload = b"test"
        input_path = self._make_packaged_file(tmp_path, payload)

        args = build_parser().parse_args(["inspect", str(input_path), "--json"])
        args.handler(args)

        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert data["magic_ascii"] == "XLAB"
        assert data["version"]["string"] == "1.2.3"
        assert data["size"] == len(payload)

    def test_wrong_magic(self, tmp_path: Path):
        path = tmp_path / "bad.bin"
        path.write_bytes(b"BAD!" + b"\x00" * 100)

        args = build_parser().parse_args(["inspect", str(path)])

        with pytest.raises(ValueError, match="Invalid header magic"):
            args.handler(args)

    def test_file_too_small(self, tmp_path: Path):
        path = tmp_path / "tiny.bin"
        path.write_bytes(b"\x00" * 5)

        args = build_parser().parse_args(["inspect", str(path)])

        with pytest.raises(ValueError, match="too small"):
            args.handler(args)

    def test_empty_file(self, tmp_path: Path):
        path = tmp_path / "empty.bin"
        path.write_bytes(b"")

        args = build_parser().parse_args(["inspect", str(path)])

        with pytest.raises(ValueError, match="too small"):
            args.handler(args)

    def test_json_output_has_crc_hex(self, tmp_path: Path, capsys):
        input_path = self._make_packaged_file(tmp_path, b"data")

        args = build_parser().parse_args(["inspect", str(input_path), "--json"])
        args.handler(args)

        data = json.loads(capsys.readouterr().out)
        assert data["crc"]["hex"].startswith("0x")

    def test_inspect_version_zero(self, tmp_path: Path, capsys):
        input_path = self._make_packaged_file(tmp_path, b"data", version="0.0.0")

        args = build_parser().parse_args(["inspect", str(input_path), "--json"])
        args.handler(args)

        data = json.loads(capsys.readouterr().out)
        assert data["version"]["string"] == "0.0.0"

    def test_inspect_empty_payload(self, tmp_path: Path, capsys):
        input_path = self._make_packaged_file(tmp_path, b"")

        args = build_parser().parse_args(["inspect", str(input_path), "--json"])
        args.handler(args)

        data = json.loads(capsys.readouterr().out)
        assert data["size"] == 0


# ===========================================================================
# 15. verify subcommand
# ===========================================================================


class TestHandleVerify:
    """Tests for the verify subcommand handler."""

    def _make_packaged_file(
        self,
        tmp_path: Path,
        payload: bytes,
        version: str = "1.2.3",
        header_size: int = DEFAULT_HEADER_SIZE,
    ) -> Path:
        path = tmp_path / "packaged.bin"
        path.write_bytes(make_packaged_binary(payload, version, header_size))
        return path

    def test_success_exit_code(self, tmp_path: Path):
        input_path = self._make_packaged_file(tmp_path, b"firmware")

        args = build_parser().parse_args(["verify", str(input_path), "--quiet"])

        with pytest.raises(SystemExit) as exc_info:
            args.handler(args)
        assert exc_info.value.code == 0

    def test_failure_exit_code(self, tmp_path: Path):
        path = tmp_path / "bad.bin"
        packaged = make_packaged_binary(b"firmware")
        path.write_bytes(corrupt_byte(packaged, len(packaged) - 1))

        args = build_parser().parse_args(["verify", str(path), "--quiet"])

        with pytest.raises(SystemExit) as exc_info:
            args.handler(args)
        assert exc_info.value.code == 1

    def test_text_output(self, tmp_path: Path, capsys):
        input_path = self._make_packaged_file(tmp_path, b"firmware")

        args = build_parser().parse_args(["verify", str(input_path)])

        with pytest.raises(SystemExit):
            args.handler(args)

        captured = capsys.readouterr()
        assert "OK" in captured.out

    def test_json_output(self, tmp_path: Path, capsys):
        input_path = self._make_packaged_file(tmp_path, b"firmware")

        args = build_parser().parse_args(["verify", str(input_path), "--json"])

        with pytest.raises(SystemExit):
            args.handler(args)

        data = json.loads(capsys.readouterr().out)
        assert data["ok"] is True

    def test_quiet_no_output(self, tmp_path: Path, capsys):
        input_path = self._make_packaged_file(tmp_path, b"firmware")

        args = build_parser().parse_args(["verify", str(input_path), "--quiet"])

        with pytest.raises(SystemExit):
            args.handler(args)

        captured = capsys.readouterr()
        assert captured.out == ""

    def test_infers_header_size(self, tmp_path: Path):
        input_path = self._make_packaged_file(tmp_path, b"firmware", header_size=256)

        args = build_parser().parse_args(["verify", str(input_path), "--quiet"])

        with pytest.raises(SystemExit) as exc_info:
            args.handler(args)
        assert exc_info.value.code == 0

    def test_explicit_header_size(self, tmp_path: Path):
        header_size = 1024
        input_path = self._make_packaged_file(
            tmp_path, b"firmware", header_size=header_size
        )

        args = build_parser().parse_args(
            [
                "verify",
                str(input_path),
                "--quiet",
                "--header-size",
                str(header_size),
            ]
        )

        with pytest.raises(SystemExit) as exc_info:
            args.handler(args)
        assert exc_info.value.code == 0

    def test_json_output_shows_header_size(self, tmp_path: Path, capsys):
        header_size = 256
        input_path = self._make_packaged_file(tmp_path, b"fw", header_size=header_size)

        args = build_parser().parse_args(["verify", str(input_path), "--json"])

        with pytest.raises(SystemExit):
            args.handler(args)

        data = json.loads(capsys.readouterr().out)
        assert data["header_size"] == header_size

    def test_verify_truncated_file(self, tmp_path: Path):
        payload = b"firmware" * 100
        packaged = make_packaged_binary(payload)
        path = tmp_path / "truncated.bin"
        path.write_bytes(packaged[:-1])

        args = build_parser().parse_args(["verify", str(path), "--quiet"])

        with pytest.raises(SystemExit) as exc_info:
            args.handler(args)
        assert exc_info.value.code == 1

    def test_verify_appended_bytes(self, tmp_path: Path):
        payload = b"firmware"
        packaged = make_packaged_binary(payload)
        path = tmp_path / "extended.bin"
        path.write_bytes(packaged + b"\x00")

        args = build_parser().parse_args(["verify", str(path), "--quiet"])

        with pytest.raises(SystemExit) as exc_info:
            args.handler(args)
        assert exc_info.value.code == 1

    def test_verify_wrong_header_size(self, tmp_path: Path):
        payload = b"firmware"
        input_path = self._make_packaged_file(tmp_path, payload, header_size=512)

        args = build_parser().parse_args(
            [
                "verify",
                str(input_path),
                "--quiet",
                "--header-size",
                "256",
            ]
        )

        with pytest.raises(SystemExit) as exc_info:
            args.handler(args)
        assert exc_info.value.code == 1


# ===========================================================================
# 16. End-to-end workflows
# ===========================================================================


class TestEndToEnd:
    """End-to-end workflow tests."""

    def test_attach_then_verify(self, tmp_path: Path):
        payload = b"firmware-payload"
        raw = tmp_path / "raw.bin"
        packaged = tmp_path / "packaged.bin"
        raw.write_bytes(payload)

        attach_args = build_parser().parse_args(
            ["attach", str(raw), "1.0.0", str(packaged)]
        )
        attach_args.handler(attach_args)

        verify_args = build_parser().parse_args(["verify", str(packaged), "--quiet"])
        with pytest.raises(SystemExit) as exc_info:
            verify_args.handler(verify_args)
        assert exc_info.value.code == 0

    def test_attach_then_edit_then_verify(self, tmp_path: Path):
        payload = b"firmware-payload"
        raw = tmp_path / "raw.bin"
        packaged = tmp_path / "packaged.bin"
        updated = tmp_path / "updated.bin"
        raw.write_bytes(payload)

        attach_args = build_parser().parse_args(
            ["attach", str(raw), "1.0.0", str(packaged)]
        )
        attach_args.handler(attach_args)

        edit_args = build_parser().parse_args(
            ["edit", str(packaged), "1.0.1", str(updated)]
        )
        edit_args.handler(edit_args)

        verify_args = build_parser().parse_args(["verify", str(updated), "--quiet"])
        with pytest.raises(SystemExit) as exc_info:
            verify_args.handler(verify_args)
        assert exc_info.value.code == 0

        # payload preserved
        assert updated.read_bytes()[DEFAULT_HEADER_SIZE:] == payload

        # version updated
        info = HeaderInfo.from_bytes(updated.read_bytes())
        assert info.version == VersionInfo(1, 0, 1)

    def test_attach_corrupt_then_verify_fails(self, tmp_path: Path):
        payload = b"firmware-payload"
        raw = tmp_path / "raw.bin"
        packaged = tmp_path / "packaged.bin"
        raw.write_bytes(payload)

        attach_args = build_parser().parse_args(
            ["attach", str(raw), "1.0.0", str(packaged)]
        )
        attach_args.handler(attach_args)

        # corrupt payload
        data = bytearray(packaged.read_bytes())
        data[-1] ^= 0xFF
        packaged.write_bytes(bytes(data))

        verify_args = build_parser().parse_args(["verify", str(packaged), "--quiet"])
        with pytest.raises(SystemExit) as exc_info:
            verify_args.handler(verify_args)
        assert exc_info.value.code == 1

    @pytest.mark.parametrize("header_size", [64, 128, 256, 512, 1024])
    def test_attach_verify_different_sizes(self, tmp_path: Path, header_size: int):
        payload = b"firmware"
        raw = tmp_path / "raw.bin"
        packaged = tmp_path / "packaged.bin"
        raw.write_bytes(payload)

        attach_args = build_parser().parse_args(
            [
                "attach",
                str(raw),
                "1.0.0",
                str(packaged),
                "--header-size",
                str(header_size),
            ]
        )
        attach_args.handler(attach_args)

        data = packaged.read_bytes()
        assert len(data) == header_size + len(payload)

        verify_args = build_parser().parse_args(["verify", str(packaged), "--quiet"])
        with pytest.raises(SystemExit) as exc_info:
            verify_args.handler(verify_args)
        assert exc_info.value.code == 0

    def test_edit_preserves_payload_across_versions(self, tmp_path: Path):
        payload = b"original-firmware"
        packaged_v1 = tmp_path / "v1.bin"
        packaged_v2 = tmp_path / "v2.bin"
        packaged_v3 = tmp_path / "v3.bin"

        packaged_v1.write_bytes(make_packaged_binary(payload, "1.0.0"))

        edit_args_v2 = build_parser().parse_args(
            ["edit", str(packaged_v1), "2.0.0", str(packaged_v2)]
        )
        edit_args_v2.handler(edit_args_v2)

        edit_args_v3 = build_parser().parse_args(
            ["edit", str(packaged_v2), "3.0.0", str(packaged_v3)]
        )
        edit_args_v3.handler(edit_args_v3)

        assert (
            packaged_v1.read_bytes()[DEFAULT_HEADER_SIZE:]
            == packaged_v2.read_bytes()[DEFAULT_HEADER_SIZE:]
            == packaged_v3.read_bytes()[DEFAULT_HEADER_SIZE:]
            == payload
        )

    def test_attach_inspect_roundtrip(self, tmp_path: Path, capsys):
        payload = b"firmware"
        raw = tmp_path / "raw.bin"
        packaged = tmp_path / "packaged.bin"
        raw.write_bytes(payload)

        attach_args = build_parser().parse_args(
            ["attach", str(raw), "4.5.6", str(packaged)]
        )
        attach_args.handler(attach_args)

        inspect_args = build_parser().parse_args(["inspect", str(packaged), "--json"])
        inspect_args.handler(inspect_args)

        data = json.loads(capsys.readouterr().out)
        assert data["version"]["string"] == "4.5.6"
        assert data["size"] == len(payload)


# ===========================================================================
# 17. CLI argument validation
# ===========================================================================


class TestCLIArguments:
    """Tests for CLI argument parsing and validation."""

    def test_version_flag(self, capsys):
        parser = build_parser()
        with pytest.raises(SystemExit) as exc_info:
            parser.parse_args(["--version"])
        assert exc_info.value.code == 0

    def test_help_flag(self, capsys):
        parser = build_parser()
        with pytest.raises(SystemExit) as exc_info:
            parser.parse_args(["--help"])
        assert exc_info.value.code == 0

    def test_no_subcommand(self):
        parser = build_parser()
        with pytest.raises(SystemExit) as exc_info:
            parser.parse_args([])
        assert exc_info.value.code != 0

    def test_attach_help(self):
        parser = build_parser()
        with pytest.raises(SystemExit) as exc_info:
            parser.parse_args(["attach", "--help"])
        assert exc_info.value.code == 0

    def test_edit_help(self):
        parser = build_parser()
        with pytest.raises(SystemExit) as exc_info:
            parser.parse_args(["edit", "--help"])
        assert exc_info.value.code == 0

    def test_inspect_help(self):
        parser = build_parser()
        with pytest.raises(SystemExit) as exc_info:
            parser.parse_args(["inspect", "--help"])
        assert exc_info.value.code == 0

    def test_verify_help(self):
        parser = build_parser()
        with pytest.raises(SystemExit) as exc_info:
            parser.parse_args(["verify", "--help"])
        assert exc_info.value.code == 0

    def test_attach_requires_version(self):
        parser = build_parser()
        with pytest.raises(SystemExit):
            parser.parse_args(["attach", "input.bin"])

    def test_attach_requires_output_or_in_place(self):
        parser = build_parser()
        with pytest.raises(SystemExit):
            parser.parse_args(["attach", "input.bin", "1.0.0"])

    def test_attach_parses_header_size(self):
        parser = build_parser()
        args = parser.parse_args(
            ["attach", "in.bin", "1.0.0", "out.bin", "--header-size", "1024"]
        )
        assert args.header_size == 1024

    def test_attach_default_header_size(self):
        parser = build_parser()
        args = parser.parse_args(["attach", "in.bin", "1.0.0", "out.bin"])
        assert args.header_size == DEFAULT_HEADER_SIZE

    def test_edit_default_header_size_is_none(self):
        parser = build_parser()
        args = parser.parse_args(["edit", "in.bin", "1.0.0", "out.bin"])
        assert args.header_size is None

    def test_verify_default_header_size_is_none(self):
        parser = build_parser()
        args = parser.parse_args(["verify", "in.bin"])
        assert args.header_size is None

    def test_verify_parses_quiet(self):
        parser = build_parser()
        args = parser.parse_args(["verify", "in.bin", "--quiet"])
        assert args.quiet is True

    def test_verify_parses_json(self):
        parser = build_parser()
        args = parser.parse_args(["verify", "in.bin", "--json"])
        assert args.json is True

    def test_inspect_parses_json(self):
        parser = build_parser()
        args = parser.parse_args(["inspect", "in.bin", "--json"])
        assert args.json is True


# ===========================================================================
# 18. Direct unit tests for previously untested functions
# ===========================================================================


class TestReadBinary:
    """Direct tests for read_binary()."""

    def test_reads_file_contents(self, tmp_path: Path):
        f = tmp_path / "data.bin"
        f.write_bytes(b"\x01\x02\x03")
        assert read_binary(f) == b"\x01\x02\x03"

    def test_reads_empty_file(self, tmp_path: Path):
        f = tmp_path / "empty.bin"
        f.write_bytes(b"")
        assert read_binary(f) == b""

    def test_reads_large_file(self, tmp_path: Path):
        f = tmp_path / "large.bin"
        data = b"\xab" * 1_000_000
        f.write_bytes(data)
        assert read_binary(f) == data

    def test_reads_binary_data_not_text(self, tmp_path: Path):
        f = tmp_path / "binary.bin"
        data = bytes(range(256))
        f.write_bytes(data)
        assert read_binary(f) == data

    def test_nonexistent_file_raises(self, tmp_path: Path):
        with pytest.raises(FileNotFoundError):
            read_binary(tmp_path / "missing.bin")


class TestWriteOutput:
    """Direct tests for write_output()."""

    def test_write_to_path(self, tmp_path: Path):
        out = tmp_path / "output.bin"
        write_output(path=out, data=b"hello", in_place=None)
        assert out.read_bytes() == b"hello"

    def test_write_in_place(self, tmp_path: Path):
        f = tmp_path / "existing.bin"
        f.write_bytes(b"old-data")
        write_output(path=None, data=b"new-data", in_place=f)
        assert f.read_bytes() == b"new-data"

    def test_write_to_path_creates_parents(self, tmp_path: Path):
        out = tmp_path / "a" / "b" / "out.bin"
        write_output(path=out, data=b"data", in_place=None)
        assert out.read_bytes() == b"data"

    def test_write_empty_data(self, tmp_path: Path):
        out = tmp_path / "empty.bin"
        write_output(path=out, data=b"", in_place=None)
        assert out.read_bytes() == b""


class TestResolveHeaderSizeForBuild:
    """Direct tests for resolve_header_size_for_build()."""

    def test_explicit_header_size(self):
        args = build_parser().parse_args(
            ["attach", "in.bin", "1.0.0", "out.bin", "--header-size", "1024"]
        )
        assert resolve_header_size_for_build(args) == 1024

    def test_default_when_no_data(self):
        args = build_parser().parse_args(["attach", "in.bin", "1.0.0", "out.bin"])
        assert resolve_header_size_for_build(args) == DEFAULT_HEADER_SIZE

    def test_inferred_from_data(self):
        payload = b"test-payload"
        packaged = make_packaged_binary(payload, header_size=256)
        args = build_parser().parse_args(["edit", "in.bin", "1.0.0", "out.bin"])
        result = resolve_header_size_for_build(args, data=packaged)
        assert result == 256

    def test_explicit_overrides_inference(self):
        payload = b"test-payload"
        packaged = make_packaged_binary(payload, header_size=256)
        args = build_parser().parse_args(
            ["edit", "in.bin", "1.0.0", "out.bin", "--header-size", "512"]
        )
        result = resolve_header_size_for_build(args, data=packaged)
        assert result == 512

    def test_invalid_explicit_size_raises(self):
        args = build_parser().parse_args(
            ["attach", "in.bin", "1.0.0", "out.bin", "--header-size", "100"]
        )
        with pytest.raises(ValueError, match="power of 2"):
            resolve_header_size_for_build(args)

    def test_too_small_explicit_size_raises(self):
        args = build_parser().parse_args(
            ["attach", "in.bin", "1.0.0", "out.bin", "--header-size", "8"]
        )
        with pytest.raises(ValueError, match="at least"):
            resolve_header_size_for_build(args)


class TestResolveHeaderSizeForVerify:
    """Direct tests for resolve_header_size_for_verify()."""

    def test_explicit_header_size(self):
        args = build_parser().parse_args(["verify", "in.bin", "--header-size", "512"])
        result = resolve_header_size_for_verify(args, b"\x00" * 1024)
        assert result == 512

    def test_inferred_from_data(self):
        payload = b"test-payload"
        packaged = make_packaged_binary(payload, header_size=128)
        args = build_parser().parse_args(["verify", "in.bin"])
        result = resolve_header_size_for_verify(args, packaged)
        assert result == 128

    def test_inference_fails_on_bad_data(self):
        args = build_parser().parse_args(["verify", "in.bin"])
        bad_data = HEADER_MAGIC + b"\x00" * 4 + struct.pack("<I", 0) + b"\x00" * 4
        with pytest.raises(ValueError):
            resolve_header_size_for_verify(args, bad_data)


# ===========================================================================
# 19. Error/exception paths — I/O failure and cleanup
# ===========================================================================


class TestWriteBinaryInPlaceFailure:
    """Tests for write_binary_in_place() cleanup on failure."""

    def test_cleans_up_temp_on_replace_failure(self, tmp_path: Path):
        path = tmp_path / "firmware.bin"
        path.write_bytes(b"original")

        with patch("fwtool.cli.os.replace", side_effect=OSError("disk error")):
            with pytest.raises(OSError, match="disk error"):
                write_binary_in_place(path, b"new-data")

        # Original file should be untouched
        assert path.read_bytes() == b"original"

        # No temp files left behind
        temps = list(tmp_path.glob("*.tmp"))
        assert len(temps) == 0

    def test_cleans_up_temp_on_write_failure(self, tmp_path: Path):
        path = tmp_path / "firmware.bin"
        path.write_bytes(b"original")

        with patch("fwtool.cli.os.fdopen", side_effect=OSError("write error")):
            with pytest.raises(OSError, match="write error"):
                write_binary_in_place(path, b"new-data")

        assert path.read_bytes() == b"original"

        temps = list(tmp_path.glob("*.tmp"))
        assert len(temps) == 0

    def test_succeeds_when_target_does_not_exist_yet(self, tmp_path: Path):
        path = tmp_path / "new_file.bin"
        write_binary_in_place(path, b"data")
        assert path.read_bytes() == b"data"


# ===========================================================================
# 20. Handler negative tests (bad inputs, missing files)
# ===========================================================================


class TestHandlerNegativePaths:
    """Tests for handler error paths with bad inputs."""

    # -- attach ---------------------------------------------------------------

    def test_attach_nonexistent_file(self, tmp_path: Path):
        args = build_parser().parse_args(
            [
                "attach",
                str(tmp_path / "missing.bin"),
                "1.0.0",
                str(tmp_path / "out.bin"),
            ]
        )
        with pytest.raises(FileNotFoundError):
            args.handler(args)

    def test_attach_directory_as_input(self, tmp_path: Path):
        args = build_parser().parse_args(
            ["attach", str(tmp_path), "1.0.0", str(tmp_path / "out.bin")]
        )
        with pytest.raises(ValueError, match="not a file"):
            args.handler(args)

    def test_attach_invalid_version_string(self, tmp_path: Path):
        f = tmp_path / "fw.bin"
        f.write_bytes(b"payload")
        args = build_parser().parse_args(
            ["attach", str(f), "abc", str(tmp_path / "out.bin")]
        )
        with pytest.raises(ValueError):
            args.handler(args)

    def test_attach_empty_version_string(self, tmp_path: Path):
        f = tmp_path / "fw.bin"
        f.write_bytes(b"payload")
        args = build_parser().parse_args(
            ["attach", str(f), "", str(tmp_path / "out.bin")]
        )
        with pytest.raises(ValueError):
            args.handler(args)

    def test_attach_version_out_of_range(self, tmp_path: Path):
        f = tmp_path / "fw.bin"
        f.write_bytes(b"payload")
        args = build_parser().parse_args(
            ["attach", str(f), "256.0.0", str(tmp_path / "out.bin")]
        )
        with pytest.raises(ValueError, match="major"):
            args.handler(args)

    def test_attach_invalid_header_size(self, tmp_path: Path):
        f = tmp_path / "fw.bin"
        f.write_bytes(b"payload")
        args = build_parser().parse_args(
            [
                "attach",
                str(f),
                "1.0.0",
                str(tmp_path / "out.bin"),
                "--header-size",
                "100",
            ]
        )
        with pytest.raises(ValueError, match="power of 2"):
            args.handler(args)

    def test_attach_header_size_too_small(self, tmp_path: Path):
        f = tmp_path / "fw.bin"
        f.write_bytes(b"payload")
        args = build_parser().parse_args(
            [
                "attach",
                str(f),
                "1.0.0",
                str(tmp_path / "out.bin"),
                "--header-size",
                "4",
            ]
        )
        with pytest.raises(ValueError, match="at least"):
            args.handler(args)

    # -- edit -----------------------------------------------------------------

    def test_edit_nonexistent_file(self, tmp_path: Path):
        args = build_parser().parse_args(
            ["edit", str(tmp_path / "missing.bin"), "1.0.0", str(tmp_path / "out.bin")]
        )
        with pytest.raises(FileNotFoundError):
            args.handler(args)

    def test_edit_directory_as_input(self, tmp_path: Path):
        args = build_parser().parse_args(
            ["edit", str(tmp_path), "1.0.0", str(tmp_path / "out.bin")]
        )
        with pytest.raises(ValueError, match="not a file"):
            args.handler(args)

    def test_edit_invalid_version_string(self, tmp_path: Path):
        f = tmp_path / "fw.bin"
        f.write_bytes(make_packaged_binary(b"payload"))
        args = build_parser().parse_args(
            ["edit", str(f), "not-a-version", str(tmp_path / "out.bin")]
        )
        with pytest.raises(ValueError):
            args.handler(args)

    def test_edit_invalid_header_size(self, tmp_path: Path):
        f = tmp_path / "fw.bin"
        f.write_bytes(make_packaged_binary(b"payload"))
        args = build_parser().parse_args(
            [
                "edit",
                str(f),
                "1.0.0",
                str(tmp_path / "out.bin"),
                "--header-size",
                "100",
            ]
        )
        with pytest.raises(ValueError, match="power of 2"):
            args.handler(args)

    # -- inspect --------------------------------------------------------------

    def test_inspect_nonexistent_file(self, tmp_path: Path):
        args = build_parser().parse_args(["inspect", str(tmp_path / "missing.bin")])
        with pytest.raises(FileNotFoundError):
            args.handler(args)

    def test_inspect_directory_as_input(self, tmp_path: Path):
        args = build_parser().parse_args(["inspect", str(tmp_path)])
        with pytest.raises(ValueError, match="not a file"):
            args.handler(args)

    # -- verify ---------------------------------------------------------------

    def test_verify_nonexistent_file(self, tmp_path: Path):
        args = build_parser().parse_args(
            ["verify", str(tmp_path / "missing.bin"), "--quiet"]
        )
        with pytest.raises(FileNotFoundError):
            args.handler(args)

    def test_verify_directory_as_input(self, tmp_path: Path):
        args = build_parser().parse_args(["verify", str(tmp_path), "--quiet"])
        with pytest.raises(ValueError, match="not a file"):
            args.handler(args)

    def test_verify_file_too_small(self, tmp_path: Path):
        f = tmp_path / "tiny.bin"
        f.write_bytes(b"\x00" * 5)
        args = build_parser().parse_args(
            ["verify", str(f), "--quiet", "--header-size", "16"]
        )
        with pytest.raises(ValueError, match="too small"):
            args.handler(args)


# ===========================================================================
# 21. User mistake scenarios
# ===========================================================================


class TestUserMistakeScenarios:
    """Tests for common user mistakes."""

    def test_attach_to_already_packaged_binary(self, tmp_path: Path):
        """Attaching to a packaged binary creates a double header.
        Verify should still pass on the outer layer."""
        payload = b"firmware"
        packaged = make_packaged_binary(payload)

        f = tmp_path / "packaged.bin"
        f.write_bytes(packaged)
        out = tmp_path / "double.bin"

        args = build_parser().parse_args(["attach", str(f), "2.0.0", str(out)])
        args.handler(args)

        data = out.read_bytes()
        result = verify_header(data, DEFAULT_HEADER_SIZE)
        assert result.ok is True
        # The "payload" now includes the original header + original payload
        assert result.payload_size == len(packaged)

    def test_edit_raw_binary_without_header(self, tmp_path: Path):
        """Editing a raw binary (no header) with explicit header size
        should still produce output, but the 'payload' will be truncated."""
        raw = tmp_path / "raw.bin"
        raw.write_bytes(b"\xaa" * 1024)
        out = tmp_path / "out.bin"

        args = build_parser().parse_args(
            ["edit", str(raw), "1.0.0", str(out), "--header-size", "512"]
        )
        args.handler(args)

        data = out.read_bytes()
        info = HeaderInfo.from_bytes(data)
        assert info.version == VersionInfo(1, 0, 0)
        # Payload is the part after the header_size bytes
        assert info.size == 512  # 1024 - 512

    def test_verify_raw_binary_without_header(self, tmp_path: Path):
        """Verifying a raw binary (wrong magic) should fail."""
        raw = tmp_path / "raw.bin"
        raw.write_bytes(b"\xaa" * 1024)

        args = build_parser().parse_args(
            ["verify", str(raw), "--quiet", "--header-size", "512"]
        )
        with pytest.raises(SystemExit) as exc_info:
            args.handler(args)
        assert exc_info.value.code == 1

    def test_inspect_raw_binary_without_header(self, tmp_path: Path):
        """Inspecting a raw binary (wrong magic) should raise."""
        raw = tmp_path / "raw.bin"
        raw.write_bytes(b"\xaa" * 1024)

        args = build_parser().parse_args(["inspect", str(raw)])
        with pytest.raises(ValueError, match="Invalid header magic"):
            args.handler(args)

    def test_double_edit_preserves_payload(self, tmp_path: Path):
        """Editing twice in succession preserves the original payload."""
        payload = b"original-firmware"
        packaged_v1 = tmp_path / "v1.bin"
        packaged_v2 = tmp_path / "v2.bin"
        packaged_v3 = tmp_path / "v3.bin"

        packaged_v1.write_bytes(make_packaged_binary(payload, "1.0.0"))

        args_v2 = build_parser().parse_args(
            ["edit", str(packaged_v1), "2.0.0", str(packaged_v2)]
        )
        args_v2.handler(args_v2)

        args_v3 = build_parser().parse_args(
            ["edit", str(packaged_v2), "3.0.0", str(packaged_v3)]
        )
        args_v3.handler(args_v3)

        v3_data = packaged_v3.read_bytes()
        assert v3_data[DEFAULT_HEADER_SIZE:] == payload
        info = HeaderInfo.from_bytes(v3_data)
        assert info.version == VersionInfo(3, 0, 0)

    def test_attach_then_edit_with_wrong_header_size(self, tmp_path: Path):
        """Editing with a wrong --header-size corrupts the output."""
        payload = b"firmware"
        packaged_path = tmp_path / "packaged.bin"
        packaged_path.write_bytes(make_packaged_binary(payload, header_size=512))

        out = tmp_path / "edited.bin"
        args = build_parser().parse_args(
            ["edit", str(packaged_path), "2.0.0", str(out), "--header-size", "256"]
        )
        args.handler(args)

        # Verification with correct header size should fail because
        # the edit used the wrong header size
        result = verify_header(out.read_bytes(), 512)
        assert result.ok is False


# ===========================================================================
# 22. Immutability and direct validation
# ===========================================================================


class TestVersionInfoImmutability:
    """Tests that VersionInfo is immutable (frozen dataclass)."""

    def test_cannot_set_major(self):
        v = VersionInfo(1, 2, 3)
        with pytest.raises(AttributeError):
            v.major = 99

    def test_cannot_set_minor(self):
        v = VersionInfo(1, 2, 3)
        with pytest.raises(AttributeError):
            v.minor = 99

    def test_cannot_set_patch(self):
        v = VersionInfo(1, 2, 3)
        with pytest.raises(AttributeError):
            v.patch = 99


class TestHeaderInfoImmutability:
    """Tests that HeaderInfo is immutable (frozen dataclass)."""

    def test_cannot_set_magic(self):
        payload = b"test"
        packaged = make_packaged_binary(payload)
        info = HeaderInfo.from_bytes(packaged)
        with pytest.raises(AttributeError):
            info.magic = b"BAD!"

    def test_cannot_set_version(self):
        payload = b"test"
        packaged = make_packaged_binary(payload)
        info = HeaderInfo.from_bytes(packaged)
        with pytest.raises(AttributeError):
            info.version = VersionInfo(9, 9, 9)

    def test_cannot_set_size(self):
        payload = b"test"
        packaged = make_packaged_binary(payload)
        info = HeaderInfo.from_bytes(packaged)
        with pytest.raises(AttributeError):
            info.size = 9999

    def test_cannot_set_crc(self):
        payload = b"test"
        packaged = make_packaged_binary(payload)
        info = HeaderInfo.from_bytes(packaged)
        with pytest.raises(AttributeError):
            info.crc = 0xDEADBEEF


class TestVersionInfoValidateDirect:
    """Tests for VersionInfo.validate() called directly."""

    def test_valid_version(self):
        VersionInfo(0, 0, 0).validate()
        VersionInfo(255, 255, 255).validate()
        VersionInfo(1, 2, 3).validate()

    def test_negative_major(self):
        v = VersionInfo(major=-1, minor=0, patch=0)
        with pytest.raises(ValueError, match="major"):
            v.validate()

    def test_negative_minor(self):
        v = VersionInfo(major=0, minor=-1, patch=0)
        with pytest.raises(ValueError, match="minor"):
            v.validate()

    def test_negative_patch(self):
        v = VersionInfo(major=0, minor=0, patch=-1)
        with pytest.raises(ValueError, match="patch"):
            v.validate()

    def test_major_too_large(self):
        v = VersionInfo(major=256, minor=0, patch=0)
        with pytest.raises(ValueError, match="major"):
            v.validate()

    def test_minor_too_large(self):
        v = VersionInfo(major=0, minor=999, patch=0)
        with pytest.raises(ValueError, match="minor"):
            v.validate()

    def test_patch_too_large(self):
        v = VersionInfo(major=0, minor=0, patch=300)
        with pytest.raises(ValueError, match="patch"):
            v.validate()

    def test_all_out_of_range(self):
        v = VersionInfo(major=1000, minor=1000, patch=1000)
        with pytest.raises(ValueError):
            v.validate()


# ===========================================================================
# 23. Flag combinations
# ===========================================================================


class TestFlagCombinations:
    """Tests for various CLI flag combinations."""

    def test_verify_json_and_quiet(self, tmp_path: Path, capsys):
        """--json and --quiet together: quiet should suppress output."""
        f = tmp_path / "fw.bin"
        f.write_bytes(make_packaged_binary(b"firmware"))

        args = build_parser().parse_args(["verify", str(f), "--json", "--quiet"])
        with pytest.raises(SystemExit) as exc_info:
            args.handler(args)

        assert exc_info.value.code == 0
        captured = capsys.readouterr()
        assert captured.out == ""

    def test_edit_in_place_with_explicit_header_size(self, tmp_path: Path):
        payload = b"firmware"
        f = tmp_path / "fw.bin"
        f.write_bytes(make_packaged_binary(payload, header_size=256))

        args = build_parser().parse_args(
            ["edit", str(f), "2.0.0", "--in-place", "--header-size", "256"]
        )
        args.handler(args)

        data = f.read_bytes()
        info = HeaderInfo.from_bytes(data)
        assert info.version == VersionInfo(2, 0, 0)
        assert data[256:] == payload

    def test_attach_in_place_uses_default_header_size(self, tmp_path: Path):
        payload = b"firmware"
        f = tmp_path / "fw.bin"
        f.write_bytes(payload)

        args = build_parser().parse_args(["attach", str(f), "1.0.0", "--in-place"])
        args.handler(args)

        data = f.read_bytes()
        assert len(data) == DEFAULT_HEADER_SIZE + len(payload)
        result = verify_header(data, DEFAULT_HEADER_SIZE)
        assert result.ok is True

    def test_verify_json_output_on_failure(self, tmp_path: Path, capsys):
        packaged = make_packaged_binary(b"firmware")
        corrupted = corrupt_byte(packaged, len(packaged) - 1)
        f = tmp_path / "bad.bin"
        f.write_bytes(corrupted)

        args = build_parser().parse_args(["verify", str(f), "--json"])
        with pytest.raises(SystemExit) as exc_info:
            args.handler(args)

        assert exc_info.value.code == 1
        data = json.loads(capsys.readouterr().out)
        assert data["ok"] is False
        assert data["crc_ok"] is False


# ===========================================================================
# 24. Property-based testing with Hypothesis
# ===========================================================================


class TestPropertyBased:
    """Property-based tests using Hypothesis."""

    @given(payload=st.binary(min_size=1, max_size=50_000))
    @settings(max_examples=50)
    def test_attach_verify_roundtrip_any_payload(self, payload: bytes):
        """Any non-empty payload should produce a valid packaged binary."""
        packaged = make_packaged_binary(payload)
        result = verify_header(packaged, DEFAULT_HEADER_SIZE)
        assert result.ok is True
        assert result.payload_size == len(payload)
        assert result.payload_crc == Crc32Mpeg2.calc(payload)

    @given(
        major=st.integers(0, 255),
        minor=st.integers(0, 255),
        patch=st.integers(0, 255),
    )
    @settings(max_examples=100)
    def test_version_bytes_roundtrip(self, major: int, minor: int, patch: int):
        """Any valid version should survive a to_bytes/from_bytes roundtrip."""
        v = VersionInfo(major, minor, patch)
        restored = VersionInfo.from_bytes(v.to_bytes())
        assert restored == v

    @given(
        major=st.integers(0, 255),
        minor=st.integers(0, 255),
        patch=st.integers(0, 255),
    )
    @settings(max_examples=100)
    def test_version_string_roundtrip(self, major: int, minor: int, patch: int):
        """Any valid version should survive a str/from_string roundtrip."""
        v = VersionInfo(major, minor, patch)
        restored = VersionInfo.from_string(str(v))
        assert restored == v

    @given(payload=st.binary(min_size=1, max_size=50_000))
    @settings(max_examples=50)
    def test_build_parse_roundtrip(self, payload: bytes):
        """Building a header and parsing it back should match."""
        version = VersionInfo(1, 2, 3)
        header = build_header(payload, version, DEFAULT_HEADER_SIZE)
        info = HeaderInfo.from_bytes(header)

        assert info.magic == HEADER_MAGIC
        assert info.version == version
        assert info.size == len(payload)
        assert info.crc == Crc32Mpeg2.calc(payload)

    @given(
        payload=st.binary(min_size=1, max_size=10_000),
        header_size_exp=st.integers(min_value=4, max_value=12),
    )
    @settings(max_examples=50)
    def test_infer_header_size_roundtrip(self, payload: bytes, header_size_exp: int):
        """Inferred header size should match the one used to build."""
        header_size = 2**header_size_exp
        packaged = make_packaged_binary(payload, header_size=header_size)
        assert infer_header_size(packaged) == header_size

    @given(payload=st.binary(min_size=1, max_size=10_000))
    @settings(max_examples=50)
    def test_split_recovers_payload(self, payload: bytes):
        """Splitting a packaged binary should recover the original payload."""
        packaged = make_packaged_binary(payload)
        _, extracted = split_payload_from_packaged(packaged, DEFAULT_HEADER_SIZE)
        assert extracted == payload

    @given(
        payload=st.binary(min_size=1, max_size=10_000),
        flip_offset=st.integers(min_value=0),
    )
    @settings(max_examples=50)
    def test_any_payload_corruption_detected(self, payload: bytes, flip_offset: int):
        """Flipping any byte in the payload should be detected by CRC."""
        packaged = make_packaged_binary(payload)
        # Constrain offset to be within payload region
        payload_start = DEFAULT_HEADER_SIZE
        actual_offset = payload_start + (flip_offset % len(payload))
        corrupted = corrupt_byte(packaged, actual_offset)
        result = verify_header(corrupted, DEFAULT_HEADER_SIZE)
        assert result.crc_ok is False
        assert result.ok is False

    @given(
        version_str=st.from_regex(r"[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}", fullmatch=True)
    )
    @settings(max_examples=100)
    def test_version_from_string_never_crashes(self, version_str: str):
        """Parsing a well-formed version string should not crash
        (it may raise ValueError for out-of-range values)."""
        try:
            v = VersionInfo.from_string(version_str)
            assert 0 <= v.major <= 255
            assert 0 <= v.minor <= 255
            assert 0 <= v.patch <= 255
        except ValueError:
            pass  # Expected for out-of-range values like "999.999.999"


# ===========================================================================
# 25. Permission / OS-level error tests
# ===========================================================================


class TestPermissionErrors:
    """Tests for permission and OS-level errors."""

    @pytest.mark.skipif(
        os.name == "nt", reason="POSIX permissions not applicable on Windows"
    )
    def test_write_to_readonly_directory(self, tmp_path: Path):
        readonly_dir = tmp_path / "readonly"
        readonly_dir.mkdir()
        readonly_dir.chmod(0o444)

        try:
            with pytest.raises(PermissionError):
                write_binary(readonly_dir / "out.bin", b"data")
        finally:
            readonly_dir.chmod(0o755)

    @pytest.mark.skipif(
        os.name == "nt", reason="POSIX permissions not applicable on Windows"
    )
    def test_read_unreadable_file(self, tmp_path: Path):
        f = tmp_path / "secret.bin"
        f.write_bytes(b"data")
        f.chmod(0o000)

        try:
            with pytest.raises(PermissionError):
                read_binary(f)
        finally:
            f.chmod(0o644)

    @pytest.mark.skipif(
        os.name == "nt", reason="POSIX permissions not applicable on Windows"
    )
    def test_write_binary_in_place_readonly_directory(self, tmp_path: Path):
        readonly_dir = tmp_path / "readonly"
        readonly_dir.mkdir()
        f = readonly_dir / "fw.bin"
        f.write_bytes(b"original")
        readonly_dir.chmod(0o444)

        try:
            with pytest.raises(PermissionError):
                write_binary_in_place(f, b"new-data")
            # Original should be untouched
            readonly_dir.chmod(0o755)
            assert f.read_bytes() == b"original"
        finally:
            readonly_dir.chmod(0o755)


# ===========================================================================
# 26. Text output format verification for failure cases
# ===========================================================================


class TestTextOutputFormat:
    """Tests for text output formatting in various scenarios."""

    def test_verify_text_shows_fail_for_bad_crc(self, tmp_path: Path, capsys):
        packaged = make_packaged_binary(b"firmware")
        corrupted = corrupt_byte(packaged, len(packaged) - 1)
        path = tmp_path / "bad.bin"
        path.write_bytes(corrupted)

        args = build_parser().parse_args(["verify", str(path)])
        with pytest.raises(SystemExit):
            args.handler(args)

        output = capsys.readouterr().out
        assert "FAIL" in output
        assert "crc32:" in output or "crc" in output.lower()

    def test_verify_text_shows_fail_for_bad_magic(self, tmp_path: Path, capsys):
        packaged = bytearray(make_packaged_binary(b"firmware"))
        packaged[:4] = b"BAD!"
        path = tmp_path / "bad.bin"
        path.write_bytes(bytes(packaged))

        args = build_parser().parse_args(["verify", str(path)])
        with pytest.raises(SystemExit):
            args.handler(args)

        output = capsys.readouterr().out
        assert "FAIL" in output

    def test_verify_text_shows_fail_for_bad_size(self, tmp_path: Path, capsys):
        payload = b"firmware"
        packaged = bytearray(make_packaged_binary(payload))
        packaged[8:12] = struct.pack("<I", len(payload) + 999)
        path = tmp_path / "bad.bin"
        path.write_bytes(bytes(packaged))

        args = build_parser().parse_args(
            ["verify", str(path), "--header-size", str(DEFAULT_HEADER_SIZE)]
        )
        with pytest.raises(SystemExit):
            args.handler(args)

        output = capsys.readouterr().out
        assert "FAIL" in output
        assert "size" in output.lower()

    def test_verify_text_shows_ok_for_valid(self, tmp_path: Path, capsys):
        path = tmp_path / "good.bin"
        path.write_bytes(make_packaged_binary(b"firmware"))

        args = build_parser().parse_args(["verify", str(path)])
        with pytest.raises(SystemExit):
            args.handler(args)

        output = capsys.readouterr().out
        assert "verification:  OK" in output

    def test_verify_text_shows_verification_fail(self, tmp_path: Path, capsys):
        packaged = make_packaged_binary(b"firmware")
        corrupted = corrupt_byte(packaged, len(packaged) - 1)
        path = tmp_path / "bad.bin"
        path.write_bytes(corrupted)

        args = build_parser().parse_args(["verify", str(path)])
        with pytest.raises(SystemExit):
            args.handler(args)

        output = capsys.readouterr().out
        assert "verification:  FAIL" in output

    def test_inspect_text_shows_all_fields(self, tmp_path: Path, capsys):
        payload = b"firmware"
        path = tmp_path / "fw.bin"
        path.write_bytes(make_packaged_binary(payload, version="5.6.7"))

        args = build_parser().parse_args(["inspect", str(path)])
        args.handler(args)

        output = capsys.readouterr().out
        assert "magic:" in output
        assert "XLAB" in output
        assert "version:" in output
        assert "5.6.7" in output
        assert "size:" in output
        assert str(len(payload)) in output
        assert "crc32:" in output
        assert "0x" in output

    def test_verify_text_shows_actual_and_header_crc(self, tmp_path: Path, capsys):
        payload = b"firmware"
        packaged = make_packaged_binary(payload)
        corrupted = corrupt_byte(packaged, len(packaged) - 1)
        path = tmp_path / "bad.bin"
        path.write_bytes(corrupted)

        args = build_parser().parse_args(["verify", str(path)])
        with pytest.raises(SystemExit):
            args.handler(args)

        output = capsys.readouterr().out
        # Should show both stored and computed CRC
        assert "header=0x" in output
        assert "actual=0x" in output

    def test_verify_text_shows_actual_and_header_size(self, tmp_path: Path, capsys):
        payload = b"firmware"
        packaged = bytearray(make_packaged_binary(payload))
        packaged[8:12] = struct.pack("<I", len(payload) + 1)
        path = tmp_path / "bad.bin"
        path.write_bytes(bytes(packaged))

        args = build_parser().parse_args(
            ["verify", str(path), "--header-size", str(DEFAULT_HEADER_SIZE)]
        )
        with pytest.raises(SystemExit):
            args.handler(args)

        output = capsys.readouterr().out
        assert f"header={len(payload) + 1}" in output
        assert f"actual={len(payload)}" in output


# ===========================================================================
# 27. main() entry point
# ===========================================================================


class TestMain:
    """Tests for the main() entry point."""

    def test_main_attach(self, tmp_path: Path, monkeypatch):
        f = tmp_path / "fw.bin"
        f.write_bytes(b"payload")
        out = tmp_path / "out.bin"

        monkeypatch.setattr(
            "sys.argv",
            ["fwtool", "attach", str(f), "1.0.0", str(out)],
        )
        main()
        assert out.exists()
        result = verify_header(out.read_bytes(), DEFAULT_HEADER_SIZE)
        assert result.ok is True

    def test_main_inspect(self, tmp_path: Path, monkeypatch, capsys):
        f = tmp_path / "fw.bin"
        f.write_bytes(make_packaged_binary(b"payload", version="3.2.1"))

        monkeypatch.setattr(
            "sys.argv",
            ["fwtool", "inspect", str(f)],
        )
        main()
        output = capsys.readouterr().out
        assert "3.2.1" in output

    def test_main_verify_success(self, tmp_path: Path, monkeypatch):
        f = tmp_path / "fw.bin"
        f.write_bytes(make_packaged_binary(b"payload"))

        monkeypatch.setattr(
            "sys.argv",
            ["fwtool", "verify", str(f), "--quiet"],
        )
        with pytest.raises(SystemExit) as exc_info:
            main()
        assert exc_info.value.code == 0

    def test_main_verify_failure(self, tmp_path: Path, monkeypatch):
        packaged = make_packaged_binary(b"payload")
        corrupted = corrupt_byte(packaged, len(packaged) - 1)
        f = tmp_path / "fw.bin"
        f.write_bytes(corrupted)

        monkeypatch.setattr(
            "sys.argv",
            ["fwtool", "verify", str(f), "--quiet"],
        )
        with pytest.raises(SystemExit) as exc_info:
            main()
        assert exc_info.value.code == 1

    def test_main_no_args(self, monkeypatch):
        monkeypatch.setattr("sys.argv", ["fwtool"])
        with pytest.raises(SystemExit) as exc_info:
            main()
        assert exc_info.value.code != 0

    def test_main_edit(self, tmp_path: Path, monkeypatch):
        payload = b"firmware"
        f = tmp_path / "fw.bin"
        f.write_bytes(make_packaged_binary(payload, version="1.0.0"))
        out = tmp_path / "edited.bin"

        monkeypatch.setattr(
            "sys.argv",
            ["fwtool", "edit", str(f), "2.0.0", str(out)],
        )
        main()

        data = out.read_bytes()
        info = HeaderInfo.from_bytes(data)
        assert info.version == VersionInfo(2, 0, 0)
        assert data[DEFAULT_HEADER_SIZE:] == payload


# ===========================================================================
# 28. VerificationResult immutability
# ===========================================================================


class TestVerificationResultImmutability:
    """Tests that VerificationResult is immutable (frozen dataclass)."""

    def _make_result(self) -> VerificationResult:
        payload = b"firmware"
        packaged = make_packaged_binary(payload)
        return verify_header(packaged, DEFAULT_HEADER_SIZE)

    def test_cannot_set_magic_ok(self):
        result = self._make_result()
        with pytest.raises(AttributeError):
            result.magic_ok = False

    def test_cannot_set_size_ok(self):
        result = self._make_result()
        with pytest.raises(AttributeError):
            result.size_ok = False

    def test_cannot_set_crc_ok(self):
        result = self._make_result()
        with pytest.raises(AttributeError):
            result.crc_ok = False

    def test_cannot_set_header(self):
        result = self._make_result()
        with pytest.raises(AttributeError):
            result.header = None

    def test_cannot_set_payload_size(self):
        result = self._make_result()
        with pytest.raises(AttributeError):
            result.payload_size = 9999

    def test_cannot_set_payload_crc(self):
        result = self._make_result()
        with pytest.raises(AttributeError):
            result.payload_crc = 0


# ===========================================================================
# 29. Edge cases for header size at boundary
# ===========================================================================


class TestHeaderSizeBoundary:
    """Tests for header size at exact boundaries."""

    def test_header_size_exactly_header_info_size(self):
        """Header size == HEADER_INFO_SIZE means zero padding."""
        payload = b"data"
        header = build_header(payload, VersionInfo(1, 0, 0), HEADER_INFO_SIZE)
        assert len(header) == HEADER_INFO_SIZE
        # The entire header is info, no padding bytes
        info = HeaderInfo.from_bytes(header)
        assert info.magic == HEADER_MAGIC

    def test_verify_with_minimum_header_size(self):
        payload = b"firmware"
        packaged = make_packaged_binary(payload, header_size=HEADER_INFO_SIZE)
        result = verify_header(packaged, HEADER_INFO_SIZE)
        assert result.ok is True

    def test_very_large_header_size(self):
        """A very large header size (e.g., 65536) should still work."""
        header_size = 65536
        payload = b"firmware"
        packaged = make_packaged_binary(payload, header_size=header_size)
        assert len(packaged) == header_size + len(payload)
        result = verify_header(packaged, header_size)
        assert result.ok is True

    def test_header_larger_than_payload(self):
        """Header can be much larger than the payload."""
        header_size = 4096
        payload = b"x"
        packaged = make_packaged_binary(payload, header_size=header_size)
        result = verify_header(packaged, header_size)
        assert result.ok is True
        assert result.payload_size == 1


# ===========================================================================
# 30. JSON serialization edge cases
# ===========================================================================


class TestJsonSerialization:
    """Tests for JSON output edge cases."""

    def test_verify_json_is_valid_json(self, tmp_path: Path, capsys):
        path = tmp_path / "fw.bin"
        path.write_bytes(make_packaged_binary(b"firmware"))

        args = build_parser().parse_args(["verify", str(path), "--json"])
        with pytest.raises(SystemExit):
            args.handler(args)

        output = capsys.readouterr().out
        data = json.loads(output)  # Should not raise
        assert isinstance(data, dict)

    def test_inspect_json_is_valid_json(self, tmp_path: Path, capsys):
        path = tmp_path / "fw.bin"
        path.write_bytes(make_packaged_binary(b"firmware"))

        args = build_parser().parse_args(["inspect", str(path), "--json"])
        args.handler(args)

        output = capsys.readouterr().out
        data = json.loads(output)  # Should not raise
        assert isinstance(data, dict)

    def test_verify_json_failure_contains_payload_info(self, tmp_path: Path, capsys):
        packaged = make_packaged_binary(b"firmware")
        corrupted = corrupt_byte(packaged, len(packaged) - 1)
        path = tmp_path / "bad.bin"
        path.write_bytes(corrupted)

        args = build_parser().parse_args(["verify", str(path), "--json"])
        with pytest.raises(SystemExit):
            args.handler(args)

        data = json.loads(capsys.readouterr().out)
        assert "payload" in data
        assert "size" in data["payload"]
        assert "crc" in data["payload"]
        assert data["payload"]["crc"]["hex"].startswith("0x")

    def test_inspect_json_version_has_all_fields(self, tmp_path: Path, capsys):
        path = tmp_path / "fw.bin"
        path.write_bytes(make_packaged_binary(b"data", version="10.20.30"))

        args = build_parser().parse_args(["inspect", str(path), "--json"])
        args.handler(args)

        data = json.loads(capsys.readouterr().out)
        v = data["version"]
        assert v["major"] == 10
        assert v["minor"] == 20
        assert v["patch"] == 30
        assert v["string"] == "10.20.30"

    def test_header_info_to_dict_json_serializable(self):
        """HeaderInfo.to_dict() output should be JSON-serializable."""
        payload = b"test"
        packaged = make_packaged_binary(payload)
        info = HeaderInfo.from_bytes(packaged)
        serialized = json.dumps(info.to_dict())  # Should not raise
        assert isinstance(serialized, str)

    def test_verification_result_to_dict_json_serializable(self):
        """VerificationResult.to_dict() output should be JSON-serializable."""
        payload = b"test"
        packaged = make_packaged_binary(payload)
        result = verify_header(packaged, DEFAULT_HEADER_SIZE)
        serialized = json.dumps(result.to_dict())  # Should not raise
        assert isinstance(serialized, str)

    def test_version_info_to_dict_json_serializable(self):
        """VersionInfo.to_dict() output should be JSON-serializable."""
        v = VersionInfo(1, 2, 3)
        serialized = json.dumps(v.to_dict())  # Should not raise
        assert isinstance(serialized, str)
