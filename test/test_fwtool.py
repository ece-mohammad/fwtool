"""
Pytest test suite for the firmware header utility.

These tests cover:
- version parsing and packing
- header construction
- header parsing
- header verification
- binary splitting for attach/edit modes
- file writing helpers
- CLI argument validation

Adjust the import below to match the filename of the script under test.
For example, if the script is saved as `main.py`, keep `import main as fwtool`.
If it is saved as `fw_header.py`, change it to `import fw_header as fwtool`.
"""

import struct
from pathlib import Path

import pytest
from crccheck.crc import Crc32Mpeg2

from fwtool import cli as fwtool


def make_packaged_binary(payload: bytes, version: str = "1.2.3") -> bytes:
    """Create a packaged binary [header][payload] for tests."""
    version_info = fwtool.VersionInfo.from_string(version)
    header = fwtool.build_header(payload, version_info)
    return header + payload


def test_version_from_string_full():
    version = fwtool.VersionInfo.from_string("1.2.3")
    assert version.major == 1
    assert version.minor == 2
    assert version.patch == 3


def test_version_from_string_partial_one_component():
    version = fwtool.VersionInfo.from_string("7")
    assert version == fwtool.VersionInfo(7, 0, 0)


def test_version_from_string_partial_two_components():
    version = fwtool.VersionInfo.from_string("7.8")
    assert version == fwtool.VersionInfo(7, 8, 0)


def test_version_from_string_truncates_extra_components():
    version = fwtool.VersionInfo.from_string("1.2.3.4")
    assert version == fwtool.VersionInfo(1, 2, 3)


def test_version_validate_rejects_large_values():
    with pytest.raises(ValueError, match="major must be in range 0..255"):
        fwtool.VersionInfo.from_string("256.2.3")


def test_version_to_bytes():
    version = fwtool.VersionInfo(major=1, minor=2, patch=3)
    assert version.to_bytes() == b"\x00\x03\x02\x01"


def test_version_from_bytes():
    version = fwtool.VersionInfo.from_bytes(b"\x00\x03\x02\x01")
    assert version == fwtool.VersionInfo(1, 2, 3)


def test_build_header_layout():
    payload = b"abc123"
    version = fwtool.VersionInfo(1, 2, 3)

    header = fwtool.build_header(payload, version)

    assert len(header) == fwtool.HEADER_SIZE
    assert header[:4] == fwtool.HEADER_MAGIC
    assert header[4:8] == b"\x00\x03\x02\x01"
    assert header[8:12] == struct.pack("<I", len(payload))
    assert header[12:16] == struct.pack("<I", Crc32Mpeg2.calc(payload))
    assert header[16:] == b"\xff" * (fwtool.HEADER_SIZE - 16)


def test_parse_header_extracts_expected_fields():
    payload = b"\x01\x02\x03\x04"
    packaged = make_packaged_binary(payload, version="1.2.3")

    info = fwtool.parse_header(packaged)

    assert info.magic == b"XLAB"
    assert info.version == fwtool.VersionInfo(1, 2, 3)
    assert info.size == len(payload)
    assert info.crc == Crc32Mpeg2.calc(payload)


def test_parse_header_rejects_small_input():
    with pytest.raises(ValueError, match="too small to contain a header"):
        fwtool.parse_header(b"\x00" * 10)


def test_parse_header_rejects_invalid_magic():
    bad = bytearray(b"\x00" * fwtool.HEADER_SIZE)
    bad[:4] = b"ABCD"

    with pytest.raises(ValueError, match="Invalid header magic"):
        fwtool.parse_header(bytes(bad))


def test_verify_header_success():
    payload = b"firmware-data"
    packaged = make_packaged_binary(payload, version="1.2.3")

    result = fwtool.verify_header(packaged)

    assert result.ok is True
    assert result.magic_ok is True
    assert result.size_ok is True
    assert result.crc_ok is True
    assert result.payload_size == len(payload)
    assert result.payload_crc == Crc32Mpeg2.calc(payload)


def test_verify_header_detects_bad_crc():
    payload = b"firmware-data"
    packaged = bytearray(make_packaged_binary(payload, version="1.2.3"))

    packaged[-1] ^= 0xFF

    result = fwtool.verify_header(bytes(packaged))

    assert result.magic_ok is True
    assert result.size_ok is True
    assert result.crc_ok is False
    assert result.ok is False


def test_verify_header_detects_bad_size():
    payload = b"firmware-data"
    packaged = bytearray(make_packaged_binary(payload, version="1.2.3"))

    wrong_size = len(payload) + 1
    packaged[8:12] = struct.pack("<I", wrong_size)

    result = fwtool.verify_header(bytes(packaged))

    assert result.magic_ok is True
    assert result.size_ok is False
    assert result.crc_ok is True
    assert result.ok is False


def test_verify_header_detects_bad_magic():
    payload = b"firmware-data"
    packaged = bytearray(make_packaged_binary(payload, version="1.2.3"))
    packaged[:4] = b"BAD!"

    result = fwtool.verify_header(bytes(packaged))

    assert result.magic_ok is False
    assert result.ok is False


def test_split_binary_attach_mode():
    payload = b"raw-binary"
    header, extracted_payload = fwtool.split_binary(payload, "attach")

    assert header == b""
    assert extracted_payload == payload


def test_split_binary_edit_mode():
    payload = b"raw-binary"
    packaged = make_packaged_binary(payload, version="1.2.3")

    header, extracted_payload = fwtool.split_binary(packaged, "edit")

    assert len(header) == fwtool.HEADER_SIZE
    assert header[:4] == b"XLAB"
    assert extracted_payload == payload


def test_split_binary_edit_mode_rejects_small_input():
    with pytest.raises(ValueError, match="too small for edit mode"):
        fwtool.split_binary(b"\x00" * 100, "edit")


def test_split_binary_edit_mode_rejects_invalid_magic():
    bad = b"BAD!" + b"\x00" * (fwtool.HEADER_SIZE - 4) + b"payload"

    with pytest.raises(ValueError, match="does not appear to contain a valid header"):
        fwtool.split_binary(bad, "edit")


def test_write_binary(tmp_path: Path):
    out = tmp_path / "out.bin"
    data = b"hello"

    fwtool.write_binary(out, data)

    assert out.read_bytes() == data


def test_write_binary_in_place(tmp_path: Path):
    path = tmp_path / "firmware.bin"
    path.write_bytes(b"old-data")

    fwtool.write_binary_in_place(path, b"new-data")

    assert path.read_bytes() == b"new-data"


def test_validate_input_file_missing(tmp_path: Path):
    missing = tmp_path / "missing.bin"
    with pytest.raises(FileNotFoundError):
        fwtool.validate_input_file(missing)


def test_validate_input_file_not_a_file(tmp_path: Path):
    with pytest.raises(ValueError, match="not a file"):
        fwtool.validate_input_file(tmp_path)


def test_header_info_to_dict():
    payload = b"abc"
    packaged = make_packaged_binary(payload, version="1.2.3")
    info = fwtool.parse_header(packaged)

    data = info.to_dict()

    assert data["magic_ascii"] == "XLAB"
    assert data["magic_hex"] == "584c4142"
    assert data["version"]["string"] == "1.2.3"
    assert data["size"] == 3
    assert data["crc"]["hex"].startswith("0x")


def test_verification_result_to_dict():
    payload = b"abc"
    packaged = make_packaged_binary(payload, version="1.2.3")
    result = fwtool.verify_header(packaged)

    data = result.to_dict()

    assert data["ok"] is True
    assert data["magic_ok"] is True
    assert data["size_ok"] is True
    assert data["crc_ok"] is True
    assert data["header"]["magic_ascii"] == "XLAB"
    assert data["payload"]["size"] == len(payload)


def test_validate_args_print_header_mode():
    parser = fwtool.build_parser()
    args = parser.parse_args(["input.bin", "--print-header"])
    fwtool.validate_args(args)


def test_validate_args_verify_header_mode():
    parser = fwtool.build_parser()
    args = parser.parse_args(["input.bin", "--verify-header"])
    fwtool.validate_args(args)


def test_validate_args_json_without_special_mode_fails():
    parser = fwtool.build_parser()
    args = parser.parse_args(["input.bin", "1.2.3", "out.bin", "--json"])

    with pytest.raises(ValueError, match="--json may only be used"):
        fwtool.validate_args(args)


def test_validate_args_quiet_without_verify_fails():
    parser = fwtool.build_parser()
    args = parser.parse_args(["input.bin", "1.2.3", "out.bin", "--quiet"])

    with pytest.raises(ValueError, match="--quiet may only be used"):
        fwtool.validate_args(args)


def test_validate_args_quiet_and_json_together_fail():
    parser = fwtool.build_parser()
    args = parser.parse_args(["input.bin", "--verify-header", "--quiet", "--json"])

    with pytest.raises(ValueError, match="--quiet and --json cannot be used together"):
        fwtool.validate_args(args)


def test_validate_args_in_place_without_output_ok():
    parser = fwtool.build_parser()
    args = parser.parse_args(["input.bin", "1.2.3", "--in-place"])
    fwtool.validate_args(args)


def test_validate_args_missing_output_without_in_place_fails():
    parser = fwtool.build_parser()
    args = parser.parse_args(["input.bin", "1.2.3"])

    with pytest.raises(ValueError, match="output argument is required"):
        fwtool.validate_args(args)


def test_attach_like_flow_produces_expected_packaged_binary():
    payload = b"\x11\x22\x33\x44"
    version = fwtool.VersionInfo.from_string("2.5.7")

    header = fwtool.build_header(payload, version)
    packaged = header + payload

    info = fwtool.parse_header(packaged)

    assert packaged[fwtool.HEADER_SIZE :] == payload
    assert info.version == fwtool.VersionInfo(2, 5, 7)
    assert info.size == len(payload)
    assert info.crc == Crc32Mpeg2.calc(payload)


def test_edit_like_flow_replaces_header_but_preserves_payload():
    payload = b"\xaa\xbb\xcc\xdd"
    old_packaged = make_packaged_binary(payload, version="1.0.0")

    _, extracted_payload = fwtool.split_binary(old_packaged, "edit")
    new_header = fwtool.build_header(
        extracted_payload, fwtool.VersionInfo.from_string("2.0.0")
    )
    new_packaged = new_header + extracted_payload

    old_info = fwtool.parse_header(old_packaged)
    new_info = fwtool.parse_header(new_packaged)

    assert old_packaged[fwtool.HEADER_SIZE :] == new_packaged[fwtool.HEADER_SIZE :]
    assert old_info.version == fwtool.VersionInfo(1, 0, 0)
    assert new_info.version == fwtool.VersionInfo(2, 0, 0)
    assert new_info.size == len(payload)
    assert new_info.crc == Crc32Mpeg2.calc(payload)
