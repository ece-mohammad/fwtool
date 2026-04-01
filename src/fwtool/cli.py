#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Firmware header utility.

A command-line interface for working with a custom firmware header
placed at the beginning of a binary image.

Header format
-------------
The header is 256 bytes long and has the following layout:

    0x00..0x03   magic:   b"XLAB"
    0x04..0x07   version: little-endian bytes [0x00, patch, minor, major]
    0x08..0x0B   size:    payload size in bytes, little-endian uint32
    0x0C..0x0F   crc32:   CRC-32/MPEG-2 of payload, little-endian uint32
    0x10..0xFF   padding: 0xFF

Supported operations
--------------------
- attach a new header to a raw firmware binary
- edit/replace the header of an already packaged binary
- print header contents
- verify header magic, payload size, and payload CRC

Examples
--------
Attach a header to a raw firmware binary:
    python main.py firmware.bin 1.2.3 out.bin --mode attach

Replace an existing header:
    python main.py packaged.bin 1.2.4 out.bin --mode edit

Replace an existing header in place:
    python main.py packaged.bin 1.2.4 --mode edit --in-place

Print header information:
    python main.py packaged.bin --print-header

Print header information as JSON:
    python main.py packaged.bin --print-header --json

Verify header:
    python main.py packaged.bin --verify-header

Verify header quietly using only the exit code:
    python main.py packaged.bin --verify-header --quiet
"""

import argparse
import json
import os
import struct
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Final

from crccheck.crc import Crc32Mpeg2


HEADER_MAGIC: Final[bytes] = b"XLAB"
HEADER_SIZE: Final[int] = 256
HEADER_INFO_SIZE: Final[int] = 16
HEADER_PADDING_SIZE: Final[int] = HEADER_SIZE - HEADER_INFO_SIZE
HEADER_PADDING: Final[bytes] = b"\xff" * HEADER_PADDING_SIZE


@dataclass(frozen=True)
class VersionInfo:
    """Semantic firmware version stored as major.minor.patch."""

    major: int = 0
    minor: int = 0
    patch: int = 0

    @classmethod
    def from_string(cls, value: str) -> "VersionInfo":
        """
        Parse a version string into a VersionInfo instance.

        Accepted formats include:
            "1"
            "1.2"
            "1.2.3"

        Missing components are padded with zero. Extra components are ignored.

        Args:
            value: Version string.

        Returns:
            Parsed VersionInfo object.

        Raises:
            ValueError: If version components are out of range or not integers.
        """
        parts = [int(part) for part in value.strip().split(".") if part]

        if len(parts) > 3:
            parts = parts[:3]

        while len(parts) < 3:
            parts.append(0)

        version = cls(*parts)
        version.validate()
        return version

    @classmethod
    def from_bytes(cls, data: bytes) -> "VersionInfo":
        """
        Parse the 4-byte packed version field from the binary header.

        The byte layout is:
            [0x00, patch, minor, major]

        Args:
            data: 4-byte version field.

        Returns:
            Parsed VersionInfo object.

        Raises:
            ValueError: If the input length is not 4 bytes.
        """
        if len(data) != 4:
            raise ValueError(f"Version field must be 4 bytes, got {len(data)}")
        unused, patch, minor, major = data
        _ = unused
        return cls(major=major, minor=minor, patch=patch)

    def validate(self) -> None:
        """
        Validate that all version components fit in one byte.

        Raises:
            ValueError: If major, minor, or patch is outside the range 0..255.
        """
        for name, part in (
            ("major", self.major),
            ("minor", self.minor),
            ("patch", self.patch),
        ):
            if not 0 <= part <= 255:
                raise ValueError(f"{name} must be in range 0..255, got {part}")

    def to_bytes(self) -> bytes:
        """
        Convert the version into the 4-byte packed header representation.

        Returns:
            Packed version bytes as [0x00, patch, minor, major].
        """
        return bytes((0x00, self.patch, self.minor, self.major))

    def to_dict(self) -> dict:
        """
        Convert the version into a JSON-friendly dictionary.

        Returns:
            Dictionary representation of the version.
        """
        return {
            "major": self.major,
            "minor": self.minor,
            "patch": self.patch,
            "string": str(self),
        }

    def __str__(self) -> str:
        """
        Format the version as a dotted string.

        Returns:
            Version string in major.minor.patch format.
        """
        return f"{self.major}.{self.minor}.{self.patch}"


@dataclass(frozen=True)
class HeaderInfo:
    """Parsed header fields extracted from a packaged firmware binary."""

    magic: bytes
    version: VersionInfo
    size: int
    crc: int

    @classmethod
    def from_bytes(cls, data: bytes) -> "HeaderInfo":
        """
        Parse a header from the first HEADER_SIZE bytes of a binary blob.

        Args:
            data: Byte buffer containing at least one full header.

        Returns:
            Parsed HeaderInfo object.

        Raises:
            ValueError: If fewer than HEADER_SIZE bytes are provided.
        """
        if len(data) < HEADER_SIZE:
            raise ValueError(
                f"Header requires at least {HEADER_SIZE} bytes, got {len(data)}"
            )

        magic = data[0:4]
        version = VersionInfo.from_bytes(data[4:8])
        size = struct.unpack("<I", data[8:12])[0]
        crc = struct.unpack("<I", data[12:16])[0]

        return cls(
            magic=magic,
            version=version,
            size=size,
            crc=crc,
        )

    def to_dict(self) -> dict:
        """
        Convert the header to a JSON-friendly dictionary.

        Returns:
            Dictionary representation of the header.
        """
        return {
            "magic_ascii": self.magic.decode("ascii", errors="replace"),
            "magic_hex": self.magic.hex(),
            "version": self.version.to_dict(),
            "size": self.size,
            "crc": {
                "int": self.crc,
                "hex": f"0x{self.crc:08x}",
            },
        }


@dataclass(frozen=True)
class VerificationResult:
    """Verification outcome for an existing packaged firmware binary."""

    magic_ok: bool
    size_ok: bool
    crc_ok: bool
    header: HeaderInfo
    payload_size: int
    payload_crc: int

    @property
    def ok(self) -> bool:
        """
        Return whether all verification checks passed.

        Returns:
            True if magic, size, and CRC checks all passed, otherwise False.
        """
        return self.magic_ok and self.size_ok and self.crc_ok

    def to_dict(self) -> dict:
        """
        Convert the verification result to a JSON-friendly dictionary.

        Returns:
            Dictionary representation of the verification result.
        """
        return {
            "ok": self.ok,
            "magic_ok": self.magic_ok,
            "size_ok": self.size_ok,
            "crc_ok": self.crc_ok,
            "header": self.header.to_dict(),
            "payload": {
                "size": self.payload_size,
                "crc": {
                    "int": self.payload_crc,
                    "hex": f"0x{self.payload_crc:08x}",
                },
            },
        }


def build_parser() -> argparse.ArgumentParser:
    """
    Build the command-line argument parser.

    Returns:
        Configured ArgumentParser instance.
    """
    parser = argparse.ArgumentParser(
        description="Add, update, inspect, or verify a 256-byte header in a binary file",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "binary",
        type=Path,
        help="Path to input binary file",
    )
    parser.add_argument(
        "version",
        nargs="?",
        type=str,
        help="Version string, e.g. 1, 1.2, or 1.2.3",
    )
    parser.add_argument(
        "output",
        nargs="?",
        type=Path,
        help="Path to output file",
    )
    parser.add_argument(
        "--mode",
        choices=("attach", "edit"),
        default="edit",
        help=(
            "attach: prepend a new header to a raw binary; "
            "edit: replace the existing header of a packaged binary"
        ),
    )
    parser.add_argument(
        "--print-header",
        action="store_true",
        help="Print header fields from an existing packaged binary and exit",
    )
    parser.add_argument(
        "--verify-header",
        action="store_true",
        help="Verify header magic, payload size, and payload CRC of an existing packaged binary",
    )
    parser.add_argument(
        "--in-place",
        action="store_true",
        help="Modify the input file directly instead of writing to a separate output file",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Emit machine-readable JSON output for --print-header or --verify-header",
    )
    parser.add_argument(
        "--quiet",
        action="store_true",
        help="Suppress output for --verify-header; use exit code only",
    )
    return parser


def validate_input_file(path: Path) -> None:
    """
    Validate that the input path exists and refers to a regular file.

    Args:
        path: Input file path.

    Raises:
        FileNotFoundError: If the file does not exist.
        ValueError: If the path exists but is not a regular file.
    """
    if not path.exists():
        raise FileNotFoundError(f"Input file does not exist: {path}")
    if not path.is_file():
        raise ValueError(f"Input path is not a file: {path}")


def read_binary(path: Path) -> bytes:
    """
    Read the full contents of a binary file.

    Args:
        path: Input file path.

    Returns:
        File contents as bytes.
    """
    with path.open("rb") as f:
        return f.read()


def split_binary(data: bytes, mode: str) -> tuple[bytes, bytes]:
    """
    Split binary data into header and payload according to the selected mode.

    In attach mode, the input is treated as a raw payload with no header.
    In edit mode, the input is expected to begin with an existing header.

    Args:
        data: Input binary data.
        mode: Either "attach" or "edit".

    Returns:
        A tuple of (existing_header, payload).

    Raises:
        ValueError: If edit mode is selected but the input is too small or does
            not begin with the expected magic.
    """
    if mode == "attach":
        return b"", data

    if len(data) < HEADER_SIZE:
        raise ValueError(
            f"Input file is too small for edit mode: "
            f"{len(data)} bytes, expected at least {HEADER_SIZE}"
        )

    existing_header = data[:HEADER_SIZE]
    payload = data[HEADER_SIZE:]

    # allow editing headers that doesn't contain a valid header
    # if existing_header[:4] != HEADER_MAGIC:
    #     raise ValueError(
    #         "Input file does not appear to contain a valid header "
    #         f"(expected magic {HEADER_MAGIC!r})"
    #     )

    return existing_header, payload


def build_header(payload: bytes, version: VersionInfo) -> bytes:
    """
    Build a new firmware header for the given payload and version.

    The size and CRC are computed from the payload only.

    Args:
        payload: Firmware payload bytes.
        version: Firmware version to store in the header.

    Returns:
        Complete HEADER_SIZE-byte header.

    Raises:
        RuntimeError: If the generated header size is not exactly HEADER_SIZE.
    """
    size = len(payload)
    crc = Crc32Mpeg2.calc(payload)

    header = b"".join(
        (
            HEADER_MAGIC,
            version.to_bytes(),
            struct.pack("<I", size),
            struct.pack("<I", crc),
            HEADER_PADDING,
        )
    )

    if len(header) != HEADER_SIZE:
        raise RuntimeError(
            f"Expected {HEADER_SIZE}-byte header, got {len(header)} bytes"
        )

    return header


def parse_header(data: bytes) -> HeaderInfo:
    """
    Parse and validate the header from a packaged firmware binary.

    Args:
        data: Input binary data that should start with a valid header.

    Returns:
        Parsed HeaderInfo.

    Raises:
        ValueError: If the input is too small or does not begin with the expected
            magic.
    """
    if len(data) < HEADER_SIZE:
        raise ValueError(
            f"Input file is too small to contain a header: "
            f"{len(data)} bytes, expected at least {HEADER_SIZE}"
        )

    header = data[:HEADER_SIZE]

    if header[:4] != HEADER_MAGIC:
        raise ValueError(
            f"Invalid header magic: expected {HEADER_MAGIC!r}, got {header[:4]!r}"
        )

    return HeaderInfo.from_bytes(header)


def print_header(info: HeaderInfo, as_json: bool = False) -> None:
    """
    Print parsed header information in text or JSON format.

    Args:
        info: Parsed header information.
        as_json: If True, print JSON instead of human-readable text.
    """
    if as_json:
        print(json.dumps(info.to_dict(), indent=2))
        return

    print(f"magic:   {info.magic!r}")
    print(f"version: {info.version}")
    print(f"size:    {info.size} bytes")
    print(f"crc32:   0x{info.crc:08x}")


def verify_header(data: bytes) -> VerificationResult:
    """
    Verify the header of a packaged firmware binary against its payload.

    The following checks are performed:
        - magic matches HEADER_MAGIC
        - stored size matches actual payload size
        - stored CRC matches CRC-32/MPEG-2 of payload

    Args:
        data: Packaged firmware binary data.

    Returns:
        VerificationResult containing parsed header fields and check results.

    Raises:
        ValueError: If the input is too small to contain a header.
    """
    if len(data) < HEADER_SIZE:
        raise ValueError(
            f"Input file is too small to contain a header: "
            f"{len(data)} bytes, expected at least {HEADER_SIZE}"
        )

    raw_header = data[:HEADER_SIZE]
    payload = data[HEADER_SIZE:]

    magic_ok = raw_header[:4] == HEADER_MAGIC
    header = HeaderInfo.from_bytes(raw_header)
    payload_size = len(payload)
    payload_crc = Crc32Mpeg2.calc(payload)

    size_ok = header.size == payload_size
    crc_ok = header.crc == payload_crc

    return VerificationResult(
        magic_ok=magic_ok,
        size_ok=size_ok,
        crc_ok=crc_ok,
        header=header,
        payload_size=payload_size,
        payload_crc=payload_crc,
    )


def print_verification_result(
    result: VerificationResult, as_json: bool = False
) -> None:
    """
    Print a verification result in text or JSON format.

    Args:
        result: Verification result to print.
        as_json: If True, print JSON instead of human-readable text.
    """
    if as_json:
        print(json.dumps(result.to_dict(), indent=2))
        return

    print(f"magic:         {'OK' if result.magic_ok else 'FAIL'}")
    print(f"version:       {result.header.version}")
    print(
        f"size:          {'OK' if result.size_ok else 'FAIL'} "
        f"(header={result.header.size}, actual={result.payload_size})"
    )
    print(
        f"crc32:         {'OK' if result.crc_ok else 'FAIL'} "
        f"(header=0x{result.header.crc:08x}, actual=0x{result.payload_crc:08x})"
    )
    print(f"verification:  {'OK' if result.ok else 'FAIL'}")


def write_binary(path: Path, data: bytes) -> None:
    """
    Write binary data to the given path, creating parent directories if needed.

    Args:
        path: Output file path.
        data: Data to write.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("wb") as f:
        f.write(data)


def write_binary_in_place(path: Path, data: bytes) -> None:
    """
    Safely replace an existing file with new binary data.

    The replacement is done by writing to a temporary file in the same directory,
    flushing it to disk, and then atomically replacing the target file.

    Args:
        path: File to replace.
        data: New file contents.

    Raises:
        OSError: If writing or replacement fails.
    """
    path.parent.mkdir(parents=True, exist_ok=True)

    fd, tmp_name = tempfile.mkstemp(
        dir=path.parent,
        prefix=f"{path.name}.",
        suffix=".tmp",
    )

    tmp_path = Path(tmp_name)

    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())

        os.replace(tmp_path, path)
    except Exception:
        if tmp_path.exists():
            tmp_path.unlink()
        raise


def validate_args(args: argparse.Namespace) -> None:
    """
    Validate command-line argument combinations.

    Rules enforced:
        - only one of --print-header and --verify-header may be used
        - --json only works with --print-header or --verify-header
        - --quiet only works with --verify-header
        - --quiet and --json cannot be combined
        - --print-header / --verify-header cannot be combined with version,
          output, or --in-place
        - attach/edit operations require a version
        - output is required unless --in-place is used

    Args:
        args: Parsed argparse namespace.

    Raises:
        ValueError: If the argument combination is invalid.
    """
    special_modes = int(args.print_header) + int(args.verify_header)

    if special_modes > 1:
        raise ValueError("Only one of --print-header or --verify-header may be used")

    if args.json and not (args.print_header or args.verify_header):
        raise ValueError(
            "--json may only be used with --print-header or --verify-header"
        )

    if args.quiet and not args.verify_header:
        raise ValueError("--quiet may only be used with --verify-header")

    if args.quiet and args.json:
        raise ValueError("--quiet and --json cannot be used together")

    if args.print_header or args.verify_header:
        if args.version is not None:
            raise ValueError(
                "version must not be provided with --print-header or --verify-header"
            )
        if args.output is not None:
            raise ValueError(
                "output must not be provided with --print-header or --verify-header"
            )
        if args.in_place:
            raise ValueError(
                "--in-place cannot be used with --print-header or --verify-header"
            )
        return

    if args.version is None:
        raise ValueError(
            "version argument is required unless --print-header or --verify-header is used"
        )

    if args.in_place and args.output is not None:
        raise ValueError("output must not be provided when --in-place is used")

    if not args.in_place and args.output is None:
        raise ValueError("output argument is required unless --in-place is used")


def main() -> None:
    """
    Run the command-line tool.

    This function:
        - parses command-line arguments
        - validates argument combinations and input file existence
        - performs one of the supported operations:
            - print header
            - verify header
            - attach header
            - edit header
        - writes output when needed
        - returns exit code 0/1 for verification mode

    Raises:
        ValueError, FileNotFoundError, OSError:
            Propagated from validation, parsing, or file operations.
    """
    args = build_parser().parse_args()

    validate_args(args)
    validate_input_file(args.binary)

    input_data = read_binary(args.binary)

    if args.print_header:
        header_info = parse_header(input_data)
        print_header(header_info, as_json=args.json)
        return

    if args.verify_header:
        result = verify_header(input_data)
        if not args.quiet:
            print_verification_result(result, as_json=args.json)
        sys.exit(0 if result.ok else 1)

    version = VersionInfo.from_string(args.version)
    _, payload = split_binary(input_data, args.mode)

    header = build_header(payload, version)
    output_data = header + payload

    if args.in_place:
        write_binary_in_place(args.binary, output_data)
    else:
        write_binary(args.output, output_data)


if __name__ == "__main__":
    main()
