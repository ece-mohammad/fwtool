#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Firmware header utility.

A command-line interface for working with a custom firmware header
placed at the beginning of a binary image.

Header format
-------------
The first 16 bytes of the header contain metadata fields.  The remaining
bytes up to the configured header size are filled with 0xFF padding.

    0x00..0x03   magic:   b"XLAB"
    0x04..0x07   version: little-endian bytes [0x00, patch, minor, major]
    0x08..0x0B   size:    payload size in bytes, little-endian uint32
    0x0C..0x0F   crc32:   CRC-32/MPEG-2 of payload, little-endian uint32
    0x10..end    padding: 0xFF

The total header size is configurable via ``--header-size`` and must be a
power of two so that the application vector table that follows it is
correctly aligned.  The default is 512 bytes.

Supported operations
--------------------
- attach:  prepend a new header to a raw firmware binary
- edit:    replace the header of an already packaged binary
- inspect: print header contents
- verify:  verify header magic, payload size, and payload CRC

Examples
--------
Attach a header (default 512 bytes):
    fwtool attach firmware.bin 1.2.3 out.bin

Attach with custom header size:
    fwtool attach firmware.bin 1.2.3 out.bin --header-size 1024

Edit an existing header:
    fwtool edit packaged.bin 1.2.4 out.bin

Edit in place:
    fwtool edit packaged.bin 1.2.4 --in-place

Inspect header:
    fwtool inspect packaged.bin

Inspect as JSON:
    fwtool inspect packaged.bin --json

Verify header:
    fwtool verify packaged.bin

Verify quietly:
    fwtool verify packaged.bin --quiet
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

from fwtool import __version__

HEADER_MAGIC: Final[bytes] = b"XLAB"
HEADER_INFO_SIZE: Final[int] = 16
DEFAULT_HEADER_SIZE: Final[int] = 512


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------


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

        Missing components are padded with zero.  Extra components are
        ignored.

        Args:
            value: Version string.

        Returns:
            Parsed VersionInfo object.

        Raises:
            ValueError: If version components are out of range or not
                integers.
            ValueError: If version string is empty
        """
        value = value.strip()
        if not value:
            raise ValueError("Version string is empty!")

        parts = [int(part.strip()) for part in value.split(".") if part]

        if len(parts) == 0:
            raise ValueError(f"Invalid version string: {value}")

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
        _, patch, minor, major = data
        return cls(major=major, minor=minor, patch=patch)

    def validate(self) -> None:
        """
        Validate that all version components fit in one byte.

        Raises:
            ValueError: If major, minor, or patch is outside 0..255.
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
        Parse header info fields from a binary blob.

        Only the first :data:`HEADER_INFO_SIZE` bytes are read.

        Args:
            data: Byte buffer containing at least HEADER_INFO_SIZE bytes.

        Returns:
            Parsed HeaderInfo object.

        Raises:
            ValueError: If fewer than HEADER_INFO_SIZE bytes are provided.
        """
        if len(data) < HEADER_INFO_SIZE:
            raise ValueError(
                f"Header requires at least {HEADER_INFO_SIZE} bytes, got {len(data)}"
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
    header_size: int
    payload_size: int
    payload_crc: int

    @property
    def ok(self) -> bool:
        """
        Return whether all verification checks passed.

        Returns:
            True if magic, size, and CRC checks all passed.
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
            "header_size": self.header_size,
            "header": self.header.to_dict(),
            "payload": {
                "size": self.payload_size,
                "crc": {
                    "int": self.payload_crc,
                    "hex": f"0x{self.payload_crc:08x}",
                },
            },
        }


# ---------------------------------------------------------------------------
# Validation helpers
# ---------------------------------------------------------------------------


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


def validate_header_size(size: int) -> None:
    """
    Validate that a header size is acceptable.

    The size must be at least :data:`HEADER_INFO_SIZE` bytes and must be a
    power of two so that the vector table following it in flash is
    correctly aligned.

    Args:
        size: Proposed header size in bytes.

    Raises:
        ValueError: If the size is too small or not a power of two.
    """
    if size < HEADER_INFO_SIZE:
        raise ValueError(
            f"Header size must be at least {HEADER_INFO_SIZE} bytes, got {size}"
        )
    if size & (size - 1) != 0:
        raise ValueError(f"Header size must be a power of 2, got {size}")


# ---------------------------------------------------------------------------
# File helpers
# ---------------------------------------------------------------------------


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


def write_binary(path: Path, data: bytes) -> None:
    """
    Write binary data to the given path, creating parent directories if
    needed.

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

    The replacement is done by writing to a temporary file in the same
    directory, flushing it to disk, and then atomically replacing the
    target file.

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


def write_output(path: Path | None, data: bytes, in_place: Path | None) -> None:
    """
    Write output data to the appropriate destination.

    Args:
        path: Output file path, or None if in-place is used.
        data: Data to write.
        in_place: Original input path for in-place replacement, or None.
    """
    if in_place is not None:
        write_binary_in_place(in_place, data)
    else:
        assert path is not None
        write_binary(path, data)


# ---------------------------------------------------------------------------
# Header helpers
# ---------------------------------------------------------------------------


def infer_header_size(data: bytes) -> int:
    """
    Infer the header size of a packaged binary from its stored payload
    size field.

    The header size is calculated as:
        ``len(data) - stored_payload_size``

    Args:
        data: Packaged binary data.

    Returns:
        Inferred header size in bytes.

    Raises:
        ValueError: If the file is too small, the stored payload size is
            invalid, or the inferred header size is unreasonable.
    """
    if len(data) < HEADER_INFO_SIZE:
        raise ValueError(
            f"File is too small to contain header info: "
            f"{len(data)} bytes, need at least {HEADER_INFO_SIZE}"
        )

    stored_size = struct.unpack("<I", data[8:12])[0]

    if stored_size == 0 or stored_size > len(data):
        raise ValueError(
            f"Cannot infer header size: stored payload size ({stored_size}) "
            f"is invalid for a file of {len(data)} bytes. "
            f"Use --header-size to specify explicitly."
        )

    inferred = len(data) - stored_size

    if inferred < HEADER_INFO_SIZE:
        raise ValueError(
            f"Inferred header size ({inferred}) is less than the minimum "
            f"({HEADER_INFO_SIZE}). Use --header-size to specify explicitly."
        )

    return inferred


def split_payload_from_packaged(data: bytes, header_size: int) -> tuple[bytes, bytes]:
    """
    Split a packaged binary into header and payload.

    Args:
        data: Packaged binary data.
        header_size: Expected header size in bytes.

    Returns:
        A tuple of (existing_header, payload).

    Raises:
        ValueError: If the data is smaller than *header_size*.
    """
    if len(data) < header_size:
        raise ValueError(
            f"Input file is too small for edit mode: "
            f"{len(data)} bytes, expected at least {header_size}"
        )

    return data[:header_size], data[header_size:]


def build_header(payload: bytes, version: VersionInfo, header_size: int) -> bytes:
    """
    Build a new firmware header for the given payload and version.

    The size and CRC are computed from the payload only.  The header is
    padded with 0xFF to *header_size* bytes.

    Args:
        payload: Firmware payload bytes.
        version: Firmware version to store in the header.
        header_size: Total header size in bytes.

    Returns:
        Complete header of exactly *header_size* bytes.

    Raises:
        RuntimeError: If the generated header size does not match.
    """
    size = len(payload)
    crc = Crc32Mpeg2.calc(payload)

    info = b"".join(
        (
            HEADER_MAGIC,
            version.to_bytes(),
            struct.pack("<I", size),
            struct.pack("<I", crc),
        )
    )

    padding_size = header_size - len(info)
    header = info + (b"\xff" * padding_size)

    if len(header) != header_size:
        raise RuntimeError(
            f"Expected {header_size}-byte header, got {len(header)} bytes"
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
        ValueError: If the input is too small or does not begin with the
            expected magic.
    """
    if len(data) < HEADER_INFO_SIZE:
        raise ValueError(
            f"Input file is too small to contain a header: "
            f"{len(data)} bytes, expected at least {HEADER_INFO_SIZE}"
        )

    if data[:4] != HEADER_MAGIC:
        raise ValueError(
            f"Invalid header magic: expected {HEADER_MAGIC!r}, got {data[:4]!r}"
        )

    return HeaderInfo.from_bytes(data)


def verify_header(data: bytes, header_size: int) -> VerificationResult:
    """
    Verify the header of a packaged firmware binary against its payload.

    The following checks are performed:
        - magic matches :data:`HEADER_MAGIC`
        - stored size matches actual payload size
        - stored CRC matches CRC-32/MPEG-2 of payload

    Args:
        data: Packaged firmware binary data.
        header_size: Header size in bytes used to locate the payload.

    Returns:
        VerificationResult with parsed header fields and check results.

    Raises:
        ValueError: If the input is too small to contain a header.
    """
    if len(data) < header_size:
        raise ValueError(
            f"Input file is too small to contain a header: "
            f"{len(data)} bytes, expected at least {header_size}"
        )

    raw_header = data[:header_size]
    payload = data[header_size:]

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
        header_size=header_size,
        payload_size=payload_size,
        payload_crc=payload_crc,
    )


# ---------------------------------------------------------------------------
# Output helpers
# ---------------------------------------------------------------------------


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
    print(f"header size:   {result.header_size} bytes")
    print(
        f"size:          {'OK' if result.size_ok else 'FAIL'} "
        f"(header={result.header.size}, actual={result.payload_size})"
    )
    print(
        f"crc32:         {'OK' if result.crc_ok else 'FAIL'} "
        f"(header=0x{result.header.crc:08x}, "
        f"actual=0x{result.payload_crc:08x})"
    )
    print(f"verification:  {'OK' if result.ok else 'FAIL'}")


# ---------------------------------------------------------------------------
# Subcommand handlers
# ---------------------------------------------------------------------------


def resolve_header_size_for_build(
    args: argparse.Namespace, data: bytes | None = None
) -> int:
    """
    Determine and validate the header size for attach/edit operations.

    For attach mode the default is :data:`DEFAULT_HEADER_SIZE`.
    For edit mode the size is inferred from the existing file when
    ``--header-size`` is not provided.

    Args:
        args: Parsed CLI arguments (must contain ``header_size``).
        data: Existing packaged binary data used for inference, or None.

    Returns:
        Validated header size.

    Raises:
        ValueError: If the resolved size is invalid.
    """
    if args.header_size is not None:
        header_size = args.header_size
    elif data is not None:
        header_size = infer_header_size(data)
    else:
        header_size = DEFAULT_HEADER_SIZE

    validate_header_size(header_size)
    return header_size


def resolve_header_size_for_verify(args: argparse.Namespace, data: bytes) -> int:
    """
    Determine the header size for verification.

    If ``--header-size`` is provided it is used directly; otherwise the
    size is inferred from the stored payload size.

    Args:
        args: Parsed CLI arguments (must contain ``header_size``).
        data: Packaged binary data.

    Returns:
        Header size in bytes.

    Raises:
        ValueError: If inference fails and no explicit size was given.
    """
    if args.header_size is not None:
        return args.header_size
    return infer_header_size(data)


def handle_attach(args: argparse.Namespace) -> None:
    """
    Handle the ``attach`` subcommand.

    Reads a raw firmware binary, builds a new header, and writes the
    combined packaged binary.

    Args:
        args: Parsed CLI arguments for the attach subcommand.
    """
    validate_input_file(args.binary)
    payload = read_binary(args.binary)

    header_size = resolve_header_size_for_build(args)
    version = VersionInfo.from_string(args.version)
    header = build_header(payload, version, header_size)

    write_output(
        path=args.output,
        data=header + payload,
        in_place=args.binary if args.in_place else None,
    )


def handle_edit(args: argparse.Namespace) -> None:
    """
    Handle the ``edit`` subcommand.

    Reads a packaged firmware binary, strips its existing header, builds
    a new header with the given version, and writes the result.

    Args:
        args: Parsed CLI arguments for the edit subcommand.
    """
    validate_input_file(args.binary)
    input_data = read_binary(args.binary)

    header_size = resolve_header_size_for_build(args, data=input_data)
    _, payload = split_payload_from_packaged(input_data, header_size)

    version = VersionInfo.from_string(args.version)
    header = build_header(payload, version, header_size)

    write_output(
        path=args.output,
        data=header + payload,
        in_place=args.binary if args.in_place else None,
    )


def handle_inspect(args: argparse.Namespace) -> None:
    """
    Handle the ``inspect`` subcommand.

    Reads a packaged firmware binary and prints parsed header information.

    Args:
        args: Parsed CLI arguments for the inspect subcommand.
    """
    validate_input_file(args.binary)
    input_data = read_binary(args.binary)

    info = parse_header(input_data)
    print_header(info, as_json=args.json)


def handle_verify(args: argparse.Namespace) -> None:
    """
    Handle the ``verify`` subcommand.

    Reads a packaged firmware binary, verifies its header against the
    payload, and exits with 0 on success or 1 on failure.

    Args:
        args: Parsed CLI arguments for the verify subcommand.
    """
    validate_input_file(args.binary)
    input_data = read_binary(args.binary)

    header_size = resolve_header_size_for_verify(args, input_data)
    result = verify_header(input_data, header_size)

    if not args.quiet:
        print_verification_result(result, as_json=args.json)

    sys.exit(0 if result.ok else 1)


# ---------------------------------------------------------------------------
# CLI parser
# ---------------------------------------------------------------------------


def add_binary_arg(parser: argparse.ArgumentParser) -> None:
    """
    Add the ``binary`` positional argument to a subparser.

    Args:
        parser: Subparser to add the argument to.
    """
    parser.add_argument(
        "binary",
        type=Path,
        help="Path to input binary file",
    )


def add_version_arg(parser: argparse.ArgumentParser) -> None:
    """
    Add the ``version`` positional argument to a subparser.

    Args:
        parser: Subparser to add the argument to.
    """
    parser.add_argument(
        "version",
        type=str,
        help="Firmware version string, e.g. 1, 1.2, or 1.2.3",
    )


def add_output_args(parser: argparse.ArgumentParser) -> None:
    """
    Add mutually exclusive ``output`` / ``--in-place`` arguments to a
    subparser.

    Args:
        parser: Subparser to add the arguments to.
    """
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument(
        "output",
        nargs="?",
        type=Path,
        default=None,
        help="Path to output file",
    )
    group.add_argument(
        "--in-place",
        action="store_true",
        help="Modify the input file directly instead of writing to a separate output",
    )


def add_header_size_arg(
    parser: argparse.ArgumentParser,
    default: int | None = None,
    help_suffix: str = "",
) -> None:
    """
    Add the ``--header-size`` option to a subparser.

    Args:
        parser: Subparser to add the argument to.
        default: Default value; None means "infer from file".
        help_suffix: Extra text appended to the help string.
    """
    inferred_note = (
        f" (default: {default})"
        if default is not None
        else " (default: inferred from file)"
    )
    parser.add_argument(
        "--header-size",
        type=int,
        default=default,
        help="Total header/metadata region size in bytes; "
        f"must be a power of 2{inferred_note}{help_suffix}",
    )


def add_json_arg(parser: argparse.ArgumentParser) -> None:
    """
    Add the ``--json`` flag to a subparser.

    Args:
        parser: Subparser to add the argument to.
    """
    parser.add_argument(
        "--json",
        action="store_true",
        help="Emit machine-readable JSON output",
    )


def build_parser() -> argparse.ArgumentParser:
    """
    Build the top-level argument parser with subcommands.

    Subcommands:
        attach:  attach a new header to a raw firmware binary
        edit:    replace the header of a packaged binary
        inspect: print parsed header fields
        verify:  verify header against the payload

    Returns:
        Configured ArgumentParser instance.
    """
    parser = argparse.ArgumentParser(
        prog="fwtool",
        description="Add, update, inspect, or verify a firmware header",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )

    subparsers = parser.add_subparsers(
        dest="command",
        required=True,
        help="Available commands",
    )

    # -- attach ---------------------------------------------------------------
    attach_parser = subparsers.add_parser(
        "attach",
        help="Attach a new header to a raw firmware binary",
        description=(
            "Read a raw firmware binary, build a header, and write the packaged image."
        ),
    )
    add_binary_arg(attach_parser)
    add_version_arg(attach_parser)
    add_output_args(attach_parser)
    add_header_size_arg(attach_parser, default=DEFAULT_HEADER_SIZE)
    attach_parser.set_defaults(handler=handle_attach)

    # -- edit -----------------------------------------------------------------
    edit_parser = subparsers.add_parser(
        "edit",
        help="Replace the header of a packaged binary",
        description=(
            "Read a packaged binary, replace the header with a new "
            "version, and write the result."
        ),
    )
    add_binary_arg(edit_parser)
    add_version_arg(edit_parser)
    add_output_args(edit_parser)
    add_header_size_arg(edit_parser)
    edit_parser.set_defaults(handler=handle_edit)

    # -- inspect --------------------------------------------------------------
    inspect_parser = subparsers.add_parser(
        "inspect",
        help="Print header fields from a packaged binary",
        description=("Read a packaged binary and print the parsed header fields."),
    )
    add_binary_arg(inspect_parser)
    add_json_arg(inspect_parser)
    inspect_parser.set_defaults(handler=handle_inspect)

    # -- verify ---------------------------------------------------------------
    verify_parser = subparsers.add_parser(
        "verify",
        help="Verify header of a packaged binary",
        description=(
            "Read a packaged binary and verify its header against the payload."
        ),
    )
    add_binary_arg(verify_parser)
    add_json_arg(verify_parser)
    add_header_size_arg(verify_parser)
    verify_parser.add_argument(
        "--quiet",
        action="store_true",
        help="Suppress output; use exit code only",
    )
    verify_parser.set_defaults(handler=handle_verify)

    return parser


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def main() -> None:
    """
    Parse arguments and dispatch to the appropriate subcommand handler.
    """
    parser = build_parser()
    args = parser.parse_args()
    args.handler(args)


if __name__ == "__main__":
    main()
