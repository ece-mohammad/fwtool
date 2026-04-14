# fwtool

`fwtool` is a command-line utility for creating, updating, inspecting, and verifying
a custom firmware metadata header prepended to a binary image.

It is intended for firmware packaging workflows where a raw application binary is
post-processed into a single flashable image:

- a fixed-size header is placed at the beginning that contains version,
  firmware size, and CRC information
- the firmware firmware follows immediately after

This is useful for bootloaders or firmware update logic that need to validate
and identify an application image before booting or programming it.

---

## What it does

`fwtool` supports four subcommands:

1. **attach** — prepend a new header to a raw firmware binary
2. **edit** — replace the header of an already packaged binary
3. **inspect** — print the parsed contents of an existing header
4. **verify** — verify that an existing header matches the firmware

---

## Header format

The tool generates a header with the following layout:

| Offset       | Size | Field   | Description                                         |
|--------------|------|---------|-----------------------------------------------------|
| `0x00..0x03` | 4    | magic   | ASCII string `XLAB`                                 |
| `0x04..0x07` | 4    | version | Little-endian bytes: `[0x00, patch, minor, major]`  |
| `0x08..0x0B` | 4    | size    | firmware size in bytes, little-endian `uint32`      |
| `0x0C..0x0F` | 4    | crc32   | CRC-32/MPEG-2 of firmware, little-endian `uint32`   |
| `0x10..end`  | —    | padding | Filled with `0xFF`                                  |

The total header size defaults to **512 bytes** and is configurable via
`--header-size`. It must be a power of two (minimum 16 bytes) so that the
application vector table following it in flash is correctly aligned.

With the default 512-byte header, the padding region spans `0x10..0x1FF`
(496 bytes of `0xFF`).

### Notes

- The CRC is calculated over the **firmware only**, not over the header.
- The size stored in the header is the **firmware size only**.
- The version is stored as:
  - byte 0: `0x00`
  - byte 1: patch
  - byte 2: minor
  - byte 3: major

For example, version `1.2.3` is stored as:

```text
0x00030201
```

### Typical use case

A common workflow looks like this:

- Link the firmware application so that it expects to execute after the reserved header space.
- Build the raw application binary.
- Use `fwtool` to prepend the metadata header.
- Program the resulting combined binary into flash.

For example, with the default 512-byte header:

```text
Flash address 0x08004000:
    [512-byte metadata header]
    [firmware payload]
```

---

## Installation

### Install using pip

```bash
pip install fwtool
```

### Install using pipx

```bash
pipx install fwtool
```

### Install using uv

```bash
uv tool install fwtool
```

### Check installation

```bash
fwtool --version
```

---

## Usage

```bash
fwtool <command> [arguments] [options]
  Subcommands
    Command Description
    attach Attach a new header to a raw firmware binary
    edit Replace the header of a packaged binary
    inspect Print header fields from a packaged binary
    verify Verify header of a packaged binary

  Common options
    --version Show program version and exit
    --help Show help message and exit
```

**attach**:

```bash
fwtool attach <binary> <version> <output> [options]
fwtool attach <binary> <version> --in-place [options]
  Argument / Option Description
  binary Path to raw input binary file
  version Firmware version string (e.g. 1, 1.2, 1.2.3)
  output Path to output file
  --in-place Modify the input file directly instead of writing output
  --header-size N Total header size in bytes; must be a power of 2 (default: 512)
```

**edit**:

```bash
fwtool edit <binary> <version> <output> [options]
fwtool edit <binary> <version> --in-place [options]
  Argument / Option Description
  binary Path to packaged binary file with existing header
  version New firmware version string
  output Path to output file
  --in-place Modify the input file directly instead of writing output
  --header-size N Total header size in bytes; must be a power of 2 (default: inferred from file)
```

**inspect**:

```bash
fwtool inspect <binary> [options]
  Argument / Option Description
  binary Path to packaged binary file
  --json Emit machine-readable JSON output
```

**verify**:

```bash
fwtool verify <binary> [options]
  Argument / Option Description
  binary Path to packaged binary file
  --json Emit machine-readable JSON output
  --quiet Suppress output; use exit code only
  --header-size N Total header size in bytes; must be a power of 2 (default: inferred from file)
```

#### Examples

Attach a new header to a raw binary

  ```bash
  fwtool attach firmware.bin 1.2.3 packaged.bin
  ```

This creates:

  ```text
  packaged.bin = [512-byte header][firmware.bin firmware]
  ```

---

Attach with a custom header size

```bash
fwtool attach firmware.bin 1.2.3 packaged.bin --header-size 1024
```

---

Replace the header of an existing packaged binary

```bash
fwtool edit packaged.bin 1.2.4 updated.bin
```

This keeps the firmware but replaces the header with updated metadata.

---

Replace the header in place

```bash
fwtool edit packaged.bin 1.2.4 --in-place
```

This modifies packaged.bin directly.

---

Attach a header in place

```bash
fwtool attach firmware.bin 1.2.3 --in-place
```

This replaces the raw input file with a packaged binary containing the header.

---

Print header contents

```bash
fwtool inspect packaged.bin
```

Example output:

```text
magic:   b'XLAB'
version: 1.2.3
size:    123456 bytes
crc32:   0x1a2b3c4d
```

---

Print header contents as JSON

```bash
fwtool inspect packaged.bin --json
```

Example output:

```json
{
  "magic_ascii": "XLAB",
  "magic_hex": "584c4142",
  "version": {
    "major": 1,
    "minor": 2,
    "patch": 3,
    "string": "1.2.3"
  },
  "size": 123456,
  "crc": {
    "int": 439041101,
    "hex": "0x1a2b3c4d"
  }
}
```

---

Verify a packaged binary

```bash
fwtool verify packaged.bin
```

Example output:

```text
magic:         OK
version:       1.2.3
header size:   512 bytes
size:          OK (header=123456, actual=123456)
crc32:         OK (header=0x1a2b3c4d, actual=0x1a2b3c4d)
verification:  OK
```

---

Verify quietly using only the exit code

```bash
fwtool verify packaged.bin --quiet
echo $?
```

Exit code meanings:

`0`: verification passed
`1`: verification failed

---

Verify with JSON output

```bash
fwtool verify packaged.bin --json
```

Example output:

```json
{
  "ok": true,
  "magic_ok": true,
  "size_ok": true,
  "crc_ok": true,
  "header_size": 512,
  "header": {
    "magic_ascii": "XLAB",
    "magic_hex": "584c4142",
    "version": {
      "major": 1,
      "minor": 2,
      "patch": 3,
      "string": "1.2.3"
    },
    "size": 123456,
    "crc": {
      "int": 439041101,
      "hex": "0x1a2b3c4d"
    }
  },
  "firmware": {
    "size": 123456,
    "crc": {
      "int": 439041101,
      "hex": "0x1a2b3c4d"
    }
  }
}
```

### Header size

The header size is configurable and defaults to 512 bytes.

**Rules**:

- must be a power of two (16, 32, 64, 128, 256, 512, 1024, …)
- must be at least 16 bytes (the minimum to hold the metadata fields)
- ensures the application vector table following the header is correctly aligned
- For edit and verify, if --header-size is not specified, the tool infers the header size from the stored firmware size field:

```text
header_size = file_size - stored_firmware_size
```

If inference fails (e.g. corrupted size field), use --header-size to specify the size explicitly.

### Version handling

Accepted version formats:

- `1` -> `1.0.0`
- `1.2` -> `1.2.0`
- `1.2.3` -> `1.2.3`

**Rules**:

- missing components are filled with zero
- extra components are ignored
- each component must be in the range 0..255

### Verification behavior

When fwtool verify is used, the tool checks:

- the magic field is `XLAB`
- the firmware size matches the size stored in the header
- the firmware CRC matches the CRC stored in the header
- The header itself is not included in the size or CRC calculation.

### Exit codes

#### General operations

- `0` on success
- non-zero on failure

#### verify

- `0` if verification succeeds
- `1` if verification fails

### Common workflow example

- Build a raw firmware image:

```bash
arm-none-eabi-objcopy -O binary app.elf app.bin
```

- Attach metadata header:

```bash
fwtool attach app.bin 1.2.3 app_packed.bin
```

- Verify the packaged image:

```bash
fwtool verify app_packed.bin
```

- Program the combined image to flash:

```bash
st-flash write app_packed.bin 0x08004000
```

---

## Notes for embedded use

If your firmware image is packaged with a prepended header, the application must
typically be linked to execute after the reserved header region.

Example with the default 512-byte (`0x200`) header:

- metadata region starts at `0x08004000`
- header size is `0x200` (512 bytes)
- application is linked to start at `0x08004200`
- Then the combined image can be programmed at `0x08004000`, and the application
- firmware will land at the correct runtime address.

---

## Development

### Run tests

```bash
pytest -q
```

---

## License

MIT License
