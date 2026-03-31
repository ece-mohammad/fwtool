# fwtool

`fwtool` is a command-line utility for creating, updating, inspecting, and verifying
a custom firmware metadata header prepended to a binary image.

It is intended for firmware packaging workflows where a raw application binary is
post-processed into a single flashable image:

- a fixed-size header is placed at the beginning
- the firmware payload follows immediately after
- the header contains version, payload size, and CRC information

This is useful for bootloaders or firmware update logic that need to validate
and identify an application image before booting or programming it.

---

## What it does

`fwtool` supports four main operations:

1. **Attach** a new header to a raw firmware binary
2. **Edit** an existing header in a packaged binary
3. **Print** the parsed contents of an existing header
4. **Verify** that an existing header matches the payload

---

## Header format

The tool generates a **256-byte header** with the following layout:

| Offset       | Size | Field   | Description                                        |
|--------------|------|---------|----------------------------------------------------|
| `0x00..0x03` | 4    | magic   | ASCII string `XLAB`                                |
| `0x04..0x07` | 4    | version | Little-endian bytes: `[0x00, patch, minor, major]` |
| `0x08..0x0B` | 4    | size    | Payload size in bytes, little-endian `uint32`      |
| `0x0C..0x0F` | 4    | crc32   | CRC-32/MPEG-2 of payload, little-endian `uint32`   |
| `0x10..0xFF` | 240  | padding | Filled with `0xFF`                                 |
### Notes

- The CRC is calculated over the **payload only**, not over the header.
- The size stored in the header is the **payload size only**.
- The version is stored as:
  - byte 0: `0x00`
  - byte 1: patch
  - byte 2: minor
  - byte 3: major

For example, version `1.2.3` is stored as:

```text
00 03 02 01
```

---

## Typical use case

A common workflow looks like this:

1. Link the firmware application so that it expects to execute after the reserved header space.
2. Build the raw application binary.
3. Use `fwtool` to prepend the metadata header.
4. Program the resulting combined binary into flash.

For example:

```text
Flash address 0x08004000:
    [256-byte metadata header]
    [firmware payload]
```

---

## Installation

### Requirements

- Python 3.9+
- [`crccheck`](https://pypi.org/project/crccheck/)

### Install dependency manually

```bash
pip install crccheck
```

### Run directly

If you have the script as `fwtool.py`, you can run it with:

```bash
python fwtool.py ...
```

### Install as a CLI tool

If the project includes a `pyproject.toml`, install it in editable mode:

```bash
pip install -e .
```

Then run it as:

```bash
fwtool ...
```

---

## Usage

```bash
fwtool binary [version] [output] [options]
```

### Positional arguments

- `binary`  
  Path to input binary file

- `version`  
  Firmware version string such as:
  - `1`
  - `1.2`
  - `1.2.3`

- `output`  
  Output path for attach/edit operations

### Options

- `--mode {attach,edit}`  
  Select how the tool treats the input file:
  - `attach`: input is a raw binary without a header
  - `edit`: input already contains a header and it will be replaced

- `--in-place`  
  Modify the input file directly instead of writing to a separate output file

- `--print-header`  
  Parse and print the header from an existing packaged binary

- `--verify-header`  
  Verify header magic, payload size, and payload CRC against the payload

- `--json`  
  Print machine-readable JSON output for `--print-header` or `--verify-header`

- `--quiet`  
  Suppress output for `--verify-header` and use exit code only

---

## Examples

### 1. Attach a new header to a raw binary

```bash
fwtool firmware.bin 1.2.3 packaged.bin --mode attach
```

This creates:

```text
packaged.bin = [256-byte header][firmware.bin payload]
```

---

### 2. Replace the header of an existing packaged binary

```bash
fwtool packaged.bin 1.2.4 updated.bin --mode edit
```

This keeps the payload but replaces the header with updated metadata.

---

### 3. Replace the header in place

```bash
fwtool packaged.bin 1.2.4 --mode edit --in-place
```

This modifies `packaged.bin` directly.

---

### 4. Attach a header in place

```bash
fwtool firmware.bin 1.2.3 --mode attach --in-place
```

This replaces the raw input file with a packaged binary containing the header.

---

### 5. Print header contents

```bash
fwtool packaged.bin --print-header
```

Example output:

```text
magic:   b'XLAB'
version: 1.2.3
size:    123456 bytes
crc32:   0x1a2b3c4d
```

---

### 6. Print header contents as JSON

```bash
fwtool packaged.bin --print-header --json
```

Example output:

```json
{
  \"magic_ascii\": \"XLAB\",
  \"magic_hex\": \"584c4142\",
  \"version\": {
    \"major\": 1,
    \"minor\": 2,
    \"patch\": 3,
    \"string\": \"1.2.3\"
  },
  \"size\": 123456,
  \"crc\": {
    \"int\": 439041101,
    \"hex\": \"0x1a2b3c4d\"
  }
}
```

---

### 7. Verify a packaged binary

```bash
fwtool packaged.bin --verify-header
```

Example output:

```text
magic:         OK
version:       1.2.3
size:          OK (header=123456, actual=123456)
crc32:         OK (header=0x1a2b3c4d, actual=0x1a2b3c4d)
verification:  OK
```

---

### 8. Verify quietly using only the exit code

```bash
fwtool packaged.bin --verify-header --quiet
echo $?
```

Exit code meanings:

- `0`: verification passed
- `1`: verification failed

---

### 9. Verify with JSON output

```bash
fwtool packaged.bin --verify-header --json
```

Example output:

```json
{
  \"ok\": true,
  \"magic_ok\": true,
  \"size_ok\": true,
  \"crc_ok\": true,
  \"header\": {
    \"magic_ascii\": \"XLAB\",
    \"magic_hex\": \"584c4142\",
    \"version\": {
      \"major\": 1,
      \"minor\": 2,
      \"patch\": 3,
      \"string\": \"1.2.3\"
    },
    \"size\": 123456,
    \"crc\": {
      \"int\": 439041101,
      \"hex\": \"0x1a2b3c4d\"
    }
  },
  \"payload\": {
    \"size\": 123456,
    \"crc\": {
      \"int\": 439041101,
      \"hex\": \"0x1a2b3c4d\"
    }
  }
}
```

---

## Version handling

Accepted version formats:

- `1` → `1.0.0`
- `1.2` → `1.2.0`
- `1.2.3` → `1.2.3`

Rules:

- missing components are filled with zero
- extra components are ignored
- each component must be in the range `0..255`

---

## Verification behavior

When `--verify-header` is used, the tool checks:

- the magic field is `XLAB`
- the payload size matches the size stored in the header
- the payload CRC matches the CRC stored in the header

The header itself is **not** included in the size or CRC calculation.

---

## Exit codes

### General operations

- `0` on success
- non-zero on failure

### `--verify-header`

- `0` if verification succeeds
- `1` if verification fails

---

## Common workflow example

Build a raw firmware image:

```bash
arm-none-eabi-objcopy -O binary app.elf app.bin
```

Attach metadata header:

```bash
fwtool app.bin 1.2.3 app_packed.bin --mode attach
```

Program the combined image to flash:

```bash
st-flash write app_packed.bin 0x08004000
```

---

## Notes for embedded use

If your firmware image is packaged with a prepended header, the application must
typically be linked to execute **after** the reserved header region.

Example:

- metadata region starts at `0x08004000`
- header size is `0x100`
- application is linked to start at `0x08004100`

Then the combined image can be programmed at `0x08004000`, and the application
payload will land at the correct runtime address.

---

## Development

### Run tests

If you have a `pytest` test suite:

```bash
pytest -q
```

---

## License

MIT License
