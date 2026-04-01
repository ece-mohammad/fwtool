CLI Usage
=========

Basic usage:

.. code-block:: bash

   usage: fwtool [-h] [--mode {attach,edit}] [--print-header] [--verify-header]
              [--in-place] [--json] [--quiet]
              binary [version] [output]

   Add, update, inspect, or verify a 256-byte header in a binary file

   positional arguments:
     binary                Path to input binary file
     version               Version string, e.g. 1, 1.2, or 1.2.3 (default: None)
     output                Path to output file (default: None)

   options:
     -h, --help            show this help message and exit
     --mode {attach,edit}  attach: prepend a new header to a raw binary; edit:
                           replace the existing header of a packaged binary
                           (default: attach)
     --print-header        Print header fields from an existing packaged binary
                           and exit (default: False)
     --verify-header       Verify header magic, payload size, and payload CRC of
                           an existing packaged binary (default: False)
     --in-place            Modify the input file directly instead of writing to a
                           separate output file (default: False)
     --json                Emit machine-readable JSON output for --print-header
                           or --verify-header (default: False)
     --quiet               Suppress output for --verify-header; use exit code
                           only (default: False)


Examples:

Attach a header:

.. code-block:: bash

   fwtool firmware.bin 1.2.3 packaged.bin --mode attach

Verify a packaged binary:

.. code-block:: bash

   fwtool packaged.bin --verify-header
