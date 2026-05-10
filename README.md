# dkim2
DKIM2 library and tools

## CLI tools

`dkim2sign` signs a message.

`dkim2verify` verifies all the Dkim2 signatures in a message.

`dkim2explain` unpacks all the Dkim2-Signature and
Message-Instance  headers, displaying their fields in a human
readable format.

`dkim2history` generates previous versions of a message, from
the history stored in Message-Instance headers.

### Installation

Pre-built binaries are available at [github releases](https://github.com/turscar/dkim2/releases/latest).

Download and unpack the appropriate .zip or .tar.gz file for
your OS and architecture.

The Windows binaries are not signed.

## Status

The library seems to generate and parse messages correctly.

## Missing

Message-instance recipes that return a "we
can't reconstruct this" result aren't returned to the
caller in any useful way. I'm waiting to see how the
requirements change there before firming up the API.
