# Security policy

fwsign signs and encrypts firmware images that a bootloader trusts, so security reports are
taken seriously.

## Reporting a vulnerability

Please **do not open a public issue**. Report privately using one of these:

- GitHub: [Report a vulnerability](https://github.com/amazeng-co/fwsign/security/advisories/new)
  (preferred).
- E-mail: mustafa.kus@amazeng.com.tr

Include the affected version or commit, the command line, and a description or proof of concept.
We aim to acknowledge reports within 3 working days and to agree on a disclosure timeline with you.

## Scope

**In scope:** this repository. Examples:

- a signature or hash that `verify` accepts but MCUboot would reject, or the other way round,
- encryption that leaks the image key or plaintext,
- key material that is handled insecurely,
- crashes on crafted input files.

**Out of scope:** issues in MCUboot itself, or in the Python imgtool. Report those to the
[MCUboot project](https://github.com/mcu-tools/mcuboot/security).

## Supported versions

Only the latest release and `main` receive security fixes.
