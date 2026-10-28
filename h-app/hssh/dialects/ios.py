"""Cisco IOS and IOS-XE. Also the shape NX-OS, EOS and the `none` dialect
borrow for their CLI: `Router>`, `Router#`, `Router(config-if)#`. NX-OS and
EOS take its refusals too, a line that starts with `%` or `ERROR:`, and its
warnings."""

import re

from .base import CliSyntax, Dialect

CLI = CliSyntax(
    prompt=re.compile(r'[\w\-\.]+(\([^\s()]+\))?[>#]\s*$'),
    prompt_name=re.compile(r'^([\w\-\.]+)(\([^\s()]+\))?[>#]\s*$'),
    prompt_tail=r'(\([^\s()]+\))?[>#]\s*$',
    config_enter="configure terminal",
    config_exit="end",
)

# A line that starts with `!` is a comment to an IOS-shaped CLI (a `show
# running-config` is full of them): never typed, and a payload of nothing
# else has nothing to apply.
COMMENTS = ("!",)

# How an IOS-shaped CLI refuses a line: `% ` first (`% Invalid input
# detected at '^' marker.`), a `%` with no space after it (`%Inconsistent
# address and mask`, `%Error opening flash:x.cfg`), or `ERROR:` (`ERROR:
# The secret you entered is not a valid encrypted secret.`, and NX-OS's
# word on a value it will not take). A syslog message the device prints
# into the session, `%LINK-3-UPDOWN: Interface Gi0/1, changed state to up`
# (a facility, a severity, a mnemonic, a colon; a Catalyst's SP or DFC puts
# its source after the facility, `%OIR-SP-6-INSCARD:`), is not one (#142).
REFUSED = re.compile(r"^\s*(% |%(?![A-Z0-9_]+(?:-[A-Z0-9_]+)*-\d+-[A-Z0-9_]+:)\S|ERROR:)", re.M)

# What IOS says, a `%` first, of a line it took: a warning (`%Warning:
# portfast should only be enabled on ports connected to a single host`,
# and the `%Portfast has been configured on Gi0/1 but will only have
# effect ...` under it; `% Warning: use /31 mask on non point-to-point
# interface cautiously`), its note on a default route out of an interface
# (`%Default route without gateway, if not a point-to-point interface,
# may impact performance`) or on a command it took and calls obsolete
# (`%Command accepted but obsolete, unreleased or unsupported; see
# documentation.`), what it says as it makes the RSA keys of `crypto key
# generate rsa modulus 2048` (`% The key modulus size is 2048 bits`,
# `% Generating 2048 bit RSA keys, keys will be non-exportable...`) and as
# a switch leaves a VLAN's mode (`% Applying VLAN changes may take few
# minutes.  Please wait...`), or the note that a VRF enabled on an
# interface removed its addresses (`% Interface Gi0/1 IPv4 disabled and
# address(es) removed due to enabling VRF CUST`), which the payload's next
# line puts back. None is a refusal: a lines edit goes on past it and
# reports it (#142).
INFORMATIONAL = re.compile(r"^\s*%\s*(warning\b|portfast (has been|will be) configured\b"
                           r"|default route without gateway\b|command accepted but obsolete\b"
                           r"|the key modulus size is \d+ bits|generating \d+ bit rsa keys\b"
                           r"|applying vlan changes\b"
                           r"|interface \S+ .*\bremoved due to (en|dis)abling vrf\b)",
                           re.M | re.I)

DIALECT = Dialect("ios", "IOS", "Cisco IOS and IOS-XE", refused=REFUSED, informational=INFORMATIONAL, cli=CLI,
                  comments=COMMENTS)
