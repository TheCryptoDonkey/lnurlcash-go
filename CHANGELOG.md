# Changelog

Semantic versioning. While the LUD-25 draft is unmerged, `0.x` minor bumps may
carry breaking changes; pin an exact version.

## 0.1.0 — unreleased

First release. An independent Go implementation of LNURLcash, checked against
the shared
[conformance vectors](https://github.com/TheCryptoDonkey/lnurlcash-conformance)
and the adversarial mock mint.

### Design notes

**`NewClient` disables keep-alives.** `net/http` retries an idempotent request
that was sent on a reused connection, and every LNURLcash mutation is a GET
that is not idempotent — so a retry gets "already spent" for its second attempt
and reports a definitive rejection, discarding the fresh secret of a note the
service just minted. Worse, a client with no `Transport` uses the
process-wide default pool, so the behaviour depends on what unrelated code did
first. Found by the mock mint's `dropAfterMutation` mode, which failed two
tests until the transport changed.

**The protocol layer has no I/O.** Each operation is a `Request` — a URL, and
the fresh secrets that must survive a lost answer — paired with a `Parse*`
function. `Client` is a thin loop over exactly those.

**The proportional fee term is computed split**, as
`(g/1e6)*ppm + ((g%1e6)*ppm)/1e6`. A direct multiply overflows `int64` at
realistic amounts: 21M BTC is 2.1e15 msat, and at 999_999 ppm the product is
about 2.1e21.

**`GrossUpForMintFee` is a binary search**, not an estimate-then-walk. At a
99.9999% fee a one-msat walk is around a million steps, so any guard on it
returns a non-minimal answer — and the fee is chosen by the service.

**A service's reason is carried through exactly as sent**, empty string
included. Substituting a friendly default before classification would be read
back as though the service had said it: "unknown service error" matches the
rule for an unknown note.

**Note URLs keep their parameter order.** `url.Values` is a map and cannot, but
a note URL's shape is user-visible — quoted in bug reports and compared by eye.
