package lnurlcash

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// MintFee is what a service withholds when minting (LUD-25, optional).
//
// A service signals it via an extra ["text/plain", "Mint fees:
// <base_fee_msat>,<fee_percent_ppm>"] entry in a payRequest's metadata, so a
// wallet can warn the payer up front that the note they end up holding is worth
// less than the invoice they paid. A service that omits the entry is fee-free,
// not unknown.
type MintFee struct {
	BaseFeeMsat int64
	FeePpm      int64
}

var mintFeeRe = regexp.MustCompile(`^Mint fees:\s*(\d+)\s*,\s*(\d+)\s*$`)

// ParseMintFee reads a fee out of payRequest metadata. Returns false when the
// service advertised none, which the spec says to read as fee-free.
func ParseMintFee(metadata string) (MintFee, bool) {
	var entries [][]json.RawMessage
	if err := json.Unmarshal([]byte(metadata), &entries); err != nil {
		return MintFee{}, false
	}
	for _, entry := range entries {
		if len(entry) < 2 {
			continue
		}
		var kind, text string
		if json.Unmarshal(entry[0], &kind) != nil || kind != "text/plain" {
			continue
		}
		if json.Unmarshal(entry[1], &text) != nil {
			continue
		}
		match := mintFeeRe.FindStringSubmatch(text)
		if match == nil {
			continue
		}
		base, err1 := strconv.ParseInt(match[1], 10, 64)
		ppm, err2 := strconv.ParseInt(match[2], 10, 64)
		if err1 != nil || err2 != nil {
			continue
		}
		// A fee of 100% or more can never net anything. Refusing it here is also
		// what keeps GrossUpForMintFee's search bounded, so a service cannot
		// stall a caller simply by advertising one.
		if ppm >= 1_000_000 {
			continue
		}
		// An explicit "Mint fees: 0,0" has exactly the effect of omitting the
		// entry - treat it identically, so callers never have to special-case a
		// fee that is present but withholds nothing.
		if base == 0 && ppm == 0 {
			return MintFee{}, false
		}
		return MintFee{BaseFeeMsat: base, FeePpm: ppm}, true
	}
	return MintFee{}, false
}

// proportionalFee is floor(gross * ppm / 1_000_000), computed so it cannot
// overflow.
//
// The obvious gross * ppm is wrong at realistic amounts: 21M BTC is 2.1e15
// msat, and at 999_999 ppm the product is about 2.1e21 - past int64's 9.2e18.
// Splitting the multiplication keeps both halves small: the quotient half
// reaches at most 2.1e15, the remainder half at most 1e12.
//
// This is the single most likely thing for a port to get wrong, because a naive
// version passes every small test.
func proportionalFee(grossMsat, feePpm int64) int64 {
	return (grossMsat/1_000_000)*feePpm + ((grossMsat%1_000_000)*feePpm)/1_000_000
}

// ApplyMintFee returns what a service is expected to credit after withholding
// its advertised fee.
//
// Only ever an estimate to show before paying: the authoritative value is
// whatever the informational GET reports once the note is claimed.
func ApplyMintFee(grossMsat int64, fee MintFee) int64 {
	net := grossMsat - fee.BaseFeeMsat - proportionalFee(grossMsat, fee.FeePpm)
	if net < 0 {
		return 0
	}
	return net
}

// GrossUpForMintFee returns the SMALLEST invoice amount whose note nets
// netMsat after the fee.
//
// ApplyMintFee is non-decreasing in gross with per-msat steps of 0 or 1 (the
// proportional term grows by at most 1 per msat, since ppm is below
// 1_000_000), so the minimal such gross exists and binary search finds it
// exactly. The tempting alternative - estimate linearly, then walk one msat at
// a time - is both unbounded and wrong at the edge: at 999_999 ppm the walk is
// roughly a million steps, so any guard on it returns a non-minimal answer, and
// the service picks the fee.
func GrossUpForMintFee(netMsat int64, fee MintFee) int64 {
	if netMsat <= 0 {
		return 0
	}
	hi := netMsat + fee.BaseFeeMsat
	if hi < 1 {
		hi = 1
	}
	for ApplyMintFee(hi, fee) < netMsat {
		if hi > (1<<62)/2 {
			// unreachable with ppm < 1_000_000, but a library holding somebody's
			// money should saturate rather than overflow
			return hi
		}
		hi *= 2
	}
	lo := int64(0)
	for lo < hi {
		mid := lo + (hi-lo)/2
		if ApplyMintFee(mid, fee) >= netMsat {
			hi = mid
		} else {
			lo = mid + 1
		}
	}
	return lo
}

// FormatFeePercent renders ppm as a percentage: /10_000 for a percent, then
// trim the trailing zeros (2000 ppm -> "0.2000" -> "0.2").
func FormatFeePercent(ppm int64) string {
	text := strconv.FormatFloat(float64(ppm)/10_000.0, 'f', 4, 64)
	trimmed := strings.TrimRight(strings.TrimRight(text, "0"), ".")
	if trimmed == "" {
		return "0"
	}
	return trimmed
}

// DescribeMintFee renders a fee for a human.
func DescribeMintFee(fee MintFee) string {
	parts := make([]string, 0, 2)
	if fee.BaseFeeMsat > 0 {
		parts = append(parts, fmt.Sprintf("%d sat flat", (fee.BaseFeeMsat+500)/1000))
	}
	if fee.FeePpm > 0 {
		parts = append(parts, FormatFeePercent(fee.FeePpm)+"% of the amount paid")
	}
	return strings.Join(parts, " + ")
}
