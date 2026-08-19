package lnurlcash

import (
	"strconv"
	"strings"
)

// Only what a caller needs to bind a service's response to the payment it asked
// for. No full TLV decode: the amount lives in the human-readable part, and
// equality is a normalised string compare.

// IsBolt11Invoice is a loose shape check, anchored to actual bolt11 prefixes
// rather than a bare "ln", which a bech32 LNURL would also match.
//
// It splits at the separator first, exactly as the decoder does. Scanning left
// to right instead is subtly wrong: an amountless invoice's separator IS a
// digit, so a greedy digit scan swallows it and then finds no separator at all.
func IsBolt11Invoice(value string) bool {
	lowered := strings.ToLower(strings.TrimSpace(value))
	hrp, data, ok := splitAtSeparator(lowered)
	if !ok || data == "" {
		return false
	}
	for i := 0; i < len(data); i++ {
		c := data[i]
		if !((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')) {
			return false
		}
	}
	_, _, ok = parseHrp(hrp)
	return ok
}

// SameInvoice compares two invoices. bolt11 is bech32, so case-insensitive.
//
// Used to bind a verify response, or a melt proof, to the exact invoice it
// claims to report on - a settled result for some OTHER invoice must never
// confirm this payment.
func SameInvoice(a, b string) bool {
	return strings.EqualFold(strings.TrimSpace(a), strings.TrimSpace(b))
}

func stripNetworkPrefix(lowered string) (string, bool) {
	rest, found := strings.CutPrefix(lowered, "ln")
	if !found {
		return "", false
	}
	// longest first: "bcrt" must win over "bc"
	for _, prefix := range []string{"bcrt", "bc", "tbs", "tb", "sb"} {
		if tail, found := strings.CutPrefix(rest, prefix); found {
			return tail, true
		}
	}
	return "", false
}

// the bech32 separator is the LAST '1', since data characters can be '1' too
func splitAtSeparator(lowered string) (string, string, bool) {
	index := strings.LastIndex(lowered, "1")
	if index < 2 {
		return "", "", false
	}
	return lowered[:index], lowered[index+1:], true
}

// parseHrp reads the human-readable part after "ln" and the network: an
// optional amount and an optional multiplier, and nothing else.
func parseHrp(hrp string) (string, string, bool) {
	rest, ok := stripNetworkPrefix(hrp)
	if !ok {
		return "", "", false
	}
	end := 0
	for end < len(rest) && rest[end] >= '0' && rest[end] <= '9' {
		end++
	}
	digits, multiplier := rest[:end], rest[end:]
	switch multiplier {
	case "", "m", "u", "n", "p":
		return digits, multiplier, true
	default:
		return "", "", false
	}
}

// DecodeBolt11AmountMsat reads the amount out of an invoice's human-readable
// part. Returns false for an amountless invoice, for anything that does not
// parse, and for a pico amount that is not a whole number of msat.
func DecodeBolt11AmountMsat(pr string) (int64, bool) {
	lowered := strings.ToLower(strings.TrimSpace(pr))
	hrp, _, ok := splitAtSeparator(lowered)
	if !ok {
		return 0, false
	}
	digits, multiplier, ok := parseHrp(hrp)
	if !ok || digits == "" {
		return 0, false
	}
	value, err := strconv.ParseInt(digits, 10, 64)
	if err != nil {
		return 0, false
	}
	switch multiplier {
	case "":
		return value * 100_000_000_000, true
	case "m":
		return value * 100_000_000, true
	case "u":
		return value * 100_000, true
	case "n":
		return value * 100, true
	case "p":
		// 1 pico-BTC is 0.1 msat, so only multiples of 10 are whole msat
		if value%10 != 0 {
			return 0, false
		}
		return value / 10, true
	}
	return 0, false
}
