package lnurlcash

import (
	"net/url"
	"regexp"
	"strings"

	"github.com/btcsuite/btcd/btcutil/bech32"
)

// these hosts (plus .onion) resolve to http:// rather than https://
var insecureHosts = map[string]bool{"127.0.0.1": true, "0.0.0.0": true, "localhost": true}

func isInsecureHost(host string) bool {
	host = strings.ToLower(host)
	return insecureHosts[host] || strings.HasSuffix(host, ".onion")
}

func trimSpace(s string) string { return strings.TrimSpace(s) }

var (
	lud17Re            = regexp.MustCompile(`(?i)^(?:lnurlw|lnurlp|lnurlc|keyauth)://([^/]+)`)
	lightningAddressRe = regexp.MustCompile(`^[^\s@]+@[^\s@]+\.[^\s@]+$`)
	bareDomainRe       = regexp.MustCompile(`^@?[^\s@/]+\.[^\s@/]+$`)
	lnurlpPathRe       = regexp.MustCompile(`^(.*/\.well-known/)lnurlp/([^/]+)$`)
)

// IsBech32Lnurl reports whether text looks like a bech32 LNURL.
func IsBech32Lnurl(data string) bool {
	return strings.HasPrefix(strings.ToUpper(strings.TrimSpace(data)), "LNURL1")
}

// ToBech32Lnurl encodes a URL as an LNURL (LUD-01).
func ToBech32Lnurl(rawURL string) (string, error) {
	converted, err := bech32.ConvertBits([]byte(rawURL), 8, 5, true)
	if err != nil {
		return "", err
	}
	encoded, err := bech32.Encode("lnurl", converted)
	if err != nil {
		return "", err
	}
	return strings.ToUpper(encoded), nil
}

// FromBech32Lnurl decodes an LNURL back to its URL, or "" if it is not one.
func FromBech32Lnurl(data string) string {
	trimmed := strings.TrimSpace(data)
	if !IsBech32Lnurl(trimmed) {
		return ""
	}
	// DecodeNoLimit, not Decode: bech32's 90-character cap is far below what a
	// note URL carrying k1, amount and sig needs.
	hrp, words, err := bech32.DecodeNoLimit(strings.ToLower(trimmed))
	if err != nil || hrp != "lnurl" {
		return ""
	}
	decoded, err := bech32.ConvertBits(words, 5, 8, false)
	if err != nil {
		return ""
	}
	return string(decoded)
}

// IsAllowedServiceURL is the one admission rule every URL must pass, whether it
// came from a scanned or pasted note or from a service's own response
// (callback, verify, payLink): https anywhere, http only for loopback and
// .onion.
//
// Anything else - data:, file:, a bare http:// clearnet host - is rejected, so
// a crafted note cannot answer its own informational GET (a data: URL carrying
// withdrawRequest JSON would otherwise mint a self-contained fake note), and a
// service cannot redirect a k1-bearing callback onto cleartext.
func IsAllowedServiceURL(value string) bool {
	parsed, err := url.Parse(value)
	if err != nil || parsed.Host == "" {
		return false
	}
	switch parsed.Scheme {
	case "https":
		return true
	case "http":
		return isInsecureHost(parsed.Hostname())
	default:
		return false
	}
}

// FromLud17 rewrites an lnurlw:// style URL to the scheme it should be fetched
// over.
func FromLud17(rawURL string) string {
	match := lud17Re.FindStringSubmatch(rawURL)
	if match == nil {
		return rawURL
	}
	host := strings.Split(match[1], ":")[0]
	scheme := "https"
	if isInsecureHost(host) {
		scheme = "http"
	}
	index := strings.Index(rawURL, "://")
	return scheme + rawURL[index:]
}

// ToLud17w rewrites an http(s) URL to the lnurlw:// form a note is shared in.
func ToLud17w(rawURL string) string {
	for _, prefix := range []string{"https://", "http://"} {
		if strings.HasPrefix(rawURL, prefix) {
			return "lnurlw://" + strings.TrimPrefix(rawURL, prefix)
		}
	}
	return rawURL
}

// IsLightningAddress reports whether text is a LUD-16 address. Strict: a host
// with no dot is not a domain name.
func IsLightningAddress(value string) bool {
	return lightningAddressRe.MatchString(strings.TrimSpace(value))
}

// isLoopbackLightningAddress covers a local dev address, "mint@localhost:8000".
// LUD-16 has no notion of it - IsLightningAddress stays strict - but pointing a
// wallet at a mint running on this machine is an ordinary thing to want, and
// the resolution below already handles the port and the cleartext scheme such a
// host needs.
func isLoopbackLightningAddress(value string) bool {
	parts := strings.Split(strings.TrimSpace(value), "@")
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return false
	}
	return isInsecureHost(strings.Split(parts[1], ":")[0])
}

func lnAddressToURL(address string) string {
	parts := strings.SplitN(strings.TrimSpace(address), "@", 2)
	if len(parts) != 2 {
		return ""
	}
	// the domain may carry a port (mint@127.0.0.1:8000) - the insecure-host
	// check is about the host part only
	scheme := "https"
	if isInsecureHost(strings.Split(parts[1], ":")[0]) {
		scheme = "http"
	}
	return scheme + "://" + parts[1] + "/.well-known/lnurlp/" + parts[0]
}

// isBareMintDomain covers a bare mint domain with no local part. It assumes the
// "mint" username that lnurl-mint itself defaults to, so a mint using a
// different one simply fails to resolve and must be typed out in full.
func isBareMintDomain(value string) bool {
	trimmed := strings.TrimSpace(value)
	if IsLightningAddress(trimmed) {
		return false
	}
	if bareDomainRe.MatchString(trimmed) {
		return true
	}
	return isInsecureHost(strings.Split(strings.TrimPrefix(trimmed, "@"), ":")[0])
}

// ResolveMintInput accepts a bech32 LNURL, a Lightning Address, or a bare mint
// domain - all of which point unambiguously at one payRequest.
func ResolveMintInput(value string) string {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return ""
	}
	if IsBech32Lnurl(trimmed) {
		decoded := FromBech32Lnurl(trimmed)
		if decoded != "" && IsAllowedServiceURL(decoded) {
			return decoded
		}
		return ""
	}
	if IsLightningAddress(trimmed) || isLoopbackLightningAddress(trimmed) {
		return lnAddressToURL(trimmed)
	}
	if isBareMintDomain(trimmed) {
		return lnAddressToURL("mint@" + strings.TrimPrefix(trimmed, "@"))
	}
	return ""
}

// ResolveLnurlInput resolves arbitrary LNURL-ish input down to a fetchable URL.
//
// Every URL-producing branch passes IsAllowedServiceURL, so a decoded or pasted
// URL can never smuggle in a non-https scheme or cleartext http to a clearnet
// host.
func ResolveLnurlInput(value string) string {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return ""
	}
	if IsBech32Lnurl(trimmed) {
		decoded := FromBech32Lnurl(trimmed)
		if decoded != "" && IsAllowedServiceURL(decoded) {
			return decoded
		}
		return ""
	}
	if lud17Re.MatchString(trimmed) {
		resolved := FromLud17(trimmed)
		if IsAllowedServiceURL(resolved) {
			return resolved
		}
		return ""
	}
	if IsLightningAddress(trimmed) || isLoopbackLightningAddress(trimmed) {
		return lnAddressToURL(trimmed)
	}
	lowered := strings.ToLower(trimmed)
	if strings.HasPrefix(lowered, "http://") || strings.HasPrefix(lowered, "https://") {
		if IsAllowedServiceURL(trimmed) {
			return trimmed
		}
	}
	return ""
}

// MintAddressURL returns the LUD-25 mint address (experimental): the
// withdraw-side mirror of a payRequest URL. Derived from the resolved
// payRequest URL rather than guessed - "" for anything not at the conventional
// well-known path.
func MintAddressURL(payURL string) string {
	parsed, err := url.Parse(payURL)
	if err != nil || parsed.Host == "" {
		return ""
	}
	match := lnurlpPathRe.FindStringSubmatch(parsed.Path)
	if match == nil {
		return ""
	}
	return parsed.Scheme + "://" + parsed.Host + match[1] + "lnurlw/" + match[2]
}

// LightningAddressUsername returns the username segment of a resolved
// payRequest URL, or "" if it is not at that path.
func LightningAddressUsername(payURL string) string {
	parsed, err := url.Parse(payURL)
	if err != nil {
		return ""
	}
	match := lnurlpPathRe.FindStringSubmatch(parsed.Path)
	if match == nil {
		return ""
	}
	return match[2]
}

// ServerOf returns a URL's host, for display and grouping.
func ServerOf(rawURL string) string {
	parsed, err := url.Parse(rawURL)
	if err != nil || parsed.Host == "" {
		return rawURL
	}
	return parsed.Host
}
