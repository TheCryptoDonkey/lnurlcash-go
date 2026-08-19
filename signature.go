package lnurlcash

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/btcsuite/btcd/btcec/v2/ecdsa"
)

// LUD-25 offline verification.
//
// A service may sign each note it issues with its Lightning node identity key
// (the same key it signs BOLT-11 invoices with), so a holder can confirm a
// note's issuer and amount without contacting anyone. Signed via the node's own
// signmessage RPC (lnd's /v1/signmessage, cln's signmessage), which wraps the
// message with this prefix and double-SHA256s it before signing. That is
// deliberate reuse: any tool that already verifies a Lightning node's signed
// messages can verify a note.
//
//	message = "LNURLcash:" || amount_msat (decimal ASCII) || ":" || hex(sha256(k1))
//	digest  = sha256(sha256("Lightning Signed Message:" || message))
//
// The signature commits to the note's HASH, not its secret, so a holder can
// prove issuance - to expose a mint that will not honour its own note - without
// revealing what would let anyone spend it.

const lightningSignedMessagePrefix = "Lightning Signed Message:"

// NoteSignatureMessage returns the message a note's signature commits to.
func NoteSignatureMessage(k1 string, amountMsat int64) (string, error) {
	id, err := HashK1(k1)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("LNURLcash:%d:%s", amountMsat, id), nil
}

// NoteSignatureDigest returns the digest a signer actually put its pen to.
func NoteSignatureDigest(k1 string, amountMsat int64) ([]byte, error) {
	message, err := NoteSignatureMessage(k1, amountMsat)
	if err != nil {
		return nil, err
	}
	inner := sha256.Sum256([]byte(lightningSignedMessagePrefix + message))
	outer := sha256.Sum256(inner[:])
	return outer[:], nil
}

// VerifyNoteSignature recovers the signer's pubkey and checks it against
// mintPubkeyHex.
//
// The signature is 65 bytes, but which end carries the recovery id varies by
// implementation: LUD-25 calls for r || s || recovery_id, the layout raw
// BOLT-11 signatures use, while lnurl-mint once forwarded its node's
// signmessage output unreordered as recovery_id || r || s. That is fixed
// upstream, but other implementations may still get it wrong.
//
// Trying both orderings costs nothing security-wise - recovering against the
// wrong one yields an unrelated pubkey that cannot match - and means a note
// verifies regardless of which convention issued it.
//
// Never panics. An unverifiable signature is a false.
func VerifyNoteSignature(k1 string, amountMsat int64, signatureHex, mintPubkeyHex string) bool {
	signature, err := hex.DecodeString(strings.TrimSpace(signatureHex))
	if err != nil || len(signature) != 65 {
		return false
	}
	digest, err := NoteSignatureDigest(k1, amountMsat)
	if err != nil {
		// a malformed k1 cannot be hashed - not a panic, a "no"
		return false
	}
	target := strings.ToLower(strings.TrimSpace(mintPubkeyHex))

	// btcec wants the recovery id FIRST, offset by 27 (the compact-signature
	// convention). Neither wire layout is that, so both need rebuilding.
	trailing := make([]byte, 65)
	trailing[0] = signature[64] + 27
	copy(trailing[1:], signature[:64])

	leading := make([]byte, 65)
	leading[0] = signature[0] + 27
	copy(leading[1:], signature[1:])

	for _, candidate := range [][]byte{trailing, leading} {
		if candidate[0] < 27 || candidate[0] > 34 {
			continue
		}
		pubkey, _, err := ecdsa.RecoverCompact(candidate, digest)
		if err != nil {
			// not a valid recovery under this ordering - try the other
			continue
		}
		if hex.EncodeToString(pubkey.SerializeCompressed()) == target {
			return true
		}
	}
	return false
}
