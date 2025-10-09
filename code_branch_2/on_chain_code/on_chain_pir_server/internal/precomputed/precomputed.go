// internal/precomputed/precomputed.go
package precomputed

// Fill these with your actual Base64 ciphertexts.
// NOTE: Must match EXACTLY the params used to build m_DB (LogN, LogQi/LogPi, T, levels).
// use this crap only if you want to invoke via cli (peer query..); otherwise just use client app

// PrecomputedCtqB64 maps LogN -> Base64-encoded selector ciphertext.
// Exported so you can inspect or test if needed.
var PrecomputedCtqB64 = map[int]string{
	13: ctqLogN13,
	14: ctqLogN14,
	15: ctqLogN15,
}

// B64ForLogN returns the baked Base64 ciphertext for a given LogN.
func B64ForLogN(logN int) (string, bool) {
	b64, ok := PrecomputedCtqB64[logN]
	return b64, ok && len(b64) > 0
}
