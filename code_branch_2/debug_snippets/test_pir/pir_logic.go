package main

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/schemes/bgv"
)

/********************************************************************
 * GLOBAL debug switch – set to true to see all trace output
 ********************************************************************/
var Debug = true

// ---------- 1. Key & Parameter helpers ----------

// ParamsLiteral128 returns a minimal BGV parameter set that
// supports 1 ciphertext×plaintext multiplication at ≈128-bit
// security and 8192 plaintext slots (N = 2¹³).
//
//   - LogN            : ring degree = 8192
//   - Q               : ciphertext modulus chain (one 46-bit prime)
//   - P               : special primes for key-switching (not used here
//     but must be non-empty if you later add relinearisation)
//   - PlaintextModulus: an NTT-friendly prime (T ≡ 1 mod 2·N)
//     65537 is the textbook choice.
func ParamsLiteral128() bgv.ParametersLiteral {
	lit := bgv.ParametersLiteral{
		LogN:             13,        // 2^13 = 8192
		LogQ:             []int{54}, // one 54-bit ciphertext prime (picked automatically)
		LogP:             []int{54}, // one 54-bit special prime for keyswitch (future-proof)
		PlaintextModulus: 65537,     // T
	}
	if Debug {
		fmt.Printf("[DBG] ParamsLiteral: N=%d | Qbits=%v | Pbits=%v | T=%d\n",
			1<<lit.LogN, lit.LogQ, lit.LogP, lit.PlaintextModulus)
	}
	return lit
}

// GenKeys produces a fresh BGV keypair and returns (params, sk, pk).
func GenKeys() (bgv.Parameters, *rlwe.SecretKey, *rlwe.PublicKey, error) {
	params, err := bgv.NewParametersFromLiteral(ParamsLiteral128())
	if err != nil {
		return params, nil, nil, err
	}
	kgen := bgv.NewKeyGenerator(params)
	sk, pk := kgen.GenKeyPairNew()

	if Debug {
		fmt.Printf("[DBG] KeyGen done   : skID=%p  pkID=%p\n", sk, pk)
		fmt.Printf("       MaxLevel     : %d  (|Q|=%d prime)\n",
			params.MaxLevel(), len(params.Q()))
		fmt.Printf("       MaxSlots     : %d\n", params.MaxSlots())
	}

	return params, sk, pk, nil
}

// ---------- 2. Encrypt PIR query ----------

// EncryptQueryBase64 creates a one-hot vector for index i and returns
// the ciphertext as Base64 (ready to send to chaincode).
func EncryptQueryBase64(params bgv.Parameters, pk *rlwe.PublicKey, index, dbSize int) (string, error) {
	if index < 0 || index >= dbSize {
		return "", fmt.Errorf("index %d out of range 0..%d", index, dbSize-1)
	}
	slots := params.MaxSlots() // ≤ 8192 in our 2¹³ setup
	if dbSize > slots {
		return "", fmt.Errorf("dbSize (%d) exceeds slot capacity (%d)", dbSize, slots)
	}

	encoder := bgv.NewEncoder(params)
	encryptor := bgv.NewEncryptor(params, pk)

	// 1. Build one-hot vector of full slot length (padding zeros automatically OK)
	vec := make([]uint64, slots)
	vec[index] = 1

	if Debug {
		// show first 100 entries of plaintext vector
		peek := 100
		if peek > len(vec) {
			peek = len(vec)
		}
		fmt.Printf("[DBG] PlaintextVec  (first %d slots): %v ...\n",
			peek, vec[:peek])
	}

	// 2. Encode at *max level* for best noise budget
	pt := bgv.NewPlaintext(params, params.MaxLevel()) // len(Q)-1
	if err := encoder.Encode(vec, pt); err != nil {
		return "", err
	}

	ct, err := encryptor.EncryptNew(pt)
	if err != nil {
		return "", err
	}

	ctBytes, _ := ct.MarshalBinary()
	b64 := base64.StdEncoding.EncodeToString(ctBytes)

	if Debug {
		fmt.Printf("[DBG] EncryptQuery  : index=%d  dbSize=%d  slots=%d\n",
			index, dbSize, slots)
		fmt.Printf("       Ciphertext   : byteLen=%d  level=%d  degree=%d\n",
			len(ctBytes), ct.Level(), ct.Degree())
		// Show first 48 chars of Base64 for sanity
		head := b64
		if len(head) > 48 {
			head = head[:48] + "..."
		}
		fmt.Printf("       EncQueryB64  : %s\n", head)
	}

	return b64, nil
}

// ---------- 3. Decrypt result ----------

// DecryptResult decodes the Base64 ciphertext returned by chaincode,
// decrypts it and returns either an integer (single-slot) or a JSON string.
type Decoded struct {
	IntValue   uint64 // if single slot record
	JSONString string // if record was multi-slot JSON
}

// DecryptResult decrypts the ciphertext (base64) and extracts either
// a single-slot integer or a multi-slot JSON string.
//
//   - index           : record index originally queried (0-based)
//   - dbSize          : total number of records in the DB
//   - slotsPerRecord  : 1 for a single-slot record; >1 if each record spans
//     several slots (e.g. JSON bytes)
func DecryptResult(params bgv.Parameters, sk *rlwe.SecretKey, encResBase64 string,
	index, dbSize, slotsPerRecord int) (Decoded, error) {

	var out Decoded

	// --- 1) deserialize ciphertext ------------------------------
	ctBytes, err := base64.StdEncoding.DecodeString(encResBase64)
	if err != nil {
		return out, err
	}
	ct := rlwe.NewCiphertext(params, 1) // degree-1 result (one mul)
	if err = ct.UnmarshalBinary(ctBytes); err != nil {
		return out, err
	}

	// --- 2) decrypt ---------------------------------------------
	decryptor := bgv.NewDecryptor(params, sk)
	encoder := bgv.NewEncoder(params)

	pt := decryptor.DecryptNew(ct)

	// allocate a slice large enough for all slots
	slots := params.MaxSlots()
	vec := make([]uint64, slots)

	// Decode writes into our slice
	if err = encoder.Decode(pt, vec); err != nil {
		return out, err
	}

	/* -------------------- debugging prints -------------------- */
	if Debug {
		fmt.Printf("[DBG] DecCiphertext : byteLen=%d  level=%d  degree=%d\n",
			len(ctBytes), ct.Level(), ct.Degree())
		fmt.Printf("       Slot[%d]      : %d  (expect non-zero)\n", index, vec[index])

		// print a sparse view of vector (first 8 non-zero slots)
		if slotsPerRecord == 1 {
			var idxVals []string
			for i, v := range vec {
				if v != 0 {
					idxVals = append(idxVals, fmt.Sprintf("%d:%d", i, v))
					if len(idxVals) == 8 {
						break
					}
				}
			}
			fmt.Printf("       NonZeroSlots : %s\n", strings.Join(idxVals, ", "))
		}
	}

	// --- 3) extract requested record ----------------------------
	if len(vec) < dbSize*slotsPerRecord {
		return out, errors.New("vec slice shorter than expected")
	}

	if slotsPerRecord == 1 {
		out.IntValue = vec[index]
		return out, nil
	}

	start := index * slotsPerRecord
	end := start + slotsPerRecord

	// convert non-zero uint64s back to bytes
	buf := make([]byte, 0, slotsPerRecord)
	for _, v := range vec[start:end] {
		if v == 0 { // padding terminator
			break
		}
		buf = append(buf, byte(v))
	}
	if !json.Valid(buf) {
		return out, errors.New("decoded payload is not valid JSON")
	}
	out.JSONString = string(buf)
	if Debug {
		fmt.Printf("       JSON record  : %s\n", out.JSONString)
	}
	return out, nil
}
