package main

import (
	"encoding/csv"
	"fmt"
	"log"
	"os"
	"testing"

	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/schemes/bgv"
)

// Parameters for benchmark
const (
	logN     = 13
	ptMod    = 65537
	logQ     = 54
	logP     = 54
	outFile  = "noise_growth.csv"
	maxIters = 1000
)

func BenchmarkNoiseGrowth(b *testing.B) {
	// Setup BGV parameters
	paramsLit := bgv.ParametersLiteral{
		LogN:             logN,
		LogQ:             []int{logQ},
		LogP:             []int{logP},
		PlaintextModulus: ptMod,
	}
	params, err := bgv.NewParametersFromLiteral(paramsLit)
	if err != nil {
		log.Fatalf("failed to create params: %v", err)
	}

	// KeyGen
	kgen := bgv.NewKeyGenerator(params)
	sk, pk := kgen.GenKeyPairNew()

	// Setup encoder/evaluator/encrypter
	encoder := bgv.NewEncoder(params)
	evaluator := bgv.NewEvaluator(params, nil)
	encryptor := bgv.NewEncryptor(params, pk)
	decryptor := bgv.NewDecryptor(params, sk)

	// Create a plaintext with small values
	slots := params.MaxSlots()
	plaintext := bgv.NewPlaintext(params, params.MaxLevel())
	data := make([]uint64, slots)
	for i := range data {
		data[i] = uint64(i % 2) // low Hamming weight to keep noise low
	}
	encoder.Encode(data, plaintext)

	// Encrypt
	cipher, _ := encryptor.EncryptNew(plaintext)

	// Open CSV file
	f, err := os.Create(outFile)
	if err != nil {
		log.Fatalf("failed to create csv: %v", err)
	}
	defer f.Close()
	writer := csv.NewWriter(f)
	defer writer.Flush()
	writer.Write([]string{"iteration", "noise_stddev", "level"})

	// Loop: multiply and measure noise
	for i := 0; i < maxIters; i++ {
		// Estimate noise
		stddev, _, _ := rlwe.Norm(cipher, decryptor)
		fmt.Printf("Iteration %d: noise = %.3f\n", i, stddev)

		// Write to CSV
		writer.Write([]string{
			fmt.Sprint(i),
			fmt.Sprintf("%.3f", stddev),
			fmt.Sprint(cipher.Level()),
		})

		// Try decryption
		ptres := bgv.NewPlaintext(params, params.MaxLevel())
		decryptor.Decrypt(cipher, ptres)
		if err != nil {
			fmt.Printf("Decryption failed at iteration %d\n", i)
			break
		}

		// Multiply ciphertext with itself
		err = evaluator.Mul(cipher, plaintext, cipher)
		if err != nil {
			fmt.Printf("Multiplication failed at iteration %d: %v\n", i, err)
			break
		}

		// Optional rescale
		// evaluator.Rescale(cipher, cipher)
	}
}
