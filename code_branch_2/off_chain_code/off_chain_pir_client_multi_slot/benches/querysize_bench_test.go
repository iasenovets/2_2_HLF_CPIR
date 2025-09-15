// querysize_bench_test.go
package main

import (
	"encoding/csv"
	"fmt"
	"os"
	"testing"
)

const (
	epochs      = 30
	dbSize      = 128
	slotsPerRec = 256
	targetIndex = 13
)

func BenchmarkQuerySize(b *testing.B) {
	params, _, pk, err := GenKeys()
	if err != nil {
		b.Fatal(err)
	}

	f, err := os.Create("query_size.csv")
	if err != nil {
		b.Fatal(err)
	}
	defer f.Close()
	w := csv.NewWriter(f)
	defer w.Flush()
	w.Write([]string{"epoch", "query_bytes", "query_kb"}) // Header

	for epoch := 1; epoch <= epochs; epoch++ {
		_, byteLen, err := EncryptQueryBase64(params, pk, targetIndex, dbSize, slotsPerRec)
		if err != nil {
			b.Fatalf("epoch %d: %v", epoch, err)
		}
		kb := float64(byteLen) / 1024.0
		w.Write([]string{fmt.Sprint(epoch), fmt.Sprint(byteLen), fmt.Sprintf("%.3f", kb)})
	}
}
