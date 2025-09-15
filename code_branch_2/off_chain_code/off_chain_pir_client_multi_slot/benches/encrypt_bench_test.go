// encrypt_bench_test.go
package main

import (
	"encoding/csv"
	"fmt"
	"os"
	"testing"
	"time"
)

// сколько раз подряд меряем latency (≡ «эпохи»)
const epochs = 30

// фиксируем базовые настройки БД, чтобы сравнивать «чистую» энеркрипцию
const (
	dbSize       = 64    // записей в БД
	slotsPerRec  = 512   // должен совпадать с сервером
	targetIndex  = 13    // любой допустимый индекс
	debugEncrypt = false // выключаем трейс внутри EncryptQueryBase64
)

// BenchmarkEncryptLatency запускается go test -bench
func BenchmarkEncryptLatency(b *testing.B) {
	// ❶ генерим ключи/параметры ОДИН раз перед всей серией
	params, _, pk, err := GenKeys()
	if err != nil {
		b.Fatal(err)
	}
	if debugEncrypt {
		Debug = true
	} else {
		Debug = false
	}

	// ❷ открываем CSV-файл для записи результатов
	f, err := os.Create("encrypt_latency.csv")
	if err != nil {
		b.Fatal(err)
	}
	defer f.Close()
	w := csv.NewWriter(f)
	defer w.Flush()
	w.Write([]string{"epoch", "latency_ms"}) // заголовок

	// ❸ собственно измерение
	for epoch := 1; epoch <= epochs; epoch++ {
		start := time.Now()
		_, byteLen, err := EncryptQueryBase64(params, pk, targetIndex, dbSize, slotsPerRec)
		elapsed := time.Since(start)
		if err != nil {
			b.Fatalf("epoch %d: %v", epoch, err)
		}
		fmt.Println("byte size =", byteLen)
		latMs := float64(elapsed.Nanoseconds()) / 1e6
		w.Write([]string{fmt.Sprint(epoch), fmt.Sprintf("%.3f", latMs)})
	}
}
