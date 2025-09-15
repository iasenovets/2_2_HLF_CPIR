package main

import (
	"encoding/csv"
	"fmt"
	"os"
	"strconv"
	"testing"
	"time"
)

// сколько раз подряд меряем latency (≡ «эпохи»)
const epochs = 30

// настройки теста
const (
	targetIndex = 13    // индекс для PIR-запроса
	numRecords  = "64"  // количество записей для InitLedger
	maxJsonLen  = "512" // максимальная длина JSON записи
	channelName = "channel_rich"
	//serverURL   = "http://localhost:8080/invoke"
)

// BenchmarkDecryptLatency измеряет только расшифровку + декодирование
func BenchmarkDecryptLatency(b *testing.B) {
	// ❶ генерим ключи и параметры (один раз для всех эпох)
	params, sk, pk, err := GenKeys()
	if err != nil {
		b.Fatal(err)
	}

	// ❷ инициализируем PTDB на сервере
	_, err = call("InitLedger", numRecords, maxJsonLen, channelName)
	if err != nil {
		b.Fatal("InitLedger failed:", err)
	}

	// получаем slotsPerRecord
	slotsStr, _ := call("GetSlotsPerRecord")
	slotsPerRec, _ := strconv.Atoi(slotsStr)

	// получаем общее количество записей
	totalStr, _ := call("PublicQueryALL")
	dbSize, _ := strconv.Atoi(totalStr)

	// шифруем запрос
	encQueryB64, _, err := EncryptQueryBase64(params, pk, targetIndex, dbSize, slotsPerRec)
	if err != nil {
		b.Fatal(err)
	}

	// отправляем PIR-запрос на сервер
	encResB64, err := call("PIRQuery", encQueryB64)
	if err != nil {
		b.Fatal("PIRQuery failed:", err)
	}

	// ❸ создаем CSV-файл для записи результатов
	f, err := os.Create("decrypt_latency.csv")
	if err != nil {
		b.Fatal(err)
	}
	defer f.Close()
	w := csv.NewWriter(f)
	defer w.Flush()
	w.Write([]string{"epoch", "latency_ms"}) // заголовок

	// ❹ измеряем расшифровку 30 раз
	for epoch := 1; epoch <= epochs; epoch++ {
		start := time.Now()
		_, err := DecryptResult(params, sk, encResB64, targetIndex, dbSize, slotsPerRec)
		if err != nil {
			b.Fatalf("epoch %d: %v", epoch, err)
		}
		elapsed := time.Since(start)
		latMs := float64(elapsed.Nanoseconds()) / 1e6
		w.Write([]string{fmt.Sprint(epoch), fmt.Sprintf("%.3f", latMs)})
	}
}
