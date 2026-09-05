package util

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

const (
	benchmarkGeoHTTPConcurrency = http.DefaultMaxIdleConnsPerHost
	benchmarkGeoHTTPClientCount = 4
)

var (
	benchmarkGeoHTTPBytesSink  int64
	benchmarkGeoHTTPClientSink *http.Client
)

func BenchmarkNewGeoHTTPClient(b *testing.B) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "geo")
	}))
	b.Cleanup(server.Close)

	b.Run("Construct", func(b *testing.B) {
		b.ReportAllocs()
		var client *http.Client
		for b.Loop() {
			client = NewGeoHTTPClient(5 * time.Second)
		}
		b.ReportMetric(1, "clients/op")
		benchmarkGeoHTTPClientSink = client
	})

	b.Run("Sequential", func(b *testing.B) {
		client := NewGeoHTTPClient(5 * time.Second)
		b.Cleanup(client.CloseIdleConnections)

		b.ReportAllocs()
		var total int64
		for b.Loop() {
			n, err := runGeoHTTPBenchmarkRequest(client, server.URL)
			if err != nil {
				b.Fatal(err)
			}
			total += n
		}
		benchmarkGeoHTTPBytesSink = total
	})

	b.Run(fmt.Sprintf("Concurrent%d", benchmarkGeoHTTPConcurrency), func(b *testing.B) {
		client := NewGeoHTTPClient(5 * time.Second)
		b.Cleanup(client.CloseIdleConnections)
		results := make([]int64, benchmarkGeoHTTPConcurrency)
		errs := make([]error, benchmarkGeoHTTPConcurrency)

		b.ReportAllocs()
		var total int64
		for b.Loop() {
			var wg sync.WaitGroup
			wg.Add(benchmarkGeoHTTPConcurrency)
			for i := 0; i < benchmarkGeoHTTPConcurrency; i++ {
				go func(index int) {
					defer wg.Done()
					results[index], errs[index] = runGeoHTTPBenchmarkRequest(client, server.URL)
				}(i)
			}
			wg.Wait()
			for i, err := range errs {
				if err != nil {
					b.Fatalf("request %d: %v", i, err)
				}
				total += results[i]
			}
		}
		b.ReportMetric(benchmarkGeoHTTPConcurrency, "requests/op")
		benchmarkGeoHTTPBytesSink = total
	})

	b.Run("MultiClientSequential", func(b *testing.B) {
		clients := newGeoHTTPBenchmarkClients(benchmarkGeoHTTPClientCount)
		b.Cleanup(func() { closeGeoHTTPBenchmarkClients(clients) })
		warmGeoHTTPBenchmarkClients(b, clients, server.URL)

		b.ReportAllocs()
		var total int64
		clientIndex := 0
		for b.Loop() {
			n, err := runGeoHTTPBenchmarkRequest(clients[clientIndex], server.URL)
			if err != nil {
				b.Fatalf("client %d: %v", clientIndex, err)
			}
			total += n
			clientIndex++
			if clientIndex == len(clients) {
				clientIndex = 0
			}
		}
		b.ReportMetric(benchmarkGeoHTTPClientCount, "clients/set")
		b.ReportMetric(1, "requests/op")
		benchmarkGeoHTTPBytesSink = total
	})

	b.Run("MultiClientConcurrent", func(b *testing.B) {
		clients := newGeoHTTPBenchmarkClients(benchmarkGeoHTTPClientCount)
		b.Cleanup(func() { closeGeoHTTPBenchmarkClients(clients) })
		warmGeoHTTPBenchmarkClients(b, clients, server.URL)
		results := make([]int64, benchmarkGeoHTTPClientCount)
		errs := make([]error, benchmarkGeoHTTPClientCount)

		b.ReportAllocs()
		var total int64
		for b.Loop() {
			var wg sync.WaitGroup
			wg.Add(benchmarkGeoHTTPClientCount)
			for i, client := range clients {
				go func(index int, requestClient *http.Client) {
					defer wg.Done()
					results[index], errs[index] = runGeoHTTPBenchmarkRequest(requestClient, server.URL)
				}(i, client)
			}
			wg.Wait()
			for i, err := range errs {
				if err != nil {
					b.Fatalf("client %d: %v", i, err)
				}
				total += results[i]
			}
		}
		b.ReportMetric(benchmarkGeoHTTPClientCount, "clients/set")
		b.ReportMetric(benchmarkGeoHTTPClientCount, "requests/op")
		benchmarkGeoHTTPBytesSink = total
	})
}

func BenchmarkNewSharedGeoHTTPClient(b *testing.B) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "geo")
	}))
	b.Cleanup(server.Close)

	b.Run("Construct", func(b *testing.B) {
		b.ReportAllocs()
		var client *http.Client
		for b.Loop() {
			client = NewSharedGeoHTTPClient(5 * time.Second)
		}
		b.ReportMetric(1, "clients/op")
		benchmarkGeoHTTPClientSink = client
	})

	b.Run("MultiClientSequential", func(b *testing.B) {
		clients := newSharedGeoHTTPBenchmarkClients(benchmarkGeoHTTPClientCount)
		b.Cleanup(func() { closeGeoHTTPBenchmarkClients(clients) })
		warmGeoHTTPBenchmarkClients(b, clients, server.URL)

		b.ReportAllocs()
		var total int64
		clientIndex := 0
		for b.Loop() {
			n, err := runGeoHTTPBenchmarkRequest(clients[clientIndex], server.URL)
			if err != nil {
				b.Fatalf("client %d: %v", clientIndex, err)
			}
			total += n
			clientIndex++
			if clientIndex == len(clients) {
				clientIndex = 0
			}
		}
		b.ReportMetric(benchmarkGeoHTTPClientCount, "clients/set")
		b.ReportMetric(1, "requests/op")
		benchmarkGeoHTTPBytesSink = total
	})

	b.Run("MultiClientConcurrent", func(b *testing.B) {
		clients := newSharedGeoHTTPBenchmarkClients(benchmarkGeoHTTPClientCount)
		b.Cleanup(func() { closeGeoHTTPBenchmarkClients(clients) })
		warmGeoHTTPBenchmarkClients(b, clients, server.URL)
		results := make([]int64, benchmarkGeoHTTPClientCount)
		errs := make([]error, benchmarkGeoHTTPClientCount)

		b.ReportAllocs()
		var total int64
		for b.Loop() {
			var wg sync.WaitGroup
			wg.Add(benchmarkGeoHTTPClientCount)
			for i, client := range clients {
				go func(index int, requestClient *http.Client) {
					defer wg.Done()
					results[index], errs[index] = runGeoHTTPBenchmarkRequest(requestClient, server.URL)
				}(i, client)
			}
			wg.Wait()
			for i, err := range errs {
				if err != nil {
					b.Fatalf("client %d: %v", i, err)
				}
				total += results[i]
			}
		}
		b.ReportMetric(benchmarkGeoHTTPClientCount, "clients/set")
		b.ReportMetric(benchmarkGeoHTTPClientCount, "requests/op")
		benchmarkGeoHTTPBytesSink = total
	})
}

func newGeoHTTPBenchmarkClients(count int) []*http.Client {
	clients := make([]*http.Client, count)
	for i := range clients {
		clients[i] = NewGeoHTTPClient(5 * time.Second)
	}
	return clients
}

func newSharedGeoHTTPBenchmarkClients(count int) []*http.Client {
	clients := make([]*http.Client, count)
	for i := range clients {
		clients[i] = NewSharedGeoHTTPClient(5 * time.Second)
	}
	return clients
}

func closeGeoHTTPBenchmarkClients(clients []*http.Client) {
	for _, client := range clients {
		client.CloseIdleConnections()
	}
}

func warmGeoHTTPBenchmarkClients(b *testing.B, clients []*http.Client, url string) {
	b.Helper()
	for i, client := range clients {
		if _, err := runGeoHTTPBenchmarkRequest(client, url); err != nil {
			b.Fatalf("warm client %d: %v", i, err)
		}
	}
}

func runGeoHTTPBenchmarkRequest(client *http.Client, url string) (int64, error) {
	resp, err := client.Get(url)
	if err != nil {
		return 0, err
	}
	n, readErr := io.Copy(io.Discard, resp.Body)
	closeErr := resp.Body.Close()
	if readErr != nil {
		return 0, readErr
	}
	if closeErr != nil {
		return 0, closeErr
	}
	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("unexpected HTTP status %s", resp.Status)
	}
	return n, nil
}
