package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"
)

func main() {
	baseURL := getenv("PROVIDAPT_URL", "http://localhost:18080")
	client := &http.Client{Timeout: 10 * time.Second}

	for _, path := range []string{"/api/v1/status", "/api/v1/control/fleet", "/api/v1/alerts"} {
		body, err := get(client, baseURL+path)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s: %v\n", path, err)
			continue
		}
		var value any
		if err := json.Unmarshal(body, &value); err != nil {
			fmt.Printf("== %s ==\n%s\n", path, string(body))
			continue
		}
		pretty, _ := json.MarshalIndent(value, "", "  ")
		fmt.Printf("== %s ==\n%s\n", path, pretty)
	}
}

func get(client *http.Client, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return body, fmt.Errorf("HTTP %s: %s", resp.Status, string(body))
	}
	return body, nil
}

func getenv(key string, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}
