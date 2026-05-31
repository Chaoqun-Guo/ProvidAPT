// ProvidAPT De-anonymization Tool
//
// Authorized auditors use this tool to recover original sensitive
// values (file paths, IP addresses) from anonymized hashes.
//
// Usage:
//   providapt-deanon -hash a3f8b2c1e4d5f6a7 -key /etc/providapt/deanon.key
//   providapt-deanon -hash a3f8b2c1e4d5f6a7 -store /var/lib/providapt/deanon.json
//
// The tool requires the encryption key that was used when the
// data was anonymized.  This key must be stored securely and
// only accessible to authorized personnel.
package main

import (
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/Chaoqun-Guo/ProvidAPT/pkg/anonymize"
)

func main() {
	var (
		hash       = flag.String("hash", "", "Anonymized hash to de-anonymize")
		hashFile   = flag.String("hash-file", "", "File containing hashes (one per line)")
		storePath  = flag.String("store", "/var/lib/providapt/deanon.json", "De-anonymization store path")
		keyFile    = flag.String("key", "", "Key file (JSON with HMACKeyHex and EncKeyHex)")
		listKeys   = flag.Bool("list", false, "List all available de-anon entries")
	)
	flag.Parse()

	if *hash == "" && *hashFile == "" && !*listKeys {
		fmt.Println("ProvidAPT De-anonymization Tool")
		fmt.Println("================================")
		fmt.Println()
		fmt.Println("Usage:")
		fmt.Println("  providapt-deanon -hash <hash> -key <keyfile>")
		fmt.Println("  providapt-deanon -hash-file <path> -key <keyfile>")
		fmt.Println("  providapt-deanon -list -key <keyfile>")
		fmt.Println()
		flag.PrintDefaults()
		os.Exit(1)
	}

	// Load encryption key
	var encKeyHex string
	if *keyFile != "" {
		cfg, err := anonymize.LoadKeyFile(*keyFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error loading key file %s: %v\n", *keyFile, err)
			os.Exit(1)
		}
		encKeyHex = cfg.EncKeyHex
	}

	// Initialize de-anon store
	store, err := anonymize.NewDeAnonStore(*storePath, hexToKey(encKeyHex))
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error opening de-anon store: %v\n", err)
		os.Exit(1)
	}

	// List entries
	if *listKeys {
		fmt.Printf("De-anonymization store: %s (%d entries)\n", *storePath, store.EntryCount())
		os.Exit(0)
	}

	// Single hash lookup
	if *hash != "" {
		original, err := store.Lookup(*hash)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Lookup failed: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Hash:     %s\n", *hash)
		fmt.Printf("Original: %s\n", original)
	}

	// File of hashes
	if *hashFile != "" {
		data, err := os.ReadFile(*hashFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Read hash file: %v\n", err)
			os.Exit(1)
		}
		var lookup []struct {
			Hash     string `json:"hash"`
			Original string `json:"original"`
		}
		if err := json.Unmarshal(data, &lookup); err == nil {
			for _, item := range lookup {
				orig, err := store.Lookup(item.Hash)
				if err == nil {
					fmt.Printf("%s → %s\n", item.Hash, orig)
				}
			}
		}
	}
}

func hexToKey(hexKey string) []byte {
	if hexKey == "" {
		return make([]byte, 32)
	}
	key, err := hex.DecodeString(hexKey)
	if err != nil || len(key) != 32 {
		return make([]byte, 32)
	}
	return key
}
