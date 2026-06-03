package main

import (
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/Chaoqun-Guo/ProvidAPT/internal/version"
	"github.com/Chaoqun-Guo/ProvidAPT/pkg/anonymize"
	"github.com/Chaoqun-Guo/ProvidAPT/pkg/clioutput"
)

func usage() {
	fmt.Fprint(os.Stderr, `SYNOPSIS
    providapt-deanon [OPTIONS]

DESCRIPTION
    Recover original sensitive values (file paths, IP addresses)
    from anonymized hashes.  Requires the encryption key that was
    used during anonymization.

    ⚠  This tool is for AUTHORIZED auditors only.  The encryption
    key must be stored securely and accessible only to authorized
    personnel.

OPTIONS
`)
	flag.PrintDefaults()
	fmt.Fprint(os.Stderr, `
EXAMPLES
    providapt-deanon -hash a3f8b2c1... -key /etc/providapt/deanon.key
        Look up a single hash.

    providapt-deanon -hash-file hashes.json -key /etc/providapt/deanon.key
        Batch look up hashes from a JSON file.

    providapt-deanon -list -key /etc/providapt/deanon.key
        List all entries in the de-anonymization store.

    providapt-deanon -hash a3f8b2c1... -key deanon.key -json
        Output the result as JSON.
`)
}

func main() {
	var (
		hash       = flag.String("hash", "", "Anonymized hash to de-anonymize")
		hashFile   = flag.String("hash-file", "", "File containing hashes (one per line)")
		storePath  = flag.String("store", "/var/lib/providapt/deanon.json", "De-anonymization store path")
		keyFile    = flag.String("key", "", "Key file (JSON with HMACKeyHex and EncKeyHex)")
		listKeys   = flag.Bool("list", false, "List all available de-anon entries")
		jsonOut    = flag.Bool("json", false, "Output in JSON format")
	)
	flag.Usage = usage
	flag.Parse()

	clioutput.Init(*jsonOut)

	if *hash == "" && *hashFile == "" && !*listKeys {
		flag.Usage()
		os.Exit(1)
	}

	clioutput.PrintBanner(version.Version)

	// Load encryption key
	var encKeyHex string
	if *keyFile != "" {
		cfg, err := anonymize.LoadKeyFile(*keyFile)
		if err != nil {
			clioutput.Fatalf("Error loading key file %s: %v", *keyFile, err)
		}
		encKeyHex = cfg.EncKeyHex
	}

	// Initialize de-anon store
	store, err := anonymize.NewDeAnonStore(*storePath, hexToKey(encKeyHex))
	if err != nil {
		clioutput.Fatalf("Error opening de-anon store: %v", err)
	}

	// List entries
	if *listKeys {
		if clioutput.IsJSONMode() {
			clioutput.PrintJSON(struct {
				StorePath  string `json:"store_path"`
				EntryCount int    `json:"entry_count"`
			}{
				StorePath:  *storePath,
				EntryCount: store.EntryCount(),
			})
		} else {
			fmt.Printf("De-anonymization store: %s\n", clioutput.Infof(*storePath))
			t := clioutput.NewTable("Store", "Entries")
			t.AddRow(*storePath, fmt.Sprintf("%d", store.EntryCount()))
			t.Render()
		}
		os.Exit(0)
	}

	type lookupResult struct {
		Hash     string `json:"hash"`
		Original string `json:"original"`
		Found    bool   `json:"found"`
	}

	var results []lookupResult

	// Single hash lookup
	if *hash != "" {
		original, err := store.Lookup(*hash)
		found := err == nil
		results = append(results, lookupResult{
			Hash:     *hash,
			Original: original,
			Found:    found,
		})
	}

	// File of hashes
	if *hashFile != "" {
		data, err := os.ReadFile(*hashFile)
		if err != nil {
			clioutput.Fatalf("Read hash file: %v", err)
		}
		var lookup []struct {
			Hash string `json:"hash"`
		}
		if err := json.Unmarshal(data, &lookup); err == nil {
			for _, item := range lookup {
				orig, err := store.Lookup(item.Hash)
				results = append(results, lookupResult{
					Hash:     item.Hash,
					Original: orig,
					Found:    err == nil,
				})
			}
		}
	}

	if clioutput.IsJSONMode() {
		clioutput.PrintJSON(struct {
			Results []lookupResult `json:"results"`
		}{Results: results})
		return
	}

	t := clioutput.NewTable("Hash", "Original", "Status")
	for _, r := range results {
		status := clioutput.Okf("found")
		if !r.Found {
			status = clioutput.Errf("not found")
		}
		t.AddRow(r.Hash, r.Original, status)
	}
	t.Render()
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
