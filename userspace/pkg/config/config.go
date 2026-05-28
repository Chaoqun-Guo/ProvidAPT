package config

import (
	"encoding/json"
	"os"
)

// Config holds all ProvidAPT configuration.
type Config struct {
	Kernel struct {
		Verbose bool     `json:"verbose"`
		Hooks   []string `json:"hooks"` // which LSM hooks to enable
	} `json:"kernel"`
	Output struct {
		Dir    string `json:"dir"`
		Format string `json:"format"` // "json" or "parquet"
	} `json:"output"`
	Capture struct {
		MaxEvents    int  `json:"max_events"`    // 0 = unlimited
		EnableNet    bool `json:"enable_net"`    // capture network events
		EnableFile   bool `json:"enable_file"`   // capture file events
		EnableProc   bool `json:"enable_proc"`   // capture process events
		SensitiveDir bool `json:"sensitive_dir"` // /etc, /home, /var/log only
	} `json:"capture"`
	API struct {
		GRPC string `json:"grpc"` // gRPC listen address, e.g. ":50051"
		REST string `json:"rest"` // REST listen address, e.g. ":8080"
	} `json:"api"`
}

// DefaultConfig returns a configuration with sensible defaults.
func DefaultConfig() *Config {
	c := &Config{}
	c.Kernel.Verbose = false
	c.Kernel.Hooks = []string{"task_alloc", "task_free", "file_open",
		"bprm_check_security", "socket_connect"}
	c.Output.Dir = "/var/log/providapt"
	c.Output.Format = "json"
	c.Capture.EnableNet = true
	c.Capture.EnableFile = true
	c.Capture.EnableProc = true
	c.API.GRPC = ":50051"
	return c
}

// Load reads configuration from a JSON file.
// Falls back to defaults if the file doesn't exist.
func Load(path string) (*Config, error) {
	cfg := DefaultConfig()

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return cfg, nil
		}
		return nil, err
	}

	if err := json.Unmarshal(data, cfg); err != nil {
		return nil, err
	}
	return cfg, nil
}
