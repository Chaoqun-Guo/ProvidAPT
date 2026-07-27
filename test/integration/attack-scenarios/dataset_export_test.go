package attackscenarios

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestGroundTruthDatasetExport(t *testing.T) {
	if runtime.GOOS == "windows" {
		if _, err := exec.LookPath("python"); err != nil {
			t.Skip("python not available")
		}
	} else if _, err := exec.LookPath("python3"); err != nil {
		t.Skip("python3 not available")
	}

	root := filepath.Clean(filepath.Join("..", "..", ".."))
	script := filepath.Join(root, "scripts", "evaluation", "export_ground_truth_dataset.py")
	inputDir := t.TempDir()
	outDir := filepath.Join(t.TempDir(), "dataset")
	truth := filepath.Join(inputDir, "truth.jsonl")
	data := strings.Join([]string{
		`{"schema":"providapt.attack_ground_truth.v1","run_id":"r1","category":"compromise","step_index":1,"step_id":"fc-01","step_name":"Execute shell","phase":"execution","tactic_id":"TA0002","tactic_name":"Execution","technique_id":"T1059.004","technique_name":"Unix Shell","command":"bash payload.sh","expected_event":"process_exec","expected_relation":"prov:wasInformedBy","actor":"bash","object":"pid:1","malicious":true}`,
		`{"schema":"providapt.attack_ground_truth.v1","run_id":"r1","category":"benign","step_index":2,"step_id":"fc-02","step_name":"Benign identity","phase":"benign","tactic_id":"benign","tactic_name":"Benign","technique_id":"benign","technique_name":"Identity Query","command":"whoami","expected_event":"process_exec","expected_relation":"prov:wasInformedBy","actor":"whoami","object":"stdout","malicious":false}`,
		"",
	}, "\n")
	if err := os.WriteFile(truth, []byte(data), 0o600); err != nil {
		t.Fatalf("write truth: %v", err)
	}

	python := "python3"
	if runtime.GOOS == "windows" {
		python = "python"
	}
	cmd := exec.Command(python, script, inputDir, "--out-dir", outDir, "--train-ratio", "0.5", "--seed", "test")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("export failed: %v\n%s", err, out)
	}
	for _, name := range []string{"labels.jsonl", "train.jsonl", "test.jsonl", "coverage.json", "coverage.md", "manifest.json"} {
		if _, err := os.Stat(filepath.Join(outDir, name)); err != nil {
			t.Fatalf("missing %s: %v", name, err)
		}
	}
	var coverage struct {
		Total     int            `json:"total"`
		Malicious int            `json:"malicious"`
		ByTactic  map[string]any `json:"by_tactic"`
	}
	raw, err := os.ReadFile(filepath.Join(outDir, "coverage.json"))
	if err != nil {
		t.Fatalf("read coverage: %v", err)
	}
	if err := json.Unmarshal(raw, &coverage); err != nil {
		t.Fatalf("decode coverage: %v", err)
	}
	if coverage.Total != 2 || coverage.Malicious != 1 {
		t.Fatalf("coverage = %#v", coverage)
	}
	if _, ok := coverage.ByTactic["TA0002"]; !ok {
		t.Fatalf("missing TA0002 coverage: %#v", coverage.ByTactic)
	}

	var manifest struct {
		DatasetID    string `json:"dataset_id"`
		RecordCount  int    `json:"record_count"`
		SplitSummary struct {
			Splits map[string]map[string]int `json:"splits"`
		} `json:"split_summary"`
		Files map[string]struct {
			Path   string `json:"path"`
			Bytes  int64  `json:"bytes"`
			SHA256 string `json:"sha256"`
		} `json:"files"`
	}
	raw, err = os.ReadFile(filepath.Join(outDir, "manifest.json"))
	if err != nil {
		t.Fatalf("read manifest: %v", err)
	}
	if err := json.Unmarshal(raw, &manifest); err != nil {
		t.Fatalf("decode manifest: %v", err)
	}
	if !strings.HasPrefix(manifest.DatasetID, "ds-") || manifest.RecordCount != 2 {
		t.Fatalf("manifest identity = %#v", manifest)
	}
	if manifest.Files["labels"].SHA256 == "" || manifest.Files["labels"].Bytes == 0 {
		t.Fatalf("labels inventory missing hash/size: %#v", manifest.Files["labels"])
	}
	if len(manifest.SplitSummary.Splits) == 0 {
		t.Fatalf("split summary missing: %#v", manifest.SplitSummary)
	}
}
