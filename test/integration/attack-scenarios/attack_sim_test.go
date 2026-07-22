package attackscenarios

import (
	"os"
	"strings"
	"testing"
)

func TestAttackSimulationRecordsGroundTruth(t *testing.T) {
	data, err := os.ReadFile("attack_sim.sh")
	if err != nil {
		t.Fatalf("read attack_sim.sh: %v", err)
	}
	script := string(data)
	required := []string{
		"GROUND_TRUTH_PATH",
		"/var/log/providapt/ground-truth",
		"providapt.attack_ground_truth.v1",
		`"step_index"`,
		`"step_id"`,
		`"step_name"`,
		`"tactic_id"`,
		`"tactic_name"`,
		`"technique_id"`,
		`"technique_name"`,
		`"mitre_url"`,
		`"expected_event"`,
		`"expected_relation"`,
		`"malicious"`,
		`https://attack.mitre.org/techniques/`,
		`record_truth 9 "Attempt HTTP C2 with curl" "command_and_control"`,
		`record_truth 13 "Benign identity query" "benign"`,
	}
	for _, want := range required {
		if !strings.Contains(script, want) {
			t.Fatalf("attack_sim.sh missing %q", want)
		}
	}
}
