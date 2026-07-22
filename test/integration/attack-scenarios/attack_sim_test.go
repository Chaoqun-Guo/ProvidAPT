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
		`"expected_event"`,
		`"expected_relation"`,
		`"malicious"`,
		"record_truth \"command_and_control\"",
		"record_truth \"benign\"",
	}
	for _, want := range required {
		if !strings.Contains(script, want) {
			t.Fatalf("attack_sim.sh missing %q", want)
		}
	}
}
