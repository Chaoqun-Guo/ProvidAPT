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

func TestFullChainSimulationClassifiesAttackSteps(t *testing.T) {
	data, err := os.ReadFile("attack_full_chain.sh")
	if err != nil {
		t.Fatalf("read attack_full_chain.sh: %v", err)
	}
	script := string(data)
	required := []string{
		"providapt.attack_manifest.v1",
		"providapt.attack_ground_truth.v1",
		`"chain":"full_chain"`,
		`"category"`,
		`"step_index"`,
		`"tactic_id"`,
		`"technique_id"`,
		`https://attack.mitre.org/matrices/enterprise/`,
		`https://attack.mitre.org/techniques/`,
		`"TA0043"`,
		`"TA0042"`,
		`"TA0001"`,
		`"TA0002"`,
		`"TA0003"`,
		`"TA0004"`,
		`"TA0005"`,
		`"TA0006"`,
		`"TA0007"`,
		`"TA0008"`,
		`"TA0009"`,
		`"TA0011"`,
		`"TA0010"`,
		`"TA0040"`,
		`"benign"`,
	}
	for _, want := range required {
		if !strings.Contains(script, want) {
			t.Fatalf("attack_full_chain.sh missing %q", want)
		}
	}
}
