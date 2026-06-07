// Copyright (c) 2026 Chaoqun-Guo
// SPDX-License-Identifier: Apache-2.0

package supplychain

import (
	"testing"
)

// ─── Types tests ───────────────────────────────────────────────

func TestNewPackageInfo(t *testing.T) {
	pi := &PackageInfo{
		Name:    "nginx",
		Version: "1.24.0-1",
		SourceRepo: "official",
		PackageManager: "apt",
		SigningVerified: true,
	}
	if pi.Name != "nginx" {
		t.Errorf("name = %s", pi.Name)
	}
}

// ─── Package manager monitor tests ─────────────────────────────

func TestNewPackageManagerMonitor(t *testing.T) {
	pmm := NewPackageManagerMonitor()
	if pmm == nil {
		t.Fatal("NewPackageManagerMonitor returned nil")
	}
	stats := pmm.Stats()
	if stats["active_sessions"].(int) != 0 {
		t.Errorf("expected 0 sessions, got %d", stats["active_sessions"])
	}
}

func TestIdentifyManager(t *testing.T) {
	cases := []struct {
		comm    string
		manager string
		ok      bool
	}{
		{"apt", "apt", true},
		{"apt-get", "apt", true},
		{"dpkg", "dpkg", true},
		{"pip3", "pip", true},
		{"npm", "npm", true},
		{"curl", "", false},
		{"bash", "", false},
	}
	for _, c := range cases {
		mgr, ok := IdentifyManager(c.comm)
		if ok != c.ok {
			t.Errorf("IdentifyManager(%q) ok=%v, want %v", c.comm, ok, c.ok)
		}
		if ok && mgr != c.manager {
			t.Errorf("IdentifyManager(%q) = %q, want %q", c.comm, mgr, c.manager)
		}
	}
}

func TestMonitorAptInstall(t *testing.T) {
	pmm := NewPackageManagerMonitor()

	// Simulate: apt-get execve with PID 100.
	pmm.OnExecve(100, 1, "apt-get", "/usr/bin/apt-get")
	if pmm.SessionByPID(100) == nil {
		t.Fatal("session should exist for PID 100")
	}

	// Simulate: dpkg child process (PID 101, parent 100).
	pmm.OnExecve(101, 100, "dpkg", "/usr/bin/dpkg")

	// Simulate: file write to /usr/bin/nginx by dpkg (PID 101).
	pkgName := pmm.OnFileWrite(101, "/usr/bin/nginx", 12345)
	if pkgName == "" {
		t.Error("expected package name, got empty")
	}

	// Verify the package was indexed.
	pkg := pmm.ResolvePackage("/usr/bin/nginx")
	if pkg == nil {
		t.Fatal("expected package info")
	}
	if pkg.Name != "nginx" {
		t.Errorf("pkg.Name = %q, want %q", pkg.Name, "nginx")
	}
	if pkg.PackageManager != "apt" {
		t.Errorf("pkg.PackageManager = %q, want %q", pkg.PackageManager, "apt")
	}
	if !pkg.SigningVerified {
		t.Error("expected signing verified for apt")
	}

	stats := pmm.Stats()
	if stats["indexed_files"].(int) < 1 {
		t.Errorf("indexed_files = %d", stats["indexed_files"])
	}
}

func TestMonitorNpmInstall(t *testing.T) {
	pmm := NewPackageManagerMonitor()

	pmm.OnExecve(200, 1, "npm", "/usr/bin/npm")
	pmm.OnFileWrite(200, "/usr/lib/node_modules/express/index.js", 20001)

	pkg := pmm.ResolvePackage("/usr/lib/node_modules/express/index.js")
	if pkg == nil {
		t.Fatal("expected package info for npm install")
	}
	if pkg.PackageManager != "npm" {
		t.Errorf("manager = %q", pkg.PackageManager)
	}
	if pkg.SigningVerified != false {
		t.Error("npm should not have verified signatures by default")
	}
}

func TestMonitorUntrustedWrite(t *testing.T) {
	// A file write outside a package manager session should not
	// produce package info.
	pmm := NewPackageManagerMonitor()

	// Simulate a write by PID 300 that is NOT in a pm session.
	pkgName := pmm.OnFileWrite(300, "/usr/bin/random-binary", 30001)
	if pkgName != "" {
		t.Errorf("expected empty package name for untracked write, got %q", pkgName)
	}
}

func TestIsUntrustedWriter(t *testing.T) {
	if !IsUntrustedWriter("curl") {
		t.Error("curl should be untrusted")
	}
	if !IsUntrustedWriter("wget") {
		t.Error("wget should be untrusted")
	}
	if IsUntrustedWriter("apt") {
		t.Error("apt should NOT be untrusted")
	}
	if IsUntrustedWriter("dpkg") {
		t.Error("dpkg should NOT be untrusted")
	}
}

func TestIsInWatchedDir(t *testing.T) {
	if !IsInWatchedDir("/usr/bin/nginx") {
		t.Error("/usr/bin/ should be watched")
	}
	if !IsInWatchedDir("/usr/lib/libssl.so") {
		t.Error("/usr/lib/ should be watched")
	}
	if IsInWatchedDir("/tmp/random-file") {
		t.Error("/tmp/ should NOT be watched")
	}
	if IsInWatchedDir("/home/user/test.sh") {
		t.Error("/home/ should NOT be watched")
	}
}

func TestInferPackageName(t *testing.T) {
	cases := []struct {
		path     string
		expected string
	}{
		{"/usr/bin/nginx", "nginx"},
		{"/usr/sbin/sshd", "sshd"},
		{"/usr/lib/python3/dist-packages/requests/model.py", "python3-requests"},
		{"/usr/lib/node_modules/express/index.js", "node-express"},
		{"/opt/mysql/bin/mysqld", "mysql"},
	}
	for _, c := range cases {
		name := inferPackageName(c.path, nil)
		if name != c.expected {
			t.Errorf("inferPackageName(%q) = %q, want %q", c.path, name, c.expected)
		}
	}
}

// ─── SBOM tests ────────────────────────────────────────────────

func TestNewSBOMStore(t *testing.T) {
	s := NewSBOMStore()
	if s == nil {
		t.Fatal("NewSBOMStore returned nil")
	}
}

func TestImportSPDX(t *testing.T) {
	spdxJSON := `{
		"spdxId": "SPDXRef-DOCUMENT",
		"name": "nginx-1.24.0",
		"documentNamespace": "spdx://nginx-1.24.0",
		"packages": [
			{
				"spdxId": "SPDXRef-Package-nginx",
				"name": "nginx",
				"versionInfo": "1.24.0-1",
				"supplier": "Organization: NGINX Inc",
				"licenseDeclared": "BSD-2-Clause",
				"checksums": [
					{"algorithm": "SHA256", "value": "abc123def456"}
				],
				"externalRefs": [
					{
						"referenceCategory": "PACKAGE-MANAGER",
						"referenceLocator": "pkg:deb/debian/nginx@1.24.0-1"
					}
				]
			}
		],
		"creationInfo": {
			"created": "2024-06-01T00:00:00Z"
		}
	}`

	store := NewSBOMStore()
	doc, err := store.ImportSPDX([]byte(spdxJSON), "test-source")
	if err != nil {
		t.Fatalf("ImportSPDX: %v", err)
	}

	if doc.Format != "spdx" {
		t.Errorf("format = %q", doc.Format)
	}
	if len(doc.Packages) != 1 {
		t.Fatalf("expected 1 package, got %d", len(doc.Packages))
	}

	pkg := doc.Packages[0]
	if pkg.Name != "nginx" {
		t.Errorf("Name = %q", pkg.Name)
	}
	if pkg.Version != "1.24.0-1" {
		t.Errorf("Version = %q", pkg.Version)
	}
	if pkg.Purl != "pkg:deb/debian/nginx@1.24.0-1" {
		t.Errorf("Purl = %q", pkg.Purl)
	}
	if pkg.License != "BSD-2-Clause" {
		t.Errorf("License = %q", pkg.License)
	}
	if pkg.Checksums["sha256"] != "abc123def456" {
		t.Errorf("sha256 checksum = %q", pkg.Checksums["sha256"])
	}
}

func TestImportCycloneDX(t *testing.T) {
	cdxJSON := `{
		"bomFormat": "CycloneDX",
		"specVersion": "1.4",
		"serialNumber": "urn:uuid:1234-5678",
		"metadata": {"timestamp": "2024-06-01T00:00:00Z"},
		"components": [
			{
				"type": "library",
				"name": "openssl",
				"version": "3.0.12",
				"supplier": {"name": "OpenSSL Foundation"},
				"licenses": [{"license": {"name": "Apache-2.0"}}],
				"hashes": [
					{"alg": "SHA-256", "content": "def789abc012"}
				],
				"purl": "pkg:generic/openssl@3.0.12"
			}
		]
	}`

	store := NewSBOMStore()
	doc, err := store.ImportCycloneDX([]byte(cdxJSON), "test-cdx")
	if err != nil {
		t.Fatalf("ImportCycloneDX: %v", err)
	}

	if doc.Format != "cyclonedx" {
		t.Errorf("format = %q", doc.Format)
	}
	if len(doc.Packages) != 1 {
		t.Fatalf("expected 1 component, got %d", len(doc.Packages))
	}

	pkg := doc.Packages[0]
	if pkg.Name != "openssl" {
		t.Errorf("Name = %q", pkg.Name)
	}
	if pkg.Version != "3.0.12" {
		t.Errorf("Version = %q", pkg.Version)
	}
	if pkg.Checksums["sha-256"] != "def789abc012" {
		t.Errorf("sha-256 checksum = %q", pkg.Checksums["sha-256"])
	}
}

func TestAutoDetectFormat(t *testing.T) {
	store := NewSBOMStore()

	// SPDX JSON
	spdx := `{"spdxId":"SPDXRef-DOCUMENT","name":"test","documentNamespace":"spdx://test","packages":[],"creationInfo":{}}`
	doc, err := store.ImportSBOM([]byte(spdx), "auto-spdx")
	if err != nil {
		t.Fatalf("ImportSBOM SPDX: %v", err)
	}
	if doc.Format != "spdx" {
		t.Errorf("expected spdx, got %s", doc.Format)
	}

	// CycloneDX JSON
	cdx := `{"bomFormat":"CycloneDX","specVersion":"1.4","serialNumber":"urn:uuid:x","metadata":{},"components":[]}`
	doc, err = store.ImportSBOM([]byte(cdx), "auto-cdx")
	if err != nil {
		t.Fatalf("ImportSBOM CycloneDX: %v", err)
	}
	if doc.Format != "cyclonedx" {
		t.Errorf("expected cyclonedx, got %s", doc.Format)
	}

	// Invalid
	_, err = store.ImportSBOM([]byte("invalid"), "bad")
	if err == nil {
		t.Error("expected error for invalid SBOM")
	}
}

func TestBindToNode(t *testing.T) {
	store := NewSBOMStore()
	spdx := `{
		"spdxId":"SPDXRef-DOCUMENT","name":"test","documentNamespace":"spdx://test",
		"packages":[{
			"spdxId":"SPDXRef-Pkg",
			"name":"curl","versionInfo":"7.88.1",
			"checksums":[{"algorithm":"SHA256","value":"deadbeef"}],
			"externalRefs":[{"referenceCategory":"PACKAGE-MANAGER","referenceLocator":"pkg:deb/debian/curl@7.88.1"}]
		}],
		"creationInfo":{}
	}`
	_, err := store.ImportSPDX([]byte(spdx), "bind-test")
	if err != nil {
		t.Fatalf("Import: %v", err)
	}

	// Register a path mapping; BindToNode needs a resolved path.
	store.RegisterPathMapping("/usr/bin/curl", "pkg:deb/debian/curl@7.88.1")

	attrs := make(map[string]string)
	store.BindToNode("/usr/bin/curl", attrs)

	if attrs["package_name"] != "curl" {
		t.Errorf("package_name = %q", attrs["package_name"])
	}
	if attrs["package_version"] != "7.88.1" {
		t.Errorf("package_version = %q", attrs["package_version"])
	}
	if attrs["sbom_ref"] != "pkg:curl@7.88.1" {
		t.Errorf("sbom_ref = %q", attrs["sbom_ref"])
	}
	if attrs["artifact_hash"] != "sha256:deadbeef" {
		t.Errorf("artifact_hash = %q", attrs["artifact_hash"])
	}
}

func TestBindByPrefix(t *testing.T) {
	store := NewSBOMStore()

	// Import SPDX with nginx and curl packages
	_, err := store.ImportSPDX([]byte(`{
		"spdxId": "SPDXRef-DOCUMENT",
		"name": "system-sbom",
		"documentNamespace": "spdx://system",
		"packages": [
			{
				"spdxId": "SPDXRef-nginx",
				"name": "nginx",
				"versionInfo": "1.24.0-1",
				"supplier": "Organization: Debian",
				"licenseDeclared": "BSD-2-Clause",
				"checksums": [{"algorithm": "SHA256", "value": "abc123"}],
				"externalRefs": [{"referenceCategory": "PACKAGE-MANAGER", "referenceLocator": "pkg:deb/debian/nginx@1.24.0-1"}]
			}
		],
		"creationInfo": {"created": "2024-01-01T00:00:00Z"}
	}`), "test")
	if err != nil {
		t.Fatalf("ImportSPDX: %v", err)
	}

	tests := []struct {
		name     string
		path     string
		wantPkg  string
		wantVer  string
	}{
		{
			name:    "system binary exact match",
			path:    "/usr/bin/nginx",
			wantPkg: "nginx",
			wantVer: "1.24.0-1",
		},
		{
			name:    "doc file under nginx package",
			path:    "/usr/share/doc/nginx/NEWS.gz",
			wantPkg: "nginx",
			wantVer: "1.24.0-1",
		},
		{
			name:    "library file suffix match",
			path:    "/usr/lib/nginx/modules/ngx_http_modsecurity.so",
			wantPkg: "nginx",
			wantVer: "1.24.0-1",
		},
		{
			name:     "unrelated file no match",
			path:     "/usr/bin/python3",
			wantPkg:  "",
			wantVer:  "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// First try ResolveByPath — should fail since no mapping registered
			entry := store.ResolveByPath(tt.path)
			if entry != nil {
				t.Skip("unexpected direct hit — test setup issue")
			}

			attrs := make(map[string]string)
			store.BindByPrefix(tt.path, attrs)

			if tt.wantPkg == "" {
				if len(attrs) > 0 {
					t.Errorf("expected no attrs, got %v", attrs)
				}
				return
			}

			if attrs["package_name"] != tt.wantPkg {
				t.Errorf("package_name = %q, want %q", attrs["package_name"], tt.wantPkg)
			}
			if attrs["package_version"] != tt.wantVer {
				t.Errorf("package_version = %q, want %q", attrs["package_version"], tt.wantVer)
			}
			if attrs["sbom_ref"] == "" {
				t.Error("sbom_ref should be set")
			}
			if attrs["artifact_hash"] == "" {
				t.Error("artifact_hash should be set")
			}

			// Verify path mapping was registered for future lookups
			if entry := store.ResolveByPath(tt.path); entry == nil {
				t.Error("expected ResolveByPath to succeed after BindByPrefix")
			}
		})
	}
}

func TestGuessPackageName(t *testing.T) {
	tests := []struct {
		path string
		want []string
	}{
		{"/usr/bin/curl", []string{"curl"}},
		{"/usr/bin/curl.so", []string{"curl"}},
		{"/usr/lib/python3/dist-packages/requests/__init__.py", []string{"python3-requests", "requests", "requests"}},
		{"/usr/lib/python3.11/site-packages/flask/app.py", []string{"python3-flask", "flask", "app", "flask"}},
		{"/usr/lib/node_modules/express/index.js", []string{"node-express", "express", "express"}},
		{"/opt/nginx/sbin/nginx", []string{"nginx"}},
		{"/home/user/random/file.txt", []string{"file", "random"}},
		{"/usr/share/doc/nginx/NEWS.gz", []string{"NEWS", "nginx"}},
	}
	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			got := guessPackageCandidates(tt.path)
			if len(got) != len(tt.want) {
				t.Errorf("guessPackageCandidates(%q) = %v, want %v", tt.path, got, tt.want)
				return
			}
			for i := range got {
				if i < len(tt.want) && got[i] != tt.want[i] {
					t.Errorf("guessPackageCandidates(%q)[%d] = %q, want %q", tt.path, i, got[i], tt.want[i])
				}
			}
		})
	}
}

func TestNewIllegalSourceDetector(t *testing.T) {
	pmm := NewPackageManagerMonitor()
	sbom := NewSBOMStore()
	isd := NewIllegalSourceDetector(pmm, sbom)
	if isd == nil {
		t.Fatal("NewIllegalSourceDetector returned nil")
	}
}

func TestDetectCurlDrop(t *testing.T) {
	pmm := NewPackageManagerMonitor()
	sbom := NewSBOMStore()
	isd := NewIllegalSourceDetector(pmm, sbom)

	// Simulate: curl downloads to /usr/bin/malware.
	isd.RecordWrite(500, "curl", "/usr/bin/malware")

	// Simulate: binary execution.
	risk := isd.OnBinaryExecution("/usr/bin/malware", 501)
	if risk == nil {
		t.Fatal("expected risk for curl-dropped binary")
	}

	if risk.RiskLevel != "critical" && risk.RiskLevel != "high" {
		t.Errorf("risk_level = %q, want critical or high", risk.RiskLevel)
	}
	if risk.RiskScore < 40 {
		t.Errorf("risk_score = %f, want >= 40", risk.RiskScore)
	}

	// Verify an alert was raised.
	alerts := isd.Alerts()
	if len(alerts) < 1 {
		t.Fatal("expected at least 1 alert")
	}
	found := false
	for _, a := range alerts {
		if a.BinaryPath == "/usr/bin/malware" {
			found = true
			if a.Severity != "CRITICAL" {
				t.Errorf("severity = %q, want CRITICAL", a.Severity)
			}
			break
		}
	}
	if !found {
		t.Error("alert for /usr/bin/malware not found")
	}
}

func TestDetectAptInstallNoAlert(t *testing.T) {
	pmm := NewPackageManagerMonitor()
	sbom := NewSBOMStore()
	isd := NewIllegalSourceDetector(pmm, sbom)

	// Simulate: apt install nginx.
	pmm.OnExecve(600, 1, "apt-get", "/usr/bin/apt-get")
	pmm.OnExecve(601, 600, "dpkg", "/usr/bin/dpkg")
	pmm.OnFileWrite(601, "/usr/bin/nginx", 60001)
	isd.RecordWrite(601, "dpkg", "/usr/bin/nginx")

	// Execution should produce no risk.
	risk := isd.OnBinaryExecution("/usr/bin/nginx", 602)
	if risk != nil {
		t.Errorf("expected no risk for apt-installed binary, got level=%s score=%f",
			risk.RiskLevel, risk.RiskScore)
	}
}

func TestDetectTamperedPackage(t *testing.T) {
	pmm := NewPackageManagerMonitor()
	sbom := NewSBOMStore()
	isd := NewIllegalSourceDetector(pmm, sbom)

	// Simulate: apt install nginx (PID 700).
	pmm.OnExecve(700, 1, "apt-get", "/usr/bin/apt-get")
	pmm.OnExecve(701, 700, "dpkg", "/usr/bin/dpkg")
	pmm.OnFileWrite(701, "/usr/bin/nginx", 70001)
	isd.RecordWrite(701, "dpkg", "/usr/bin/nginx")

	// The binary is clean at this point.
	risk := isd.OnBinaryExecution("/usr/bin/nginx", 702)
	if risk != nil {
		t.Fatal("expected no risk before tamper")
	}

	// Simulate tamper: curl overwrites nginx (PID 710).
	isd.RecordWrite(710, "curl", "/usr/bin/nginx")

	// Check with CheckTampered.
	tamperRisk := isd.CheckTampered("/usr/bin/nginx", "apt")
	if tamperRisk == nil {
		t.Fatal("expected tamper risk")
	}
	if tamperRisk.RiskLevel != "critical" {
		t.Errorf("risk_level = %q, want critical", tamperRisk.RiskLevel)
	}
}

// ─── Risk scoring tests ────────────────────────────────────────

func TestAssessBinaryUntrusted(t *testing.T) {
	pmm := NewPackageManagerMonitor()
	sbom := NewSBOMStore()
	isd := NewIllegalSourceDetector(pmm, sbom)

	isd.RecordWrite(800, "wget", "/usr/bin/evil-tool")

	risk := AssessBinary("/usr/bin/evil-tool", pmm, sbom, isd)
	if risk == nil {
		t.Fatal("expected risk assessment")
	}
	if risk.RiskScore < 60 {
		t.Errorf("risk_score = %f, want >= 60 for wget", risk.RiskScore)
	}
}

func TestAssessBinaryClean(t *testing.T) {
	pmm := NewPackageManagerMonitor()
	sbom := NewSBOMStore()
	isd := NewIllegalSourceDetector(pmm, sbom)

	// apt install with proper session tracking.
	pmm.OnExecve(900, 1, "apt-get", "/usr/bin/apt-get")
	pmm.OnExecve(901, 900, "dpkg", "/usr/bin/dpkg")
	pmm.OnFileWrite(901, "/usr/bin/clean-binary", 90001)
	isd.RecordWrite(901, "dpkg", "/usr/bin/clean-binary")

	risk := AssessBinary("/usr/bin/clean-binary", pmm, sbom, isd)
	if risk == nil {
		t.Fatal("expected assessment result")
	}
	// Should be low risk for apt-installed, signed package.
	if risk.RiskLevel != "low" {
		t.Errorf("risk_level = %q, want low (score=%f)", risk.RiskLevel, risk.RiskScore)
	}
}

func TestSummariseRisks(t *testing.T) {
	pmm := NewPackageManagerMonitor()
	sbom := NewSBOMStore()
	isd := NewIllegalSourceDetector(pmm, sbom)

	pmm.OnExecve(100, 1, "apt-get", "/usr/bin/apt-get")

	// Clean binary.
	pmm.OnExecve(101, 100, "dpkg", "/usr/bin/dpkg")
	pmm.OnFileWrite(101, "/usr/bin/safe-binary", 10001)
	isd.RecordWrite(101, "dpkg", "/usr/bin/safe-binary")

	// Untrusted binary.
	isd.RecordWrite(102, "curl", "/usr/bin/evil-binary")

	paths := []string{"/usr/bin/safe-binary", "/usr/bin/evil-binary"}
	results := BatchAssess(paths, pmm, sbom, isd)

	summary := SummariseRisks(results)
	if summary["total"] != 2 {
		t.Errorf("total = %d, want 2", summary["total"])
	}
	if summary["critical"] < 1 {
		t.Errorf("critical = %d, want >= 1 for curl binary", summary["critical"])
	}
}

func TestNodeAttributesForRisk(t *testing.T) {
	risk := &SupplyChainRisk{
		FilePath:  "/usr/bin/test",
		RiskScore: 60,
		RiskLevel: "critical",
		PackageInfo: &PackageInfo{
			Name: "test-pkg", Version: "1.0", PackageManager: "apt",
			SourceRepo: "official", SigningVerified: true,
		},
		SuspectChain: []string{"unknown_origin"},
	}

	attrs := NodeAttributesForRisk(risk)
	if attrs["supply_chain_risk"] != "critical" {
		t.Errorf("supply_chain_risk = %q", attrs["supply_chain_risk"])
	}
	if attrs["package_name"] != "test-pkg" {
		t.Errorf("package_name = %q", attrs["package_name"])
	}
	if attrs["signing_verified"] != "true" {
		t.Errorf("signing_verified = %q", attrs["signing_verified"])
	}
	if attrs["suspect_chain"] == "" {
		t.Error("suspect_chain should not be empty")
	}

	// Nil risk should produce low.
	attrs2 := NodeAttributesForRisk(nil)
	if attrs2["supply_chain_risk"] != "low" {
		t.Errorf("nil risk: supply_chain_risk = %q", attrs2["supply_chain_risk"])
	}
}

// ─── Edge cases ────────────────────────────────────────────────

func TestNonSystemPathIgnored(t *testing.T) {
	pmm := NewPackageManagerMonitor()
	sbom := NewSBOMStore()
	isd := NewIllegalSourceDetector(pmm, sbom)

	// Write to /tmp should be ignored.
	isd.RecordWrite(900, "curl", "/tmp/test.sh")
	risk := isd.OnBinaryExecution("/tmp/test.sh", 901)
	if risk != nil {
		t.Errorf("expected no risk for /tmp file, got level=%s", risk.RiskLevel)
	}
}

func TestEmptySBOMImport(t *testing.T) {
	store := NewSBOMStore()
	_, err := store.ImportSBOM([]byte{}, "empty")
	if err == nil {
		t.Error("expected error for empty SBOM")
	}
}

func TestMultipleSBOMImports(t *testing.T) {
	store := NewSBOMStore()

	doc1 := `{"spdxId":"SPDXRef-1","name":"app-a","documentNamespace":"spdx://app-a","packages":[{"spdxId":"p1","name":"lib-a","versionInfo":"1.0","checksums":[],"externalRefs":[]}],"creationInfo":{}}`
	doc2 := `{"spdxId":"SPDXRef-2","name":"app-b","documentNamespace":"spdx://app-b","packages":[{"spdxId":"p2","name":"lib-b","versionInfo":"2.0","checksums":[],"externalRefs":[]}],"creationInfo":{}}`

	d1, err := store.ImportSPDX([]byte(doc1), "src1")
	if err != nil {
		t.Fatalf("doc1: %v", err)
	}
	d2, err := store.ImportSPDX([]byte(doc2), "src2")
	if err != nil {
		t.Fatalf("doc2: %v", err)
	}

	if len(store.Documents()) != 2 {
		t.Errorf("documents = %d, want 2", len(store.Documents()))
	}
	_ = d1
	_ = d2
}

func TestSessionChildTracking(t *testing.T) {
	pmm := NewPackageManagerMonitor()

	pmm.OnExecve(1000, 1, "apt-get", "/usr/bin/apt-get")
	pmm.OnExecve(1001, 1000, "dpkg", "/usr/bin/dpkg")
	pmm.OnExecve(1002, 1000, "dpkg", "/usr/bin/dpkg")

	session := pmm.SessionByPID(1001)
	if session == nil {
		t.Fatal("child PID 1001 should be in session")
	}
	if session.Manager != "apt" {
		t.Errorf("child session manager = %q", session.Manager)
	}

	// PID 1002 should also share the same session (apt).
	session2 := pmm.SessionByPID(1002)
	if session2 == nil {
		t.Fatal("child PID 1002 should be in session")
	}
	if session2.Manager != "apt" {
		t.Errorf("child2 session manager = %q", session2.Manager)
	}
}

func TestAlertChannel(t *testing.T) {
	pmm := NewPackageManagerMonitor()
	sbom := NewSBOMStore()
	isd := NewIllegalSourceDetector(pmm, sbom)

	// Trigger an alert.
	isd.RecordWrite(1100, "curl", "/usr/bin/chan-test")

	select {
	case alert := <-isd.AlertChan():
		if alert.BinaryPath != "/usr/bin/chan-test" {
			t.Errorf("alert path = %q", alert.BinaryPath)
		}
		if alert.Severity != "CRITICAL" {
			t.Errorf("alert severity = %q", alert.Severity)
		}
	default:
		t.Error("expected alert on channel")
	}
}

// ─── Integration test ──────────────────────────────────────────

func TestSupplyChainIntegration(t *testing.T) {
	t.Log("=== Supply Chain Integration ===")

	pmm := NewPackageManagerMonitor()
	sbom := NewSBOMStore()
	isd := NewIllegalSourceDetector(pmm, sbom)

	// 1. Import an SBOM.
	spdxJSON := `{
		"spdxId":"SPDXRef-DOCUMENT","name":"system-sbom",
		"documentNamespace":"spdx://system-sbom",
		"packages":[{
			"spdxId":"nginx-pkg","name":"nginx","versionInfo":"1.24.0-1",
			"supplier":"Organization: NGINX Inc","licenseDeclared":"BSD-2-Clause",
			"checksums":[{"algorithm":"SHA256","value":"abc123"}],
			"externalRefs":[{"referenceCategory":"PACKAGE-MANAGER","referenceLocator":"pkg:deb/debian/nginx@1.24.0-1"}]
		}],
		"creationInfo":{}
	}`
	_, err := sbom.ImportSPDX([]byte(spdxJSON), "integration-test")
	if err != nil {
		t.Fatalf("SBOM import: %v", err)
	}

	// 2. Simulate apt install nginx.
	pmm.OnExecve(2000, 1, "apt-get", "/usr/bin/apt-get")
	pmm.OnExecve(2001, 2000, "dpkg", "/usr/bin/dpkg")
	pkgName := pmm.OnFileWrite(2001, "/usr/bin/nginx", 20001)
	isd.RecordWrite(2001, "dpkg", "/usr/bin/nginx")
	t.Logf("Package install: %s", pkgName)

	// 3. Register SBOM path mapping.
	sbom.RegisterPathMapping("/usr/bin/nginx", "pkg:deb/debian/nginx@1.24.0-1")

	// 4. Bind SBOM metadata.
	attrs := make(map[string]string)
	sbom.BindToNode("/usr/bin/nginx", attrs)
	t.Logf("SBOM attrs: %+v", attrs)

	// 5. Verify apt install is clean.
	risk := isd.OnBinaryExecution("/usr/bin/nginx", 2002)
	if risk != nil {
		t.Errorf("apt install should be clean, got level=%s score=%f",
			risk.RiskLevel, risk.RiskScore)
	}
	t.Logf("Apt install risk: clean (as expected)")

	// 6. Simulate curl drop.
	isd.RecordWrite(2010, "curl", "/usr/bin/malware")
	risk = isd.OnBinaryExecution("/usr/bin/malware", 2011)
	if risk == nil || risk.RiskLevel != "critical" {
		t.Errorf("curl drop should be critical, got %v", risk)
	}
	t.Logf("Curl drop risk: %s (score=%.0f)", risk.RiskLevel, risk.RiskScore)

	// 7. Assess both binaries.
	paths := []string{"/usr/bin/nginx", "/usr/bin/malware"}
	results := BatchAssess(paths, pmm, sbom, isd)
	summary := SummariseRisks(results)
	t.Logf("Risk summary: %+v", summary)

	if summary["critical"] < 1 {
		t.Errorf("expected >= 1 critical, got %d", summary["critical"])
	}
	if summary["low"] < 1 {
		t.Errorf("expected >= 1 low, got %d", summary["low"])
	}

	t.Log("Supply chain integration OK")
}
