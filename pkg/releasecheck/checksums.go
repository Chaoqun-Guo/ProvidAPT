package releasecheck

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"unicode"
)

type checksumEntry struct {
	Digest   string
	Artifact string
}

func checkChecksums(report *Report, path, artifactsDir string, requiredArtifactTypes []string) {
	if strings.TrimSpace(path) == "" {
		return
	}

	file, err := os.Open(path)
	if err != nil {
		add(report, Check{
			Name:          "release_checksums",
			Status:        StatusWarn,
			Message:       fmt.Sprintf("checksums file unavailable: %v", err),
			FixSuggestion: "Generate dist/checksums.txt during the release build and pass it with -release-checksums.",
		})
		return
	}
	defer func() {
		_ = file.Close()
	}()

	entries, err := parseChecksumEntries(file)
	if err != nil {
		add(report, Check{
			Name:          "release_checksums",
			Status:        StatusFail,
			Message:       err.Error(),
			FixSuggestion: "Regenerate checksums.txt from the release artifacts.",
		})
		return
	}
	if len(entries) == 0 {
		add(report, Check{
			Name:          "release_checksums",
			Status:        StatusFail,
			Message:       "checksums file contains no artifact entries",
			FixSuggestion: "Regenerate checksums.txt after release artifacts are built.",
		})
		return
	}

	add(report, Check{
		Name:    "release_checksums",
		Status:  StatusPass,
		Message: fmt.Sprintf("checksums file contains %d artifact entries", len(entries)),
	})
	checkArtifactMatrix(report, entries, requiredArtifactTypes)
	checkArtifactHashes(report, entries, artifactsDir)
}

func parseChecksumEntries(reader io.Reader) ([]checksumEntry, error) {
	scanner := bufio.NewScanner(reader)
	var entries []checksumEntry
	lineNo := 0
	for scanner.Scan() {
		lineNo++
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			return nil, fmt.Errorf("checksums line %d must contain sha256 and artifact name", lineNo)
		}
		if !isSHA256Hex(fields[0]) {
			return nil, fmt.Errorf("checksums line %d has invalid SHA-256 digest", lineNo)
		}
		artifact := strings.TrimPrefix(strings.TrimSpace(fields[1]), "*")
		if artifact == "" {
			return nil, fmt.Errorf("checksums line %d has an empty artifact name", lineNo)
		}
		entries = append(entries, checksumEntry{Digest: strings.ToLower(fields[0]), Artifact: artifact})
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("cannot read checksums file: %w", err)
	}
	return entries, nil
}

func checkArtifactHashes(report *Report, entries []checksumEntry, artifactsDir string) {
	if strings.TrimSpace(artifactsDir) == "" {
		return
	}
	base, err := filepath.Abs(artifactsDir)
	if err != nil {
		add(report, Check{
			Name:          "release_artifact_hashes",
			Status:        StatusFail,
			Message:       fmt.Sprintf("cannot resolve artifact directory: %v", err),
			FixSuggestion: "Pass a readable release artifact directory with -release-artifacts-dir.",
		})
		return
	}

	for _, entry := range entries {
		artifactPath, err := safeArtifactPath(base, entry.Artifact)
		if err != nil {
			add(report, Check{
				Name:          "release_artifact_hashes",
				Status:        StatusFail,
				Message:       err.Error(),
				FixSuggestion: "Ensure checksums.txt only references artifacts inside -release-artifacts-dir.",
			})
			return
		}
		digest, err := sha256File(artifactPath)
		if err != nil {
			add(report, Check{
				Name:          "release_artifact_hashes",
				Status:        StatusFail,
				Message:       fmt.Sprintf("cannot hash artifact %q: %v", entry.Artifact, err),
				FixSuggestion: "Build all artifacts listed in checksums.txt before commercial sign-off.",
			})
			return
		}
		if digest != entry.Digest {
			add(report, Check{
				Name:          "release_artifact_hashes",
				Status:        StatusFail,
				Message:       fmt.Sprintf("artifact %q SHA-256 mismatch", entry.Artifact),
				FixSuggestion: "Regenerate checksums.txt from the final release artifacts.",
			})
			return
		}
	}

	add(report, Check{
		Name:    "release_artifact_hashes",
		Status:  StatusPass,
		Message: fmt.Sprintf("verified SHA-256 for %d release artifacts", len(entries)),
	})
}

func checkArtifactMatrix(report *Report, entries []checksumEntry, requiredTypes []string) {
	requiredTypes = cleanPathList(requiredTypes)
	if len(requiredTypes) == 0 {
		return
	}

	found := map[string]int{}
	for _, entry := range entries {
		for _, artifactType := range classifyArtifactTypes(entry.Artifact) {
			found[artifactType]++
		}
	}

	var missing []string
	for _, requiredType := range requiredTypes {
		requiredType = normalizeArtifactType(requiredType)
		if requiredType == "" {
			continue
		}
		if found[requiredType] == 0 {
			missing = append(missing, requiredType)
		}
	}
	if len(missing) > 0 {
		add(report, Check{
			Name:          "release_artifact_matrix",
			Status:        StatusFail,
			Message:       fmt.Sprintf("checksum manifest is missing required artifact type(s): %s", strings.Join(missing, ", ")),
			FixSuggestion: "Build and include every required commercial artifact in checksums.txt before release sign-off.",
		})
		return
	}

	var coverage []string
	for artifactType, count := range found {
		coverage = append(coverage, fmt.Sprintf("%s=%d", artifactType, count))
	}
	sortStrings(coverage)
	add(report, Check{
		Name:    "release_artifact_matrix",
		Status:  StatusPass,
		Message: fmt.Sprintf("required artifact types present (%s)", strings.Join(coverage, ", ")),
	})
}

func classifyArtifactTypes(name string) []string {
	lower := strings.ToLower(strings.TrimSpace(filepath.Base(name)))
	switch {
	case strings.HasSuffix(lower, ".deb"):
		return []string{"deb"}
	case strings.HasSuffix(lower, ".rpm"):
		return []string{"rpm"}
	case strings.HasSuffix(lower, ".tar.gz"), strings.HasSuffix(lower, ".tgz"), strings.HasSuffix(lower, ".zip"):
		if strings.Contains(lower, "helm") || strings.Contains(lower, "chart") {
			return []string{"helm_chart"}
		}
		if strings.Contains(lower, "oci") || strings.Contains(lower, "image") || strings.Contains(lower, "container") {
			return []string{"container_image"}
		}
		return []string{"archive"}
	case strings.HasSuffix(lower, ".spdx.json"), strings.HasSuffix(lower, ".cdx.json"), strings.Contains(lower, "sbom"):
		return []string{"sbom"}
	default:
		return nil
	}
}

func normalizeArtifactType(value string) string {
	normalized := strings.ToLower(strings.TrimSpace(value))
	normalized = strings.ReplaceAll(normalized, "-", "_")
	switch normalized {
	case "tar", "tarball", "tgz", "zip":
		return "archive"
	case "debian":
		return "deb"
	case "redhat", "centos", "fedora":
		return "rpm"
	case "docker", "oci", "container":
		return "container_image"
	case "helm":
		return "helm_chart"
	default:
		return normalized
	}
}

func sortStrings(values []string) {
	for i := 1; i < len(values); i++ {
		value := values[i]
		j := i - 1
		for ; j >= 0 && values[j] > value; j-- {
			values[j+1] = values[j]
		}
		values[j+1] = value
	}
}

func safeArtifactPath(base, artifact string) (string, error) {
	if filepath.IsAbs(artifact) {
		return "", fmt.Errorf("artifact %q must be relative to artifact directory", artifact)
	}
	path := filepath.Clean(filepath.Join(base, artifact))
	rel, err := filepath.Rel(base, path)
	if err != nil {
		return "", fmt.Errorf("cannot resolve artifact %q: %w", artifact, err)
	}
	if rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("artifact %q escapes artifact directory", artifact)
	}
	return path, nil
}

func sha256File(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer func() {
		_ = file.Close()
	}()
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", err
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

func checkChecksumsSignature(report *Report, path string) {
	if strings.TrimSpace(path) == "" {
		return
	}

	info, err := os.Stat(path)
	if err != nil {
		add(report, Check{
			Name:          "release_checksums_signature",
			Status:        StatusWarn,
			Message:       fmt.Sprintf("checksums signature file unavailable: %v", err),
			FixSuggestion: "Sign dist/checksums.txt and pass the detached signature with -release-checksums-signature.",
		})
		return
	}
	if info.IsDir() {
		add(report, Check{
			Name:          "release_checksums_signature",
			Status:        StatusFail,
			Message:       "checksums signature path is a directory",
			FixSuggestion: "Pass the detached signature file for dist/checksums.txt.",
		})
		return
	}
	if info.Size() == 0 {
		add(report, Check{
			Name:          "release_checksums_signature",
			Status:        StatusFail,
			Message:       "checksums signature file is empty",
			FixSuggestion: "Regenerate the detached signature for dist/checksums.txt.",
		})
		return
	}

	data, err := os.ReadFile(path)
	if err != nil {
		add(report, Check{
			Name:          "release_checksums_signature",
			Status:        StatusFail,
			Message:       fmt.Sprintf("cannot read checksums signature file: %v", err),
			FixSuggestion: "Fix filesystem permissions or regenerate the detached signature for dist/checksums.txt.",
		})
		return
	}
	format := classifySignatureFormat(data)
	add(report, Check{
		Name:    "release_checksums_signature",
		Status:  StatusPass,
		Message: fmt.Sprintf("checksums signature file is present: %s (format: %s)", path, format),
	})
}

func classifySignatureFormat(data []byte) string {
	trimmed := strings.TrimSpace(string(data))
	switch {
	case strings.HasPrefix(trimmed, "-----BEGIN PGP SIGNATURE-----"):
		return "gpg-armored"
	case strings.HasPrefix(trimmed, "untrusted comment:") && strings.Contains(trimmed, "\ntrusted comment:"):
		return "minisign"
	case looksLikeCosignBundle(data):
		return "cosign-bundle"
	default:
		return "unknown-or-binary"
	}
}

func looksLikeCosignBundle(data []byte) bool {
	var obj map[string]any
	if err := json.Unmarshal(data, &obj); err != nil {
		return false
	}
	if mediaType, ok := obj["mediaType"].(string); ok && strings.Contains(strings.ToLower(mediaType), "cosign") {
		return true
	}
	if _, ok := obj["verificationMaterial"]; ok {
		return true
	}
	if _, ok := obj["dsseEnvelope"]; ok {
		return true
	}
	if _, ok := obj["Payload"]; ok {
		if _, hasSignature := obj["Base64Signature"]; hasSignature {
			return true
		}
	}
	return false
}

func isSHA256Hex(value string) bool {
	if len(value) != 64 {
		return false
	}
	for _, ch := range value {
		if !unicode.IsDigit(ch) && (ch < 'a' || ch > 'f') && (ch < 'A' || ch > 'F') {
			return false
		}
	}
	return true
}
