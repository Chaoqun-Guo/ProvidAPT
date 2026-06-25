// Copyright (c) 2026 Chaoqun-Guo
// SPDX-License-Identifier: Apache-2.0

package ja3

import (
	"fmt"
	"log"
	"sync"
	"time"
)

// ═══════════════════════════════════════════════════════════════
// Central JA3 correlator — detects coordinated C2 clusters
// ═══════════════════════════════════════════════════════════════

// JA3Cluster represents a group of processes sharing the same JA3.
type JA3Cluster struct {
	JA3       string   `json:"ja3"`
	Count     int      `json:"count"`
	Hosts     []string `json:"hosts"`
	Processes []string `json:"processes"` // "host:pid:comm"
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
	IsC2      bool     `json:"is_c2"`      // flagged as potential C2
	RiskScore float64  `json:"risk_score"`
}

// CentralCorrelator matches JA3 fingerprints across hosts
// to detect coordinated C2 activity.
type CentralCorrelator struct {
	mu      sync.Mutex
	byJA3   map[string]*JA3Cluster // ja3 → cluster
	alerts  []C2Alert
}

// C2Alert is triggered when coordinated C2 is detected.
type C2Alert struct {
	ID          string    `json:"id"`
	JA3         string    `json:"ja3"`
	Hosts       []string  `json:"hosts"`
	Processes   []string  `json:"processes"`
	ClusterSize int       `json:"cluster_size"`
	RiskScore   float64   `json:"risk_score"`
	Timestamp   time.Time `json:"timestamp"`
}

// NewCentralCorrelator creates a JA3 correlation engine.
func NewCentralCorrelator() *CentralCorrelator {
	return &CentralCorrelator{
		byJA3: make(map[string]*JA3Cluster),
	}
}

// Ingest processes a JA3 record from any agent.
func (cc *CentralCorrelator) Ingest(record *JA3Record) *C2Alert {
	cc.mu.Lock()
	defer cc.mu.Unlock()

	cluster, exists := cc.byJA3[record.JA3]
	if !exists {
		cluster = &JA3Cluster{
			JA3:       record.JA3,
			FirstSeen: record.Timestamp,
		}
		cc.byJA3[record.JA3] = cluster
	}

	cluster.Count++
	cluster.LastSeen = record.Timestamp
	cluster.Hosts = addUnique(cluster.Hosts, record.SourceHost)
	cluster.Processes = addUnique(cluster.Processes,
		fmt.Sprintf("%s:%d:%s", record.SourceHost, record.PID, record.Comm))

	// Calculate risk score
	cluster.RiskScore = cc.calcRisk(cluster, record)
	cluster.IsC2 = cluster.RiskScore > 50

	// Alert on coordinated C2
	if cluster.IsC2 && cluster.Count >= 2 {
		alertPrefix := prefix(record.JA3, 8)
		logPrefix := prefix(record.JA3, 16)
		alert := &C2Alert{
			ID:          fmt.Sprintf("C2-%s-%d", alertPrefix, time.Now().Unix()),
			JA3:         record.JA3,
			Hosts:       cluster.Hosts,
			Processes:   cluster.Processes,
			ClusterSize: cluster.Count,
			RiskScore:   cluster.RiskScore,
			Timestamp:   time.Now(),
		}
		cc.alerts = append(cc.alerts, *alert)
		log.Printf("[ja3] C2 ALERT: %s (%d hosts, risk=%.0f)",
			logPrefix, len(cluster.Hosts), cluster.RiskScore)
		return alert
	}

	return nil
}

func prefix(value string, limit int) string {
	if len(value) <= limit {
		return value
	}
	return value[:limit]
}

// calcRisk computes the C2 risk score based on cluster properties.
func (cc *CentralCorrelator) calcRisk(cluster *JA3Cluster, record *JA3Record) float64 {
	score := 0.0

	// Atypical JA3 is suspicious
	if record.IsAtypical {
		score += 30
	}

	// Multi-host clusters are more suspicious
	score += float64(len(cluster.Hosts)) * 15

	// Different processes using same JA3
	score += float64(len(cluster.Processes)) * 10

	// C2-destination ports
	if record.DestPort == 443 || record.DestPort == 8443 {
		score += 5
	}

	if score > 100 {
		score = 100
	}
	return score
}

// Clusters returns all tracked JA3 clusters.
func (cc *CentralCorrelator) Clusters() []*JA3Cluster {
	cc.mu.Lock()
	defer cc.mu.Unlock()
	out := make([]*JA3Cluster, 0, len(cc.byJA3))
	for _, c := range cc.byJA3 {
		out = append(out, c)
	}
	return out
}

// Alerts returns all C2 alerts.
func (cc *CentralCorrelator) Alerts() []C2Alert {
	cc.mu.Lock()
	defer cc.mu.Unlock()
	out := make([]C2Alert, len(cc.alerts))
	copy(out, cc.alerts)
	return out
}

// Stats returns correlator statistics.
func (cc *CentralCorrelator) Stats() map[string]interface{} {
	cc.mu.Lock()
	defer cc.mu.Unlock()
	c2Count := 0
	for _, c := range cc.byJA3 {
		if c.IsC2 {
			c2Count++
		}
	}
	return map[string]interface{}{
		"ja3_fingerprints": len(cc.byJA3),
		"c2_clusters":      c2Count,
		"alerts":           len(cc.alerts),
	}
}

func addUnique(slice []string, item string) []string {
	for _, s := range slice {
		if s == item {
			return slice
		}
	}
	return append(slice, item)
}
