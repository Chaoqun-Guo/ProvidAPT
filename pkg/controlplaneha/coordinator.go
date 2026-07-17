package controlplaneha

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
)

const (
	DefaultHeartbeatInterval = 10 * time.Second
	DefaultElectionTimeout   = 45 * time.Second
)

type Config struct {
	Mode              string
	NodeID            string
	ConfiguredRole    string
	ConfiguredLeader  string
	Peers             []string
	StateBackend      string
	Address           string
	Version           string
	HeartbeatInterval time.Duration
	ElectionTimeout   time.Duration
	Now               func() time.Time
	Healthy           func() bool
}

type Status struct {
	UpdatedAt      time.Time
	Mode           string
	NodeID         string
	Role           string
	LeaderID       string
	Healthy        bool
	PeerCount      int
	Peers          []string
	StateBackend   string
	LastCheckpoint time.Time
	FailoverReady  bool
	Message        string
}

type Coordinator struct {
	mu     sync.RWMutex
	cfg    Config
	status Status
}

type persistedState struct {
	Version   int                      `json:"version"`
	UpdatedAt time.Time                `json:"updated_at"`
	LeaderID  string                   `json:"leader_id,omitempty"`
	Nodes     map[string]persistedNode `json:"nodes"`
}

type persistedNode struct {
	NodeID   string    `json:"node_id"`
	Role     string    `json:"role"`
	Address  string    `json:"address,omitempty"`
	Healthy  bool      `json:"healthy"`
	LastSeen time.Time `json:"last_seen"`
	Version  string    `json:"version,omitempty"`
}

func New(cfg Config) *Coordinator {
	cfg.Mode = normalizeMode(cfg.Mode)
	cfg.ConfiguredRole = normalizeRole(cfg.ConfiguredRole)
	cfg.NodeID = strings.TrimSpace(cfg.NodeID)
	cfg.ConfiguredLeader = strings.TrimSpace(cfg.ConfiguredLeader)
	cfg.StateBackend = strings.TrimSpace(cfg.StateBackend)
	cfg.Peers = dedupe(cfg.Peers)
	if cfg.HeartbeatInterval <= 0 {
		cfg.HeartbeatInterval = DefaultHeartbeatInterval
	}
	if cfg.ElectionTimeout <= 0 {
		cfg.ElectionTimeout = DefaultElectionTimeout
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Healthy == nil {
		cfg.Healthy = func() bool { return true }
	}
	c := &Coordinator{cfg: cfg}
	c.status = c.standaloneStatus(cfg.Now().UTC(), cfg.Healthy())
	return c
}

func (c *Coordinator) Start(ctx context.Context) {
	_ = c.Tick()
	interval := c.cfg.HeartbeatInterval
	if interval <= 0 {
		interval = DefaultHeartbeatInterval
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			_ = c.Tick()
		}
	}
}

func (c *Coordinator) Tick() error {
	now := c.cfg.Now().UTC()
	healthy := c.cfg.Healthy()
	status, err := c.reconcile(now, healthy)
	if err != nil {
		status = c.degradedStatus(now, healthy, err)
	}
	c.mu.Lock()
	c.status = status
	c.mu.Unlock()
	return err
}

func (c *Coordinator) Status() Status {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.status
}

func (c *Coordinator) reconcile(now time.Time, healthy bool) (Status, error) {
	if c.cfg.Mode == "standalone" || c.cfg.Mode == "external" {
		return c.standaloneStatus(now, healthy), nil
	}
	if c.cfg.StateBackend == "" || strings.EqualFold(c.cfg.StateBackend, "local") {
		return c.degradedStatus(now, healthy, fmt.Errorf("shared state backend is not configured")), nil
	}
	if strings.Contains(c.cfg.StateBackend, "://") {
		if isPostgresBackend(c.cfg.StateBackend) {
			return c.reconcilePostgres(now, healthy)
		}
		return c.degradedStatus(now, healthy, fmt.Errorf("unsupported shared state backend %q", c.cfg.StateBackend)), nil
	}
	state, err := readState(c.cfg.StateBackend)
	if err != nil {
		return Status{}, err
	}
	state, status := c.reconcileState(state, now, healthy)
	if err := writeState(c.cfg.StateBackend, state); err != nil {
		return Status{}, err
	}
	return status, nil
}

func (c *Coordinator) reconcilePostgres(now time.Time, healthy bool) (Status, error) {
	state, status, err := updatePostgresState(c.cfg.StateBackend, func(state persistedState) (persistedState, Status, error) {
		nextState, nextStatus := c.reconcileState(state, now, healthy)
		return nextState, nextStatus, nil
	})
	if err != nil {
		return Status{}, err
	}
	status.LastCheckpoint = state.UpdatedAt
	return status, nil
}

func (c *Coordinator) reconcileState(state persistedState, now time.Time, healthy bool) (persistedState, Status) {
	nodeID := c.nodeID()
	if state.Nodes == nil {
		state.Nodes = map[string]persistedNode{}
	}
	state.Nodes[nodeID] = persistedNode{
		NodeID:   nodeID,
		Role:     c.cfg.ConfiguredRole,
		Address:  strings.TrimSpace(c.cfg.Address),
		Healthy:  healthy,
		LastSeen: now,
		Version:  strings.TrimSpace(c.cfg.Version),
	}
	active := activeNodes(state.Nodes, now, c.cfg.ElectionTimeout)
	leaderID := c.electLeader(active)
	if leaderID == "" {
		leaderID = nodeID
	}
	state.Version = 1
	state.UpdatedAt = now
	state.LeaderID = leaderID
	for id, node := range state.Nodes {
		if now.Sub(node.LastSeen) > c.cfg.ElectionTimeout*3 {
			delete(state.Nodes, id)
		}
	}
	role := "follower"
	if nodeID == leaderID {
		role = "leader"
	}
	failoverReady := c.cfg.Mode == "active-passive" && healthy && len(active) > 1
	status := Status{
		UpdatedAt:      now,
		Mode:           c.cfg.Mode,
		NodeID:         nodeID,
		Role:           role,
		LeaderID:       leaderID,
		Healthy:        healthy,
		PeerCount:      len(c.cfg.Peers),
		Peers:          c.cfg.Peers,
		StateBackend:   c.cfg.StateBackend,
		LastCheckpoint: state.UpdatedAt,
		FailoverReady:  failoverReady,
		Message:        fmt.Sprintf("control plane %s; role=%s leader=%s active_nodes=%d failover_ready=%t", c.cfg.Mode, role, leaderID, len(active), failoverReady),
	}
	return state, status
}

func (c *Coordinator) standaloneStatus(now time.Time, healthy bool) Status {
	nodeID := c.nodeID()
	role := c.cfg.ConfiguredRole
	if role == "" || role == "observer" {
		role = "leader"
	}
	leaderID := c.cfg.ConfiguredLeader
	if leaderID == "" && role == "leader" {
		leaderID = nodeID
	}
	return Status{
		UpdatedAt:     now,
		Mode:          c.cfg.Mode,
		NodeID:        nodeID,
		Role:          role,
		LeaderID:      leaderID,
		Healthy:       healthy,
		PeerCount:     len(c.cfg.Peers),
		Peers:         c.cfg.Peers,
		StateBackend:  c.cfg.StateBackend,
		FailoverReady: false,
		Message:       "single-node control plane",
	}
}

func (c *Coordinator) degradedStatus(now time.Time, healthy bool, err error) Status {
	status := c.standaloneStatus(now, healthy)
	status.Mode = c.cfg.Mode
	status.Role = "follower"
	if c.cfg.ConfiguredRole == "leader" {
		status.Role = "leader"
	}
	status.LeaderID = firstNonEmpty(c.cfg.ConfiguredLeader, status.LeaderID)
	status.FailoverReady = false
	status.Message = fmt.Sprintf("control plane %s degraded: %v", c.cfg.Mode, err)
	return status
}

func (c *Coordinator) nodeID() string {
	if c.cfg.NodeID != "" {
		return c.cfg.NodeID
	}
	return "control-plane"
}

func (c *Coordinator) electLeader(nodes []persistedNode) string {
	if c.cfg.ConfiguredLeader != "" {
		for _, node := range nodes {
			if node.NodeID == c.cfg.ConfiguredLeader && node.Healthy {
				return node.NodeID
			}
		}
	}
	sort.Slice(nodes, func(i, j int) bool {
		return nodes[i].NodeID < nodes[j].NodeID
	})
	for _, node := range nodes {
		if node.Healthy {
			return node.NodeID
		}
	}
	return ""
}

func readState(path string) (persistedState, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return persistedState{Version: 1, Nodes: map[string]persistedNode{}}, nil
		}
		return persistedState{}, err
	}
	if len(strings.TrimSpace(string(data))) == 0 {
		return persistedState{Version: 1, Nodes: map[string]persistedNode{}}, nil
	}
	var state persistedState
	if err := json.Unmarshal(data, &state); err != nil {
		return persistedState{}, err
	}
	if state.Nodes == nil {
		state.Nodes = map[string]persistedNode{}
	}
	return state, nil
}

func writeState(path string, state persistedState) error {
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}
	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	tmp := fmt.Sprintf("%s.tmp.%d", path, os.Getpid())
	if err := os.WriteFile(tmp, data, 0644); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(path)
		if err := os.Rename(tmp, path); err != nil {
			_ = os.Remove(tmp)
			return err
		}
	}
	return nil
}

func updatePostgresState(dsn string, update func(persistedState) (persistedState, Status, error)) (persistedState, Status, error) {
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		return persistedState{}, Status{}, err
	}
	defer func() {
		_ = db.Close()
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return persistedState{}, Status{}, err
	}
	defer func() {
		_ = tx.Rollback()
	}()
	if _, err := tx.ExecContext(ctx, `
CREATE TABLE IF NOT EXISTS providapt_control_plane_ha (
	cluster_id text PRIMARY KEY,
	state jsonb NOT NULL,
	updated_at timestamptz NOT NULL DEFAULT now()
)`); err != nil {
		return persistedState{}, Status{}, err
	}
	if _, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(hashtext('providapt_control_plane_ha'))`); err != nil {
		return persistedState{}, Status{}, err
	}
	state := persistedState{Version: 1, Nodes: map[string]persistedNode{}}
	var raw []byte
	err = tx.QueryRowContext(ctx, `SELECT state FROM providapt_control_plane_ha WHERE cluster_id = 'default'`).Scan(&raw)
	if err != nil && err != sql.ErrNoRows {
		return persistedState{}, Status{}, err
	}
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &state); err != nil {
			return persistedState{}, Status{}, err
		}
	}
	if state.Nodes == nil {
		state.Nodes = map[string]persistedNode{}
	}
	nextState, status, err := update(state)
	if err != nil {
		return persistedState{}, Status{}, err
	}
	data, err := json.Marshal(nextState)
	if err != nil {
		return persistedState{}, Status{}, err
	}
	if _, err := tx.ExecContext(ctx, `
INSERT INTO providapt_control_plane_ha (cluster_id, state, updated_at)
VALUES ('default', $1::jsonb, $2)
ON CONFLICT (cluster_id) DO UPDATE SET state = EXCLUDED.state, updated_at = EXCLUDED.updated_at`,
		string(data), nextState.UpdatedAt); err != nil {
		return persistedState{}, Status{}, err
	}
	if err := tx.Commit(); err != nil {
		return persistedState{}, Status{}, err
	}
	return nextState, status, nil
}

func isPostgresBackend(value string) bool {
	trimmed := strings.ToLower(strings.TrimSpace(value))
	return strings.HasPrefix(trimmed, "postgres://") || strings.HasPrefix(trimmed, "postgresql://")
}

func activeNodes(nodes map[string]persistedNode, now time.Time, timeout time.Duration) []persistedNode {
	out := make([]persistedNode, 0, len(nodes))
	for _, node := range nodes {
		if node.NodeID == "" || now.Sub(node.LastSeen) > timeout {
			continue
		}
		out = append(out, node)
	}
	return out
}

func normalizeMode(mode string) string {
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case "active-passive", "external":
		return strings.ToLower(strings.TrimSpace(mode))
	default:
		return "standalone"
	}
}

func normalizeRole(role string) string {
	switch strings.ToLower(strings.TrimSpace(role)) {
	case "leader", "follower", "observer":
		return strings.ToLower(strings.TrimSpace(role))
	default:
		return "leader"
	}
}

func dedupe(values []string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(values))
	for _, value := range values {
		trimmed := strings.TrimSpace(value)
		if trimmed == "" {
			continue
		}
		if _, ok := seen[trimmed]; ok {
			continue
		}
		seen[trimmed] = struct{}{}
		out = append(out, trimmed)
	}
	return out
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if trimmed := strings.TrimSpace(value); trimmed != "" {
			return trimmed
		}
	}
	return ""
}
