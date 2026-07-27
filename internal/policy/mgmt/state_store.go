package mgmt

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
)

const postgresStateTimeout = 5 * time.Second

func loadPersistedControlPlaneState(backend string) (persistedControlPlaneState, bool, error) {
	backend = strings.TrimSpace(backend)
	if backend == "" {
		return persistedControlPlaneState{}, false, nil
	}
	if isPostgresStateBackend(backend) {
		return loadPostgresControlPlaneState(backend)
	}
	data, err := os.ReadFile(backend)
	if err != nil {
		if os.IsNotExist(err) {
			return persistedControlPlaneState{}, false, nil
		}
		return persistedControlPlaneState{}, false, fmt.Errorf("read control-plane state: %w", err)
	}
	var state persistedControlPlaneState
	if err := json.Unmarshal(data, &state); err != nil {
		return persistedControlPlaneState{}, false, fmt.Errorf("decode control-plane state: %w", err)
	}
	return state, true, nil
}

func savePersistedControlPlaneState(backend string, state persistedControlPlaneState) error {
	backend = strings.TrimSpace(backend)
	if backend == "" {
		return nil
	}
	if isPostgresStateBackend(backend) {
		return savePostgresControlPlaneState(backend, state)
	}
	if err := os.MkdirAll(filepath.Dir(backend), 0750); err != nil {
		return fmt.Errorf("create control-plane state dir: %w", err)
	}
	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return fmt.Errorf("encode control-plane state: %w", err)
	}
	tmp := backend + ".tmp"
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		return fmt.Errorf("write control-plane state: %w", err)
	}
	if err := os.Rename(tmp, backend); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("replace control-plane state: %w", err)
	}
	return nil
}

func loadPostgresControlPlaneState(dsn string) (persistedControlPlaneState, bool, error) {
	db, err := openPostgresStateDB(dsn)
	if err != nil {
		return persistedControlPlaneState{}, false, err
	}
	defer db.Close()
	ctx, cancel := context.WithTimeout(context.Background(), postgresStateTimeout)
	defer cancel()
	if err := ensurePostgresStateTable(ctx, db); err != nil {
		return persistedControlPlaneState{}, false, err
	}
	var raw []byte
	err = db.QueryRowContext(ctx, `SELECT state FROM providapt_mgmt_state WHERE state_id = 'default'`).Scan(&raw)
	if err != nil {
		if err == sql.ErrNoRows {
			return persistedControlPlaneState{}, false, nil
		}
		return persistedControlPlaneState{}, false, fmt.Errorf("read postgres control-plane state: %w", err)
	}
	var state persistedControlPlaneState
	if err := json.Unmarshal(raw, &state); err != nil {
		return persistedControlPlaneState{}, false, fmt.Errorf("decode postgres control-plane state: %w", err)
	}
	return state, true, nil
}

func savePostgresControlPlaneState(dsn string, state persistedControlPlaneState) error {
	db, err := openPostgresStateDB(dsn)
	if err != nil {
		return err
	}
	defer db.Close()
	ctx, cancel := context.WithTimeout(context.Background(), postgresStateTimeout)
	defer cancel()
	if err := ensurePostgresStateTable(ctx, db); err != nil {
		return err
	}
	data, err := json.Marshal(state)
	if err != nil {
		return fmt.Errorf("encode postgres control-plane state: %w", err)
	}
	_, err = db.ExecContext(ctx, `
INSERT INTO providapt_mgmt_state (state_id, state, updated_at)
VALUES ('default', $1::jsonb, $2)
ON CONFLICT (state_id) DO UPDATE SET state = EXCLUDED.state, updated_at = EXCLUDED.updated_at`,
		string(data), state.SavedAt)
	if err != nil {
		return fmt.Errorf("write postgres control-plane state: %w", err)
	}
	return nil
}

func openPostgresStateDB(dsn string) (*sql.DB, error) {
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		return nil, fmt.Errorf("open postgres control-plane state: %w", err)
	}
	return db, nil
}

func ensurePostgresStateTable(ctx context.Context, db *sql.DB) error {
	if _, err := db.ExecContext(ctx, `
CREATE TABLE IF NOT EXISTS providapt_mgmt_state (
	state_id text PRIMARY KEY,
	state jsonb NOT NULL,
	updated_at timestamptz NOT NULL DEFAULT now()
)`); err != nil {
		return fmt.Errorf("ensure postgres control-plane state table: %w", err)
	}
	return nil
}

func isPostgresStateBackend(value string) bool {
	trimmed := strings.ToLower(strings.TrimSpace(value))
	return strings.HasPrefix(trimmed, "postgres://") || strings.HasPrefix(trimmed, "postgresql://")
}
