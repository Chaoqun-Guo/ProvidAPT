// Copyright (c) 2026 Chaoqun-Guo
// SPDX-License-Identifier: Apache-2.0

// Package orch implements global response orchestration for ProvidAPT.
//
// Features:
//  1. Policy dispatcher 鈥-central broadcast of blocking commands
//  2. Multi-dimensional isolation 鈥-UID block, file hash lock
//  3. Local policy cache 鈥-offline execution during network partitions
package orch

import (
	"fmt"
	"log"
	"sync"
	"time"
)

// 鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺-// Policy dispatcher
// 鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺-
// CommandType defines the type of isolation command.
type CommandType string

const (
	CmdBlockUID     CommandType = "block_uid"
	CmdBlockPID     CommandType = "block_pid"
	CmdLockFile     CommandType = "lock_file"
	CmdBlockComm    CommandType = "block_comm"
	CmdBlockIP      CommandType = "block_ip"
	CmdBlockProcess CommandType = "block_process_tree"
)

// PolicyCommand is a single isolation command broadcast to agents.
type PolicyCommand struct {
	ID          string        `json:"id"`
	Type        CommandType   `json:"type"`
	Target      string        `json:"target"` // UID, PID, file hash, IP
	Description string        `json:"description"`
	RiskScore   float64       `json:"risk_score"`
	Issuer      string        `json:"issuer"` // triggering host/agent
	Timestamp   time.Time     `json:"timestamp"`
	TTL         time.Duration `json:"ttl"` // how long the command is active
}

// PolicyDispatcher manages command broadcast to all agents.
type PolicyDispatcher struct {
	mu       sync.Mutex
	commands []*PolicyCommand
	agents   []string // registered agent IDs
	seq      int
}

// NewPolicyDispatcher creates a policy dispatcher.
func NewPolicyDispatcher() *PolicyDispatcher {
	return &PolicyDispatcher{}
}

// RegisterAgent adds an agent to the broadcast list.
func (pd *PolicyDispatcher) RegisterAgent(agentID string) {
	pd.mu.Lock()
	defer pd.mu.Unlock()
	for _, a := range pd.agents {
		if a == agentID {
			return
		}
	}
	pd.agents = append(pd.agents, agentID)
}

// Broadcast issues a command to all registered agents.
func (pd *PolicyDispatcher) Broadcast(cmdType CommandType, target, description string, riskScore float64, issuer string, ttl time.Duration) *PolicyCommand {
	pd.mu.Lock()
	defer pd.mu.Unlock()

	pd.seq++
	cmd := &PolicyCommand{
		ID:          fmt.Sprintf("CMD-%d-%s", pd.seq, cmdType),
		Type:        cmdType,
		Target:      target,
		Description: description,
		RiskScore:   riskScore,
		Issuer:      issuer,
		Timestamp:   time.Now(),
		TTL:         ttl,
	}
	pd.commands = append(pd.commands, cmd)

	log.Printf("[dispatch] BROADCAST: %s %s (risk=%.0f, agents=%d, desc=%s)",
		cmdType, target, riskScore, len(pd.agents), description)

	// In production: send gRPC command to each agent
	for _, agentID := range pd.agents {
		log.Printf("[dispatch] 鈫-%s: %s %s", agentID, cmdType, target)
	}

	return cmd
}

// BroadcastIfHighRisk evaluates risk and broadcasts if above threshold.
func (pd *PolicyDispatcher) BroadcastIfHighRisk(riskScore float64, issuer string,
	blockedUID uint32, blockedComm string, fileHash string, ip string) []*PolicyCommand {

	if riskScore <= 95 {
		return nil
	}

	var cmds []*PolicyCommand

	if blockedUID > 0 {
		cmd := pd.Broadcast(CmdBlockUID, fmt.Sprintf("%d", blockedUID),
			fmt.Sprintf("Block compromised UID %d from %s", blockedUID, issuer),
			riskScore, issuer, 30*time.Minute)
		cmds = append(cmds, cmd)
	}

	if blockedComm != "" {
		cmd := pd.Broadcast(CmdBlockComm, blockedComm,
			fmt.Sprintf("Block process %s from %s", blockedComm, issuer),
			riskScore, issuer, 30*time.Minute)
		cmds = append(cmds, cmd)
	}

	if fileHash != "" {
		cmd := pd.Broadcast(CmdLockFile, fileHash,
			fmt.Sprintf("Lock file hash %s from %s", fileHash, issuer),
			riskScore, issuer, 24*time.Hour)
		cmds = append(cmds, cmd)
	}

	if ip != "" {
		cmd := pd.Broadcast(CmdBlockIP, ip,
			fmt.Sprintf("Block IP %s from %s", ip, issuer),
			riskScore, issuer, 1*time.Hour)
		cmds = append(cmds, cmd)
	}

	return cmds
}

// Commands returns all issued commands.
func (pd *PolicyDispatcher) Commands() []*PolicyCommand {
	pd.mu.Lock()
	defer pd.mu.Unlock()
	out := make([]*PolicyCommand, len(pd.commands))
	copy(out, pd.commands)
	return out
}

// Stats returns dispatcher statistics.
func (pd *PolicyDispatcher) Stats() map[string]interface{} {
	pd.mu.Lock()
	defer pd.mu.Unlock()
	return map[string]interface{}{
		"commands_issued": len(pd.commands),
		"agents":          len(pd.agents),
	}
}
