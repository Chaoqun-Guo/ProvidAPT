//go:build ignore

// sshrun connects to the Linux VM and runs provisioning + tests.
package main

import (
	"fmt"
	"log"
	"os"
	"time"

	"golang.org/x/crypto/ssh"
)

func main() {
	host := envDefault("PROVIDAPT_SSH_HOST", "vm-ubuntu-slave.<TAILSCALE_DOMAIN>")
	user := envDefault("PROVIDAPT_SSH_USER", "ubuntu")
	pass := os.Getenv("PROVIDAPT_SSH_PASSWORD")
	if pass == "" {
		log.Fatal("set PROVIDAPT_SSH_PASSWORD before running")
	}

	config := &ssh.ClientConfig{
		User:            user,
		Auth:            []ssh.AuthMethod{ssh.Password(pass)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         10 * time.Second,
	}

	addr := fmt.Sprintf("%s:22", host)
	client, err := ssh.Dial("tcp", addr, config)
	if err != nil {
		log.Fatalf("Failed to dial: %v", err)
	}
	defer client.Close()

	fmt.Println("=== Connected to VM ===")

	// Run commands
	commands := []struct {
		name string
		cmd  string
	}{
		{"hostname", "hostname && uname -a"},
		{"go version", "go version 2>&1"},
	}

	for _, c := range commands {
		fmt.Printf("\n--- %s ---\n", c.name)
		out, err := runSSH(client, c.cmd)
		if err != nil {
			log.Printf("Command %q failed: %v, output: %s", c.name, err, out)
		} else {
			fmt.Print(string(out))
		}
	}

	// Check git and rsync availability
	fmt.Println("\n=== Checking tools ===")
	for _, tool := range []string{"git", "rsync", "make", "docker"} {
		out, _ := runSSH(client, fmt.Sprintf("which %s 2>&1 || echo 'not found'", tool))
		fmt.Printf("  %s: %s", tool, out)
	}

	client.Close()
}

func envDefault(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}

func runSSH(client *ssh.Client, cmd string) ([]byte, error) {
	session, err := client.NewSession()
	if err != nil {
		return nil, fmt.Errorf("session: %w", err)
	}
	defer session.Close()
	return session.CombinedOutput(cmd)
}
