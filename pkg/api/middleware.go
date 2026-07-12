// Copyright (c) 2026 Chaoqun-Guo
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"runtime/debug"
	"strings"
	"sync"
	"time"

	"github.com/Chaoqun-Guo/ProvidAPT/pkg/secure"
)

type contextKey string

const apiRoleContextKey contextKey = "providapt_api_role"
const apiActorContextKey contextKey = "providapt_api_actor"
const apiTenantContextKey contextKey = "providapt_api_tenant"

const (
	RoleAdmin   = "admin"
	RoleAnalyst = "analyst"
	RoleAuditor = "auditor"
)

type trustedHeaderAuthConfig struct {
	Enabled      bool
	UserHeader   string
	RoleHeader   string
	TenantHeader string
}

// authMiddleware validates X-API-Key header against configured keys.
// When auth is disabled, all requests pass through.
func authMiddleware(keys []string, roles map[string]string, identities map[string]string, tenants map[string]string, enabled bool, trusted trustedHeaderAuthConfig) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if trusted.Enabled {
				userHeader := trusted.UserHeader
				roleHeader := trusted.RoleHeader
				if userHeader == "" {
					userHeader = "X-Forwarded-User"
				}
				if roleHeader == "" {
					roleHeader = "X-Forwarded-Role"
				}
				tenantHeader := trusted.TenantHeader
				if tenantHeader == "" {
					tenantHeader = "X-Forwarded-Tenant"
				}
				user := strings.TrimSpace(r.Header.Get(userHeader))
				if user != "" {
					role := normalizeRole(r.Header.Get(roleHeader))
					tenant := strings.TrimSpace(r.Header.Get(tenantHeader))
					w.Header().Set("X-ProvidAPT-Role", role)
					next.ServeHTTP(w, withTenant(withActorName(withRole(r, role), user, role), tenant))
					return
				}
			}
			if !enabled || len(keys) == 0 {
				next.ServeHTTP(w, withRole(r, RoleAdmin))
				return
			}
			key := r.Header.Get("X-API-Key")
			if key == "" {
				key = r.URL.Query().Get("api_key")
			}
			valid := false
			for _, k := range keys {
				if secure.ConstantTimeCompare(key, k) {
					valid = true
					break
				}
			}
			if !valid {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusUnauthorized)
				if err := json.NewEncoder(w).Encode(map[string]string{
					"error": "unauthorized: missing or invalid API key",
				}); err != nil {
					log.Printf("[api] encode unauthorized response failed: %v", err)
				}
				return
			}
			role := normalizeRole(roles[key])
			tenant := strings.TrimSpace(tenants[key])
			w.Header().Set("X-ProvidAPT-Role", role)
			next.ServeHTTP(w, withTenant(withActor(withRole(r, role), key, role, identities[key]), tenant))
		})
	}
}

func authorizationMiddleware() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			role := CurrentRole(r)
			if role == "" {
				role = RoleAdmin
			}
			if allowed(role, r.Method, r.URL.Path) {
				next.ServeHTTP(w, r)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			if err := json.NewEncoder(w).Encode(map[string]string{
				"error": "forbidden: insufficient role",
				"role":  role,
			}); err != nil {
				log.Printf("[api] encode forbidden response failed: %v", err)
			}
		})
	}
}

func CurrentRole(r *http.Request) string {
	role, _ := r.Context().Value(apiRoleContextKey).(string)
	return role
}

func CurrentActor(r *http.Request) string {
	actor, _ := r.Context().Value(apiActorContextKey).(string)
	return actor
}

func CurrentTenant(r *http.Request) string {
	tenant, _ := r.Context().Value(apiTenantContextKey).(string)
	return tenant
}

func withRole(r *http.Request, role string) *http.Request {
	return r.WithContext(context.WithValue(r.Context(), apiRoleContextKey, normalizeRole(role)))
}

func withActor(r *http.Request, apiKey, role, identity string) *http.Request {
	actor := strings.TrimSpace(r.Header.Get("X-ProvidAPT-Actor"))
	if actor == "" {
		actor = strings.TrimSpace(r.URL.Query().Get("actor"))
	}
	if actor == "" {
		actor = strings.TrimSpace(identity)
	}
	if actor == "" {
		trimmed := strings.TrimSpace(apiKey)
		if len(trimmed) > 8 {
			trimmed = trimmed[:8]
		}
		actor = "api-key:" + trimmed
	}
	actor = actor + " (" + normalizeRole(role) + ")"
	return r.WithContext(context.WithValue(r.Context(), apiActorContextKey, actor))
}

func withActorName(r *http.Request, actor, role string) *http.Request {
	actor = strings.TrimSpace(actor)
	if actor == "" {
		actor = "trusted-proxy"
	}
	actor = actor + " (" + normalizeRole(role) + ")"
	return r.WithContext(context.WithValue(r.Context(), apiActorContextKey, actor))
}

func withTenant(r *http.Request, tenant string) *http.Request {
	return r.WithContext(context.WithValue(r.Context(), apiTenantContextKey, strings.TrimSpace(tenant)))
}

func normalizeRole(role string) string {
	switch strings.ToLower(strings.TrimSpace(role)) {
	case RoleAuditor:
		return RoleAuditor
	case RoleAnalyst:
		return RoleAnalyst
	default:
		return RoleAdmin
	}
}

func allowed(role, method, path string) bool {
	role = normalizeRole(role)
	switch role {
	case RoleAdmin:
		return true
	case RoleAnalyst:
		if strings.HasPrefix(path, "/api/v1/control/support/download") {
			return false
		}
		if strings.HasPrefix(path, "/api/v1/control/backup/download") {
			return false
		}
		if strings.HasPrefix(path, "/api/v1/control/policies/bundle") {
			return false
		}
		if method == http.MethodPost && strings.HasPrefix(path, "/api/v1/control/fleet") {
			return false
		}
		if method == http.MethodPost && strings.HasPrefix(path, "/api/v1/control/support") {
			return false
		}
		if method == http.MethodPost && strings.HasPrefix(path, "/api/v1/control/backup") {
			return false
		}
		if method == http.MethodPost && strings.HasPrefix(path, "/api/v1/control/compliance") {
			return false
		}
		if method == http.MethodPost && strings.HasPrefix(path, "/api/v1/control/security") {
			return false
		}
		if method == http.MethodPost && strings.HasPrefix(path, "/api/v1/control/policies") {
			return false
		}
		if method == http.MethodPost && strings.HasPrefix(path, "/api/v1/control/deliveries") {
			return false
		}
		if method == http.MethodPost && strings.HasPrefix(path, "/api/v1/control/license") {
			return false
		}
		if method == http.MethodPost && strings.HasPrefix(path, "/api/v1/control/upgrade") {
			return false
		}
		if strings.HasPrefix(path, "/api/v1/admin/") {
			return false
		}
		return true
	case RoleAuditor:
		if method != http.MethodGet && method != http.MethodOptions {
			return false
		}
		if strings.HasPrefix(path, "/api/v1/control/backup/download") {
			return false
		}
		return strings.HasPrefix(path, "/health") ||
			strings.HasPrefix(path, "/ready") ||
			strings.HasPrefix(path, "/api/v1/status") ||
			strings.HasPrefix(path, "/api/v1/control/overview") ||
			strings.HasPrefix(path, "/api/v1/control/fleet") ||
			strings.HasPrefix(path, "/api/v1/control/support") ||
			strings.HasPrefix(path, "/api/v1/control/backup") ||
			strings.HasPrefix(path, "/api/v1/control/compliance") ||
			strings.HasPrefix(path, "/api/v1/control/security") ||
			strings.HasPrefix(path, "/api/v1/control/audit") ||
			strings.HasPrefix(path, "/api/v1/control/license") ||
			strings.HasPrefix(path, "/api/v1/control/upgrade") ||
			strings.HasPrefix(path, "/api/v1/control/policies") ||
			strings.HasPrefix(path, "/api/v1/control/alerts") ||
			strings.HasPrefix(path, "/api/v1/control/deliveries") ||
			strings.HasPrefix(path, "/api/v1/alerts") ||
			strings.HasPrefix(path, "/dashboard") ||
			path == "/"
	default:
		return false
	}
}

type rateLimiter struct {
	mu      sync.Mutex
	buckets map[string]*tokenBucket
	rate    float64 // tokens per second
	burst   int
}

type tokenBucket struct {
	tokens    float64
	lastCheck time.Time
}

func newRateLimiter(rate float64, burst int) *rateLimiter {
	return &rateLimiter{
		buckets: make(map[string]*tokenBucket),
		rate:    rate,
		burst:   burst,
	}
}

func (rl *rateLimiter) allow(ip string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	b, ok := rl.buckets[ip]
	now := time.Now()
	if !ok {
		b = &tokenBucket{tokens: float64(rl.burst), lastCheck: now}
		rl.buckets[ip] = b
	}

	// Refill tokens based on elapsed time
	elapsed := now.Sub(b.lastCheck).Seconds()
	b.tokens += elapsed * rl.rate
	if b.tokens > float64(rl.burst) {
		b.tokens = float64(rl.burst)
	}
	b.lastCheck = now

	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

// rateLimitMiddleware limits requests per IP using a token bucket.
// rate <= 0 disables rate limiting.
func rateLimitMiddleware(rl *rateLimiter) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if rl == nil || rl.rate <= 0 {
				next.ServeHTTP(w, r)
				return
			}
			// Extract client IP
			ip := r.Header.Get("X-Forwarded-For")
			if ip == "" {
				ip = r.RemoteAddr
			}
			if !rl.allow(ip) {
				w.Header().Set("Content-Type", "application/json")
				w.Header().Set("Retry-After", "1")
				w.WriteHeader(http.StatusTooManyRequests)
				if err := json.NewEncoder(w).Encode(map[string]string{
					"error": "rate limit exceeded",
				}); err != nil {
					log.Printf("[api] encode rate limit response failed: %v", err)
				}
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// recoveryMiddleware catches panics in HTTP handlers and returns 500
// instead of crashing the daemon.
func recoveryMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rec := recover(); rec != nil {
				log.Printf("[api] PANIC recovered: %s %s: %v\n%s", r.Method, r.URL.Path, rec, debug.Stack())
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusInternalServerError)
				if err := json.NewEncoder(w).Encode(map[string]string{
					"error": "internal server error",
				}); err != nil {
					log.Printf("[api] encode panic response failed: %v", err)
				}
			}
		}()
		next.ServeHTTP(w, r)
	})
}

func corsMiddleware(origins []string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			origin := r.Header.Get("Origin")
			allowOrigin := "*"
			if len(origins) > 0 && origins[0] != "*" {
				allowOrigin = matchOrigin(origin, origins)
			}
			w.Header().Set("Access-Control-Allow-Origin", allowOrigin)
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type, X-API-Key")
			if r.Method == http.MethodOptions {
				w.WriteHeader(http.StatusNoContent)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

func matchOrigin(origin string, allowed []string) string {
	if origin == "" {
		return "null"
	}
	for _, a := range allowed {
		if a == origin || a == "*" {
			return origin
		}
	}
	return "null"
}
