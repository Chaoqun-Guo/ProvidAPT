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
)

type contextKey string

const apiRoleContextKey contextKey = "providapt_api_role"
const apiActorContextKey contextKey = "providapt_api_actor"
const apiTenantContextKey contextKey = "providapt_api_tenant"

const (
	RoleAdmin    = "admin"
	RoleAnalyst  = "analyst"
	RoleAuditor  = "auditor"
	RoleOperator = "operator"
)

type trustedHeaderAuthConfig struct {
	Enabled      bool
	UserHeader   string
	RoleHeader   string
	TenantHeader string
}

// authMiddleware preserves trusted-header identity support while keeping the
// open-source control plane reachable without built-in credentials.
func authMiddleware(trusted trustedHeaderAuthConfig) func(http.Handler) http.Handler {
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
			next.ServeHTTP(w, withActorName(withRole(r, RoleAdmin), "open-source-operator", RoleAdmin))
		})
	}
}

func authorizationMiddleware(rolePermissions map[string][]string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			role := CurrentRole(r)
			if role == "" {
				role = RoleAdmin
			}
			if allowed(role, r.Method, r.URL.Path, rolePermissions) {
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
	normalized := strings.ToLower(strings.TrimSpace(role))
	switch normalized {
	case RoleAuditor:
		return RoleAuditor
	case RoleOperator:
		return RoleOperator
	case RoleAnalyst:
		return RoleAnalyst
	case "", RoleAdmin:
		return RoleAdmin
	default:
		return normalized
	}
}

func allowed(role, method, path string, rolePermissions map[string][]string) bool {
	if isPublicDashboardPath(method, path) {
		return true
	}
	role = normalizeRole(role)
	if role != RoleAdmin && role != RoleAnalyst && role != RoleAuditor && role != RoleOperator {
		return allowedByCustomPermissions(role, method, path, rolePermissions)
	}
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
		if method == http.MethodPost && strings.HasPrefix(path, "/api/v1/control/upgrade") {
			return false
		}
		if strings.HasPrefix(path, "/api/v1/admin/") {
			return false
		}
		return true
	case RoleOperator:
		if method == http.MethodGet || method == http.MethodOptions {
			if strings.HasPrefix(path, "/api/v1/control/backup/download") ||
				strings.HasPrefix(path, "/api/v1/control/support/download") {
				return false
			}
			return strings.HasPrefix(path, "/health") ||
				strings.HasPrefix(path, "/ready") ||
				strings.HasPrefix(path, "/api/v1/status") ||
				strings.HasPrefix(path, "/api/v1/control/overview") ||
				strings.HasPrefix(path, "/api/v1/control/ha") ||
				strings.HasPrefix(path, "/api/v1/control/fleet") ||
				strings.HasPrefix(path, "/api/v1/control/policies") ||
				strings.HasPrefix(path, "/api/v1/control/alerts") ||
				strings.HasPrefix(path, "/api/v1/control/deliveries") ||
				strings.HasPrefix(path, "/api/v1/control/upgrade") ||
				strings.HasPrefix(path, "/api/v1/investigation/report") ||
				strings.HasPrefix(path, "/assets/dashboard") ||
				strings.HasPrefix(path, "/assets/trace-viewer") ||
				strings.HasPrefix(path, "/dashboard") ||
				path == "/"
		}
		if method == http.MethodPost {
			return strings.HasPrefix(path, "/api/v1/control/fleet") ||
				strings.HasPrefix(path, "/api/v1/control/alerts") ||
				strings.HasPrefix(path, "/api/v1/control/upgrade")
		}
		return false
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
			strings.HasPrefix(path, "/api/v1/control/ha") ||
			strings.HasPrefix(path, "/api/v1/control/fleet") ||
			strings.HasPrefix(path, "/api/v1/control/support") ||
			strings.HasPrefix(path, "/api/v1/control/backup") ||
			strings.HasPrefix(path, "/api/v1/control/compliance") ||
			strings.HasPrefix(path, "/api/v1/control/security") ||
			strings.HasPrefix(path, "/api/v1/control/audit") ||
			strings.HasPrefix(path, "/api/v1/control/upgrade") ||
			strings.HasPrefix(path, "/api/v1/control/policies") ||
			strings.HasPrefix(path, "/api/v1/control/alerts") ||
			strings.HasPrefix(path, "/api/v1/control/deliveries") ||
			strings.HasPrefix(path, "/api/v1/alerts") ||
			strings.HasPrefix(path, "/api/v1/investigation/report") ||
			strings.HasPrefix(path, "/assets/dashboard") ||
			strings.HasPrefix(path, "/assets/trace-viewer") ||
			strings.HasPrefix(path, "/dashboard") ||
			path == "/"
	default:
		return false
	}
}

func isPublicDashboardPath(method, path string) bool {
	if method != http.MethodGet && method != http.MethodHead {
		return false
	}
	if strings.HasPrefix(path, "/api/v1/alerts/") && strings.HasSuffix(path, "/svg/view") {
		return true
	}
	return path == "/" || path == "/dashboard" ||
		path == "/assets/dashboard.css" || path == "/assets/dashboard-responsive.css" ||
		path == "/assets/dashboard-api.js" || path == "/assets/dashboard-state.js" ||
		path == "/assets/dashboard-ui.js" || path == "/assets/dashboard-layout.js" ||
		path == "/assets/dashboard-loaders.js" ||
		path == "/assets/dashboard.js" ||
		path == "/assets/trace-viewer.css" || path == "/assets/trace-viewer.js"
}

func allowedByCustomPermissions(role, method, path string, rolePermissions map[string][]string) bool {
	for _, permission := range rolePermissions[role] {
		if permissionMatches(permission, method, path) {
			return true
		}
	}
	return false
}

func permissionMatches(permission, method, path string) bool {
	permission = strings.TrimSpace(permission)
	if permission == "*" {
		return true
	}
	parts := strings.SplitN(permission, ":", 2)
	if len(parts) != 2 {
		return false
	}
	permMethod := strings.ToUpper(strings.TrimSpace(parts[0]))
	permPath := strings.TrimSpace(parts[1])
	if permMethod != "*" && permMethod != strings.ToUpper(method) {
		return false
	}
	return permPath == "*" || path == permPath || strings.HasPrefix(path, strings.TrimRight(permPath, "/")+"/")
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
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
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
