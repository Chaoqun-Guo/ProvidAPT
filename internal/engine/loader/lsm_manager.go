package loader

// lsm_manager.go — Manages per-hook enable/disable at runtime.
// This allows selective activation of heavyweight hooks.

// HookID identifies a specific LSM hook by name.
type HookID string

const (
	HookTaskAlloc       HookID = "task_alloc"
	HookTaskFree        HookID = "task_free"
	HookFileOpen        HookID = "file_open"
	HookFilePermission  HookID = "file_permission"
	HookBprmCheck       HookID = "bprm_check_security"
	HookSocketConnect   HookID = "socket_connect"
)

// HookConfig controls which hooks are enabled at load time.
type HookConfig struct {
	EnabledHooks []HookID
}

// DefaultHooks returns the default set of enabled hooks.
func DefaultHooks() HookConfig {
	return HookConfig{
		EnabledHooks: []HookID{
			HookTaskAlloc,
			HookTaskFree,
			HookFileOpen,
			HookBprmCheck,
			HookSocketConnect,
		},
	}
}
