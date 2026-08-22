package utils

// MaxTargets returns the maximum number of scan targets allowed per task.
func (rl *ResourceLimiter) MaxTargets() int {
	rl.mu.RLock()
	defer rl.mu.RUnlock()
	return rl.maxTargets
}
