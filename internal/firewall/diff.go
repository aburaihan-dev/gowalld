package firewall

// Diff compares live against desired and returns the plan to reconcile them,
// matching rules by their content-hash ID. Shared by every backend's
// Restore implementation and by the standalone `gowalld diff` command, so
// there is exactly one definition of what "changed" means.
func Diff(live, desired []Rule) *RestorePlan {
	liveByID := make(map[string]Rule, len(live))
	for _, r := range live {
		liveByID[r.ID] = r
	}
	desiredByID := make(map[string]Rule, len(desired))
	for _, r := range desired {
		desiredByID[r.ID] = r
	}

	plan := &RestorePlan{}
	for _, r := range desired {
		if _, ok := liveByID[r.ID]; ok {
			plan.Unchanged = append(plan.Unchanged, r)
		} else {
			plan.ToAdd = append(plan.ToAdd, r)
		}
	}
	for _, r := range live {
		if _, ok := desiredByID[r.ID]; !ok {
			plan.ToRemove = append(plan.ToRemove, r)
		}
	}
	return plan
}
