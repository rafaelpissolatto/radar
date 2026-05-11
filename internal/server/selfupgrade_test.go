package server

import "testing"

// TestSelfUpgradePatchOptions is a tripwire: it pins the PatchOptions used
// by handleSelfUpgrade. FieldManager "helm" is what prevents the apiserver
// from recording "radar" as the owner of .image (derived from User-Agent
// when FieldManager is empty), which would break every later `helm
// upgrade` with a server-side-apply conflict. Force MUST stay unset on a
// StrategicMergePatch — apimachinery rejects it with a 422 Invalid so
// flipping Force back on regresses self-upgrade to "always fails."
// See selfupgrade.go for the full rationale.
func TestSelfUpgradePatchOptions(t *testing.T) {
	opts := selfUpgradePatchOptions()
	if opts.FieldManager != "helm" {
		t.Errorf("FieldManager = %q, want %q", opts.FieldManager, "helm")
	}
	if opts.Force != nil {
		t.Errorf("Force = %v, want nil (Force is forbidden on StrategicMergePatch and a non-nil value 422s the request)", opts.Force)
	}
}
