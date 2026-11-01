package actions

import "testing"

func TestEveryRegisteredActionHasACatalogRisk(t *testing.T) {
	for action := range registered {
		if Risk(action) == "" {
			t.Fatalf("action %s has no catalog risk", action)
		}
	}
	if Risk("not_an_action") != "" {
		t.Fatal("unregistered action has a risk")
	}
}

func TestEffectiveRiskNeverLowersTheCatalog(t *testing.T) {
	cases := []struct{ action, requested, want string }{
		{RestartPod, "low", "medium"},
		{RestartPod, "", "medium"},
		{RestartPod, "high", "high"},
		{CollectDiagnostics, "low", "low"},
		{CollectDiagnostics, "medium", "medium"},
		{RestartPod, "bogus", "bogus"},
	}
	for _, tc := range cases {
		if got := EffectiveRisk(tc.action, tc.requested); got != tc.want {
			t.Fatalf("EffectiveRisk(%s, %q)=%q want %q", tc.action, tc.requested, got, tc.want)
		}
	}
}
