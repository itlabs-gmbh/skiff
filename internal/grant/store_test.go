package grant

import "testing"

func TestStoreProfileRoundTrip(t *testing.T) {
	s := Store{Dir: t.TempDir()}
	text, err := s.LoadProfile("vm1")
	if err != nil || text != "" {
		t.Fatalf("no profile yet: %q, %v", text, err)
	}
	if err := s.SaveProfile("vm1", "grants = [\"claude\"]\n"); err != nil {
		t.Fatalf("SaveProfile: %v", err)
	}
	text, err = s.LoadProfile("vm1")
	if err != nil || text != "grants = [\"claude\"]\n" {
		t.Errorf("LoadProfile = %q, %v", text, err)
	}
	if err := s.Remove("vm1"); err != nil {
		t.Fatal(err)
	}
	if text, _ := s.LoadProfile("vm1"); text != "" {
		t.Error("Remove must take the profile along")
	}
	if _, err := s.LoadProfile("Bad Name"); err == nil {
		t.Error("invalid VM name must be rejected")
	}
}
