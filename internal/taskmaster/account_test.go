package taskmaster

import "testing"

func TestAccountName(t *testing.T) {
	for in, want := range map[string]string{
		`WORKGROUP\alice`: "alice",
		`bob`:             "bob",
		`DOM\`:            "",
		``:                "",
	} {
		if got := accountName(in); got != want {
			t.Errorf("accountName(%q) = %q, want %q", in, got, want)
		}
	}
}
