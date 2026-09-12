package source

import "testing"

func TestParseGitHub(t *testing.T) {
	cases := map[string][3]string{
		"teemow/patty":                        {"teemow", "patty", "ok"},
		"teemow/patty.git":                    {"teemow", "patty", "ok"},
		"https://github.com/teemow/patty":     {"teemow", "patty", "ok"},
		"https://github.com/teemow/patty.git": {"teemow", "patty", "ok"},
		"git@github.com:teemow/patty.git":     {"teemow", "patty", "ok"},
		"teemow":                              {"teemow", "", "ok"},
		"a/b/c":                               {"", "", ""},
		"bad arg":                             {"", "", ""},
		"":                                    {"", "", ""},
	}
	for in, want := range cases {
		owner, name, ok := parseGitHub(in)
		if owner != want[0] || name != want[1] || ok != (want[2] == "ok") {
			t.Errorf("parseGitHub(%q) = %q %q %v", in, owner, name, ok)
		}
	}
}
