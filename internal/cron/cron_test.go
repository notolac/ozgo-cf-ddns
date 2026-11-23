package cron

import (
	"testing"
	"time"
)

func mustParse(t *testing.T, spec string) *Schedule {
	t.Helper()
	s, err := Parse(spec)
	if err != nil {
		t.Fatalf("Parse(%q): %v", spec, err)
	}
	return s
}

func TestNext(t *testing.T) {
	base := time.Date(2026, 3, 14, 10, 3, 27, 0, time.UTC) // a Saturday
	cases := []struct {
		spec string
		want time.Time
	}{
		{"*/5 * * * *", time.Date(2026, 3, 14, 10, 5, 0, 0, time.UTC)},
		{"* * * * *", time.Date(2026, 3, 14, 10, 4, 0, 0, time.UTC)},
		{"0 * * * *", time.Date(2026, 3, 14, 11, 0, 0, 0, time.UTC)},
		{"@hourly", time.Date(2026, 3, 14, 11, 0, 0, 0, time.UTC)},
		{"30 2 * * *", time.Date(2026, 3, 15, 2, 30, 0, 0, time.UTC)},
		{"0 0 1 * *", time.Date(2026, 4, 1, 0, 0, 0, 0, time.UTC)},
		{"0 9 * * 1-5", time.Date(2026, 3, 16, 9, 0, 0, 0, time.UTC)},
		{"0 0 * * 7", time.Date(2026, 3, 15, 0, 0, 0, 0, time.UTC)},
		{"15,45 10 * * *", time.Date(2026, 3, 14, 10, 15, 0, 0, time.UTC)},
		{"0 0 29 2 *", time.Date(2028, 2, 29, 0, 0, 0, 0, time.UTC)},
		// Both day fields restricted: either matches (Vixie cron).
		{"0 0 20 * 1", time.Date(2026, 3, 16, 0, 0, 0, 0, time.UTC)},
		{"5/20 * * * *", time.Date(2026, 3, 14, 10, 5, 0, 0, time.UTC)},
	}
	for _, tc := range cases {
		got := mustParse(t, tc.spec).Next(base)
		if !got.Equal(tc.want) {
			t.Errorf("%q: Next = %s, want %s", tc.spec, got, tc.want)
		}
	}
}

func TestNextIsStrictlyAfter(t *testing.T) {
	s := mustParse(t, "*/5 * * * *")
	at := time.Date(2026, 1, 1, 0, 5, 0, 0, time.UTC)
	if got := s.Next(at); !got.Equal(at.Add(5 * time.Minute)) {
		t.Fatalf("Next = %s", got)
	}
}

func TestNextAcrossDST(t *testing.T) {
	loc, err := time.LoadLocation("Europe/Madrid")
	if err != nil {
		t.Skip("no tzdata")
	}
	s := mustParse(t, "30 2 * * *") // 02:30 does not exist on 2026-03-29
	got := s.Next(time.Date(2026, 3, 29, 1, 0, 0, 0, loc))
	if got.IsZero() || got.Before(time.Date(2026, 3, 29, 1, 0, 0, 0, loc)) {
		t.Fatalf("Next = %s", got)
	}
}

func TestParseErrors(t *testing.T) {
	for _, spec := range []string{"", "* * * *", "60 * * * *", "* 24 * * *", "* * 0 * *", "* * * 13 *", "* * * * 8", "*/0 * * * *", "a * * * *", "5-1 * * * *"} {
		if _, err := Parse(spec); err == nil {
			t.Errorf("Parse(%q) succeeded", spec)
		}
	}
}
