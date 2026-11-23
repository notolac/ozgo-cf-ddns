// Package cron parses standard five-field cron expressions and computes the
// next activation time. It supports *, numbers, ranges (a-b), steps (*/n,
// a-b/n, a/n), lists (a,b,c) and the @hourly, @daily, @weekly, @monthly and
// @yearly macros. Names (jan, mon) are not supported.
package cron

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// Schedule is a parsed cron expression.
type Schedule struct {
	spec                       string
	minute, hour, dom, month   uint64
	dow                        uint64
	domRestricted, dowRestrict bool
}

var macros = map[string]string{
	"@yearly":   "0 0 1 1 *",
	"@annually": "0 0 1 1 *",
	"@monthly":  "0 0 1 * *",
	"@weekly":   "0 0 * * 0",
	"@daily":    "0 0 * * *",
	"@midnight": "0 0 * * *",
	"@hourly":   "0 * * * *",
}

// Parse parses a cron expression.
func Parse(spec string) (*Schedule, error) {
	spec = strings.TrimSpace(spec)
	expr := spec
	if m, ok := macros[strings.ToLower(spec)]; ok {
		expr = m
	}
	f := strings.Fields(expr)
	if len(f) != 5 {
		return nil, fmt.Errorf("%q: expected 5 fields (minute hour day-of-month month day-of-week)", spec)
	}
	s := &Schedule{spec: spec}
	var err error
	var star bool
	if s.minute, _, err = parseField(f[0], 0, 59); err != nil {
		return nil, fmt.Errorf("minute: %w", err)
	}
	if s.hour, _, err = parseField(f[1], 0, 23); err != nil {
		return nil, fmt.Errorf("hour: %w", err)
	}
	if s.dom, star, err = parseField(f[2], 1, 31); err != nil {
		return nil, fmt.Errorf("day of month: %w", err)
	}
	s.domRestricted = !star
	if s.month, _, err = parseField(f[3], 1, 12); err != nil {
		return nil, fmt.Errorf("month: %w", err)
	}
	if s.dow, star, err = parseField(f[4], 0, 7); err != nil {
		return nil, fmt.Errorf("day of week: %w", err)
	}
	s.dowRestrict = !star
	if s.dow&(1<<7) != 0 { // 7 is Sunday too
		s.dow = s.dow&^(1<<7) | 1
	}
	return s, nil
}

// String returns the original expression.
func (s *Schedule) String() string { return s.spec }

func parseField(field string, lo, hi int) (bits uint64, star bool, err error) {
	for part := range strings.SplitSeq(field, ",") {
		rng, stepStr, hasStep := strings.Cut(part, "/")
		step := 1
		if hasStep {
			step, err = strconv.Atoi(stepStr)
			if err != nil || step < 1 {
				return 0, false, fmt.Errorf("invalid step %q", stepStr)
			}
		}
		var a, b int
		switch {
		case rng == "*":
			a, b = lo, hi
			if !hasStep {
				star = true
			}
		case strings.Contains(rng, "-"):
			as, bs, _ := strings.Cut(rng, "-")
			if a, err = strconv.Atoi(as); err != nil {
				return 0, false, fmt.Errorf("invalid range %q", rng)
			}
			if b, err = strconv.Atoi(bs); err != nil {
				return 0, false, fmt.Errorf("invalid range %q", rng)
			}
		default:
			if a, err = strconv.Atoi(rng); err != nil {
				return 0, false, fmt.Errorf("invalid value %q", rng)
			}
			b = a
			if hasStep {
				b = hi
			}
		}
		if a < lo || b > hi || a > b {
			return 0, false, fmt.Errorf("%q is out of range %d-%d", part, lo, hi)
		}
		for i := a; i <= b; i += step {
			bits |= 1 << uint(i)
		}
	}
	if bits == 0 {
		return 0, false, errors.New("empty field")
	}
	return bits, star, nil
}

// Next returns the first activation time strictly after t, in t's location.
// It returns the zero time if nothing matches within five years.
func (s *Schedule) Next(t time.Time) time.Time {
	loc := t.Location()
	t = t.Truncate(time.Minute).Add(time.Minute)
	limit := t.AddDate(5, 0, 0)
	for t.Before(limit) {
		switch {
		case s.month&(1<<uint(t.Month())) == 0:
			t = time.Date(t.Year(), t.Month()+1, 1, 0, 0, 0, 0, loc)
		case !s.dayMatches(t):
			t = time.Date(t.Year(), t.Month(), t.Day()+1, 0, 0, 0, 0, loc)
		case s.hour&(1<<uint(t.Hour())) == 0:
			next := time.Date(t.Year(), t.Month(), t.Day(), t.Hour()+1, 0, 0, 0, loc)
			if !next.After(t) { // DST edge: make progress
				next = t.Add(time.Hour).Truncate(time.Hour)
			}
			t = next
		case s.minute&(1<<uint(t.Minute())) == 0:
			t = t.Add(time.Minute)
		default:
			return t
		}
	}
	return time.Time{}
}

// dayMatches follows Vixie cron: when both day fields are restricted, either
// may match; otherwise both must.
func (s *Schedule) dayMatches(t time.Time) bool {
	dom := s.dom&(1<<uint(t.Day())) != 0
	dow := s.dow&(1<<uint(t.Weekday())) != 0
	if s.domRestricted && s.dowRestrict {
		return dom || dow
	}
	return dom && dow
}
