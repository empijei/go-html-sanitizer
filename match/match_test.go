package match_test

import (
	"testing"

	"github.com/empijei/sanitize/match"
)

var (
	Degrees        = match.IntegerBetween(-360, +360)
	Units          = match.Words("cm", "px", "mm")
	Byte           = match.IntegerBetween(0, 255)
	NumberWithUnit = match.Combine(match.Integer, match.OptSpace, Units)
	RGB            = match.CombineOptSpace(
		match.Exact("("),
		Byte, match.Exact(","),
		Byte, match.Exact(","),
		Byte, match.Exact(")"),
	)
)

func TestBasic(t *testing.T) {
	t.Parallel()

	check := func(t *testing.T, m match.Matcher, in string, want bool) {
		t.Helper()
		if got := match.Check(m, in); got != want {
			t.Errorf("match.Check(%q) want %v got %v", in, want, got)
		}
	}
	t.Run("None", func(t *testing.T) {
		check(t, match.None, "", true)
		check(t, match.None, "some", false)
	})

	t.Run("NaN", func(t *testing.T) {
		check(t, match.Integer, "NaN", false)
	})

	t.Run("NaN Range", func(t *testing.T) {
		check(t, match.IntegerBetween(1, 3), "NaN", false)
	})

	t.Run("Unanchored", func(t *testing.T) {
		m := match.Combine(match.Integer, match.Any)
		check(t, m, "10 this should be ignored", true)
	})

	t.Run("Overflow", func(t *testing.T) {
		m := match.IntegerBetween(1, 100000000000000000)
		check(t, m, "10999999999999999999999999999", false)
	})

	t.Run("NumberWithUnit", func(t *testing.T) {
		m := match.Combine(match.Integer, Units)
		check(t, m, "4cm", true)
	})

	t.Run("NumberWithBadUnit", func(t *testing.T) {
		m := match.Combine(match.Integer, Units)
		check(t, m, "4in", false)
	})

	t.Run("NumberWithUnitAndSpace", func(t *testing.T) {
		check(t, NumberWithUnit, "+4 mm", true)
	})

	t.Run("bad NumberWithUnit", func(t *testing.T) {
		m := match.Combine(match.Integer, Units)
		check(t, m, "-4 mm", false)
	})

	t.Run("unanchored NumberWithUnit", func(t *testing.T) {
		m := match.Combine(match.Integer, Units)
		check(t, m, "4mm ", false)
	})

	t.Run("anchored NumberWithUnit", func(t *testing.T) {
		m := match.Combine(match.Integer, Units)
		check(t, m, "4mm", true)
	})

	t.Run("RGB", func(t *testing.T) {
		check(t, RGB, "(255, 239, 0)", true)
	})

	t.Run("Or Good", func(t *testing.T) {
		m := match.Combine(
			match.Or(match.Exact("A"), match.Exact("1")),
			match.Or(match.Exact("B"), match.Exact("2")),
			match.Or(match.Exact("C"), match.Exact("3")),
		)
		check(t, m, "A2C", true)
	})

	t.Run("Or Bad", func(t *testing.T) {
		m := match.Combine(
			match.Or(match.Exact("A"), match.Exact("1")),
			match.Or(match.Exact("B"), match.Exact("2")),
			match.Or(match.Exact("C"), match.Exact("3")),
		)
		check(t, m, "AB2", false)
	})
}
