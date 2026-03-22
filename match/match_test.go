package match_test

import (
	"strings"
	"testing"

	"github.com/empijei/go-html-sanitizer/dom"
	"github.com/empijei/go-html-sanitizer/match"
	"github.com/empijei/tst"
)

var (
	Degrees = match.IntegerBetween(-360, +360)
	Byte    = match.IntegerBetween(0, 255)
	RGB     = match.CombineOptSpace(
		match.Exact("("),
		Byte, match.Exact(","),
		Byte, match.Exact(","),
		Byte, match.Exact(")"),
	)
)

func check(t *testing.T, m match.Matcher, in string, want bool) {
	t.Helper()
	if got := match.Check(m, in); got != want {
		t.Errorf("match.Check(%q) want %v got %v", in, want, got)
	}
}

func TestNumberWithUnit(t *testing.T) {
	units := match.Words("cm", "px", "mm")
	numberWithUnitAndOptSpace := match.Combine(match.Integer, match.OptSpace, units)
	numberWithUnit := match.Combine(match.Integer, units)

	t.Run("base", func(t *testing.T) {
		check(t, numberWithUnit, "4cm", true)
	})

	t.Run("bad unit", func(t *testing.T) {
		check(t, numberWithUnit, "4in", false)
	})

	t.Run("opt space", func(t *testing.T) {
		check(t, numberWithUnitAndOptSpace, "+4 mm", true)
	})

	t.Run("spurious space", func(t *testing.T) {
		check(t, numberWithUnit, "-4 mm", false)
	})

	t.Run("trailing space", func(t *testing.T) {
		check(t, numberWithUnit, "4mm ", false)
	})

	t.Run("missing unit", func(t *testing.T) {
		check(t, numberWithUnit, "4", false)
	})
}

func TestBasic(t *testing.T) {
	t.Parallel()

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

	t.Run("Letters and Numbers", func(t *testing.T) {
		check(t, match.LettersAndNumbers, "4aF8é", true)
	})

	t.Run("Letters and Numbers with extra char", func(t *testing.T) {
		check(t, match.LettersAndNumbers, "4aF8-é", false)
	})

	t.Run("Letters", func(t *testing.T) {
		check(t, match.Letters, "FégtP", true)
		check(t, match.Letters, "Fé1gtP", false)
	})

	t.Run("Numbers", func(t *testing.T) {
		check(t, match.Numbers, "156473890", true)
		check(t, match.Numbers, "1e10", false)
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

	t.Run("ASCII", func(t *testing.T) {
		m := match.ASCII('a', 'b', 'c')
		check(t, m, "abc", true)
		check(t, m, "abcd", false)
		check(t, m, "d", false)
	})

	t.Run("Runes", func(t *testing.T) {
		m := match.Runes('A', 'é')
		check(t, m, "AéA", true)
		check(t, m, "b", false)
	})

	t.Run("WordsToLower", func(t *testing.T) {
		m := match.WordsToLower("HelloWorld", "FooBar")
		check(t, m, "helloworld", true)
		check(t, m, "HELLOWORLD", true)
		check(t, m, "HelloWorld", true)
		check(t, m, "foobar", true)
		check(t, m, "FOOBAR", true)
		check(t, m, "FooBar", true)
		check(t, m, "baz", false)
	})
}

func TestAtom(t *testing.T) {
	n := tst.Do(dom.ParseInBody(strings.NewReader(`<A-CUSTOM-ELEM></A-CUSTOM-ELEM>`)))(t)
	tst.Is("a-custom-elem", n.FakeRoot.FirstChild.Data, t)
}
