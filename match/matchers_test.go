package match_test

import (
	"testing"

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

func check(t *testing.T, m match.Step, in string, want bool) {
	t.Helper()
	if got := m.Matcher()(in); got != want {
		t.Errorf("match.Check(%q) want %v got %v", in, want, got)
	}
}

func TestNumberWithUnit(t *testing.T) {
	tst.Go(t)
	units := match.Words("cm", "px", "mm")
	numberWithUnitAndOptSpace := match.Combine(match.Integer(), match.OptSpace(), units)
	numberWithUnit := match.Combine(match.Integer(), units)

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

func TestNone(t *testing.T) {
	tst.Go(t)
	check(t, match.None(), "", true)
	check(t, match.None(), "some", false)
}

func TestNaN(t *testing.T) {
	tst.Go(t)
	check(t, match.Integer(), "NaN", false)
}

func TestNaNRange(t *testing.T) {
	tst.Go(t)
	check(t, match.IntegerBetween(1, 3), "NaN", false)
}

func TestUnanchored(t *testing.T) {
	tst.Go(t)
	m := match.Combine(match.Integer(), match.Any())
	check(t, m, "10 this should be ignored", true)
}

func TestOverflow(t *testing.T) {
	tst.Go(t)
	m := match.IntegerBetween(1, 100000000000000000)
	check(t, m, "10999999999999999999999999999", false)
}

func TestLettersNumbers(t *testing.T) {
	tst.Go(t)
	check(t, match.LettersAndNumbers(), "4aF8é", true)
	check(t, match.LettersAndNumbers(), "4aF8-é", false)
}

func TestLetters(t *testing.T) {
	tst.Go(t)
	check(t, match.Letters(), "FégtP", true)
	check(t, match.Letters(), "Fé1gtP", false)
}

func TestNumbers(t *testing.T) {
	tst.Go(t)
	check(t, match.Numbers(), "156473890", true)
	check(t, match.Numbers(), "1e10", false)
}

func TestRGB(t *testing.T) {
	tst.Go(t)
	check(t, RGB, "(255, 239, 0)", true)
}

func TestOrGood(t *testing.T) {
	tst.Go(t)
	m := match.Combine(
		match.Or(match.Exact("A"), match.Exact("1")),
		match.Or(match.Exact("B"), match.Exact("2")),
		match.Or(match.Exact("C"), match.Exact("3")),
	)
	check(t, m, "A2C", true)
}

func TestOrBad(t *testing.T) {
	tst.Go(t)
	m := match.Combine(
		match.Or(match.Exact("A"), match.Exact("1")),
		match.Or(match.Exact("B"), match.Exact("2")),
		match.Or(match.Exact("C"), match.Exact("3")),
	)
	check(t, m, "AB2", false)
}

func TestASCII(t *testing.T) {
	tst.Go(t)
	m := match.ASCIISetFrom('a', 'b', 'c').Step()
	check(t, m, "abc", true)
	check(t, m, "abcd", false)
	check(t, m, "d", false)
}

func TestRunes(t *testing.T) {
	tst.Go(t)
	m := match.Runes('A', 'é')
	check(t, m, "AéA", true)
	check(t, m, "b", false)
}

func TestWordsToLower(t *testing.T) {
	tst.Go(t)
	m := match.WordsToLower("HelloWorld", "FooBar")
	check(t, m, "helloworld", true)
	check(t, m, "HELLOWORLD", true)
	check(t, m, "HelloWorld", true)
	check(t, m, "foobar", true)
	check(t, m, "FOOBAR", true)
	check(t, m, "FooBar", true)
	check(t, m, "baz", false)
	mt := match.WordsToLower("", "alt")
	check(t, mt, "", true)
	check(t, mt, "alt", true)
	check(t, mt, "nope", false)
}

func TestRepeat(t *testing.T) {
	tst.Go(t)
	s := match.Combine(
		match.Numbers(),
		match.Letters(),
	)
	s = match.Repeat(2, 4, s)
	check(t, s, "1a1a1a", true)
	check(t, s, "1ab32cd1a", true)
	check(t, s, "1a1a1a1a", true)
	check(t, s, "1a1a", true)
	check(t, s, "1a", false)
	check(t, s, "", false)
	check(t, s, "1a1a1a1a1a", false)
}

func TestFloat(t *testing.T) {
	tst.Go(t)
	m := match.Float()
	check(t, m, "+1+e-10", false)
	check(t, m, "1.1.1e10", false)
	check(t, m, "1.1e1.0", false)
	check(t, m, "1e10", true)
	check(t, m, "1.2", true)
	check(t, m, "1", true)
	check(t, m, "1.2e10", true)
	check(t, m, "1.2e-10", true)
	check(t, m, "+1.2E-10", true)
	check(t, m, "+1e-10", true)
}

func TestFloatBetween(t *testing.T) {
	tst.Go(t)
	m := match.FloatBetween(1, 100)
	check(t, m, "1e2", true)
	check(t, m, "1e1", true)
	check(t, m, "1.0", true)
	check(t, m, "101", false)
	check(t, m, "-1", false)
	check(t, m, "0", false)
}

func TestRunesNot(t *testing.T) {
	tst.Go(t)
	m := match.RunesNot('a', 'é')
	check(t, m, "ábcd", true)
	check(t, m, "bécd", false)
	check(t, m, "bacd", false)
}

// TODO Add tests to cover CombineEager
