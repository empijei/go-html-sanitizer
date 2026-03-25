package match_test

import (
	"testing"

	"github.com/empijei/go-html-sanitizer/match"
	"github.com/empijei/tst"
)

func TestASCIIPresets(t *testing.T) {
	tst.Go(t)

	t.Run("Letters", func(t *testing.T) {
		s := match.ASCIISetLetters().Step()
		check(t, s, "asb12", false)
		check(t, s, "ásb", false)
		check(t, s, "asb", true)
	})

	t.Run("LettersAndNumbers", func(t *testing.T) {
		s := match.ASCIISetLettersAndNumbers().Step()
		check(t, s, "asb12", true)
		check(t, s, "ásb", false)
		check(t, s, "asb", true)
		check(t, s, "123", true)
	})

	t.Run("WhiteSpace", func(t *testing.T) {
		s := match.ASCIISetWhiteSpace().Step()
		check(t, s, " ", true)
		check(t, s, "", false)
		check(t, s, "\t\f", true)
		check(t, s, "       ", true)
	})
}

func TestASCIISet_Negate(t *testing.T) {
	tst.Go(t)
	as := match.ASCIISetFrom('1', '2')
	check(t, as.Step(), "121", true)
	as = as.Negate()
	check(t, as.Step(), "121", false)
	check(t, as.Step(), "abc", true)
}

// TODO: GEMINI:
// Add tests to cover ASCIISet methods Negate, Union, ASCIISetLetters,
// ASCIISetLettersAndNumbers, ASCIISetWhiteSpace
