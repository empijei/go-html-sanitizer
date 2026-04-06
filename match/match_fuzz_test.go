package match_test

import (
	"regexp"
	"testing"

	"github.com/empijei/go-html-sanitizer/match"
	"github.com/empijei/tst"
)

func TestRegression(t *testing.T) {
	tst.Go(t)
	m := match.Combine(match.Integer(),
		match.OptSpace(),
		match.Words("asd", "fgh", "jkl"),
		match.Or(match.Exact("word"),
			match.Integer()),
		match.Exact("."),
		match.LettersAndNumbers(),
	)
	gotM := m.Matcher()("3jklword.045é")
	_ = gotM
}

func FuzzAll(f *testing.F) {
	r := regexp.MustCompile(`^(-|\+)?\d+[[:space:]]*(asd|fgh|jkl)(word|(-|\+)?\d+)\.[\p{N}\p{L}]+$`)
	m := match.Combine(match.Integer(),
		match.OptSpace(),
		match.Words("asd", "fgh", "jkl"),
		match.Or(match.Exact("word"),
			match.Integer()),
		match.Exact("."),
		match.LettersAndNumbers(),
	)
	f.Add(`+3  fgh-3.asd45`)
	f.Add(`3jklword.045é`)
	f.Fuzz(func(t *testing.T, a string) {
		gotR := r.MatchString(a)
		gotM := m.Matcher()(a)
		if gotR != gotM {
			t.Fatalf(`
Found mismatch on input %q
Unquoted: '%s'
regex: %v
matcher: %v
`, a, a, gotR, gotM)
		}
	})
}

func BenchmarkMatch(b *testing.B) {
	m := match.Combine(match.Integer(),
		match.OptSpace(),
		match.Words("asd", "fgh", "jkl"),
		match.Or(match.Exact("word"),
			match.Integer()),
		match.Exact("."),
		match.LettersAndNumbers(),
	)
	in := `3jklword.045é`
	for b.Loop() {
		m.Matcher()(in)
	}
}

func BenchmarkRegexp(b *testing.B) {
	r := regexp.MustCompile(`^(-|\+)?\d+[[:space:]]*(asd|fgh|jkl)(word|(-|\+)?\d+)\.[\p{N}\p{L}]+$`)
	in := `3jklword.045é`
	for b.Loop() {
		r.MatchString(in)
	}
}

func BenchmarkMatchBad(b *testing.B) {
	m := match.Combine(match.Integer(),
		match.OptSpace(),
		match.Words("asd", "fgh", "jkl"),
		match.Or(match.Exact("word"),
			match.Integer()),
		match.Exact("."),
		match.LettersAndNumbers(),
	)
	in := `3jkl_word.045é`
	for b.Loop() {
		m.Matcher()(in)
	}
}

func BenchmarkRegexpBad(b *testing.B) {
	r := regexp.MustCompile(`^(-|\+)?\d+[[:space:]]*(asd|fgh|jkl)(word|(-|\+)?\d+)\.[\p{N}\p{L}]+$`)
	in := `3jkl_word.045é`
	for b.Loop() {
		r.MatchString(in)
	}
}
