package match

import (
	"strconv"
	"strings"
	"unicode"
)

// OptSpace consumes whitespace, always matches.
//
//	/[[:space:]]*/
func OptSpace() Step { return optSpace }

func optSpace(s string) (remainder string, ok bool) {
	for {
		size, r := peek(s)
		if size == 0 || !unicode.IsSpace(r) {
			break
		}
		s = s[size:]
	}
	return s, true
}

// Integer consumes a number, only returns true if it was a number.
//
// It doesn't allow for decimal points, exponential notation or similar
// variations.
//
//	/(-|+)?\d+/
func Integer() Step { return integer }

func integer(s string) (remainder string, ok bool) {
	adv, ok := readInt(s)
	return s[adv:], ok
}

func readInt(s string) (advance int, ok bool) {
	size, r := peek(s)
	if r == '-' || r == '+' {
		advance += size
	}
	for {
		size, r := peek(s[advance:])
		if size == 0 || r < '0' || r > '9' {
			break
		}
		ok = true
		advance += size
	}
	return advance, ok
}

// IntegerBetween is like [Integer], but only matches if the number is between the two values,
// edges included.
//
// Numbers that overflow are rejected.
func IntegerBetween(low, high int64) Step {
	return func(s string) (rem string, ok bool) {
		adv, ok := readInt(s)
		if !ok {
			return s, false
		}
		val, err := strconv.ParseInt(s[:adv], 10, 64)
		if err != nil {
			return s, false
		}
		return s[adv:], low <= val && val <= high
	}
}

func readFloat(s string) (float, rem string, ok bool) {
	/*
		float = sign { digit } [ "." { digit } ] [ ("e"|"E") [ sign ] { digit } ]
		sign  = '+' | '-'
		digit = '0' -> '9'
	*/
	sign := ASCIISetFrom('-', '+').StepBetween(0, 1)
	digit := ASCIISetNumbers().Step()
	dot := Exact(".")
	exp := Words("e", "E")
	m := Combine(sign, digit,
		Opt(Combine(dot, digit)),
		Opt(Combine(exp, sign, digit)),
	)
	rem, ok = m(s)
	if !ok {
		return "", s, false
	}
	float = s[:len(s)-len(rem)]
	return float, rem, true
}

// Float matches a valid floating point number.
func Float() Step {
	return func(s string) (remainder string, ok bool) {
		_, rem, ok := readFloat(s)
		return rem, ok
	}
}

// FloatBetween matches a valid Floating point number within the given values (included).
func FloatBetween(from, to float64) Step {
	return func(s string) (remainder string, ok bool) {
		float, rem, ok := readFloat(s)
		if !ok {
			return rem, false
		}
		val, err := strconv.ParseFloat(float, 64)
		if err != nil {
			return rem, false
		}
		return rem, from <= val && val <= to
	}
}

// Words matches a set of fixed words.
//
//	/(word1|word2|word3)/
func Words(accept ...string) Step {
	var t trie
	for _, w := range accept {
		t.insert(w)
	}
	return func(s string) (rem string, ok bool) {
		adv, ok := t.match(s, 0)
		return s[adv:], ok
	}
}

// WordsToLower matches a set of fixed words, lowercasing all parameters and inputs.
func WordsToLower(accept ...string) Step {
	t := trie{toLower: true}
	for _, w := range accept {
		t.insert(w)
	}
	return func(s string) (rem string, ok bool) {
		adv, ok := t.match(s, 0)
		return s[adv:], ok
	}
}

// Exact matches exactly the given word.
//
//	/word/
func Exact(accept string) Step {
	return func(s string) (string, bool) {
		if !strings.HasPrefix(s, accept) {
			return s, false
		}
		return s[len(accept):], true
	}
}

// Any consume the rest of the input.
//
//	/.*/
func Any() Step { return stepAny }

func stepAny(_ string) (remainder string, ok bool) {
	return "", true
}

// None only matches the empty string.
//
//	//
func None() Step { return none }

func none(s string) (remainder string, ok bool) {
	return s, s == ""
}

// RunesFunc returns a matcher that consumes a sequence of runes that match at least
// one of the provided matcher.
//
// Returns false IFF none matched.
func RunesFunc(match ...func(r rune) bool) Step {
	return func(s string) (rem string, ok bool) {
		var adv int
		for {
			size, r := peek(s[adv:])
			if size == 0 {
				break
			}
			var found bool
			for _, m := range match {
				if !m(r) {
					continue
				}
				found = true
				break
			}
			if !found {
				break
			}
			adv += size
		}
		return s[adv:], adv != 0
	}
}

// Letters returns whether the sequence is at least one Letter.
//
//	/[\p{L}]+/
func Letters() Step { return letters }

var letters = RunesFunc(unicode.IsLetter)

// Numbers returns whether the sequence is at least one number.
//
//	/[\p{N}]+/
func Numbers() Step { return numbers }

var numbers = RunesFunc(unicode.IsNumber)

// LettersAndNumbers returns whether the sequence is at least one number.
//
//	/[\p{N}\p{L}]+/
func LettersAndNumbers() Step { return lettersAndNumbers }

var lettersAndNumbers = RunesFunc(unicode.IsLetter, unicode.IsNumber)

// Runes constructs a matcher that matches the given runes.
func Runes(chars ...rune) Step {
	rs := map[rune]struct{}{}
	for _, r := range chars {
		rs[r] = struct{}{}
	}
	return RunesFunc(func(r rune) bool {
		_, ok := rs[r]
		return ok
	})
}

// RunesNot constructs a matcher that matches all but the given runes.
func RunesNot(chars ...rune) Step {
	// TODO test
	rs := map[rune]struct{}{}
	for _, r := range chars {
		rs[r] = struct{}{}
	}
	return RunesFunc(func(r rune) bool {
		_, ok := rs[r]
		return !ok
	})
}
