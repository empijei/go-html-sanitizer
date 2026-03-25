// Package attr provides matchers for HTML attribute values.
package attr

import (
	"math"
	"unicode"

	"github.com/empijei/go-html-sanitizer/match"
)

var (
	// Dir matches the "dir" attribute values: "rtl" or "ltr".
	Dir = match.WordsToLower("rtl", "ltr").Matcher()
	// Lang matches language codes.
	Lang = match.ASCIISetLetters().Insert('-').StepBetween(2, 20).Matcher() //nolint: mnd // Carried over from bluemonday.
	// FreeText matches text that does not contain HTML special characters (", ', &, <, >).
	FreeText = match.RunesNot('"', '\'', '&', '<', '>').Matcher()
	// Name matches alphanumeric characters and dashes.
	Name = match.RunesFunc(func(r rune) bool {
		return unicode.IsLetter(r) || unicode.IsNumber(r) || unicode.Is(unicode.Dash, r)
	}).Matcher()
	// Coords matches coordinate strings (e.g., "1", "10,2", "2,30,4").
	Coords = match.Combine(match.Integer(),
		match.Opt(
			match.Repeat(0, math.MaxInt32,
				match.Combine(
					match.Exact(","), match.Integer())),
		)).Matcher()
	// SpaceSeparatedTokens matches alphanumeric characters, dashes, and whitespace.
	SpaceSeparatedTokens = match.RunesFunc(func(r rune) bool {
		return unicode.IsLetter(r) || unicode.IsNumber(r) || unicode.Is(unicode.Dash, r) || unicode.IsSpace(r)
	}).Matcher()
	relToks = []string{
		"alternate", "author", "bookmark", "canonical", "compression", "dns", "expect", "external",
		"help", "icon", "license", "manifest", "me", "modulepreload", "next", "nofollow", "noopener", "noreferrer", "opener",
		"pingback", "preconnect", "prefetch", "preload", "prerender", "prev", "privacy", "search", "stylesheet", "tag",
		"terms-of-service", "ugc",
	}
	stepRelTok = match.WordsToLower(relToks...)
	// Rel matches space-separated relationship tokens (e.g., "nofollow", "noopener").
	Rel = match.Combine(
		stepRelTok,
		match.Opt(match.Repeat(1, uint(len(relToks)),
			match.Combine(
				match.ASCIIWhiteSpace().StepBetween(1, math.MaxInt64),
				stepRelTok,
			)))).Matcher()
	// Shapes matches the "shape" attribute values: "default", "circle", "rect", "poly".
	Shapes = match.WordsToLower("default", "circle", "rect", "poly").Matcher()
	id     = match.RunesFunc(func(r rune) bool {
		switch r {
		case '"', '\'', '&', '<', '>':
			return false
		}
		return !unicode.IsSpace(r)
	})
	// ID matches HTML "id" attribute values.
	ID = id.Matcher()
	// UseMap matches "#" followed by an ID.
	UseMap = match.Combine(match.Exact("#"), id).Matcher()

	stepTimeYYYY      = match.ASCIISetNumbers().StepBetween(4, 4)
	stepTimeMM        = match.Combine(match.Exact("-"), match.IntegerBetween(1, 12))
	stepTimeDD        = match.Combine(match.Exact("-"), match.IntegerBetween(1, 31))
	stepTimehh        = match.Combine(match.Exact("T"), match.IntegerBetween(0, 23))
	stepTimemmss      = match.Combine(match.Exact(":"), match.IntegerBetween(0, 59))
	stepTimeSfraction = match.Combine(match.Exact("."), match.Numbers())
	stepTimeZoneDelta = match.Or(
		match.Exact("Z"),
		match.Combine(match.Words("-", "+"), match.IntegerBetween(0, 23), stepTimemmss),
	)
	// TimeISO8601 matches ISO 8601-like date-time strings.
	TimeISO8601 = match.CombineEager(
		stepTimeYYYY,
		stepTimeMM,
		stepTimeDD,
		stepTimehh,
		stepTimemmss,
		stepTimemmss,
		match.Opt(stepTimeSfraction),
		stepTimeZoneDelta,
	).Matcher()

	// Open matches an optional "open" string (common for boolean attributes like "open").
	Open              = match.WordsToLower("", "open").Matcher()
	ListType          = match.WordsToLower("circle", "disc", "square", "a", "A", "i", "I", "1").Matcher()
	ImgAlign          = match.WordsToLower("left", "right", "top", "texttop", "middle", "absmiddle", "baseline", "bottom", "absbottom").Matcher()
	NumberOrPercent   = match.CombineEager(match.Integer(), match.Exact("%")).Matcher()
	CellAlign         = match.WordsToLower("center", "justify", "left", "right", "char").Matcher()
	CellVerticalAlign = match.WordsToLower("baseline", "bottom", "middle", "top").Matcher()
	THScope           = match.WordsToLower("row", "col", "rowgroup", "colgroup").Matcher()
	NoWrap            = match.WordsToLower("", "nowrap").Matcher()
)
