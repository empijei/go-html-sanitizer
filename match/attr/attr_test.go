package attr_test

import (
	"testing"

	"github.com/empijei/go-html-sanitizer/match"
	"github.com/empijei/go-html-sanitizer/match/attr"
	"github.com/empijei/tst"
)

func TestMatch(t *testing.T) {
	tst.Go(t)
	check := func(t *testing.T, want bool, m match.Matcher, in string) {
		t.Helper()
		if m(in) == want {
			return
		}
		t.Errorf("%q: got %v want %v", in, !want, want)
	}
	t.Run("dir", func(t *testing.T) {
		check(t, true, attr.Dir, "ltr")
		check(t, true, attr.Dir, "rtl")
		check(t, false, attr.Dir, "")
		check(t, false, attr.Dir, "foo")
	})
	t.Run("lang", func(t *testing.T) {
		check(t, false, attr.Lang, "e")
		check(t, true, attr.Lang, "en")
		check(t, true, attr.Lang, "en-US")
		check(t, false, attr.Lang, "this-language-code-is-way-too-long-to-match")
	})
	t.Run("freetext", func(t *testing.T) {
		check(t, true, attr.FreeText, "Hello World")
		check(t, false, attr.FreeText, "<script>")
		check(t, false, attr.FreeText, "foo & bar")
		check(t, false, attr.FreeText, `"quote"`)
	})
	t.Run("name", func(t *testing.T) {
		check(t, true, attr.Name, "my-element-123")
		check(t, false, attr.Name, "my element")
		check(t, false, attr.Name, "foo&bar")
	})
	t.Run("coords", func(t *testing.T) {
		check(t, true, attr.Coords, "1")
		check(t, true, attr.Coords, "10,2")
		check(t, true, attr.Coords, "2,30,4")
		check(t, false, attr.Coords, "2,30,4,")
		check(t, false, attr.Coords, ",2,30,4,")
		check(t, false, attr.Coords, ",")
	})
	t.Run("space-separated-tokens", func(t *testing.T) {
		check(t, true, attr.SpaceSeparatedTokens, "foo bar baz-123")
		check(t, false, attr.SpaceSeparatedTokens, "foo & bar")
	})
	t.Run("rel", func(t *testing.T) {
		check(t, true, attr.Rel, "nofollow")
		check(t, true, attr.Rel, "noopener noreferrer")
		check(t, true, attr.Rel, "alternate  author")
		check(t, false, attr.Rel, "foo")
		check(t, false, attr.Rel, "nofollow foo")
	})
	t.Run("shapes", func(t *testing.T) {
		check(t, true, attr.Shapes, "rect")
		check(t, true, attr.Shapes, "circle")
		check(t, true, attr.Shapes, "poly")
		check(t, true, attr.Shapes, "default")
		check(t, false, attr.Shapes, "square")
	})
	t.Run("id", func(t *testing.T) {
		check(t, true, attr.ID, "main-content")
		check(t, false, attr.ID, "main content")
		check(t, false, attr.ID, "foo<bar")
	})
	t.Run("usemap", func(t *testing.T) {
		check(t, true, attr.UseMap, "#my-map")
		check(t, false, attr.UseMap, "my-map")
		check(t, false, attr.UseMap, "#my map")
	})
	t.Run("time-iso8601", func(t *testing.T) {
		check(t, true, attr.TimeISO8601, "2023-10-27")
		check(t, true, attr.TimeISO8601, "2023-10-27T10:30:00Z")
		check(t, true, attr.TimeISO8601, "2023-10-27T10:30:00.123+02:00")
		check(t, false, attr.TimeISO8601, "2023/10/27")
		check(t, false, attr.TimeISO8601, "10:30:00")
	})
	t.Run("open", func(t *testing.T) {
		check(t, true, attr.Open, "open")
		check(t, true, attr.Open, "")
		check(t, false, attr.Open, "closed")
	})
}
