package sanitize

import (
	"slices"
	"strings"
	"testing"

	"github.com/empijei/tst"
)

func TestTokenizeStyleAttr(t *testing.T) {
	tst.Go(t)
	t.Run("simple", func(t *testing.T) {
		in := "color: white ; position :absolute !important; font-family: sans-serif !important "
		want := []StyleToken{
			{Property: "color", Expression: "white"},
			{Property: "position", Expression: "absolute", Important: true},
			{Property: "font-family", Expression: "sans-serif", Important: true},
		}
		got := slices.Collect(tokenizeStyleAttr(in))
		tst.Is(want, got, t)
	})
	t.Run("complex", func(t *testing.T) {
		in := ` font-FamIly : "Fira Code",
monospace ;position :absolute;
	color:    #fff !important; property with space: true; property-without-value:; prop: value is weird and ! has bangs`
		want := []StyleToken{
			{Property: "font-family", Expression: `"Fira Code",
monospace`},
			{Property: "position", Expression: "absolute"},
			{Property: "color", Expression: "#fff", Important: true},
			{Property: "property with space", Expression: "true"},
		}
		got := slices.Collect(tokenizeStyleAttr(in))
		tst.Is(want, got, t)
	})
}

func FuzzTokenizeStyleAttr(f *testing.F) {
	f.Add(` font-FamIly : "Fira Code",
monospace ;position :absolute;
	color:    #fff !important; property with space: true; property-without-value:; prop: value is weird and ! has bangs`)
	f.Add("color: white ; position :absolute !important; font-family: sans-serif !important")
	f.Fuzz(func(t *testing.T, in string) {
		got := slices.Collect(tokenizeStyleAttr(in))
		t.Logf("Input: %q", in)
		t.Logf("Got: %v", got)
		for _, tok := range got {
			if strings.Contains(tok.Property, ":") {
				t.Errorf("property contains ':': %q", tok.Property)
			}
			if trimmed := strings.TrimSpace(tok.Property); trimmed != tok.Property {
				t.Errorf("failed to trim property: %q %q", tok.Property, trimmed)
			}
			if trimmed := strings.TrimSpace(tok.Expression); trimmed != tok.Expression {
				t.Errorf("failed to trim value: %q %q", tok.Expression, trimmed)
			}
			if strings.Contains(tok.Expression, "!") {
				t.Errorf("value contains '!': %q", tok.Expression)
			}
			if strings.Contains(tok.Expression, ";") {
				t.Errorf("value contains ';': %q", tok.Expression)
			}
		}
	})
}

func FuzzStyleRoundTrip(f *testing.F) {
	f.Add(` font-FamIly : "Fira Code",
monospace ;position :absolute;
	color:    #fff !important; property with space: true; property-without-value:; prop: value is weird and ! has bangs`)
	f.Add("color: white ; position :absolute !important; font-family: sans-serif !important")
	f.Fuzz(func(t *testing.T, in string) {
		got1 := slices.Collect(tokenizeStyleAttr(in))
		ser1 := serializeStyle(slices.Values(got1))
		got2 := slices.Collect(tokenizeStyleAttr(ser1))
		ser2 := serializeStyle(slices.Values(got2))
		if ser1 != ser2 {
			t.Errorf("failed roundtrip for %q:\n1)%q\n2)%q", in, ser1, ser2)
		}
	})
}
