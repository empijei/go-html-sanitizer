package sanitize_test

import (
	"strings"
	"testing"

	"github.com/empijei/go-html-sanitizer/sanitize"
	"github.com/empijei/tst"
	"golang.org/x/net/html"
)

func TestPolicy_Sanitize(t *testing.T) {
	tst.Go(t)
	t.Run("empty allow", func(t *testing.T) {
		p := &sanitize.Policy{}
		got := p.SanitizeString(`prefix <a href="javascript:void(0)">link text</a> suffix`)
		tst.Is(`prefix link text suffix`, got, t)
	})
	t.Run("all are allowed", func(t *testing.T) {
		p := &sanitize.Policy{
			Allow: map[sanitize.TagName]map[sanitize.AttributeName]sanitize.AttributeFilter{
				"b": nil,
				"u": nil,
			},
		}
		got := p.SanitizeString(`normal text <b>bold text</b> <u>underlined</u>`)
		tst.Is(`normal text <b>bold text</b> <u>underlined</u>`, got, t)
	})
	t.Run("allow harmless", func(t *testing.T) {
		p := &sanitize.Policy{
			Allow: map[sanitize.TagName]map[sanitize.AttributeName]sanitize.AttributeFilter{
				"b": nil,
			},
		}
		got := p.SanitizeString(`normal text <b>bold text</b> <div>not allowed</div>`)
		tst.Is(`normal text <b>bold text</b> not allowed`, got, t)
	})
	t.Run("allow global", func(t *testing.T) {
		p := &sanitize.Policy{
			Allow: map[sanitize.TagName]map[sanitize.AttributeName]sanitize.AttributeFilter{
				"span": nil,
			},
			AllowGlobal: map[sanitize.AttributeName]sanitize.AttributeFilter{
				"lang": func(attrValue string) (keep bool) { return len(attrValue) >= 2 },
			},
		}
		got := p.SanitizeString(`normal text <span lang="en">english text</span> <span lang="">bad lang</span>`)
		tst.Is(`normal text <span lang="en">english text</span> <span>bad lang</span>`, got, t)
	})

	t.Run("remove", func(t *testing.T) {
		p := &sanitize.Policy{
			Allow: map[sanitize.TagName]map[sanitize.AttributeName]sanitize.AttributeFilter{
				"b": nil,
			},
			Remove: map[sanitize.TagName]string{
				"b": "REMOVED",
			},
		}
		got := p.SanitizeString(`normal text <b>bold text</b> <div>not allowed</div>`)
		tst.Is(`normal text REMOVED not allowed`, got, t)
	})

	t.Run("add attribute", func(t *testing.T) {
		p := &sanitize.Policy{
			Allow: map[sanitize.TagName]map[sanitize.AttributeName]sanitize.AttributeFilter{
				"a": {"href": nil, "rel": nil},
			},
			ModifyAttributes: map[sanitize.TagName]sanitize.AttributeModifier{
				"a": func(_ string, attrs *[]html.Attribute) {
					*attrs = append(*attrs, html.Attribute{Key: "rel", Val: "nofollow"})
				},
			},
		}
		got := p.SanitizeString(`prefix <a href="/foo">link text</a> suffix`)
		tst.Is(`prefix <a href="/foo" rel="nofollow">link text</a> suffix`, got, t)
	})
}

func TestPolicy_Relax(t *testing.T) {
	tst.Go(t)
	t.Run("basic merge", func(t *testing.T) {
		p1 := &sanitize.Policy{
			Allow: map[sanitize.TagName]map[sanitize.AttributeName]sanitize.AttributeFilter{
				"b": nil,
			},
		}
		p2 := &sanitize.Policy{
			Allow: map[sanitize.TagName]map[sanitize.AttributeName]sanitize.AttributeFilter{
				"i": nil,
			},
		}
		p1.Relax(p2)
		got := p1.SanitizeString("<b>bold</b> <i>italic</i>")
		tst.Is("<b>bold</b> <i>italic</i>", got, t)
	})

	t.Run("attribute merge", func(t *testing.T) {
		p1 := &sanitize.Policy{
			Allow: map[sanitize.TagName]map[sanitize.AttributeName]sanitize.AttributeFilter{
				"a": {"href": nil},
			},
		}
		p2 := &sanitize.Policy{
			Allow: map[sanitize.TagName]map[sanitize.AttributeName]sanitize.AttributeFilter{
				"a": {"title": nil},
			},
		}
		p1.Relax(p2)
		got := p1.SanitizeString(`<a href="/" title="home">link</a>`)
		tst.Is(`<a href="/" title="home">link</a>`, got, t)
	})

	t.Run("filter OR", func(t *testing.T) {
		p1 := &sanitize.Policy{
			Allow: map[sanitize.TagName]map[sanitize.AttributeName]sanitize.AttributeFilter{
				"span": {"class": func(v string) bool { return v == "red" }},
			},
		}
		p2 := &sanitize.Policy{
			Allow: map[sanitize.TagName]map[sanitize.AttributeName]sanitize.AttributeFilter{
				"span": {"class": func(v string) bool { return v == "blue" }},
			},
		}
		p1.Relax(p2)
		tst.Is(`<span class="red">red</span>`, p1.SanitizeString(`<span class="red">red</span>`), t)
		tst.Is(`<span class="blue">blue</span>`, p1.SanitizeString(`<span class="blue">blue</span>`), t)
		tst.Is(`<span>green</span>`, p1.SanitizeString(`<span class="green">green</span>`), t)
	})

	t.Run("remove reduction", func(t *testing.T) {
		p1 := &sanitize.Policy{
			Remove: map[sanitize.TagName]string{"b": "REMOVED", "i": "REMOVED"},
		}
		p2 := &sanitize.Policy{
			Remove: map[sanitize.TagName]string{"b": "REMOVED"},
		}
		p1.Relax(p2)
		// Only "b" should be in p1.Remove now.
		tst.Is("REMOVED", p1.SanitizeString("<b>bold</b>"), t)
		tst.Is("italic", p1.SanitizeString("<i>italic</i>"), t)
	})

	t.Run("allow global merge", func(t *testing.T) {
		p1 := &sanitize.Policy{
			Allow:       map[sanitize.TagName]map[sanitize.AttributeName]sanitize.AttributeFilter{"span": nil},
			AllowGlobal: map[sanitize.AttributeName]sanitize.AttributeFilter{"class": func(v string) bool { return v == "red" }},
		}
		p2 := &sanitize.Policy{
			AllowGlobal: map[sanitize.AttributeName]sanitize.AttributeFilter{"class": func(v string) bool { return v == "blue" }},
		}
		p1.Relax(p2)
		tst.Is(`<span class="red">red</span>`, p1.SanitizeString(`<span class="red">red</span>`), t)
		tst.Is(`<span class="blue">blue</span>`, p1.SanitizeString(`<span class="blue">blue</span>`), t)
	})

	t.Run("modifier chaining", func(t *testing.T) {
		p1 := &sanitize.Policy{
			Allow: map[sanitize.TagName]map[sanitize.AttributeName]sanitize.AttributeFilter{
				"b": {"class": nil, "id": nil},
			},
			ModifyAttributes: map[sanitize.TagName]sanitize.AttributeModifier{
				"b": func(_ string, attrs *[]html.Attribute) {
					*attrs = append(*attrs, html.Attribute{Key: "class", Val: "bold"})
				},
			},
		}
		p2 := &sanitize.Policy{
			Allow: map[sanitize.TagName]map[sanitize.AttributeName]sanitize.AttributeFilter{
				"b": {"class": nil, "id": nil},
			},
			ModifyAttributes: map[sanitize.TagName]sanitize.AttributeModifier{
				"b": func(_ string, attrs *[]html.Attribute) {
					*attrs = append(*attrs, html.Attribute{Key: "id", Val: "b1"})
				},
			},
		}
		p1.Relax(p2)
		// Should have both modifiers.
		got := p1.SanitizeString("<b>text</b>")
		tst.Is(`<b class="bold" id="b1">text</b>`, got, t)
	})
}

func TestPolicy_Restrict(t *testing.T) {
	tst.Go(t)
	t.Run("basic intersection", func(t *testing.T) {
		p1 := &sanitize.Policy{
			Allow: map[sanitize.TagName]map[sanitize.AttributeName]sanitize.AttributeFilter{
				"b": nil,
				"i": nil,
			},
		}
		p2 := &sanitize.Policy{
			Allow: map[sanitize.TagName]map[sanitize.AttributeName]sanitize.AttributeFilter{
				"i": nil,
			},
		}
		p1.Restrict(p2)
		got := p1.SanitizeString("<b>bold</b> <i>italic</i>")
		tst.Is("bold <i>italic</i>", got, t)
	})

	t.Run("filter AND", func(t *testing.T) {
		p1 := &sanitize.Policy{
			Allow: map[sanitize.TagName]map[sanitize.AttributeName]sanitize.AttributeFilter{
				"span": {"class": func(v string) bool { return strings.HasPrefix(v, "text-") }},
			},
		}
		p2 := &sanitize.Policy{
			Allow: map[sanitize.TagName]map[sanitize.AttributeName]sanitize.AttributeFilter{
				"span": {"class": func(v string) bool { return strings.HasSuffix(v, "-red") }},
			},
		}
		p1.Restrict(p2)
		tst.Is(`<span class="text-red">red</span>`, p1.SanitizeString(`<span class="text-red">red</span>`), t)
		tst.Is(`<span>text-blue</span>`, p1.SanitizeString(`<span class="text-blue">text-blue</span>`), t)
		tst.Is(`<span>bg-red</span>`, p1.SanitizeString(`<span class="bg-red">bg-red</span>`), t)
	})

	t.Run("remove union", func(t *testing.T) {
		p1 := &sanitize.Policy{
			Remove: map[sanitize.TagName]string{"b": "REMOVED"},
		}
		p2 := &sanitize.Policy{
			Remove: map[sanitize.TagName]string{"i": "REMOVED"},
		}
		p1.Restrict(p2)
		tst.Is("REMOVED", p1.SanitizeString("<b>bold</b>"), t)
		tst.Is("REMOVED", p1.SanitizeString("<i>italic</i>"), t)
	})

	t.Run("allow global intersection", func(t *testing.T) {
		p1 := &sanitize.Policy{
			Allow:       map[sanitize.TagName]map[sanitize.AttributeName]sanitize.AttributeFilter{"span": nil},
			AllowGlobal: map[sanitize.AttributeName]sanitize.AttributeFilter{"class": func(v string) bool { return strings.HasPrefix(v, "text-") }},
		}
		p2 := &sanitize.Policy{
			Allow:       map[sanitize.TagName]map[sanitize.AttributeName]sanitize.AttributeFilter{"span": nil},
			AllowGlobal: map[sanitize.AttributeName]sanitize.AttributeFilter{"class": func(v string) bool { return strings.HasSuffix(v, "-red") }},
		}
		p1.Restrict(p2)
		tst.Is(`<span class="text-red">red</span>`, p1.SanitizeString(`<span class="text-red">red</span>`), t)
		tst.Is(`<span>text-blue</span>`, p1.SanitizeString(`<span class="text-blue">text-blue</span>`), t)
	})
}
