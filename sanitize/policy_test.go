package sanitize_test

import (
	"strings"
	"testing"

	"github.com/empijei/go-html-sanitizer/policies"
	"github.com/empijei/go-html-sanitizer/sanitize"
	"github.com/empijei/tst"
	"golang.org/x/net/html"
)

func TestPolicy_Sanitize(t *testing.T) {
	tst.Go(t)

	t.Run("null byte", func(t *testing.T) {
		p := &sanitize.Policy{}
		got := p.SanitizeString("\x00 ")
		tst.Is(` `, got, t)
	})
	t.Run("empty allow", func(t *testing.T) {
		p := &sanitize.Policy{}
		got := p.SanitizeString(`prefix <a href="javascript:void(0)">link text</a> suffix<!--comment-->`)
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
				sanitize.AllTags: {
					"lang": func(attrValue string) (keep bool) { return len(attrValue) >= 2 },
				},
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
			URIs: policies.NewURIs(),
			ModifyAttributes: map[sanitize.TagName][]sanitize.AttributeModifier{
				"a": {func(_ string, attrs *[]html.Attribute) {
					*attrs = append(*attrs, html.Attribute{Key: "rel", Val: "nofollow"})
				}},
			},
		}
		got := p.SanitizeString(`prefix <a href="/foo">link text</a> suffix`)
		tst.Is(`prefix <a href="/foo" rel="nofollow">link text</a> suffix`, got, t)
	})

	t.Run("must after filter", func(t *testing.T) {
		p := &sanitize.Policy{
			Must: map[sanitize.TagName]map[sanitize.AttributeName]sanitize.AttributeFilter{
				"a": {"href": nil},
			},
			URIs: policies.NewURIs(),
		}
		got := p.SanitizeString(`prefix <a href="javascript:foo()">link text</a> suffix`)
		tst.Is(`prefix link text suffix`, got, t)
	})

	t.Run("must before filter", func(t *testing.T) {
		p := &sanitize.Policy{
			Must: map[sanitize.TagName]map[sanitize.AttributeName]sanitize.AttributeFilter{
				"a": {"href": nil},
			},
			URIs: policies.NewURIs(),
		}
		got := p.SanitizeString(`prefix <a>link text</a> suffix`)
		tst.Is(`prefix link text suffix`, got, t)
	})

	t.Run("must yes", func(t *testing.T) {
		p := &sanitize.Policy{
			Must: map[sanitize.TagName]map[sanitize.AttributeName]sanitize.AttributeFilter{
				"a": {"href": nil},
			},
			URIs: policies.NewURIs(),
		}
		got := p.SanitizeString(`prefix <a href="https://foo.bar">link text</a> suffix`)
		tst.Is(`prefix <a href="https://foo.bar">link text</a> suffix`, got, t)
	})

	t.Run("styles", func(t *testing.T) {
		p := &sanitize.Policy{
			Allow: sanitize.Filter{
				"b":              nil,
				"u":              nil,
				sanitize.AllTags: {"style": nil},
			},
			ModifyAttributes: sanitize.Modifier{
				sanitize.AllTags: {
					sanitize.StyleAttribute(func(tag sanitize.TagName, style sanitize.StyleToken) (keep bool) {
						switch tag {
						case "u", "i":
							return style.Property == "color"
						}
						return false
					}),
				},
			},
		}
		got := p.SanitizeString(`<b style="color:red">text</b><u style="color:blue">text</u>`)
		tst.Is(`<b>text</b><u style="color: blue">text</u>`, got, t)
	})

	t.Run("styles example", func(t *testing.T) {
		p := &sanitize.Policy{
			Allow: map[sanitize.TagName]map[sanitize.AttributeName]sanitize.AttributeFilter{
				"b":              nil,
				"u":              nil,
				sanitize.AllTags: {"style": nil}, // "style" must be allowed for this to work.
				// [...] Rest of the policy
			},
			ModifyAttributes: map[sanitize.TagName][]sanitize.AttributeModifier{
				sanitize.AllTags: {
					sanitize.StyleAttribute(func(tag sanitize.TagName, style sanitize.StyleToken) (keep bool) {
						switch tag {
						case "u", "b":
							// Allow "color" and "font-size" on tag "u" and "b".
							switch style.Property {
							case "color", "font-size":
								return true
							}
						}
						return false
					}),
				},
			},
		}
		got := p.SanitizeString(`<b style="color:red">text</b><u style="color:blue">text</u>`)
		tst.Is(`<b style="color: red">text</b><u style="color: blue">text</u>`, got, t)
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
		p1.Allow.Relax(p2.Allow)
		got := p1.SanitizeString("<b>bold</b> <i>italic</i>")
		tst.Is("<b>bold</b> <i>italic</i>", got, t)
	})

	t.Run("attribute merge", func(t *testing.T) {
		p1 := &sanitize.Policy{
			Allow: map[sanitize.TagName]map[sanitize.AttributeName]sanitize.AttributeFilter{
				"a": {"href": nil},
			},
			URIs: policies.NewURIs(),
		}
		p2 := &sanitize.Policy{
			Allow: map[sanitize.TagName]map[sanitize.AttributeName]sanitize.AttributeFilter{
				"a": {"title": nil},
			},
		}
		p1.Allow.Relax(p2.Allow)
		got := p1.SanitizeString(`<a href="https://trusted.dev/" title="home">link</a>`)
		tst.Is(`<a href="https://trusted.dev/" title="home">link</a>`, got, t)
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
		p1.Allow.Relax(p2.Allow)
		tst.Is(`<span class="red">red</span>`, p1.SanitizeString(`<span class="red">red</span>`), t)
		tst.Is(`<span class="blue">blue</span>`, p1.SanitizeString(`<span class="blue">blue</span>`), t)
		tst.Is(`<span>green</span>`, p1.SanitizeString(`<span class="green">green</span>`), t)
	})

	t.Run("allow global merge", func(t *testing.T) {
		p1 := &sanitize.Policy{
			Allow: map[sanitize.TagName]map[sanitize.AttributeName]sanitize.AttributeFilter{
				"span": nil,
				sanitize.AllTags: {
					"class": func(v string) bool { return v == "red" },
				},
			},
		}
		p2 := &sanitize.Policy{
			Allow: map[sanitize.TagName]map[sanitize.AttributeName]sanitize.AttributeFilter{
				sanitize.AllTags: {"class": func(v string) bool { return v == "blue" }},
			},
		}
		p1.Allow.Relax(p2.Allow)
		tst.Is(`<span class="red">red</span>`, p1.SanitizeString(`<span class="red">red</span>`), t)
		tst.Is(`<span class="blue">blue</span>`, p1.SanitizeString(`<span class="blue">blue</span>`), t)
	})

	t.Run("modifier chaining", func(t *testing.T) {
		p1 := &sanitize.Policy{
			Allow: map[sanitize.TagName]map[sanitize.AttributeName]sanitize.AttributeFilter{
				"b": {"class": nil, "id": nil},
			},
			ModifyAttributes: map[sanitize.TagName][]sanitize.AttributeModifier{
				"b": {func(_ string, attrs *[]html.Attribute) {
					*attrs = append(*attrs, html.Attribute{Key: "class", Val: "bold"})
				}},
			},
		}
		p2 := &sanitize.Policy{
			Allow: map[sanitize.TagName]map[sanitize.AttributeName]sanitize.AttributeFilter{
				"b": {"class": nil, "id": nil},
			},
			ModifyAttributes: map[sanitize.TagName][]sanitize.AttributeModifier{
				"b": {func(_ string, attrs *[]html.Attribute) {
					*attrs = append(*attrs, html.Attribute{Key: "id", Val: "b1"})
				}},
			},
		}
		p1.Allow.Relax(p2.Allow)
		p1.ModifyAttributes.Add(p2.ModifyAttributes)
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
		p1.Allow.Restrict(p2.Allow)
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
		p1.Allow.Restrict(p2.Allow)
		tst.Is(`<span class="text-red">red</span>`, p1.SanitizeString(`<span class="text-red">red</span>`), t)
		tst.Is(`<span>text-blue</span>`, p1.SanitizeString(`<span class="text-blue">text-blue</span>`), t)
		tst.Is(`<span>bg-red</span>`, p1.SanitizeString(`<span class="bg-red">bg-red</span>`), t)
	})

	t.Run("allow global intersection", func(t *testing.T) {
		p1 := &sanitize.Policy{
			Allow: map[sanitize.TagName]map[sanitize.AttributeName]sanitize.AttributeFilter{
				"span":           nil,
				sanitize.AllTags: {"class": func(v string) bool { return strings.HasPrefix(v, "text-") }},
			},
		}
		p2 := &sanitize.Policy{
			Allow: map[sanitize.TagName]map[sanitize.AttributeName]sanitize.AttributeFilter{
				"span":           nil,
				sanitize.AllTags: {"class": func(v string) bool { return strings.HasSuffix(v, "-red") }},
			},
		}
		p1.Allow.Restrict(p2.Allow)
		tst.Is(`<span class="text-red">red</span>`, p1.SanitizeString(`<span class="text-red">red</span>`), t)
		tst.Is(`<span>text-blue</span>`, p1.SanitizeString(`<span class="text-blue">text-blue</span>`), t)
	})
}
