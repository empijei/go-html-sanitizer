package sanitize_test

import (
	"testing"

	"github.com/empijei/go-html-sanitizer/sanitize"
	"github.com/empijei/tst"
	"golang.org/x/net/html"
)

func TestPolicy(t *testing.T) {
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
				"b": "removed",
			},
		}
		got := p.SanitizeString(`normal text <b>bold text</b> <div>not allowed</div>`)
		tst.Is(`normal text removed not allowed`, got, t)
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
