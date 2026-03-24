package policies

import (
	"github.com/empijei/go-html-sanitizer/match/attr"
	"github.com/empijei/go-html-sanitizer/sanitize"
)

type URLPolicy struct {
	AllowRelative bool
	AllowSchemes  map[string]struct{}
}

func UserGeneratedContent(up *URLPolicy) *sanitize.Policy {
	p := &sanitize.Policy{
		Allow: map[sanitize.TagName]map[sanitize.AttributeName]sanitize.AttributeFilter{
			"a":          {"href": up.Valid},
			"abbr":       nil,
			"acronym":    nil,
			"area":       {"alt": attr.FreeText, "coords": attr.Coords, "href": up.Valid, "rel": attr.Rel, "shape": attr.Shapes},
			"article":    nil,
			"aside":      nil,
			"blockquote": {"cite": up.Valid},
			"br":         nil,
			"cite":       nil,
			"code":       nil,
			"details":    {"open": attr.Open},
			"dfn":        nil,
			"div":        nil,
			"em":         nil,
			"figcaption": nil,
			"figure":     nil,
			"h1":         nil,
			"h2":         nil,
			"h3":         nil,
			"h4":         nil,
			"h5":         nil,
			"h6":         nil,
			"hgroup":     nil,
			"hr":         nil,
			"img":        {"usemap": attr.UseMap},
			"map":        {"name": attr.Name},
			"mark":       nil,
			"p":          nil,
			"s":          nil,
			"samp":       nil,
			"section":    nil,
			"span":       nil,
			"strong":     nil,
			"sub":        nil,
			"q":          {"cite": up.Valid},
			"summary":    nil,
			"sup":        nil,
			"var":        nil,
			"wbr":        nil,
			"time":       {"datetime": attr.TimeISO8601},
		},
		AllowGlobal: map[sanitize.AttributeName]sanitize.AttributeFilter{
			"dir":   attr.Dir,
			"lang":  attr.Lang,
			"id":    attr.ID,
			"title": attr.FreeText,
		},
	}

	// TODO figure out a way to make sure that once we merge common urls it doesn't
	// accidentally get relaxed later on.

	// TODO src rewriters
	return p
}
