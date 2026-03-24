package policies

import (
	"maps"

	"github.com/empijei/go-html-sanitizer/match"
	"github.com/empijei/go-html-sanitizer/match/attr"
	"github.com/empijei/go-html-sanitizer/sanitize"
)

type URLPolicy struct {
	AllowRelative bool
	AllowSchemes  map[string]struct{}
}

var number = match.Numbers().Matcher()

func UserGeneratedContent(up *URLPolicy) *sanitize.Policy {
	p := &sanitize.Policy{
		Allow: map[sanitize.TagName]map[sanitize.AttributeName]sanitize.AttributeFilter{
			"a":          {"href": up.Valid},
			"abbr":       nil,
			"acronym":    nil,
			"area":       {"alt": attr.FreeText, "coords": attr.Coords, "href": up.Valid, "rel": attr.Rel, "shape": attr.Shapes},
			"article":    nil,
			"aside":      nil,
			"b":          nil,
			"bdi":        {"dir": attr.Dir},
			"bdo":        {"dir": attr.Dir},
			"blockquote": {"cite": up.Valid},
			"br":         nil,
			"cite":       nil,
			"code":       nil,
			"del":        {"cite": up.Valid, "datetime": attr.TimeISO8601},
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
			"i":          nil,
			"img":        {"align": attr.ImgAlign, "usemap": attr.UseMap, "alt": attr.FreeText, "src": up.Valid, "height": attr.HeightOrWidth, "width": attr.HeightOrWidth},
			"ins":        {"cite": up.Valid, "datetime": attr.TimeISO8601},
			"map":        {"name": attr.Name},
			"mark":       nil,
			"meter":      {"value": number, "min": number, "max": number, "low": number, "high": number, "optimum": number},
			"p":          nil,
			"pre":        nil,
			"progress":   {"value": number, "max": number},
			"q":          {"cite": up.Valid},
			"rp":         nil,
			"rt":         nil,
			"ruby":       nil,
			"s":          nil,
			"samp":       nil,
			"section":    nil,
			"small":      nil,
			"span":       nil,
			"strike":     nil,
			"strong":     nil,
			"sub":        nil,
			"summary":    nil,
			"sup":        nil,
			"time":       {"datetime": attr.TimeISO8601},
			"tt":         nil,
			"u":          nil,
			"var":        nil,
			"wbr":        nil,
		},
		// TODO tables
		AllowGlobal: map[sanitize.AttributeName]sanitize.AttributeFilter{},
	}

	maps.Insert(p.Allow, maps.All(AllowLists))
	maps.Insert(p.AllowGlobal, maps.All(AllowGlobalStandard))

	// TODO figure out a way to make sure that once we merge common urls it doesn't
	// accidentally get relaxed later on.

	// TODO src rewriters
	return p
}

var (
	// TODO: create more of these Allows, like one for tags like b, u, i etc

	AllowLists = map[sanitize.TagName]map[sanitize.AttributeName]sanitize.AttributeFilter{
		"ol": {"type": attr.ListType},
		"ul": {"type": attr.ListType},
		"li": {"type": attr.ListType, "value": match.Integer().Matcher()},
		"dl": nil,
		"dt": nil,
		"dd": nil,
	}

	AllowGlobalStandard = map[sanitize.AttributeName]sanitize.AttributeFilter{
		"dir":   attr.Dir,
		"lang":  attr.Lang,
		"id":    attr.ID,
		"title": attr.FreeText,
	}
)
