package policies

import (
	"maps"

	"github.com/empijei/go-html-sanitizer/match"
	"github.com/empijei/go-html-sanitizer/match/attr"
	"github.com/empijei/go-html-sanitizer/sanitize"
)

var (
	double  = match.Numbers().Matcher()
	integer = match.Integer().Matcher()
)

// UserGeneratedContent returns a policy that can be used for user generated content.
//
// It allows basic phrasing and text styling elements, lists, links, images and tables.
func UserGeneratedContent(up *URLs) *sanitize.Policy {
	p := &sanitize.Policy{
		Allow: map[sanitize.TagName]map[sanitize.AttributeName]sanitize.AttributeFilter{
			"a":       {"href": nil},
			"abbr":    nil,
			"acronym": nil,
			"area": {
				"alt":    attr.FreeText,
				"coords": attr.Coords,
				"href":   nil,
				"rel":    attr.Rel,
				"shape":  attr.Shapes,
			},
			"article":    nil,
			"aside":      nil,
			"b":          nil,
			"bdi":        {"dir": attr.Dir},
			"bdo":        {"dir": attr.Dir},
			"blockquote": {"cite": nil},
			"br":         nil,
			"cite":       nil,
			"code":       nil,
			"del": {
				"cite":     nil,
				"datetime": attr.TimeISO8601,
			},
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
			"img": {
				"align":  attr.ImgAlign,
				"usemap": attr.UseMap,
				"alt":    attr.FreeText,
				"src":    nil,
				"height": attr.NumberOrPercent,
				"width":  attr.NumberOrPercent,
			},
			"ins": {
				"cite":     nil,
				"datetime": attr.TimeISO8601,
			},
			"map":  {"name": attr.Name},
			"mark": nil,
			"meter": {
				"value":   double,
				"min":     double,
				"max":     double,
				"low":     double,
				"high":    double,
				"optimum": double,
			},
			"p":   nil,
			"pre": nil,
			"progress": {
				"value": double,
				"max":   double,
			},
			"q":       {"cite": nil},
			"rp":      nil,
			"rt":      nil,
			"ruby":    nil,
			"s":       nil,
			"samp":    nil,
			"section": nil,
			"small":   nil,
			"span":    nil,
			"strike":  nil,
			"strong":  nil,
			"sub":     nil,
			"summary": nil,
			"sup":     nil,
			"time":    {"datetime": attr.TimeISO8601},
			"tt":      nil,
			"u":       nil,
			"var":     nil,
			"wbr":     nil,
		},
		// TODO tables
		AllowGlobal: map[sanitize.AttributeName]sanitize.AttributeFilter{},
		Remove:      map[sanitize.TagName]string{"script": "", "style": ""},
	}

	defer up.Apply(p)
	maps.Insert(p.Allow, maps.All(AllowLists))
	maps.Insert(p.Allow, maps.All(AllowTables))
	maps.Insert(p.AllowGlobal, maps.All(AllowGlobalStandard))

	// TODO figure out a way to make sure that once we merge common urls it doesn't
	// accidentally get relaxed later on.

	// TODO src rewriters
	return p
}

var (
	// AllowLists is a map to insert into a policy Allow to enable lists.
	AllowLists = map[sanitize.TagName]map[sanitize.AttributeName]sanitize.AttributeFilter{
		"ol": {"type": attr.ListType},
		"ul": {"type": attr.ListType},
		"li": {"type": attr.ListType, "value": match.Integer().Matcher()},
		"dl": nil,
		"dt": nil,
		"dd": nil,
	}

	// AllowLists is a map to insert into a policy Allow to enable tables.
	AllowTables = map[sanitize.TagName]map[sanitize.AttributeName]sanitize.AttributeFilter{
		"caption": nil,
		"col": {
			"align":  attr.CellAlign,
			"height": attr.NumberOrPercent,
			"width":  attr.NumberOrPercent,
			"span":   integer,
			"valign": attr.CellVerticalAlign,
		},
		"colgroup": {
			"align":  attr.CellAlign,
			"height": attr.NumberOrPercent,
			"width":  attr.NumberOrPercent,
			"span":   integer,
			"valign": attr.CellVerticalAlign,
		},
		"table": {
			"height":  attr.NumberOrPercent,
			"width":   attr.NumberOrPercent,
			"summary": attr.FreeText,
		},
		"tbody": {
			"align":  attr.CellAlign,
			"valign": attr.CellVerticalAlign,
		},
		"td": {
			"abbr":    attr.FreeText,
			"align":   attr.CellAlign,
			"colspan": integer,
			"headers": attr.SpaceSeparatedTokens,
			"height":  attr.NumberOrPercent,
			"nowrap":  attr.NoWrap,
			"rowspan": integer,
			"valign":  attr.CellVerticalAlign,
			"width":   attr.NumberOrPercent,
		},
		"tfoot": {
			"align":  attr.CellAlign,
			"valign": attr.CellVerticalAlign,
		},
		"th": {
			"abbr":    attr.FreeText,
			"align":   attr.CellAlign,
			"colspan": integer,
			"headers": attr.SpaceSeparatedTokens,
			"height":  attr.NumberOrPercent,
			"nowrap":  attr.NoWrap,
			"rowspan": integer,
			"scope":   attr.THScope,
			"valign":  attr.CellVerticalAlign,
			"width":   attr.NumberOrPercent,
		},
		"thead": {
			"align":  attr.CellAlign,
			"valign": attr.CellVerticalAlign,
		},
		"tr": {
			"align":  attr.CellAlign,
			"valign": attr.CellVerticalAlign,
		},
	}

	// AllowGlobalStandard is a map to insert into a policy AllowGlobal to enable basic attributes.
	AllowGlobalStandard = map[sanitize.AttributeName]sanitize.AttributeFilter{
		"dir":   attr.Dir,
		"lang":  attr.Lang,
		"id":    attr.ID,
		"title": attr.FreeText,
	}
)
