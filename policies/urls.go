package policies

import (
	"math"
	"net/url"
	"strings"
	"unicode"

	"github.com/empijei/go-html-sanitizer/match"
	"github.com/empijei/go-html-sanitizer/sanitize"
)

func CommonURLs() *sanitize.Policy {
	return &sanitize.Policy{}
}

var matchWidthOrDensityDescriptor = match.Or(
	match.Combine(match.IntegerBetween(0, math.MaxInt64),
		match.Exact("w")),
	match.Combine(match.FloatBetween(0, math.MaxFloat64),
		match.Exact("x")),
).Matcher()

func stripWhiteSpace(s string) string {
	var sb strings.Builder
	for _, r := range s {
		if unicode.IsSpace(r) {
			continue
		}
		sb.WriteRune(r)
	}
	return sb.String()
}

func containsWhiteSpace(s string) bool {
	for _, r := range s {
		if unicode.IsSpace(r) {
			return true
		}
	}
	return false
}

func (p *URLPolicy) Valid(rawurl string) bool {
	rawurl = strings.TrimSpace(rawurl)
	if containsWhiteSpace(rawurl) {
		// URLs cannot contain whitespace, unless it is a data-uri
		if !strings.HasPrefix(rawurl, `data:`) {
			return false
		}
		rawurl = stripWhiteSpace(rawurl)
	}
	if rawurl == "" {
		return false
	}
	u, err := url.Parse(rawurl)
	if err != nil {
		return false
	}
	if u.Scheme == "" {
		return p.AllowRelative
	}
	_, ok := p.AllowSchemes[u.Scheme]
	return ok
}

func (p *URLPolicy) ValidSet(attrVal string) (keep bool) {
	// https://html.spec.whatwg.org/#srcset-attribute
	values := strings.Split(attrVal, ",")
	for _, val := range values {
		fileAndSize := strings.Fields(strings.TrimSpace(val))
		var size string
		switch len(fileAndSize) {
		case 2:
			size = fileAndSize[1]
			if !matchWidthOrDensityDescriptor(size) {
				return false
			}
		case 1:
		default:
			return false
		}
		if !p.Valid(fileAndSize[0]) {
			return false
		}
	}
	return true
}

// TODO(empijei): do we sanitize SVG? if so, svg:image.href and svg:a.href need to be added here.
// Maps tag -> attribute -> sanitizer routine.
func (p *URLPolicy) validators() map[sanitize.TagName]map[sanitize.AttributeName]sanitize.AttributeFilter {
	return map[sanitize.TagName]map[sanitize.AttributeName]sanitize.AttributeFilter{
		"a":          {"href": p.Valid, "ping": p.Valid},
		"area":       {"href": p.Valid, "ping": p.Valid},
		"audio":      {"src": p.Valid},
		"base":       {"href": p.Valid},
		"blockquote": {"cite": p.Valid},
		"button":     {"formaction": p.Valid},
		"del":        {"cite": p.Valid},
		"embed":      {"src": p.Valid},
		"form":       {"action": p.Valid},
		"iframe":     {"src": p.Valid, "longdesc": p.Valid},
		"img": {
			"src":      p.Valid,
			"srcset":   p.ValidSet,
			"longdesc": p.Valid,
			"usemap":   p.Valid,
		},
		"input": {
			"src":        p.Valid,
			"formaction": p.Valid,
			"usemap":     p.Valid,
		},
		"ins":  {"cite": p.Valid},
		"link": {"href": p.Valid, "imagesrcset": p.ValidSet},
		"object": {
			"data":     p.Valid,
			"codebase": p.Valid,
			"archive":  p.Valid,
			"classid":  p.Valid,
			"usemap":   p.Valid,
		},
		"q":      {"cite": p.Valid},
		"script": {"src": p.Valid},
		"source": {"src": p.Valid, "srcset": p.ValidSet},
		"track":  {"src": p.Valid},
		"video":  {"src": p.Valid, "poster": p.Valid},

		"body":  {"background": p.Valid},
		"table": {"background": p.Valid},
		"td":    {"background": p.Valid},
		"th":    {"background": p.Valid},
		"tr":    {"background": p.Valid},
		"thead": {"background": p.Valid},
		"tbody": {"background": p.Valid},
		"tfoot": {"background": p.Valid},
	}
}
