package policies

import (
	"math"
	"net/url"
	"strings"
	"unicode"

	"github.com/empijei/go-html-sanitizer/match"
	"github.com/empijei/go-html-sanitizer/sanitize"
)

// TODO src rewriters
type URIs struct {
	AllowSchemes  map[string]func(u *url.URL) (valid bool)
	BlockRelative bool
}

func NewURIs() *URIs {
	return &URIs{
		AllowSchemes: map[string]func(u *url.URL) (valid bool){
			"https":  nil,
			"mailto": nil,
			"data":   filterDataURIs,
		},
	}
}

func (u *URIs) Validator(tag sanitize.TagName, attr sanitize.AttributeName) (validator sanitize.AttributeFilter, applies bool) {
	v, ok := uriTypes[tag][attr]
	if !ok {
		return nil, false
	}
	switch v {
	case uriExternal, uriResource:
		return u.valid, true
	case uriResourceSet:
		return u.validSet, true
	}
	// Should not happen
	return func(attrValue string) (keep bool) { return false }, true
}

func (u *URIs) valid(rawurl string) bool {
	rawurl = strings.TrimSpace(rawurl)
	if containsWhiteSpace(rawurl) {
		// URLs cannot contain whitespace, unless it is a data-uri
		if !strings.HasPrefix(rawurl, `data:`) {
			return false
		}
		rawurl = stripNewLines(rawurl)
	}
	if rawurl == "" {
		return false
	}
	pu, err := url.Parse(rawurl)
	if err != nil {
		return false
	}
	if !pu.IsAbs() && u.BlockRelative {
		return false
	}
	if pu.Scheme == "" {
		return !u.BlockRelative
	}
	check, ok := u.AllowSchemes[pu.Scheme]
	if check == nil {
		return ok
	}
	return check(pu)
}

func (u *URIs) validSet(attrVal string) (keep bool) {
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
		if !u.valid(fileAndSize[0]) {
			return false
		}
	}
	return true
}

var matchWidthOrDensityDescriptor = match.Or(
	match.Combine(match.IntegerBetween(0, math.MaxInt64),
		match.Exact("w")),
	match.Combine(match.FloatBetween(0, math.MaxFloat64),
		match.Exact("x")),
).Matcher()

func stripNewLines(s string) string {
	var sb strings.Builder
	for _, r := range s {
		switch r {
		case '\n', '\r':
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

const maxDataURIAllowedFormatSize = len(`image/jpeg;`)

func filterDataURIs(u *url.URL) (valid bool) {
	var format string
loop:
	for pos, r := range u.Opaque {
		if pos > maxDataURIAllowedFormatSize {
			return false
		}
		switch r {
		case ',', ';':
			format = u.Opaque[:pos]
			break loop
		}
	}
	switch format {
	case "image/gif", "image/jpeg", "image/png", "image/webp":
		return true
	}
	return false
}

type uriType uint

const (
	uriExternal uriType = iota
	uriResource
	uriResourceSet
)

var uriTypes = map[sanitize.TagName]map[sanitize.AttributeName]uriType{
	"a":          {"href": uriExternal, "ping": uriExternal},
	"area":       {"href": uriExternal, "ping": uriExternal},
	"audio":      {"src": uriResource},
	"base":       {"href": uriExternal},
	"blockquote": {"cite": uriExternal},
	"button":     {"formaction": uriExternal},
	"del":        {"cite": uriExternal},
	"embed":      {"src": uriResource},
	"form":       {"action": uriExternal},
	"iframe":     {"src": uriExternal, "longdesc": uriExternal},
	"img":        {"src": uriResource, "srcset": uriResourceSet, "longdesc": uriExternal, "usemap": uriResource},
	"input":      {"src": uriExternal, "formaction": uriExternal, "usemap": uriExternal},
	"ins":        {"cite": uriExternal},
	"link":       {"href": uriExternal, "imagesrcset": uriResourceSet},
	"object":     {"data": uriResource, "codebase": uriResource, "archive": uriResource, "classid": uriResource, "usemap": uriExternal},
	"q":          {"cite": uriExternal},
	"script":     {"src": uriResource},
	"source":     {"src": uriResource, "srcset": uriResourceSet},
	"track":      {"src": uriResource},
	"video":      {"src": uriResource, "poster": uriResource},
	"body":       {"background": uriResource},
	"table":      {"background": uriResource},
	"td":         {"background": uriResource},
	"th":         {"background": uriResource},
	"tr":         {"background": uriResource},
	"thead":      {"background": uriResource},
	"tbody":      {"background": uriResource},
	"tfoot":      {"background": uriResource},
}
