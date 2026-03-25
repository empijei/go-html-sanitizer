package policies

import (
	"math"
	"net/url"
	"strings"
	"unicode"

	"github.com/empijei/go-html-sanitizer/match"
	"github.com/empijei/go-html-sanitizer/sanitize"
	"golang.org/x/net/html"
)

type URLs struct {
	AllowSchemes                 map[string]func(u *url.URL) (valid bool)
	BlockRelative                bool
	DisableRelMod                bool
	DisableTargetMod             bool
	DisableCrossOriginMod        bool
	AllowIFrameSandboxAttributes map[string]struct{}
}

func NewURLs() *URLs {
	return &URLs{
		AllowSchemes: map[string]func(u *url.URL) (valid bool){
			"https":  nil,
			"mailto": nil,
			"data":   filterDataURIs,
		},
	}
}

const maxDataURIAllowedFormatSize = len(`image/jpeg;base64,`)

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

func (p *URLs) Apply(to *sanitize.Policy) {
	validators := map[sanitize.TagName]map[sanitize.AttributeName]sanitize.AttributeFilter{
		"a":          {"href": p.valid, "ping": p.valid},
		"area":       {"href": p.valid, "ping": p.valid},
		"audio":      {"src": p.valid},
		"base":       {"href": p.valid},
		"blockquote": {"cite": p.valid},
		"button":     {"formaction": p.valid},
		"del":        {"cite": p.valid},
		"embed":      {"src": p.valid},
		"form":       {"action": p.valid},
		"iframe":     {"src": p.valid, "longdesc": p.valid},
		"img": {
			"src":      p.valid,
			"srcset":   p.validSet,
			"longdesc": p.valid,
			"usemap":   p.valid,
		},
		"input": {
			"src":        p.valid,
			"formaction": p.valid,
			"usemap":     p.valid,
		},
		"ins":  {"cite": p.valid},
		"link": {"href": p.valid, "imagesrcset": p.validSet},
		"object": {
			"data":     p.valid,
			"codebase": p.valid,
			"archive":  p.valid,
			"classid":  p.valid,
			"usemap":   p.valid,
		},
		"q":      {"cite": p.valid},
		"script": {"src": p.valid},
		"source": {"src": p.valid, "srcset": p.validSet},
		"track":  {"src": p.valid},
		"video":  {"src": p.valid, "poster": p.valid},

		"body":  {"background": p.valid},
		"table": {"background": p.valid},
		"td":    {"background": p.valid},
		"th":    {"background": p.valid},
		"tr":    {"background": p.valid},
		"thead": {"background": p.valid},
		"tbody": {"background": p.valid},
		"tfoot": {"background": p.valid},
	}

	for tag, attrFlt := range to.Allow {
		for attr, flt := range attrFlt {
			check := validators[tag][attr]
			if check == nil {
				continue
			}
			if flt == nil {
				attrFlt[attr] = check
				continue
			}
			attrFlt[attr] = func(attrValue string) (keep bool) { return flt(attrValue) && check(attrValue) }
		}
	}

	if !p.DisableRelMod {
		addRelMap := map[sanitize.TagName][]sanitize.AttributeModifier{
			"a":    {addRel},
			"area": {addRel},
			"base": {addRel},
			"link": {addRel},
		}
		to.MergeModify(addRelMap)
		p.allowIfPresent("rel", addRelMap, to)
	}
	if !p.DisableTargetMod {
		addTargetMap := map[sanitize.TagName][]sanitize.AttributeModifier{
			"a":    {addTarget},
			"area": {addTarget},
			"link": {addTarget},
		}
		to.MergeModify(addTargetMap)
		p.allowIfPresent("target", addTargetMap, to)
	}
	if !p.DisableCrossOriginMod {
		addCrossOriginMap := map[sanitize.TagName][]sanitize.AttributeModifier{
			"audio":  {addCrossOrigin},
			"img":    {addCrossOrigin},
			"link":   {addCrossOrigin},
			"script": {addCrossOrigin},
			"video":  {addCrossOrigin},
		}
		to.MergeModify(addCrossOriginMap)
		p.allowIfPresent("crossorigin", addCrossOriginMap, to)
	}
	// TODO iframe allowlist and add sandbox attr to allow if iframe is present.
	to.ModifyAttributes["iframe"] = append(to.ModifyAttributes["iframe"], p.sandbox())
}

func (p *URLs) allowIfPresent(attr sanitize.AttributeName, modif map[sanitize.TagName][]sanitize.AttributeModifier, to *sanitize.Policy) {
	for tag := range modif {
		attrs, hasTag := to.Allow[tag]
		if !hasTag {
			continue
		}
		_, hasAttr := attrs[attr]
		if hasAttr {
			continue
		}
		// TODO pass a validator instead.
		attrs[attr] = nil
	}
}

func (p *URLs) sandbox() sanitize.AttributeModifier {
	return func(_ string, attrs *[]html.Attribute) {
		var sandbox *html.Attribute
	loop:
		for i, attr := range *attrs {
			switch attr.Key {
			case "sandbox":
				sandbox = &(*attrs)[i]
				break loop
			}
		}
		if sandbox != nil {
			sandbox.Val = ""
			return
		}
		(*attrs) = append((*attrs), html.Attribute{Key: "sandbox", Val: ""})
	}
}

func addCrossOrigin(_ string, attrs *[]html.Attribute) {
	var crossOrigin *html.Attribute
loop:
	for i, attr := range *attrs {
		switch attr.Key {
		case "crossorigin":
			crossOrigin = &(*attrs)[i]
			break loop
		}
	}
	if crossOrigin == nil {
		(*attrs) = append((*attrs), html.Attribute{Key: "crossorigin", Val: "anonymous"})
		return
	}
	crossOrigin.Val = "anonymous"
}

func addTarget(_ string, attrs *[]html.Attribute) {
	var href, target *html.Attribute
	for i, attr := range *attrs {
		switch attr.Key {
		case "target":
			target = &(*attrs)[i]
		case "href":
			href = &(*attrs)[i]
		}
	}
	if href == nil {
		return
	}
	u, err := url.Parse(href.Val)
	if err != nil {
		href.Val = ""
	}
	if !u.IsAbs() {
		return
	}
	if target == nil {
		(*attrs) = append((*attrs), html.Attribute{Key: "target", Val: "_blank"})
		return
	}
	target.Val = "_blank"
}

func addRel(_ string, attrs *[]html.Attribute) {
	posRel, posHref := -1, -1
	for i, attr := range *attrs {
		switch attr.Key {
		case "rel":
			posRel = i
		case "href":
			posHref = i
		}
	}
	if posHref < 0 {
		return
	}
	if posRel < 0 {
		(*attrs) = append((*attrs), html.Attribute{
			Key: "rel",
			Val: "noreferrer nofollow ugc",
		})
		return
	}
	rel := &(*attrs)[posRel]
	if rel.Val == "" {
		rel.Val = "noreferrer nofollow ugc"
		return
	}
	var noref, nofol, ugc bool
	for tok := range strings.FieldsSeq(rel.Val) {
		switch tok {
		case "noreferrer":
			noref = true
		case "nofollow":
			nofol = true
		case "ugc":
			ugc = true
		}
	}
	if !noref {
		rel.Val += " noreferrer"
	}
	if !nofol {
		rel.Val += " nofollow"
	}
	if !ugc {
		rel.Val += " ugc"
	}
}

func (p *URLs) valid(rawurl string) bool {
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
	u, err := url.Parse(rawurl)
	if err != nil {
		return false
	}
	if !u.IsAbs() && p.BlockRelative {
		return false
	}
	if u.Scheme == "" {
		return !p.BlockRelative
	}
	check, ok := p.AllowSchemes[u.Scheme]
	if check == nil {
		return ok
	}
	return check(u)
}

func (p *URLs) validSet(attrVal string) (keep bool) {
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
		if !p.valid(fileAndSize[0]) {
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
