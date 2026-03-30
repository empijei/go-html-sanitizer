package sanitize

var uris = map[TagName]map[AttributeName]struct{}{
	"a":          {"href": struct{}{}, "ping": struct{}{}},
	"area":       {"href": struct{}{}, "ping": struct{}{}},
	"audio":      {"src": struct{}{}},
	"base":       {"href": struct{}{}},
	"blockquote": {"cite": struct{}{}},
	"button":     {"formaction": struct{}{}},
	"del":        {"cite": struct{}{}},
	"embed":      {"src": struct{}{}},
	"form":       {"action": struct{}{}},
	"iframe":     {"src": struct{}{}, "longdesc": struct{}{}},
	"img":        {"src": struct{}{}, "srcset": struct{}{}, "longdesc": struct{}{}, "usemap": struct{}{}},
	"input":      {"src": struct{}{}, "formaction": struct{}{}, "usemap": struct{}{}},
	"ins":        {"cite": struct{}{}},
	"link":       {"href": struct{}{}, "imagesrcset": struct{}{}},
	"object":     {"data": struct{}{}, "codebase": struct{}{}, "archive": struct{}{}, "classid": struct{}{}, "usemap": struct{}{}},
	"q":          {"cite": struct{}{}},
	"script":     {"src": struct{}{}},
	"source":     {"src": struct{}{}, "srcset": struct{}{}},
	"track":      {"src": struct{}{}},
	"video":      {"src": struct{}{}, "poster": struct{}{}},
	"body":       {"background": struct{}{}},
	"table":      {"background": struct{}{}},
	"td":         {"background": struct{}{}},
	"th":         {"background": struct{}{}},
	"tr":         {"background": struct{}{}},
	"thead":      {"background": struct{}{}},
	"tbody":      {"background": struct{}{}},
	"tfoot":      {"background": struct{}{}},
}

type simpleURI struct{}

func block(string) bool { return false }

func (simpleURI) Validator(tag TagName, attr AttributeName) (validator AttributeFilter, applies bool) {
	_, ok := uris[tag][attr]
	if ok {
		return block, true
	}
	return nil, false
}

var defaultURIPolicy = simpleURI{}
