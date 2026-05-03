package sanitize

import (
	"iter"
	"slices"
	"strings"
	"unicode"
	"unicode/utf8"

	"golang.org/x/net/html"
)

// StyleFilter allows to filter style attribute values.
type StyleFilter func(tag TagName, style StyleToken) (keep bool)

// StyleAttribute is a helper to create attribute modifiers that sanitize the "style"
// attribute, scanning each token and allowing for fine-grained filtering on style
// properties.
//
// # Full Example: Allow specific properties on specific tags.
//
//	p := &sanitize.Policy{
//		Allow: map[sanitize.TagName]map[sanitize.AttributeName]sanitize.AttributeFilter{
//			"b":              nil,
//			"u":              nil,
//			sanitize.AllTags: {"style": nil}, // "style" must be allowed for this to work.
//			// [...] Rest of the policy
//		},
//		ModifyAttributes: map[sanitize.TagName][]sanitize.AttributeModifier{
//			sanitize.AllTags: {
//				sanitize.StyleAttribute(func(tag sanitize.TagName, style sanitize.StyleToken) (keep bool) {
//					switch tag {
//					case "u", "b":
//						// Allow "color" and "font-size" on tag "u" and "b".
//						switch style.Property {
//						case "color", "font-size":
//							return true
//						}
//					}
//					return false
//				}),
//			},
//		},
//	}
//
// # Example: Allow properties on all tags, but only if not important.
//
//	sanitize.StyleAttribute(func(tag sanitize.TagName, style sanitize.StyleToken) (keep bool) {
//		if style.Important {
//			return false
//		}
//		switch style.Property {
//		case "font-size":
//			return true
//		// [...] Rest of the allowlist.
//		}
//		return false
//	}
func StyleAttribute(sf StyleFilter) AttributeModifier {
	return func(tag TagName, attrs *[]html.Attribute) {
		var (
			style *html.Attribute
			pos   int
		)
		for i, a := range *attrs {
			if a.Key != "style" {
				continue
			}
			style = &((*attrs)[i])
			pos = i
		}
		if style == nil {
			return
		}

		style.Val = serializeStyle(func(yield func(StyleToken) bool) {
			for tok := range tokenizeStyleAttr(style.Val) {
				if !sf(tag, tok) {
					continue
				}
				if !yield(tok) {
					return
				}
			}
		})
		if style.Val == "" {
			(*attrs) = slices.Delete((*attrs), pos, pos+1)
		}
	}
}

/*
Implementaton of https://drafts.csswg.org/css-style-attr/#syntax and https://www.w3.org/TR/CSS2/grammar.html
linked by https://html.spec.whatwg.org/#the-style-attribute.

Note that following the CSS2.1 convention, comment tokens are not shown in the rule above.

The interpreter must parse the style attribute's value using the same forward-compatible
parsing rules that apply to parsing declaration block contents in a normal CSS style sheet
(see chapter 4 of the CSS2.1 specification [CSS21]), with the following addition:
when the UA expects the start of a declaration or at-rule (i.e., an IDENT token or an ATKEYWORD token)
but finds an unexpected token instead, that token is considered to be the first token of a malformed declaration.
I.e., the rule for malformed declarations, rather than malformed statements, is used to determine which tokens to ignore in that case.

Note that because there is no open brace delimiting the declaration list in the CSS style attribute syntax,
a close brace (}) in the style attribute's value does not terminate the style data: it is merely an invalid token.

Although the grammar allows it, no at-rule valid in style attributes is define at the moment.
The forward-compatible parsing rules are such that a declaration following an at-rule is not ignored:

<span style="@unsupported { splines: reticulating } color: green">
*/

// StyleToken is a token obtained from parsing a style attribute.
type StyleToken struct {
	// Property is the property key, lowercased, trimmed.
	Property string
	// Expression is the property value, trimmed.
	Expression string
	// Important reports whether the expression was marked to be important.
	Important bool
}

func (s *StyleToken) String() string {
	v := s.Property + ": " + s.Expression
	if s.Important {
		v += " !important"
	}
	return v
}

func serializeStyle(toks iter.Seq[StyleToken]) string {
	var sb strings.Builder
	first := true
	for tok := range toks {
		if !first {
			sb.WriteString("; ")
		}
		first = false
		sb.WriteString(tok.String())
	}
	return sb.String()
}

type styleCursor struct {
	data  string
	entry StyleToken
	yield func(StyleToken) bool
}
type styleTokState func(*styleCursor) styleTokState

// declaration
//
//	: property ':' S* expr prio?
//
// property
//
//	: IDENT S*
//
// ident		-?{nmstart}{nmchar}*
// nmstart		[_a-z]|{nonascii}|{escape}
// nmchar		[_a-z0-9-]|{nonascii}|{escape}
// nonascii	[\240-\377]
// escape		{unicode}|\\[^\r\n\f0-9a-f]
// .
var stateDeclaration styleTokState

func init() {
	stateDeclaration = func(cur *styleCursor) styleTokState {
		// We can relax the parsing since we use an allowlist immediately after.
		var (
			began bool
			pos   int
		)
	scan:
		for {
			r, s := utf8.DecodeRuneInString(cur.data[pos:])
			if s == 0 {
				return nil
			}
			pos += s
			switch {
			case r == ':':
				break scan
			case !unicode.IsSpace(r):
				began = true
			default:
			}
		}
		if !began {
			return nil
		}
		cur.entry.Property = strings.ToLower(strings.TrimSpace(cur.data[:pos-1]))
		cur.data = cur.data[pos:]
		return stateExpr
	}
}

// expr
//
//	: term [ operator? term ]*
//
// term
//
//	: unary_operator?
//	  [ NUMBER S* | PERCENTAGE S* | LENGTH S* | EMS S* | EXS S* | ANGLE S* | TIME S* | FREQ S* ]
//	| STRING S* | IDENT S* | URI S* | hexcolor | function
//
// function
//
//	: FUNCTION S* expr ')' S*
//
// hexcolor (3 or 6 hex-digits)
//
//	: HASH S*
//
// operator
//
//	: '/' S* | ',' S*
var stateExpr styleTokState

func init() {
	stateExpr = func(cur *styleCursor) styleTokState {
		// We can relax the parsing since we use an allowlist immediately after.
		var (
			began        bool
			pos          int
			prio         bool
			lastNonSpace int
		)
	scan:
		for {
			r, s := utf8.DecodeRuneInString(cur.data[pos:])
			if s == 0 {
				break
			}
			pos += s
			switch {
			case unicode.IsSpace(r):
				continue
			case r == '!':
				prio = true
				break scan
			case r == ';':
				break scan
			default:
				lastNonSpace = pos
				began = true
			}
		}
		if !began {
			return nil
		}
		cur.entry.Expression = strings.TrimSpace(cur.data[:lastNonSpace])
		cur.data = cur.data[pos:]
		if prio {
			return statePrio
		}
		if !cur.yield(cur.entry) {
			return nil
		}
		cur.entry = StyleToken{}
		return stateDeclaration
	}
}

// prio
//
//	: IMPORTANT_SYM S*
//
//	 "!"({w}|{comment})*{I}{M}{P}{O}{R}{T}{A}{N}{T}	{return IMPORTANT_SYM;}
var statePrio styleTokState

func init() {
	statePrio = func(cur *styleCursor) styleTokState {
		var (
			pos       int
			begun, ok bool
			priok     int
			keyword   = "important"
		)
	scan:
		for {
			r, s := utf8.DecodeRuneInString(cur.data[pos:])
			if s == 0 {
				break
			}
			pos += s
			switch {
			case (!begun || ok) && unicode.IsSpace(r):
				continue
			case priok < len(keyword) && r == rune(keyword[priok]):
				begun = true
				priok++
				if priok == len(keyword) {
					ok = true
				}
			case r == ';':
				break scan
			default:
				return nil
			}
		}
		if !begun || !ok {
			return nil
		}
		cur.entry.Important = true
		cur.data = cur.data[pos:]
		if !cur.yield(cur.entry) {
			return nil
		}
		cur.entry = StyleToken{}
		return stateDeclaration
	}
}

func tokenizeStyleAttr(val string) iter.Seq[StyleToken] {
	return func(yield func(StyleToken) bool) {
		state := stateDeclaration
		cur := &styleCursor{data: val, yield: yield}
		for {
			state = state(cur)
			if state == nil || cur.data == "" {
				break
			}
		}
	}
}
