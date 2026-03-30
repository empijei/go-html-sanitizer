package policies

import (
	"net/url"
	"strings"

	"github.com/empijei/go-html-sanitizer/sanitize"
	"golang.org/x/net/html"
)

type SandboxValue string

const (
	SandboxAllowDownloads                      SandboxValue = "allow-downloads"
	SandboxAllowDownloadsWithoutUserActivation SandboxValue = "allow-downloads-without-user-activation"
	SandboxAllowForms                          SandboxValue = "allow-forms"
	SandboxAllowModals                         SandboxValue = "allow-modals"
	SandboxAllowOrientationLock                SandboxValue = "allow-orientation-lock"
	SandboxAllowPointerLock                    SandboxValue = "allow-pointer-lock"
	SandboxAllowPopups                         SandboxValue = "allow-popups"
	SandboxAllowPopupsToEscapeSandbox          SandboxValue = "allow-popups-to-escape-sandbox"
	SandboxAllowPresentation                   SandboxValue = "allow-presentation"
	SandboxAllowSameOrigin                     SandboxValue = "allow-same-origin"
	SandboxAllowScripts                        SandboxValue = "allow-scripts"
	SandboxAllowStorageAccessByUserActivation  SandboxValue = "allow-storage-access-by-user-activation"
	SandboxAllowTopNavigation                  SandboxValue = "allow-top-navigation"
	SandboxAllowTopNavigationByUserActivation  SandboxValue = "allow-top-navigation-by-user-activation"
)

func AddIFrameSandbox(p *sanitize.Policy, allow ...SandboxValue) {
	var sb strings.Builder
	for i, v := range allow {
		if i > 0 {
			sb.WriteRune(' ')
		}
		sb.WriteString(string(v))
	}
	sbx := sb.String()

	applySandbox := func(_ string, attrs *[]html.Attribute) {
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
			sandbox.Val = sbx
			return
		}
		(*attrs) = append((*attrs), html.Attribute{Key: "sandbox", Val: sbx})
	}
	if p.ModifyAttributes == nil {
		p.ModifyAttributes = map[sanitize.TagName][]sanitize.AttributeModifier{}
	}
	p.ModifyAttributes["iframe"] = append(p.ModifyAttributes["iframe"], applySandbox)
}

func AddAttributeCrossOrigin(p *sanitize.Policy) {
	add := func(_ string, attrs *[]html.Attribute) {
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
	addCrossOriginMap := map[sanitize.TagName][]sanitize.AttributeModifier{
		"audio": {add}, "img": {add}, "link": {add}, "script": {add}, "video": {add},
	}
	p.MergeModify(addCrossOriginMap)
}

func AddAttributeTarget(p *sanitize.Policy) {
	add := func(_ string, attrs *[]html.Attribute) {
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
	addTargetMap := map[sanitize.TagName][]sanitize.AttributeModifier{
		"a": {add}, "area": {add}, "link": {add},
	}
	p.MergeModify(addTargetMap)
}

func AddAttributeRel(p *sanitize.Policy) {
	add := func(_ string, attrs *[]html.Attribute) {
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
	addRelMap := map[sanitize.TagName][]sanitize.AttributeModifier{
		"a": {add}, "area": {add}, "base": {add}, "link": {add},
	}
	p.MergeModify(addRelMap)
}
