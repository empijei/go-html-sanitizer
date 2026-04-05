package policies

import (
	"net/url"
	"strings"

	"github.com/empijei/go-html-sanitizer/internal/mpool"
	"github.com/empijei/go-html-sanitizer/sanitize"
	"golang.org/x/net/html"
)

// SandboxValue is a value for the iframe.sandbox attribute.
type SandboxValue string

const (
	// SandboxAllowDownloads is the value for Allow Downloads.
	SandboxAllowDownloads SandboxValue = "allow-downloads"
	// SandboxAllowDownloadsWithoutUserActivation is the value for Allow Downloads Without User Activation.
	SandboxAllowDownloadsWithoutUserActivation SandboxValue = "allow-downloads-without-user-activation"
	// SandboxAllowForms is the value for Allow Forms.
	SandboxAllowForms SandboxValue = "allow-forms"
	// SandboxAllowModals is the value for Allow Modals.
	SandboxAllowModals SandboxValue = "allow-modals"
	// SandboxAllowOrientationLock is the value for Allow Orientation Lock.
	SandboxAllowOrientationLock SandboxValue = "allow-orientation-lock"
	// SandboxAllowPointerLock is the value for Allow Pointer Lock.
	SandboxAllowPointerLock SandboxValue = "allow-pointer-lock"
	// SandboxAllowPopups is the value for Allow Popups.
	SandboxAllowPopups SandboxValue = "allow-popups"
	// SandboxAllowPopupsToEscapeSandbox is the value for Allow Popups To Escape Sandbox.
	SandboxAllowPopupsToEscapeSandbox SandboxValue = "allow-popups-to-escape-sandbox"
	// SandboxAllowPresentation is the value for Allow Presentation.
	SandboxAllowPresentation SandboxValue = "allow-presentation"
	// SandboxAllowSameOrigin is the value for Allow Same Origin.
	SandboxAllowSameOrigin SandboxValue = "allow-same-origin"
	// SandboxAllowScripts is the value for Allow Scripts.
	SandboxAllowScripts SandboxValue = "allow-scripts"
	// SandboxAllowStorageAccessByUserActivation is the value for Allow Storage Access By User Activation.
	SandboxAllowStorageAccessByUserActivation SandboxValue = "allow-storage-access-by-user-activation"
	// SandboxAllowTopNavigation is the value for Allow Top Navigation.
	SandboxAllowTopNavigation SandboxValue = "allow-top-navigation"
	// SandboxAllowTopNavigationByUserActivation is the value for Allow Top Navigation By User Activation.
	SandboxAllowTopNavigationByUserActivation SandboxValue = "allow-top-navigation-by-user-activation"
)

// AddIFrameSandbox forces the sandbox value on iframes to match the specified allowlist.
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

// AddAttributeCrossOrigin adds the crossorigin=anonymous attribute to tags that support it.
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

// AddAttributeTarget adds the target=_blank attribute to tags that support it.
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

var defaultRels = []string{"nofollow", "noreferrer", "ugc"}

// AddAttributeRel adds the rel attribute to tags that support it.
// Passing no arguments adds a safe set of defaults.
func AddAttributeRel(p *sanitize.Policy, vals ...string) {
	if len(vals) == 0 {
		vals = defaultRels
	}
	prebuilt := strings.Join(vals, " ")
	set := map[string]struct{}{}
	for _, k := range vals {
		set[k] = struct{}{}
	}
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
				Val: prebuilt,
			})
			return
		}
		rel := &(*attrs)[posRel]
		if rel.Val == "" {
			rel.Val = prebuilt
			return
		}
		toAdd, release := relAddPool.Clone(set)
		defer release()
		for tok := range strings.FieldsSeq(rel.Val) {
			delete(toAdd, tok)
		}
		for _, v := range vals {
			_, missing := toAdd[v]
			if !missing {
				continue
			}
			rel.Val += " " + v
		}
	}
	addRelMap := map[sanitize.TagName][]sanitize.AttributeModifier{
		"a": {add}, "area": {add}, "base": {add}, "link": {add},
	}
	p.MergeModify(addRelMap)
}

var relAddPool = mpool.New[string, struct{}]()
