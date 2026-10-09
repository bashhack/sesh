package secretref

import (
	"fmt"
	"regexp"
	"strings"
)

// templateRef matches a reference in a template: {{ sesh://... }}, with or
// without spaces inside the braces.
var templateRef = regexp.MustCompile(`\{\{\s*(sesh://[^\s{}]+)\s*\}\}`)

// TemplateRefs returns the references in a template, called name in
// errors, each once, in the order they first appear.
func TemplateRefs(tpl, name string) ([]Ref, error) {
	var refs []Ref
	seen := map[string]bool{}
	for _, m := range templateRef.FindAllStringSubmatchIndex(tpl, -1) {
		s := tpl[m[2]:m[3]]
		if seen[s] {
			continue
		}
		seen[s] = true
		r, err := Parse(s)
		if err != nil {
			return nil, fmt.Errorf("%s line %d: %w", name, strings.Count(tpl[:m[0]], "\n")+1, err)
		}
		refs = append(refs, r)
	}
	return refs, nil
}

// Fill puts each reference's value, from values by reference, in place of
// the reference in tpl; everything else is left as it is. The caller
// zeroes the result.
func Fill(tpl string, values map[string][]byte) []byte {
	var out []byte
	last := 0
	for _, m := range templateRef.FindAllStringSubmatchIndex(tpl, -1) {
		v, ok := values[tpl[m[2]:m[3]]]
		if !ok {
			continue
		}
		out = append(out, tpl[last:m[0]]...)
		out = append(out, v...)
		last = m[1]
	}
	return append(out, tpl[last:]...)
}
