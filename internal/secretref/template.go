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

// Fill puts each reference's value, from values by the reference in the
// form Parse reads it (Ref.String), in place of the reference in tpl,
// however it's written there; everything else is left as it is. A
// reference without a value is an error. The caller zeroes the result.
func Fill(tpl string, values map[string][]byte) ([]byte, error) {
	matches := templateRef.FindAllStringSubmatchIndex(tpl, -1)
	vals := make([][]byte, len(matches))
	size := len(tpl)
	for i, m := range matches {
		r, err := Parse(tpl[m[2]:m[3]])
		if err != nil {
			return nil, err
		}
		v, ok := values[r.String()]
		if !ok {
			return nil, fmt.Errorf("%s has no value", r)
		}
		vals[i] = v
		size += len(v) - (m[1] - m[0])
	}
	// Sized up front, so no copy of a value is left behind by growing.
	out := make([]byte, 0, size)
	last := 0
	for i, m := range matches {
		out = append(out, tpl[last:m[0]]...)
		out = append(out, vals[i]...)
		last = m[1]
	}
	return append(out, tpl[last:]...), nil
}
