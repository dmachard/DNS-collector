package dnsutils

import (
	"sync"

	"github.com/flosch/pongo2"
)

// parsed templates, keyed by template source (pongo2 templates are safe for concurrent Execute)
var templateCache sync.Map

func (dm *DNSMessage) ToTextTemplate(template string) (string, error) {
	dm.NetworkInfo.GetQueryIP()
	dm.NetworkInfo.GetResponseIP()
	context := pongo2.Context{"dm": dm}

	// Parse once, reuse for every message
	var tmpl *pongo2.Template
	if cached, ok := templateCache.Load(template); ok {
		tmpl = cached.(*pongo2.Template)
	} else {
		var err error
		tmpl, err = pongo2.FromString(template)
		if err != nil {
			return "", err
		}
		templateCache.Store(template, tmpl)
	}

	result, err := tmpl.Execute(context)
	if err != nil {
		return "", err
	}
	return result, nil
}
