package dnsutils

import (
	"strings"
	"testing"
)

// To jinja templating
func TestDnsMessage_ToJinjaFormat(t *testing.T) {
	dm := DNSMessage{}
	dm.Init()

	dm.DNS.Qname = "qname_for_test"

	template := `
;; Got {% if dm.DNS.Type == "QUERY" %}query{% else %}answer{% endif %} from {{ dm.NetworkInfo.QueryIP }}#{{ dm.NetworkInfo.QueryPort }}:
;; ->>HEADER<<- opcode: {{ dm.DNS.Opcode }}, status: {{ dm.DNS.Rcode }}, id: {{ dm.DNS.ID }}
;; flags: {{ dm.DNS.Flags.QR | yesno:"qr ," }}{{ dm.DNS.Flags.RD | yesno:"rd ," }}{{ dm.DNS.Flags.RA | yesno:"ra ," }}; QUERY: {{ dm.DNS.QdCount }}, ANSWER: {{ dm.DNS.DNSRRs.AnCount }}, AUTHORITY: {{ dm.DNS.DNSRRs.NsCount }}, ADDITIONAL: {{ dm.DNS.DNSRRs.ArCount }}

;; QUESTION SECTION:
;{{ dm.DNS.Qname }}		{{ dm.DNS.Qclass }}	{{ dm.DNS.Qtype }}

;; ANSWER SECTION: {% for rr in dm.DNS.DNSRRs.Answers %}
{{ rr.Name }}		{{ rr.TTL }} {{ rr.Class }} {{ rr.Rdatatype }} {{ rr.Rdata }}{% endfor %}

;; WHEN: {{ dm.DNSTap.Timestamp }}
;; MSG SIZE  rcvd: {{ dm.DNS.Length }}`

	text, err := dm.ToTextTemplate(template)
	if err != nil {
		t.Errorf("Want no error, got: %s", err)
	}

	if !strings.Contains(text, dm.DNS.Qname) {
		t.Errorf("Want qname in template, got: %s", text)
	}
}
