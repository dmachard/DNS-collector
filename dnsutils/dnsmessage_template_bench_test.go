package dnsutils

import "testing"

const benchJinjaTemplate = `
;; Got {% if dm.DNS.Type == "QUERY" %}query{% else %}answer{% endif %} from {{ dm.NetworkInfo.QueryIP }}#{{ dm.NetworkInfo.QueryPort }}:
;; ->>HEADER<<- opcode: {{ dm.DNS.Opcode }}, status: {{ dm.DNS.Rcode }}, id: {{ dm.DNS.ID }}
;; flags: {{ dm.DNS.Flags.QR | yesno:"qr ," }}{{ dm.DNS.Flags.RD | yesno:"rd ," }}{{ dm.DNS.Flags.RA | yesno:"ra ," }}; QUERY: {{ dm.DNS.QdCount }}, ANSWER: {{ dm.DNS.DNSRRs.AnCount }}, AUTHORITY: {{ dm.DNS.DNSRRs.NsCount }}, ADDITIONAL: {{ dm.DNS.ArCount }}

;; QUESTION SECTION:
;{{ dm.DNS.Qname }}		{{ dm.DNS.Qclass }}	{{ dm.DNS.Qtype }}

;; ANSWER SECTION: {% for rr in dm.DNS.DNSRRs.Answers %}
{{ rr.Name }}		{{ rr.TTL }} {{ rr.Class }} {{ rr.Rdatatype }} {{ rr.Rdata }}{% endfor %}

;; WHEN: {{ dm.DNSTap.Timestamp }}
;; MSG SIZE  rcvd: {{ dm.DNS.Length }}`

func BenchmarkDnsMessage_ToJinjaFormat(b *testing.B) {
	dm := DNSMessage{}
	dm.Init()
	dm.InitTransforms()

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := dm.ToTextTemplate(benchJinjaTemplate)
		if err != nil {
			b.Fatalf("could not encode to template: %v\n", err)
		}
	}
}

// several workers rendering the same template concurrently (shared parsed template)
func BenchmarkDnsMessage_ToJinjaFormat_Parallel(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		dm := DNSMessage{}
		dm.Init()
		dm.InitTransforms()
		for pb.Next() {
			if _, err := dm.ToTextTemplate(benchJinjaTemplate); err != nil {
				b.Errorf("could not encode to template: %v", err)
				return
			}
		}
	})
}
