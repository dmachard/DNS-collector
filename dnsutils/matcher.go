package dnsutils

import (
	"bufio"
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"
)

// Predicate is a fast, zero-allocation matching function evaluated against a DNSMessage.
type Predicate func(dm *DNSMessage) bool

// CompiledMatcher holds precompiled predicates for fast DNSMessage matching without reflection.
type CompiledMatcher struct {
	predicates []Predicate
}

// Match returns true if all precompiled predicates match the given DNSMessage.
func (cm *CompiledMatcher) Match(dm *DNSMessage) bool {
	if cm == nil || len(cm.predicates) == 0 {
		return false
	}
	for i := 0; i < len(cm.predicates); i++ {
		if !cm.predicates[i](dm) {
			return false
		}
	}
	return true
}

// CompileMatcher precompiles a configuration map into a high-performance CompiledMatcher.
func CompileMatcher(matching map[string]interface{}) (*CompiledMatcher, error) {
	if len(matching) == 0 {
		return &CompiledMatcher{}, nil
	}

	var predicates []Predicate

	for key, value := range matching {
		normKey := strings.ToLower(strings.TrimSpace(key))
		pred, err := compileFieldMatcher(normKey, value)
		if err != nil {
			return nil, err
		}
		predicates = append(predicates, pred)
	}

	return &CompiledMatcher{predicates: predicates}, nil
}

func compileFieldMatcher(field string, expected interface{}) (Predicate, error) {
	// String fields
	switch field {
	case "dns.qname":
		return compileStringMatcher(expected, func(dm *DNSMessage) string { return dm.DNS.Qname })
	case "dns.qtype":
		return compileStringMatcher(expected, func(dm *DNSMessage) string { return dm.DNS.Qtype })
	case "dns.rcode":
		return compileStringMatcher(expected, func(dm *DNSMessage) string { return dm.DNS.Rcode })
	case "network.family":
		return compileStringMatcher(expected, func(dm *DNSMessage) string { return dm.NetworkInfo.Family })
	case "network.protocol":
		return compileStringMatcher(expected, func(dm *DNSMessage) string { return dm.NetworkInfo.Protocol })
	case "network.query-ip", "network.query_ip":
		return compileStringMatcher(expected, func(dm *DNSMessage) string { return dm.NetworkInfo.GetQueryIP() })
	case "network.response-ip", "network.response_ip":
		return compileStringMatcher(expected, func(dm *DNSMessage) string { return dm.NetworkInfo.GetResponseIP() })
	case "network.query-port", "network.query_port":
		return compileStringMatcher(expected, func(dm *DNSMessage) string { return dm.NetworkInfo.QueryPort })
	case "network.response-port", "network.response_port":
		return compileStringMatcher(expected, func(dm *DNSMessage) string { return dm.NetworkInfo.ResponsePort })
	case "dnstap.operation":
		return compileStringMatcher(expected, func(dm *DNSMessage) string { return dm.DNSTap.Operation })
	case "dnstap.identity":
		return compileStringMatcher(expected, func(dm *DNSMessage) string { return dm.DNSTap.Identity })
	case "geo.country-isocode", "geo.country-iso", "geo.country_iso":
		return compileStringMatcher(expected, func(dm *DNSMessage) string {
			if dm.Geo == nil {
				return ""
			}
			return dm.Geo.CountryIsoCode
		})
	case "geo.city":
		return compileStringMatcher(expected, func(dm *DNSMessage) string {
			if dm.Geo == nil {
				return ""
			}
			return dm.Geo.City
		})
	case "geo.as-number", "geo.as_number":
		return compileStringMatcher(expected, func(dm *DNSMessage) string {
			if dm.Geo == nil {
				return ""
			}
			return dm.Geo.AutonomousSystemNumber
		})
	case "geo.as-owner", "geo.as-org", "geo.as_org":
		return compileStringMatcher(expected, func(dm *DNSMessage) string {
			if dm.Geo == nil {
				return ""
			}
			return dm.Geo.AutonomousSystemOrg
		})

	// Integer fields
	case "dns.opcode":
		return compileIntMatcher(expected, func(dm *DNSMessage) int { return dm.DNS.Opcode })
	case "dns.id":
		return compileIntMatcher(expected, func(dm *DNSMessage) int { return dm.DNS.ID })
	case "dns.length":
		return compileIntMatcher(expected, func(dm *DNSMessage) int { return dm.DNS.Length })

	// Boolean fields
	case "dns.flags.qr":
		return compileBoolMatcher(expected, func(dm *DNSMessage) bool { return dm.DNS.Flags.QR })
	case "dns.flags.aa":
		return compileBoolMatcher(expected, func(dm *DNSMessage) bool { return dm.DNS.Flags.AA })
	case "dns.flags.tc":
		return compileBoolMatcher(expected, func(dm *DNSMessage) bool { return dm.DNS.Flags.TC })
	case "dns.flags.rd":
		return compileBoolMatcher(expected, func(dm *DNSMessage) bool { return dm.DNS.Flags.RD })
	case "dns.flags.ra":
		return compileBoolMatcher(expected, func(dm *DNSMessage) bool { return dm.DNS.Flags.RA })
	case "dns.flags.ad":
		return compileBoolMatcher(expected, func(dm *DNSMessage) bool { return dm.DNS.Flags.AD })
	case "dns.flags.cd":
		return compileBoolMatcher(expected, func(dm *DNSMessage) bool { return dm.DNS.Flags.CD })
	case "network.ip-defragmented", "network.ip_defragmented":
		return compileBoolMatcher(expected, func(dm *DNSMessage) bool { return dm.NetworkInfo.IPDefragmented })
	case "network.tcp-reassembled", "network.tcp_reassembled":
		return compileBoolMatcher(expected, func(dm *DNSMessage) bool { return dm.NetworkInfo.TCPReassembled })

	default:
		// Fallback to dynamic matcher for custom/extended fields
		return func(dm *DNSMessage) bool {
			_, isMatch := dm.Matching(map[string]interface{}{field: expected})
			return isMatch
		}, nil
	}
}

func compileStringMatcher(expected interface{}, getter func(*DNSMessage) string) (Predicate, error) {
	switch v := expected.(type) {
	case string:
		// Check if it's a regex (contains regex meta characters)
		if strings.ContainsAny(v, "^$*+?()[]{}|\\") {
			re, err := regexp.Compile(v)
			if err != nil {
				return nil, fmt.Errorf("invalid regex pattern '%s': %w", v, err)
			}
			return func(dm *DNSMessage) bool {
				return re.MatchString(getter(dm))
			}, nil
		}
		// Exact string match (fast path)
		return func(dm *DNSMessage) bool {
			return getter(dm) == v
		}, nil

	case []interface{}:
		var exactStrings []string
		var regexes []*regexp.Regexp
		for _, item := range v {
			if s, ok := item.(string); ok {
				if strings.ContainsAny(s, "^$*+?()[]{}|\\") {
					re, err := regexp.Compile(s)
					if err != nil {
						return nil, fmt.Errorf("invalid regex pattern '%s': %w", s, err)
					}
					regexes = append(regexes, re)
				} else {
					exactStrings = append(exactStrings, s)
				}
			}
		}
		return func(dm *DNSMessage) bool {
			val := getter(dm)
			for i := 0; i < len(exactStrings); i++ {
				if val == exactStrings[i] {
					return true
				}
			}
			for i := 0; i < len(regexes); i++ {
				if regexes[i].MatchString(val) {
					return true
				}
			}
			return false
		}, nil

	case map[string]interface{}:
		return compileMapStringMatcher(v, getter)

	default:
		return nil, fmt.Errorf("unsupported type %T for string matcher", expected)
	}
}

func compileMapStringMatcher(opMap map[string]interface{}, getter func(*DNSMessage) string) (Predicate, error) {
	source, hasSource := opMap[MatchingOpSource].(string)
	kind, _ := opMap[MatchingOpSourceKind].(string)

	if hasSource && strings.HasPrefix(source, "file://") {
		filePath := strings.TrimPrefix(source, "file://")
		lines, err := readLines(filePath)
		if err != nil {
			return nil, fmt.Errorf("failed to read match-source file %s: %w", filePath, err)
		}

		if kind == MatchingKindRegexp {
			var regexes []*regexp.Regexp
			for _, line := range lines {
				re, err := regexp.Compile(line)
				if err != nil {
					return nil, fmt.Errorf("invalid regex in match file '%s': %w", line, err)
				}
				regexes = append(regexes, re)
			}
			return func(dm *DNSMessage) bool {
				val := getter(dm)
				for _, re := range regexes {
					if re.MatchString(val) {
						return true
					}
				}
				return false
			}, nil
		}

		// string_list
		stringSet := make(map[string]struct{}, len(lines))
		for _, line := range lines {
			stringSet[line] = struct{}{}
		}
		return func(dm *DNSMessage) bool {
			_, exists := stringSet[getter(dm)]
			return exists
		}, nil
	}

	return nil, fmt.Errorf("unsupported map matcher for string field: %+v", opMap)
}

func compileIntMatcher(expected interface{}, getter func(*DNSMessage) int) (Predicate, error) {
	switch v := expected.(type) {
	case int:
		return func(dm *DNSMessage) bool {
			return getter(dm) == v
		}, nil
	case string:
		intVal, err := strconv.Atoi(v)
		if err != nil {
			return nil, fmt.Errorf("invalid integer string '%s': %w", v, err)
		}
		return func(dm *DNSMessage) bool {
			return getter(dm) == intVal
		}, nil
	case map[string]interface{}:
		if gtVal, ok := v[MatchingOpGreaterThan]; ok {
			limit, err := toInt(gtVal)
			if err != nil {
				return nil, err
			}
			return func(dm *DNSMessage) bool {
				return getter(dm) > limit
			}, nil
		}
		if ltVal, ok := v[MatchingOpLowerThan]; ok {
			limit, err := toInt(ltVal)
			if err != nil {
				return nil, err
			}
			return func(dm *DNSMessage) bool {
				return getter(dm) < limit
			}, nil
		}
		return nil, fmt.Errorf("unsupported operator map for int matcher: %+v", v)
	default:
		return nil, fmt.Errorf("unsupported type %T for int matcher", expected)
	}
}

func compileBoolMatcher(expected interface{}, getter func(*DNSMessage) bool) (Predicate, error) {
	switch v := expected.(type) {
	case bool:
		return func(dm *DNSMessage) bool {
			return getter(dm) == v
		}, nil
	case string:
		boolVal, err := strconv.ParseBool(v)
		if err != nil {
			return nil, fmt.Errorf("invalid boolean string '%s': %w", v, err)
		}
		return func(dm *DNSMessage) bool {
			return getter(dm) == boolVal
		}, nil
	default:
		return nil, fmt.Errorf("unsupported type %T for bool matcher", expected)
	}
}

func toInt(v interface{}) (int, error) {
	switch val := v.(type) {
	case int:
		return val, nil
	case int64:
		return int(val), nil
	case float64:
		return int(val), nil
	case string:
		return strconv.Atoi(val)
	default:
		return 0, fmt.Errorf("cannot convert %T to int", v)
	}
}

func readLines(filePath string) ([]string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var lines []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			lines = append(lines, line)
		}
	}
	return lines, scanner.Err()
}
