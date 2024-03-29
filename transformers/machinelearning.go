package transformers

import (
	"fmt"
	"math"
	"strings"
	"unicode"

	"github.com/dmachard/go-dnscollector/dnsutils"
	"github.com/dmachard/go-dnscollector/pkgconfig"
	"github.com/dmachard/go-logger"
)

func isConsonant(char rune) bool {
	if !unicode.IsLower(char) && !unicode.IsUpper(char) {
		return false
	}
	switch char {
	case 'a', 'A', 'e', 'E', 'i', 'I', 'o', 'O', 'u', 'U', 'y', 'Y':
		return false
	}
	return true
}

type MlProcessor struct {
	config      *pkgconfig.ConfigTransformers
	instance    int
	outChannels []chan dnsutils.DNSMessage
	logInfo     func(msg string, v ...interface{})
	logError    func(msg string, v ...interface{})
}

func NewMachineLearningTransform(config *pkgconfig.ConfigTransformers, logger *logger.Logger, name string,
	instance int, outChannels []chan dnsutils.DNSMessage,
	logInfo func(msg string, v ...interface{}), logError func(msg string, v ...interface{}),
) MlProcessor {
	s := MlProcessor{
		config:      config,
		instance:    instance,
		outChannels: outChannels,
		logInfo:     logInfo,
		logError:    logError,
	}

	return s
}

func (p *MlProcessor) ReloadConfig(config *pkgconfig.ConfigTransformers) {
	p.config = config
}

func (p *MlProcessor) LogInfo(msg string, v ...interface{}) {
	log := fmt.Sprintf("ml#%d - ", p.instance)
	p.logInfo(log+msg, v...)
}

func (p *MlProcessor) LogError(msg string, v ...interface{}) {
	log := fmt.Sprintf("ml#%d - ", p.instance)
	p.logError(log+msg, v...)
}

func (p *MlProcessor) InitDNSMessage(dm *dnsutils.DNSMessage) {
	if dm.MachineLearning == nil {
		dm.MachineLearning = &dnsutils.TransformML{
			Entropy:               0,
			Length:                0,
			Digits:                0,
			Lowers:                0,
			Uppers:                0,
			Labels:                0,
			Specials:              0,
			RatioDigits:           0,
			RatioLetters:          0,
			RatioSpecials:         0,
			Others:                0,
			ConsecutiveChars:      0,
			ConsecutiveVowels:     0,
			ConsecutiveDigits:     0,
			ConsecutiveConsonants: 0,
			Size:                  0,
			Occurrences:           0,
			UncommonQtypes:        0,
		}
	}
}

func (p *MlProcessor) AddFeatures(dm *dnsutils.DNSMessage) {

	if dm.MachineLearning == nil {
		p.LogError("transformer is not properly initialized")
		return
	}

	// count global number of chars
	n := float64(len(dm.DNS.Qname))
	if n == 0 {
		n = 1
	}

	// count number of unique chars
	uniq := make(map[rune]int)
	for _, c := range dm.DNS.Qname {
		uniq[c]++
	}

	// calculate the probability of occurrence for each unique character.
	probs := make(map[rune]float64)
	for char, count := range uniq {
		probs[char] = float64(count) / n
	}

	// calculate the entropy
	var entropy float64
	for _, prob := range probs {
		if prob > 0 {
			entropy -= prob * math.Log2(prob)
		}
	}

	// count digit
	countDigits := 0
	for _, char := range dm.DNS.Qname {
		if unicode.IsDigit(char) {
			countDigits++
		}
	}

	// count lower
	countLowers := 0
	for _, char := range dm.DNS.Qname {
		if unicode.IsLower(char) {
			countLowers++
		}
	}

	// count upper
	countUppers := 0
	for _, char := range dm.DNS.Qname {
		if unicode.IsUpper(char) {
			countUppers++
		}
	}

	// count specials
	countSpecials := 0
	for _, char := range dm.DNS.Qname {
		switch char {
		case '.', '-', '_', '=':
			countSpecials++
		}
	}

	// count others
	countOthers := len(dm.DNS.Qname) - (countDigits + countLowers + countUppers + countSpecials)

	// count labels
	numLabels := strings.Count(dm.DNS.Qname, ".") + 1

	// count consecutive chars
	consecutiveCount := 0
	nameLower := strings.ToLower(dm.DNS.Qname)
	for i := 1; i < len(nameLower); i++ {
		if nameLower[i] == nameLower[i-1] {
			consecutiveCount += 1
		}
	}

	// count consecutive vowel
	consecutiveVowelCount := 0
	for i := 1; i < len(nameLower); i++ {
		switch nameLower[i] {
		case 'a', 'e', 'i', 'o', 'u', 'y':
			if nameLower[i] == nameLower[i-1] {
				consecutiveVowelCount += 1
			}
		}
	}

	// count consecutive digit
	consecutiveDigitCount := 0
	for i := 1; i < len(nameLower); i++ {
		if unicode.IsDigit(rune(nameLower[i])) && unicode.IsDigit(rune(nameLower[i-1])) {
			consecutiveDigitCount += 1
		}
	}

	// count consecutive consonant
	consecutiveConsonantCount := 0
	for i := 1; i < len(nameLower); i++ {
		if isConsonant(rune(nameLower[i])) && isConsonant(rune(nameLower[i-1])) {
			consecutiveConsonantCount += 1
		}
	}

	// size
	dm.MachineLearning.Size = dm.DNS.Length
	if dm.Reducer != nil {
		dm.MachineLearning.Size = dm.Reducer.CumulativeLength
	}

	// occurences
	if dm.Reducer != nil {
		dm.MachineLearning.Occurrences = dm.Reducer.Occurrences
	}

	// qtypes
	switch dm.DNS.Qtype {
	case "A", "AAAA", "HTTPS", "SRV", "PTR", "SOA", "NS":
		dm.MachineLearning.UncommonQtypes = 0
	default:
		dm.MachineLearning.UncommonQtypes = 1
	}

	dm.MachineLearning.Entropy = entropy
	dm.MachineLearning.Length = len(dm.DNS.Qname)
	dm.MachineLearning.Digits = countDigits
	dm.MachineLearning.Lowers = countLowers
	dm.MachineLearning.Uppers = countUppers
	dm.MachineLearning.Specials = countSpecials
	dm.MachineLearning.Others = countOthers
	dm.MachineLearning.Labels = numLabels
	dm.MachineLearning.RatioDigits = float64(countDigits) / n
	dm.MachineLearning.RatioLetters = float64(countLowers+countUppers) / n
	dm.MachineLearning.RatioSpecials = float64(countSpecials) / n
	dm.MachineLearning.RatioOthers = float64(countOthers) / n
	dm.MachineLearning.ConsecutiveChars = consecutiveCount
	dm.MachineLearning.ConsecutiveVowels = consecutiveVowelCount
	dm.MachineLearning.ConsecutiveDigits = consecutiveDigitCount
	dm.MachineLearning.ConsecutiveConsonants = consecutiveConsonantCount
}
