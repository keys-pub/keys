package encoding

import (
	"html"
	"regexp"
	"strings"
)

// BreakString breaks words and lines.
func BreakString(msg string, wordLen int, lineLen int) string {
	words := []string{}
	lines := []string{}
	for i := 0; i < len(msg); i += wordLen {
		end := i + wordLen
		if end > len(msg) {
			end = len(msg)
		}
		word := msg[i:end]
		if l := len(words); l != 0 && l%lineLen == 0 {
			lines = append(lines, strings.Join(words, " "))
			words = []string{}
		}
		words = append(words, word)
	}
	lines = append(lines, strings.Join(words, " "))
	return strings.Join(lines, "\n")
}

func stripTags(body string) string {
	re := regexp.MustCompile(`<\/?[^>]+(>|$)`)
	return re.ReplaceAllString(body, "")
}

// FindSaltpack finds saltpack message in a string.
func FindSaltpack(msg string, isHTML bool) (string, string) {
	if isHTML {
		msg = html.UnescapeString(msg)
	}

	re := regexp.MustCompile(`(?s).*BEGIN (.*)MESSAGE\.(.*)END .*MESSAGE.*`)
	s := re.FindStringSubmatch(msg)

	brand, out := "", ""
	if len(s) >= 2 {
		brand = strings.TrimSpace(TrimSaltpack(s[1], true))
	}
	if len(s) >= 3 {
		out = s[2]
		out = strings.ReplaceAll(out, "\\n", "")
	}

	if isHTML {
		out = stripTags(out)
	}

	out = TrimSaltpack(out, false)
	return out, brand
}
