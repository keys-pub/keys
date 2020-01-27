package keys

import (
	"fmt"
	"html"
	"regexp"
	"strings"
)

// saltpackStart start of a saltpack message.
func saltpackStart(brand string) string {
	if brand == "" {
		return "BEGIN MESSAGE."
	}
	return fmt.Sprintf("BEGIN %s MESSAGE.", brand)
}

// saltpackEnd end of a saltpack message.
func saltpackEnd(brand string) string {
	if brand == "" {
		return "END MESSAGE."
	}
	return fmt.Sprintf("END %s MESSAGE.", brand)
}

func breakString(msg string, wordLen int, lineLen int) string {
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

func findSaltpack(msg string, isHTML bool) (string, string) {
	if isHTML {
		msg = html.UnescapeString(msg)
	}

	re := regexp.MustCompile(`(?s).*BEGIN (.*)MESSAGE\.(.*)END .*MESSAGE.*`)
	s := re.FindStringSubmatch(msg)

	brand, out := "", ""
	if len(s) >= 2 {
		brand = strings.TrimSpace(trimSaltpack(s[1], true))
	}
	if len(s) >= 3 {
		out = s[2]
		out = strings.ReplaceAll(out, "\\n", "")
	}

	if isHTML {
		out = stripTags(out)
	}

	out = trimSaltpack(out, false)
	return out, brand
}
