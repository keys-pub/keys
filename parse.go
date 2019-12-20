package keys

import (
	"fmt"
	"html"
	"regexp"
	"strings"

	"github.com/pkg/errors"
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

// findSaltpackMessageInHTML finds string in HTML data.
func findSaltpackMessageInHTML(body string, brand string) string {
	logger.Debugf("Searching for statement in message (%d)", len(body))
	start := saltpackStart(brand)
	end := saltpackEnd(brand)
	msg := find(body, start, end, true)
	if msg == "" {
		return ""
	}
	if len(msg) < len(start)+len(end) {
		return ""
	}
	return msg
}

func find(body string, start, end string, stripHTML bool) string {
	// TODO: Better parsing
	idx := strings.Index(body, start)
	if idx == -1 {
		return ""
	}
	idx2 := strings.Index(body[idx:], end)
	if idx2 == -1 {
		return ""
	}
	msg := body[idx : idx+idx2+len(end)]
	if stripHTML {
		msg = stripTags(msg)
	}
	return msg
}

func stripTags(body string) string {
	re := regexp.MustCompile(`<\/?[^>]+(>|$)`)
	return re.ReplaceAllString(body, "")
}

func trimSaltpackInHTML(msg string, brand string) (string, error) {
	msg = html.UnescapeString(msg)

	start := saltpackStart(brand)
	end := saltpackEnd(brand)

	if !strings.HasPrefix(msg, start) {
		return "", errors.Errorf("missing saltpack start")
	}
	if !strings.HasSuffix(msg, end) {
		return "", errors.Errorf("missing saltpack end")
	}
	msg = msg[len(start) : len(msg)-len(end)]
	msg = trimMessage(msg)

	return msg, nil
}
