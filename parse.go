package keys

import (
	"html"
	"regexp"
	"strings"

	"github.com/pkg/errors"
)

// saltpackStart start of a saltpack message.
const saltpackStart = "BEGIN MESSAGE."

// saltpackEnd end of a saltpack message.
const saltpackEnd = "END MESSAGE."

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

// findStringInHTML finds string in HTML data.
func findStringInHTML(body string) (string, error) {
	logger.Debugf("Searching for statement in message (%d)", len(body))
	msg, err := find(body, saltpackStart, saltpackEnd, true)
	if err != nil {
		return "", err
	}
	if msg == "" {
		return "", nil
	}
	if len(msg) < len(saltpackStart)+len(saltpackEnd) {
		return "", nil
	}
	return msg, nil
}

func find(body string, start, end string, stripHTML bool) (string, error) {
	// TODO: Better parsing
	idx := strings.Index(body, start)
	if idx == -1 {
		return "", nil
	}
	idx2 := strings.Index(body[idx:], end)
	if idx2 == -1 {
		return "", nil
	}
	msg := body[idx : idx+idx2+len(end)]
	if stripHTML {
		msg = stripTags(msg)
	}
	return msg, nil
}

func stripTags(body string) string {
	re := regexp.MustCompile(`<\/?[^>]+(>|$)`)
	return re.ReplaceAllString(body, "")
}

func trimHTML(msg string) (string, error) {
	msg = html.UnescapeString(msg)

	if !strings.HasPrefix(msg, saltpackStart) {
		return "", errors.Errorf("missing prefix")
	}
	if !strings.HasSuffix(msg, saltpackEnd) {
		return "", errors.Errorf("missing suffix")
	}
	msg = msg[len(saltpackStart) : len(msg)-len(saltpackEnd)]
	msg = trimMessage(msg)

	return msg, nil
}
