package webfinger

import (
	"regexp"
	"strings"
)

func iskeyword(str string, keyword []string) bool {
	if len(keyword) == 0 || str == "" {
		return false
	}
	for _, k := range keyword {
		if !strings.Contains(str, k) {
			return false
		}
	}
	return true
}

func isregular(str string, keyword []string) bool {
	if len(keyword) == 0 || str == "" {
		return false
	}
	for _, k := range keyword {
		re := regexp.MustCompile(k)
		if !re.Match([]byte(str)) {
			return false
		}
	}
	return true
}
