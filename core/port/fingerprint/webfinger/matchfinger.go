package webfinger

import (
	"regexp"
	"strings"
)

func iskeyword(str string, keyword []string, or bool) bool {
	if len(keyword) == 0 || str == "" {
		return false
	}
	for _, k := range keyword {
		b := strings.Contains(str, k)
		if !or && !b {
			return false
		}
		if or && b {
			return true
		}
	}
	return !or
}

func isregular(str string, keyword []string, or bool) bool {
	if len(keyword) == 0 || str == "" {
		return false
	}
	for _, k := range keyword {
		re := regexp.MustCompile(k)
		b := re.Match([]byte(str))
		if !or && !b {
			return false
		}
		if or && b {
			return true
		}
	}
	return !or
}
