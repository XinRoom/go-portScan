package webfinger

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"github.com/twmb/murmur3"
	"regexp"
)

var (
	shortcutText = regexp.MustCompile(`(?im)<link.*?rel=["']?shortcut icon["']?.*?>`)
	shortcutHref = regexp.MustCompile(`(?im)href=['"]+(.*?)['"]+`)
)

func FindFaviconUrl(body string) string {
	a := shortcutText.FindStringSubmatch(body)
	if len(a) > 0 {
		faviconLink := a[0]
		b := shortcutHref.FindStringSubmatch(faviconLink)
		if len(b) > 1 {
			return b[1]
		}
	}
	return ""
}

func mmh3Hash32(raw []byte) string {
	var h32 = murmur3.New32()
	_, err := h32.Write(raw)
	if err == nil {
		return fmt.Sprintf("%d", int32(h32.Sum32()))
	} else {
		return ""
	}
}

func standBase64(braw []byte) []byte {
	bckd := base64.StdEncoding.EncodeToString(braw)
	var buffer bytes.Buffer
	for i := 0; i < len(bckd); i++ {
		ch := bckd[i]
		buffer.WriteByte(ch)
		if (i+1)%76 == 0 {
			buffer.WriteByte('\n')
		}
	}
	buffer.WriteByte('\n')
	return buffer.Bytes()
}
