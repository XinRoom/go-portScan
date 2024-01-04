package fingerprint

import (
	"bytes"
	"fmt"
	"golang.org/x/net/html"
	"io"
	"regexp"
	"strings"
)

var (
	cutset        = "\n\t\v\f\r"
	reTitle       = regexp.MustCompile(`(?im)<\s*title.*>(.*?)<\s*/\s*title>`)
	reContentType = regexp.MustCompile(`(?im)\s*charset="(.*?)"|charset=(.*?)"\s*`)
	reRefresh     = regexp.MustCompile(`(?im)\s*content=['"]\d;url=['"](.*?)['"]`)
	reReplace     = regexp.MustCompile(`(?im)location\.replace\([\w+ ]*?['"](.*?)['"][\w+ ]*?\)`)
	reLocation    = regexp.MustCompile(`(?im)location\.href\W?=[\w+ ]*?['"](.*?)['"]`)
)

// ExtractTitle from a response
func ExtractTitle(body []byte) (title string) {
	// Try to parse the DOM
	titleDom, err := getTitleWithDom(body)
	// In case of error fallback to regex
	if err != nil {
		for _, match := range reTitle.FindAllString(string(body), -1) {
			title = match
			break
		}
	} else {
		title = renderNode(titleDom)
	}

	title = html.UnescapeString(trimTitleTags(title))

	// remove unwanted chars
	title = strings.TrimSpace(strings.Trim(title, cutset))
	title = strings.ReplaceAll(title, "\n", "")
	title = strings.ReplaceAll(title, "\r", "")

	return title
}

func getTitleWithDom(body []byte) (*html.Node, error) {
	var title *html.Node
	var crawler func(*html.Node)
	crawler = func(node *html.Node) {
		if node.Type == html.ElementNode && node.Data == "title" {
			title = node
			return
		}
		for child := node.FirstChild; child != nil && title == nil; child = child.NextSibling {
			crawler(child)
		}
	}
	htmlDoc, err := html.Parse(bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	crawler(htmlDoc)
	if title != nil {
		return title, nil
	}
	return nil, fmt.Errorf("title not found")
}

func renderNode(n *html.Node) string {
	var buf bytes.Buffer
	w := io.Writer(&buf)
	html.Render(w, n) //nolint
	return buf.String()
}

func trimTitleTags(title string) string {
	// trim <title>*</title>
	titleBegin := strings.Index(title, ">")
	titleEnd := strings.Index(title, "</")
	if titleEnd < 0 || titleBegin < 0 {
		return title
	}
	return title[titleBegin+1 : titleEnd]
}

func GetLocation(body []byte) (location string) {
	for _, match := range reRefresh.FindAllStringSubmatch(string(body), 1) {
		location = match[1]
		break
	}
	if location == "" {
		for _, match := range reReplace.FindAllStringSubmatch(string(body), 1) {
			location = match[1]
			break
		}
	}
	if location == "" {
		for _, match := range reLocation.FindAllStringSubmatch(string(body), 1) {
			location = match[1]
			break
		}
	}
	return
}
