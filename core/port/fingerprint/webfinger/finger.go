package webfinger

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"os"
)

// ref:https://github.com/EdgeSecurityTeam/EHole/blob/main/finger.json

type Date struct {
	Name     string
	Location string
	Method   string
	Keyword  []string
}

type WebFinger struct {
	Name    string
	Fingers []Date
}

var WebFingers []WebFinger

// LoadWebFingerData 加载web指纹数据
func LoadWebFingerData(file string) error {
	data, err := os.ReadFile(file)
	if err != nil {
		return err
	}
	err = ParseWebFingerData(data)
	if err != nil {
		return err
	}
	return nil
}

func ParseWebFingerData(data []byte) error {
	err := json.Unmarshal(data, &WebFingers)
	if err != nil {
		return err
	}
	return nil
}

// WebFingerIdent web系统指纹识别
func WebFingerIdent(resp *http.Response) (names []string) {
	var data string
	body, _ := io.ReadAll(resp.Body)
	for _, finger := range WebFingers {
		for _, finger2 := range finger.Fingers {
			switch finger2.Location {
			case "body":
				data = string(body)
			case "header":
				var b bytes.Buffer
				resp.Header.Write(&b)
				data = b.String()
			}
			var flag bool
			switch finger2.Method {
			case "keyword":
				if iskeyword(data, finger2.Keyword) {
					flag = true
				}
			case "regular":
				if isregular(data, finger2.Keyword) {
					flag = true
				}
			}
			if flag {
				if finger2.Name != "" {
					finger.Name += "," + finger2.Name
				}
				names = append(names, finger.Name)
				break
			}
		}
	}
	return
}

// WebFingerIdentByFavicon web系统指纹识别,通过Favicon.ico
func WebFingerIdentByFavicon(body []byte) (names []string) {
	var data string
	data = mmh3Hash32(standBase64(body))
	for _, finger := range WebFingers {
		for _, finger2 := range finger.Fingers {
			switch finger2.Method {
			case "faviconhash":
				if data != "" && len(finger2.Keyword) > 0 && data == finger2.Keyword[0] {
					if finger2.Name != "" {
						finger.Name += "," + finger2.Name
					}
					names = append(names, finger.Name)
					break
				}
			}
		}
	}
	return
}
