package util

import (
	"bufio"
	"errors"
	"os"
)

func GetLines(filename string) (out []string, err error) {
	if filename == "" {
		return out, errors.New("no filename")
	}
	file, err := os.Open(filename)
	if err != nil {
		return out, err
	}

	defer file.Close()
	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		line := scanner.Text()
		if line != "" {
			out = append(out, line)
		}
	}
	err = scanner.Err()
	return
}
