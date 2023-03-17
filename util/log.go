package util

import (
	"io"
	"log"
	"os"
)

func NewLogger(filename string, std bool) *log.Logger {
	var out io.Writer
	if filename == "" {
		out = os.Stdout
	} else {
		outFile, _ := os.OpenFile(filename, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
		if std {
			out = io.MultiWriter(os.Stdout, outFile)
		} else {
			out = outFile
		}
	}
	logger := log.New(out, "", 0)
	return logger
}
