package parser

import (
	"bufio"
	"os"
)

func LoadReqFile(filename string) ([]string, error){
	var lines []string
	fh, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer fh.Close()

	scanner := bufio.NewScanner(fh)
	for scanner.Scan() {
		line := scanner.Text()
		lines = append(lines, line)
	}
	return lines, nil
}


