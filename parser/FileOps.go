package parser

import (
	"bufio"
	"errors"
	"os"
	"regexp"
)

func LoadReqFile(filename string) ([]string, error){
	var lines []string
	fh, err := os.Open(filename)
	if err != nil {
		return nil, nil
	}
	defer fh.Close()

	scanner := bufio.NewScanner(fh)
	for scanner.Scan() {
		line := scanner.Text()
		lines = append(lines, line)
	}
	return lines, nil
}

func GetParser(filename string) (Parser, error) {
	var (
		match bool
		err error
		alg string
	)
	if match, err = regexp.Match(`SHA\\`, []byte(filename)); err == nil && match {
		if match, err = regexp.Match(`256`, []byte(filename)); err == nil && match {
			alg = "SHA256"
		} else if match, err := regexp.Match(`512`, []byte(filename)); err == nil && match {
			alg = "SHA512"
		} else {
			return nil, errors.New("Unimplemented SHA value")
		}

		if match, err = regexp.Match(`Monte`, []byte(filename)); err == nil && match {
			rpm := new(ReqParserSha2Monte)
			rpm.SetFilename(filename)
			rpm.SetAlg(alg)
			rpm.SetMonte(true)
			return rpm, nil
		} else {
			rp := new(ReqParserSha2)
			rp.SetFilename(filename)
			rp.SetAlg(alg)
			return rp, nil
		}

	}

	// default is failure
	return nil, errors.New("Unimplemented Algorithm")
}




