package main

import (
	"OpenCAV/parser"
	"errors"
	"flag"
	"fmt"
	"regexp"
	"OpenCAV/shims/gocrypto"
	"io/ioutil"
	"log"
	"path/filepath"
	"strings"
)

var (
	root string
)

func DoShaTesting(vectors []string) {
	for _, vec := range(vectors) {
		if strings.Contains(vec, "Monte") {
			TestParser := parser.ReqParserSha2Monte{}
			if strings.Contains(vec, "256") {
				TestParser.SetAlg("SHA256")
			} else if strings.Contains(vec, "512") {
				TestParser.SetAlg("SHA512")
			}
			fname := filepath.Join(root, "SHA", "req", vec)
			vectors, err := parser.LoadReqFile(fname)
			if err != nil {
				log.Fatal(err)
			} else {
				TestParser.Ingest(vectors)
				TestParser.RunTest(gocrypto.TestSha2Monte)
				re := regexp.MustCompile(`(req)`)
				outFile := re.ReplaceAllString(vec, `rsp`)
				TestParser.WriteResponse(filepath.Join(root, "SHA", "resp", outFile))
			}
		} else {
			TestParser := parser.ReqParserSha2{}
			if strings.Contains(vec, "256") {
				TestParser.SetAlg("SHA256")
			} else if strings.Contains(vec, "512") {
				TestParser.SetAlg("SHA512")
			}
			fname := filepath.Join(root, "SHA", "req", vec)
			vectors, err := parser.LoadReqFile(fname)
			if err != nil {
				log.Fatal(errors.New("Failed to load request file"))
			} else {
				_, err = TestParser.Ingest(vectors)
				if err != nil {
					log.Fatal(errors.New("Died ingesting vectors"))
				}
				TestParser.RunTest(gocrypto.TestSha2)
				re := regexp.MustCompile(`(req)`)
				outFile := re.ReplaceAllString(vec, `rsp`)
				TestParser.WriteResponse(filepath.Join(root, "SHA", "resp", outFile))
			}
		}
	}
}

func main() {
	flag.StringVar(&root, "root", "", "Root directory containng the test vectors")
	flag.Parse()
	if root == "" {
		log.Fatal("Must supply a root directory")
	}
	for _, alg := range gocrypto.ImplementedAlgs {
		reqDir := filepath.Join(root, alg, "req")
		fmt.Println(reqDir)
		reqFiles, err := ioutil.ReadDir(reqDir)
		if err != nil {
			log.Fatal(err)
		}
		fnames := []string{}
		for _, file := range reqFiles {
			fnames = append(fnames, file.Name())
		}
		if strings.Contains(alg, "SHA") && !strings.Contains(alg, "SHA3") {
			DoShaTesting(fnames)
		}
	}
}