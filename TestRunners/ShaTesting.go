package TestRunners

import (
	"OpenCAV/parser"
	"OpenCAV/shims/gocrypto"
	"errors"
	"log"
	"path/filepath"
	"regexp"
	"strings"
)

func DoShaTesting(root string, vectors []string) {
	for _, vec := range(vectors) {
		if strings.Contains(vec, "Monte") {
			TestParser := parser.ReqParserShaMonte{}
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
			TestParser := parser.ReqParserSha{}
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

func DoSha3Testing(root string, vectors []string) {
	for _, vec := range(vectors) {
		if strings.Contains(vec, "Monte") {
			TestParser := parser.ReqParserShaMonte{}
			fname := filepath.Join(root, "SHA3", "req", vec)
			vectors, err := parser.LoadReqFile(fname)
			if err != nil {
				log.Fatal(err)
			} else {
				TestParser.Ingest(vectors)
				TestParser.RunTest(gocrypto.TestSha3Monte)
				re := regexp.MustCompile(`(req)`)
				outFile := re.ReplaceAllString(vec, `rsp`)
				TestParser.WriteResponse(filepath.Join(root, "SHA3", "resp", outFile))
			}
		} else {
			TestParser := parser.ReqParserSha{}
			fname := filepath.Join(root, "SHA3", "req", vec)
			vectors, err := parser.LoadReqFile(fname)
			if err != nil {
				log.Fatal(errors.New("Failed to load request file"))
			} else {
				_, err = TestParser.Ingest(vectors)
				if err != nil {
					log.Fatal(errors.New("Died ingesting vectors"))
				}
				TestParser.RunTest(gocrypto.TestSha3)
				re := regexp.MustCompile(`(req)`)
				outFile := re.ReplaceAllString(vec, `rsp`)
				TestParser.WriteResponse(filepath.Join(root, "SHA3", "resp", outFile))
			}
		}
	}
}

func DoHmacTesting(root string, vectors []string) {
	for _, vec := range vectors {
		TestParser := parser.NewHmacParser()
		fname := filepath.Join(root, "HMAC", "req", vec)
		vectors, err := parser.LoadReqFile(fname)
		if err != nil {
			log.Fatal(err)
		}
		_, err = TestParser.Ingest(vectors)
		if err != nil {
			log.Fatal(errors.New("Died ingesting HMAC vectors"))
		}
		TestParser.RunTest(gocrypto.TestHmac)
		re := regexp.MustCompile(`(req)`)
		outfile := re.ReplaceAllString(vec, `rsp`)
		TestParser.WriteResponse(filepath.Join(root, "HMAC", "resp", outFile))
	}
}