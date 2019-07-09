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
				TestParser.RunTest(gocrypto.TestShaMonte2)
				re := regexp.MustCompile(`(req)`)
				outFile := re.ReplaceAllString(vec, `rsp`)
				TestParser.WriteResponse(filepath.Join(root, "SHA", "resp", outFile))
			}
		} else {
			TestParser := parser.ReqParserSha{}
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

func DoSha3Testing(root string, vectors []string) {
	for _, vec := range(vectors) {
		if strings.Contains(vec, "Monte") {
			TestParser := parser.ReqParserShaMonte{}
			if strings.Contains(vec, "256") {
				TestParser.SetAlg("SHA3_256")
			} else if strings.Contains(vec, "512") {
				TestParser.SetAlg("SHA3_512")
			}
			fname := filepath.Join(root, "SHA3", "req", vec)
			vectors, err := parser.LoadReqFile(fname)
			if err != nil {
				log.Fatal(err)
			} else {
				TestParser.Ingest(vectors)
				TestParser.RunTest(gocrypto.TestShaMonte3)
				re := regexp.MustCompile(`(req)`)
				outFile := re.ReplaceAllString(vec, `rsp`)
				TestParser.WriteResponse(filepath.Join(root, "SHA3", "resp", outFile))
			}
		} else {
			TestParser := parser.ReqParserSha{}
			if strings.Contains(vec, "256") {
				TestParser.SetAlg("SHA3_256")
			} else if strings.Contains(vec, "512") {
				TestParser.SetAlg("SHA3_512")
			}
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
