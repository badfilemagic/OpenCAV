package TestRunners

import (
	"OpenCAV/parser"
	"OpenCAV/shims/gocrypto"
	"errors"
	"log"
	"path/filepath"
	"regexp"
)

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
		TestParser.WriteResponse(filepath.Join(root, "HMAC", "resp", outfile))
	}
}