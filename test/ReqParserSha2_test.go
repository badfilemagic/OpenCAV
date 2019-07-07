package test

import (
	"OpenCAV/parser"
	"testing"
)

func TestIngest(t *testing.T) {
	testVector := "C:\\Users\\Dean Freeman\\Desktop\\CAVS21.3\\Products\\MyTestIUT\\SHA\\req\\Sha256ShortMsg.req"

	p := parser.ReqParserSha2{Filename: testVector}
	lines, err := parser.LoadReqFile(p.Filename)
	ops, err := p.Ingest(lines)
	if err != nil {
		t.Errorf("Ingest operation encountered an error: %s", err)
	}
	if ops != 65 {
		t.Errorf("Ingest did not get correct number of operations. Ingested only %d", ops)
	}
}