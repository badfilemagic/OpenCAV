package parser

import (
	"OpenCAV/algs"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"os"
	"regexp"
	"strings"
)

type ReqParserShaMonte struct {
	filename 	string
	alg			string
	ismonte		bool
	respheader 	[]string
	digestlen 	int
	seed 		[]byte
	digests		[][]byte
}

func NewReqParserShaMonte() ReqParserShaMonte {
	return ReqParserShaMonte{}
}


func (r *ReqParserShaMonte) SetFilename(filename string) {
	r.filename = filename
}
func (r *ReqParserShaMonte) Alg() string {
	return r.alg
}
func (r *ReqParserShaMonte) SetAlg(alg string) {
	r.alg = alg
}

func (r *ReqParserShaMonte) Filename() string {
	return r.filename
}

func (r *ReqParserShaMonte) SetMonte(m bool) {
	r.ismonte = m
}

func (r *ReqParserShaMonte) Monte() bool {
	return r.ismonte
}

func (r *ReqParserShaMonte) SetOplen(l int) {
	r.digestlen = l
}
func (r *ReqParserShaMonte) Oplen() int {
	return r.digestlen
}

func (r *ReqParserShaMonte) Seed() []byte {
	return r.seed
}


func (r *ReqParserShaMonte) Operations() [][]byte {
	return r.digests
}

func (r *ReqParserShaMonte) Ingest(lines []string) (int, error) {
	for i := 0; i < len(lines)-1; i++ {
		if match, err := regexp.Match(`^#`, []byte(lines[i])); err == nil && match {
			r.respheader = append(r.respheader, lines[i])
		} else if match, err := regexp.Match(`^\[L = \d+\]$`, []byte(lines[i])); err == nil && match {
			if match, err := regexp.Match(`32`, []byte(lines[i])); err == nil && match {
				r.SetOplen(32)
			} else if match, err := regexp.Match(`64`, []byte(lines[i])); err == nil && match {
				r.SetOplen(64)
			} else if strings.Contains(lines[i], "256") {
				r.SetOplen(256)
			} else if strings.Contains(lines[i], "512") {
				r.SetOplen(512)
			} else {
				log.Fatal(errors.New("Unknown Digest Length!" + lines[i]))
			}
		} else if lines[i] == "" && lines[i+1] != "[L = 32]" && lines[i+1] != "[L = 64]"  && lines[i+1] != "[L = 256]" && lines[i+1] != "[L = 512]" {
		} else if match, err := regexp.Match("Seed = ", []byte(lines[i])); err == nil && match {
			if r.seed, err = hex.DecodeString(strings.Split(lines[i], " = ")[1]); err != nil {
				return 0, err
			}
		}
	}
	return 1, nil
}

func (r *ReqParserShaMonte) RunTest(doMonte algs.DoHashMonte) {
	r.digests = doMonte(r.Seed(), r.Alg())
}


func (r *ReqParserShaMonte) WriteResponse(filename string) error {
	fh, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer fh.Close()

	for _, line := range r.respheader {
		line += "\r\n"
		_,_ = fh.Write([]byte(line))
	}
	_,_ = fh.Write([]byte("\r\n"))
	for i, op := range r.digests {
		line1 := fmt.Sprintf("COUNT = %d\r\n",i)
		line2 := "MD = " + hex.EncodeToString(op) + "\r\n"
		_,_ = fh.Write([]byte(line1))
		_,_ = fh.Write([]byte(line2))
		_,_ = fh.Write([]byte("\r\n"))
	}
	return nil
}