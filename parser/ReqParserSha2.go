package parser

import (
	"OpenCAV/algs"
	"encoding/hex"
	"os"
	"strings"
	"regexp"
)

type ReqParserSha2 struct {
	filename 	string
	alg 		string
	ismonte		bool
	respheader 	[]string
	digetlen 	int
	operations	[]algs.Sha2
}

func NewReqParserSha2(filename string) ReqParserSha2 {
	return ReqParserSha2{filename:filename}
}

func (r *ReqParserSha2) SetFilename(filename string) {
	r.filename = filename
}
func (r *ReqParserSha2) Alg() string {
	return r.alg
}
func (r *ReqParserSha2) SetAlg(alg string) {
	r.alg = alg
}

func (r *ReqParserSha2) Filename() string {
	return r.filename
}

func (r *ReqParserSha2) SetMonte(m bool) {
	r.ismonte = m
}

func (r *ReqParserSha2) Monte() bool {
	return r.ismonte
}

func (r *ReqParserSha2) SetOplen(l int) {
	r.digetlen = l
}
func (r *ReqParserSha2) Oplen() int {
	return r.digetlen
}


func (r *ReqParserSha2) Ingest(lines []string) (int, error) {
	for i := 0; i < len(lines)-1; i++ {
		if match, err := regexp.Match(`^#`, []byte(lines[i])); err == nil && match {
			r.respheader = append(r.respheader, lines[i])
		} else if lines[i] == "[L = 32]" {
			r.SetOplen(32)
		} else if lines[i] == "[L = 64]" {
			r.SetOplen(64)
		} else if lines[i] == "" && lines[i+1] != "[L = 32]" && lines[i+1] != "[L = 64]"{
			op := algs.Sha2{}
			op.MsgLen = strings.Split(lines[i+1], " = ")[1]
			if op.MsgLen == "0" {
				op.Msg, _ = hex.DecodeString("")
			} else {
				msg, err := hex.DecodeString(strings.TrimSuffix(strings.Split(lines[i+2], " = ")[1], "\n"))
				if err != nil {
					return len(r.operations), err
				}
				op.Msg = msg
			}
			r.operations = append(r.operations, op)
			i++
		} else if err != nil {
				return 0, err
		}
	}
	return len(r.operations), nil
}

func (r *ReqParserSha2) WriteResponse(filename string) error {
	fh, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer fh.Close()

	for _, line := range r.respheader {
		fh.Write([]byte(line + "\r\n"))
	}
	fh.Write([]byte("\n"))
	for _, op := range r.operations {
		line1 := "Len = " + op.MsgLen + "\r\n"
		line2 := "Msg = " + hex.EncodeToString(op.Msg) + "\r\n"
		line3 := "MD = " + hex.EncodeToString(op.Digest) + "\r\n"
		fh.Write([]byte(line1))
		fh.Write([]byte(line2))
		fh.Write([]byte(line3))
		fh.Write([]byte("\r\n"))
	}
	fh.Write([]byte("\r\n"))
	return nil
}
