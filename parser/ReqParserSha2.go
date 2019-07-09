package parser

import (
	"OpenCAV/algs"
	"encoding/hex"
	"os"
	"regexp"
	"strings"
)

type ReqParserSha struct {
	filename 	string
	alg 		string
	ismonte		bool
	respheader 	[]string
	digestlen 	int
	operations	[]algs.Sha2
}

func NewReqParserSha() ReqParserSha {
	return ReqParserSha{}
}

func (r *ReqParserSha) SetFilename(filename string) {
	r.filename = filename
}
func (r *ReqParserSha) Alg() string {
	return r.alg
}
func (r *ReqParserSha) SetAlg(alg string) {
	r.alg = alg
}

func (r *ReqParserSha) Filename() string {
	return r.filename
}

func (r *ReqParserSha) SetMonte(m bool) {
	r.ismonte = m
}

func (r *ReqParserSha) Monte() bool {
	return r.ismonte
}

func (r *ReqParserSha) SetOplen(l int) {
	r.digestlen = l
}
func (r *ReqParserSha) Oplen() int {
	return r.digestlen
}

func (r *ReqParserSha) Ingest(lines []string) (int, error) {
	for i := 0; i < len(lines)-1; i++ {
		if match, err := regexp.Match(`^#`, []byte(lines[i])); err == nil && match {
			r.respheader = append(r.respheader, lines[i])
		} else if lines[i] == "[L = 32]" {
			r.SetOplen(32)
		} else if lines[i] == "[L = 64]" {
			r.SetOplen(64)
		} else if lines[i] == "[L = 256]" {
			r.SetOplen(256)
		} else if lines[i] == "[L = 512]" {
			r.SetOplen(512)
		} else if lines[i] == "" && lines[i+1] != "[L = 32]" && lines[i+1] != "[L = 64]"  && lines[i+1] != "[L = 256]" && lines[i+1] != "[ L = 512]"{
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

func (r *ReqParserSha) RunTest(doHash algs.DoHash) {
	for i := 0 ; i < len(r.operations); i++ {
		r.operations[i].Digest = doHash(r.operations[i].Msg, r.Alg())
	}
}

func (r *ReqParserSha) WriteResponse(filename string) error {
	fh, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer fh.Close()

	for _, line := range r.respheader {
		_,_ = fh.Write([]byte(line + "\r\n"))
	}
	_,_ = fh.Write([]byte("\n"))
	for _, op := range r.operations {
		line1 := "Len = " + op.MsgLen + "\r\n"
		line2 := "Msg = " + hex.EncodeToString(op.Msg) + "\r\n"
		line3 := "MD = " + hex.EncodeToString(op.Digest) + "\r\n"
		_,_ = fh.Write([]byte(line1))
		_,_ = fh.Write([]byte(line2))
		_,_ = fh.Write([]byte(line3))
		_,_ = fh.Write([]byte("\r\n"))
	}
	_,_ = fh.Write([]byte("\r\n"))
	return nil
}