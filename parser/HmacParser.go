package parser

import (
	"OpenCAV/algs"
	"encoding/hex"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
)

type HmacParser struct {
	filname		string
	len			int
	shaalg		string
	respheader	[]string
	operations	[]algs.Hmac
}

func NewHmacParser() *HmacParser {
	return new(HmacParser)
}

func (h *HmacParser) SetShaAlg(a string) {
	h.shaalg = a
}

func (h *HmacParser) ShaAlg() string {
	return h.shaalg
}

func (h *HmacParser) ShaLen() int {
	return h.len
}

func (h *HmacParser) SetShaLen(l int) {
	h.len = l
}

func (h *HmacParser) Filename() string {
	return h.filname
}

func (h *HmacParser) SetFilename(f string) {
	h.filname = f
}

func (h *HmacParser) Ingest(lines []string) (int, error) {
	for i := 0; i < len(lines); i++ {
		if strings.Contains(lines[i], "#") {
			h.respheader = append(h.respheader, lines[i])
		} else if strings.Contains(lines[i], "[") {
			if strings.Contains(lines[i], "L=32") {
				h.SetShaLen(32)
			}
			if strings.Contains(lines[i], "SHA_2") {
				h.SetShaAlg("SHA_2")
			}
			if strings.Contains(lines[i], "L=64") {
				h.SetShaLen(64)
			}
			if strings.Contains(lines[i], "SHA_3") {
				h.SetShaAlg("SHA_3")
			}
			h.respheader = append(h.respheader, "")
			h.respheader = append(h.respheader, lines[i])

		} else if lines[i] == "" && strings.Contains(lines[i+1], "Count")  {
			hm := algs.Hmac{}
			klen, _ := strconv.Atoi(strings.Split(lines[i+2], " = ")[1])
			hm.Klen = klen
			tlen, _ := strconv.Atoi(strings.Split(lines[i+3], " = ")[1])
			hm.Tlen = tlen
			key, _ := hex.DecodeString(strings.Split(lines[i+4], " = ")[1])
			hm.Key = key
			msg, _ := hex.DecodeString(strings.Split(lines[i+5], " = ")[1])
			hm.Msg = msg
			h.operations = append(h.operations, hm)
			i += 4
		}
	}
	return len(h.operations), nil
}

func (h *HmacParser) RunTest(doHmac algs.DoHmac) {
	for i := 0; i < len(h.operations); i++ {
		h.operations[i].Mac = doHmac(h.operations[i].Key, h.operations[i].Msg, h.ShaAlg(), h.ShaLen())
	}
}


func (h *HmacParser) WriteResponse(outfile string) {
	out, err := os.Create(outfile)
	if err != nil {
		log.Fatal(err)
	}
	defer out.Close()
	for _, i := range h.respheader {
		if _, err = out.Write([]byte(i + "\r\n")); err != nil {
			log.Fatal(err)
		}
	}
	if _,err := out.Write([]byte("\r\n")); err != nil {
		log.Fatal(err)
	}
	for i, op := range h.operations {
		count := fmt.Sprintf("Count = %d\r\n", i)
		Klen := fmt.Sprintf("Klen = %d\r\n", op.Klen)
		Tlen := fmt.Sprintf("Tlen = %d\r\n", op.Tlen)
		Key := fmt.Sprintf("Key = %s\r\n", hex.EncodeToString(op.Key))
		Msg := fmt.Sprintf("Msg = %s\r\n", hex.EncodeToString(op.Msg))
		Mac := fmt.Sprintf("Mac = %s\r\n", hex.EncodeToString(op.Mac))

		if _, err = out.Write([]byte(count)); err != nil {
			log.Fatal(err)
		}
		if _, err = out.Write([]byte(Klen)); err != nil {
			log.Fatal(err)
		}
		if _, err = out.Write([]byte(Tlen)); err != nil {
			log.Fatal(err)
		}
		if _, err = out.Write([]byte(Key)); err != nil {
			log.Fatal(err)
		}
		if _, err = out.Write([]byte(Msg)); err != nil {
			log.Fatal(err)
		}
		if _, err := out.Write([]byte(Mac)); err != nil {
			log.Fatal(err)
		}
		if _, err := out.Write([]byte("\r\n")); err != nil {
			log.Fatal(err)
		}
	}
}