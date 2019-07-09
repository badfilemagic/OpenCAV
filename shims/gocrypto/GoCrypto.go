package gocrypto

import (
	"OpenCAV/algs"
	"crypto/sha256"
	"crypto/sha512"
	"log"
	"errors"
)

var ImplementedAlgs = []string{
	"SHA",
}


func TestSha2(data []byte, alg string) []byte {
	var md []byte
	if alg == "SHA256" {
		h := sha256.New()
		if _, err := h.Write(data); err != nil {
			log.Fatal(err)
		}
		md = h.Sum(nil)
	} else if alg == "SHA512" {
		h := sha512.New()
		if _, err := h.Write(data); err != nil {
			log.Fatal(err)
		}
		md = h.Sum(nil)
	}
	return md
}


// adapted from OpenSSL's FIPS test harness implementation of SHAVS 6.4
func TestSha2Monte(seed []byte, alg string) [][]byte {
	var checkpoints [][]byte
	var Mx []byte
	MD0 := seed
	MD1 := seed
	MD2 := seed
	for i := 0; i < algs.Sha2MonteIterations; i++ {
		for j := 0; j < 1000; j++ {
			if alg == "SHA256" {
				h := sha256.New()
				h.Write(MD0)
				h.Write(MD1)
				h.Write(MD2)
				Mx = MD0
				MD0 = MD1
				MD1 = MD2
				MD2 = Mx
				MD2 = h.Sum(nil)
			} else if alg == "SHA512" {
				h := sha512.New()
				h.Write(MD0)
				h.Write(MD1)
				h.Write(MD2)
				Mx = MD0
				MD0 = MD1
				MD1 = MD2
				MD2 = Mx
				MD2 = h.Sum(nil)
			}else {
				log.Fatal(errors.New("Unknown algorithm " + alg))
			}
		}
		checkpoints = append (checkpoints, MD2)
		MD0 = MD2
		MD1 = MD2
	}
	return checkpoints
}
