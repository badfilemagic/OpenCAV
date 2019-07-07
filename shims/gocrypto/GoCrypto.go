package gocrypto

import (
	"OpenCAV/algs"
	"OpenCAV/parser"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"hash"
	"io/ioutil"
	"log"
	"path/filepath"
)

var ImplementedAlgs = []string {
	"SHA",
}



func TestSha2(data []byte, alg string) []byte {
	var h hash.Hash
	if (alg == "SHA256") {
		h = sha256.New()
	} else if (alg == "SH512") {
		h = sha512.New()
	}
	h.Write(data)
	return h.Sum(nil)
}


// adapted from OpenSSL's FIPS test harness implementation of SHAVS 6.3
func TestSha2Monte(seed []byte, alg string) [][]byte {
	var checkpoints [][]byte
	var Mx []byte
	MD0 := seed
	MD1 := seed
	MD2 := seed
	for i := 0; i < algs.Sha2MonteIterations; i++ {
		for j := 0; j < 1000; j++ {
			var h hash.Hash
			if (alg == "SHA256") {
				h = sha256.New()
			} else if (alg == "SHA512") {
				h = sha512.New()
			}
			h.Write(MD0)
			h.Write(MD1)
			h.Write(MD2)
			Mx = MD0
			MD0 = MD1
			MD1 = MD2
			MD2 = Mx
			MD2 = h.Sum(nil)
		}
		checkpoints = append (checkpoints, MD2)
		fmt.Println(hex.EncodeToString(MD2))
		MD0 = MD2
		MD1 = MD2
	}
	return checkpoints
}




func TestMain(root string) {

	for _, alg := range ImplementedAlgs {
		reqDir := filepath.Join(root, alg, "req")
		files, err := ioutil.ReadDir(reqDir)
		if err != nil {
			log.Fatal(err)
		}
		for _, file := range(files) {
			TestParser, err := parser.GetParser(file.Name())
			if err != nil {
				log.Fatal(err)
			}
			fmt.Println(TestParser.Alg())
		}
	}
}