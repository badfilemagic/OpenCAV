package main

import (
	"OpenCAV/shims/gocrypto"
)


const (
	Sha2MonteIterations = 100
)

/*
func Hash256(data []byte) []byte {
	h := sha256.New()
	h.Write(data)
	return h.Sum(nil)
}


func Sha2Monte(len int, seed []byte) [][]byte {
	var checkpoints [][]byte
	var Mx []byte
	MD0 := seed
	MD1 := seed
	MD2 := seed
	for i := 0; i < Sha2MonteIterations; i++ {
		for j := 0; j < 1000; j++ {
			h := sha256.New()
			h.Write(MD0)
			h.Write(MD1)
			h.Write(MD2)
			Mx = MD0
			MD0 = MD1
			MD1 = MD2
			MD2 = Mx
			//h.Write(MD2)
			MD2 = h.Sum(nil)
		}
		//fmt.Println(hex.EncodeToString(checkpoint))
		checkpoints = append (checkpoints, MD2)
		fmt.Println(hex.EncodeToString(MD2))
		MD0 = MD2
		MD1 = MD2
	}
	return checkpoints
}

*/


func main() {
	root := "C:\\Users\\Dean Freeman\\Desktop\\CAVS21.3\\Products\\MyTestIUT\\"

	gocrypto.TestMain(root)

}

