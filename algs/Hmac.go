package algs

type Hmac struct {
	Klen	int
	Tlen	int
	Key		[]byte
	Msg		[]byte
	Mac		[]byte
}


type DoHmac func(key, msg []byte, alg string, len int) []byte