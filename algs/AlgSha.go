package algs

type Sha struct {
	MsgLen		string
	Msg			[]byte
	Digest		[]byte
}

type DoHash func([]byte, string) []byte

type DoHashMonte func([]byte, string) [][]byte