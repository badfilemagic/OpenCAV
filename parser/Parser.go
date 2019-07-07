package parser

type Parser interface {
	Filename() string
	SetFilename(filename string)
	Alg() string
	SetAlg(alg string)
	Ingest(lines []string) (int, error)
	WriteResponse(filename string) error
}
