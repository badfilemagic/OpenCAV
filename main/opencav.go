package main

import (
	"OpenCAV/TestRunners"
	"OpenCAV/shims/gocrypto"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"path/filepath"
	"strings"
)

var (
	root string
)


func main() {
	flag.StringVar(&root, "root", "", "Root directory containng the test vectors")
	flag.Parse()
	if root == "" {
		log.Fatal("Must supply a root directory")
	}
	for _, alg := range gocrypto.ImplementedAlgs {
		reqDir := filepath.Join(root, alg, "req")
		fmt.Println(reqDir)
		reqFiles, err := ioutil.ReadDir(reqDir)
		if err != nil {
			log.Fatal(err)
		}
		vectorfiles := []string{}
		for _, file := range reqFiles {
			vectorfiles = append(vectorfiles, file.Name())
		}
		if strings.Contains(alg, "SHA3"){
			TestRunners.DoSha3Testing(root, vectorfiles)
		} else if strings.Contains(alg, "SHA") {
			TestRunners.DoShaTesting(root, vectorfiles)
		}
	}
}