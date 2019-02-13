package main

import (
	"io/ioutil"
	"log"
	"os"

	"github.com/lesnuages/go-execute-assesmbly/assembly"
)

func main() {
	if len(os.Args) != 3 {
		log.Fatalln("Please provide a path to a .NET assembly")
		return
	}
	assemblyPath := os.Args[1]
	hostingDLLPath := os.Args[2]
	assemblyArgs := ""
	assemblyBytes, err := ioutil.ReadFile(assemblyPath)
	if err != nil {
		log.Fatal(err)
	}
	hostingDLL, err := ioutil.ReadFile(hostingDLLPath)
	if err != nil {
		log.Fatal(err)
	}
	err = assembly.ExecuteAssembly(hostingDLL, assemblyBytes, assemblyArgs)
	if err != nil {
		log.Fatal(err)
	}
}
