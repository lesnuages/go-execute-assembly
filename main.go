package main

import (
	"io/ioutil"
	"log"
	"os"

	"github.com/lesnuages/go-execute-assembly/assembly"
)

func main() {
	if len(os.Args) != 4 {
		log.Fatalln("Please provide a path to a .NET assembly")
		return
	}
	assemblyPath := os.Args[1]
	hostingDLLPath := os.Args[2]
	assemblyArgs := os.Args[3]
	assemblyBytes, err := ioutil.ReadFile(assemblyPath)
	if err != nil {
		log.Fatal(err)
	}
	hostingDLL, err := ioutil.ReadFile(hostingDLLPath)
	if err != nil {
		log.Fatal(err)
	}
	err = assembly.ExecuteAssembly(hostingDLL, assemblyBytes, assemblyArgs, true)
	if err != nil {
		log.Fatal(err)
	}
}
