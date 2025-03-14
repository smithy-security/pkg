package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"strings"

	repolanguages "github.com/smithy-security/pkg/detect-repo-languages"
)

var CodeLoc, Out, Format string

func main() {
	flag.StringVar(&CodeLoc, "repoLocation", "", "where in the file system we can find the repo")
	flag.StringVar(&Out, "out", "", "where in the filesystem to write the output on top of printing it")
	flag.StringVar(&Format, "format", "text", "output format, one of 'json' for a json array or 'text' for a newline separated list of elements, useful for scripting")
	flag.Parse()
	if CodeLoc == "" {
		log.Fatal("repoLocation needs a value")
	}
	languages, err := repolanguages.Detect(CodeLoc)
	if err != nil {
		log.Fatalf("could not detect languages, err:%s", err)
	}
	var result string
	switch Format {
	case "json":
		out, err := json.Marshal(languages)
		if err != nil {
			log.Fatalf("could not print languages err:%s", err)
		}
		result = string(out)
	case "text":
		result = strings.Join(languages, "\n")
	default:
		log.Fatalf("'%s' is not a supported format", Format)
	}

	fmt.Println(result)
	if err := os.WriteFile(Out, []byte(result), 0444); err != nil {
		log.Fatalf("could not write file to location %s,err: %s", Out, err)
	}
}
