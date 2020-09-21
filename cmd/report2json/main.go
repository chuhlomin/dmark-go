package main

import (
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io/ioutil"
	"log"
	"os"

	"github.com/chuhlomin/dmark-go"
	"github.com/pkg/errors"
)

func run() error {
	content, err := ioutil.ReadAll(os.Stdin)
	if err != nil {
		return errors.Wrap(err, "read stdin")
	}

	feedback := dmark.Feedback{}
	if err = xml.Unmarshal([]byte(content), &feedback); err != nil {
		return errors.Wrap(err, "xml unmarshal")
	}

	result, err := json.Marshal(feedback)
	if err != nil {
		return errors.Wrap(err, "json marshal")
	}

	fmt.Print(string(result))

	return nil
}

func main() {
	if err := run(); err != nil {
		log.Fatalf("ERROR: %v", err)
	}
}
