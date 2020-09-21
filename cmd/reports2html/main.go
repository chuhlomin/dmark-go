package main

import (
	"encoding"
	"encoding/xml"
	"flag"
	"html/template"
	"io/ioutil"
	"log"
	"os"
	"strings"

	"github.com/chuhlomin/dmark-go"
	"github.com/pkg/errors"
)

func loadTemplate(templatePath string) (*template.Template, error) {
	t, err := template.New("template.html").
		Funcs(template.FuncMap{
			"string": func(val encoding.TextMarshaler) string {
				text, err := val.MarshalText()
				if err != nil {
					log.Printf("ERROR marshal text: %v", err)
					return ""
				}
				return string(text)
			},
		}).
		ParseFiles(templatePath)
	if err != nil {
		return nil, errors.Wrapf(err, "template parse %q", templatePath)
	}

	return t, nil
}

func readReports(dir string) ([]dmark.Feedback, error) {
	files, err := ioutil.ReadDir(dir)
	if err != nil {
		return nil, errors.Wrap(err, "read dir")
	}

	result := []dmark.Feedback{}

	for _, f := range files {
		if !strings.HasSuffix(f.Name(), ".xml") {
			continue
		}

		content, err := ioutil.ReadFile(f.Name())
		if err != nil {
			return result, errors.Wrapf(err, "read file %q", f.Name())
		}
		feedback := dmark.Feedback{}
		if err = xml.Unmarshal([]byte(content), &feedback); err != nil {
			return result, errors.Wrapf(err, "xml unmarshal %q", f.Name())
		}

		result = append(result, feedback)
	}

	return result, nil
}

func executeTemplate(filePath string, template *template.Template, reports []dmark.Feedback) error {
	file, err := os.Create(filePath)
	if err != nil {
		return errors.Wrapf(err, "open file %q", filePath)
	}

	if err := template.Execute(file, reports); err != nil {
		if err2 := file.Close(); err2 != nil {
			log.Printf("ERROR close file %q: %v", filePath, err)
		}
		return errors.Wrap(err, "template execute")
	}

	if err = file.Close(); err != nil {
		return errors.Wrapf(err, "close file %q", filePath)
	}

	return nil
}

func run(templatePath, reportsPath, outPath string) error {
	log.Printf("Loading template from %q...", templatePath)
	template, err := loadTemplate(templatePath)
	if err != nil {
		return errors.Wrap(err, "read reports")
	}

	log.Printf("Loading reports from %q...", reportsPath)
	reports, err := readReports(reportsPath)
	if err != nil {
		return errors.Wrap(err, "read reports")
	}

	log.Printf("Rendering template to %q...", outPath)
	if err := executeTemplate(outPath, template, reports); err != nil {
		return errors.Wrap(err, "read reports")
	}

	return nil
}

func main() {
	log.Println("Starting...")

	templatePath := flag.String("t", "./template.html", "Path to template file")
	reportsPath := flag.String("r", "./", "Path to directory with DMARK XML reports")
	outPath := flag.String("o", "./report.html", "Path to output HTML report")
	flag.Parse()

	if err := run(*templatePath, *reportsPath, *outPath); err != nil {
		log.Fatalf("ERROR %v", err)
	}
	log.Println("Stopped")
}
