package host

import (
	"bufio"
	"os"
	"strings"
)

type Facts struct {
	Hostname string `json:"hostname"`
	OSID     string `json:"os_id"`
	Version  string `json:"version"`
}

func Detect() Facts {
	return detect("/etc/os-release")
}

func detect(path string) Facts {
	hostname, _ := os.Hostname()
	facts := Facts{Hostname: hostname}

	file, err := os.Open(path)
	if err != nil {
		return facts
	}
	defer func() { _ = file.Close() }()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		key, value, ok := strings.Cut(scanner.Text(), "=")
		if !ok {
			continue
		}
		value = strings.Trim(value, `"`)
		switch key {
		case "ID":
			facts.OSID = value
		case "VERSION_ID":
			facts.Version = value
		}
	}
	return facts
}
