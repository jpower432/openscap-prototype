package scan

import (
	"encoding/xml"
	"errors"
	"fmt"
	"io/fs"
	"os"

	"github.com/marcusburghardt/openscap-prototype/config"
	"github.com/marcusburghardt/openscap-prototype/oscap"
)

func isXMLFile(filePath string) (bool, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return false, fmt.Errorf("error opening file: %w", err)
	}
	defer file.Close()

	decoder := xml.NewDecoder(file)
	for {
		_, err := decoder.Token()
		if err != nil {
			if err.Error() == "EOF" {
				return true, nil
			}
			return false, fmt.Errorf("invalid XML: %w", err)
		}
	}
}

func validateDataStream(path string) (string, error) {
	datastream, err := config.ValidatePath(path, false)
	if err != nil {
		return "", err
	}

	if _, err := isXMLFile(datastream); err != nil {
		return "", err
	}
	return datastream, nil
}

func validateTailoringFile(path string) (string, error) {
	tailoringFile, err := config.ValidatePath(path, false)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return "", nil
		} else {
			return "", err
		}
	}

	if _, err := isXMLFile(tailoringFile); err != nil {
		return "", err
	}
	return tailoringFile, nil
}

func ScanSystem(cfg *config.Config) (int32, error) {
	openscapFiles, err := config.DefineFilesPaths(cfg)
	if err != nil {
		return 1, fmt.Errorf("invalid paths: %w", err)
	}

	_, err = validateDataStream(openscapFiles["datastream"])
	if err != nil {
		return 1, fmt.Errorf("invalid data stream: %w")
	}

	policy, err := validateTailoringFile(openscapFiles["policy"])
	if err != nil {
		return 1, fmt.Errorf("invalid tailoring file: %w", err)
	}
	if policy == "" {
		openscapFiles["policy"] = ""
	}

	output, err := oscap.OscapScan(openscapFiles, cfg.Files.Profile)
	if err != nil {
		return 1, fmt.Errorf("failed scan: %w", err)
	}
	// Output used during the tests. Maybe it is better to store in a file later.
	fmt.Printf("Output: \n%sņ", output)
	return 0, nil
}
