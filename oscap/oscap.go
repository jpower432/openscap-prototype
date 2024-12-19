package oscap

import (
	"errors"
	"fmt"
	"log"
	"os/exec"

	"github.com/marcusburghardt/openscap-prototype/config"
)

func constructScanCommand(openscapFiles map[string]string, profile string) ([]string, error) {
	profileName, err := config.SanitizeInput(profile)
	if err != nil {
		return nil, fmt.Errorf("invalid input %s: %w", profile, err)
	}

	datastream := openscapFiles["datastream"]
	tailoringFile := openscapFiles["policy"]
	resultsFile := openscapFiles["results"]
	arfFile := openscapFiles["arf"]

	cmd := []string{
		"oscap",
		"xccdf",
		"eval",
		"--profile",
		profileName,
		"--results",
		resultsFile,
		"--results-arf",
		arfFile,
	}

	if tailoringFile != "" {
		cmd = append(cmd, "--tailoring-file", tailoringFile)
	}
	cmd = append(cmd, datastream)
	return cmd, nil
}

func OscapScan(openscapFiles map[string]string, profile string) ([]byte, error) {
	command, err := constructScanCommand(openscapFiles, profile)
	if err != nil {
		return nil, fmt.Errorf("failed to construct command %s: %w", command, err)
	}

	log.Printf("Executing the command: '%v'", command)
	cmd := exec.Command(command[0], command[1:]...)

	output, err := cmd.CombinedOutput()
	var exiterr *exec.ExitError
	if err != nil {
		if !errors.As(err, &exiterr) {
			return nil, fmt.Errorf("invalid output %s for %s: %w", string(output), command, err)
		}
		if exiterr.ExitCode() == 2 {
			log.Printf("Exit Status: %d", exiterr.ExitCode())
		}
	}

	return output, nil
}
