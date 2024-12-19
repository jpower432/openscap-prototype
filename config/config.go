package config

import (
	"errors"
	"fmt"
	"io/fs"
	"log"
	"os"
	"path/filepath"
	"regexp"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Server struct {
		Socket string `yaml:"socket"`
	} `yaml:"server"`
	Files struct {
		Datastream string `yaml:"datastream"`
		Workspace  string `yaml:"workspace"`
		PluginDir  string `yaml:"plugindir"`
		Policy     string `yaml:"policy"`
		Profile    string `yaml:"profile"`
		Results    string `yaml:"results"`
		ARF        string `yaml:"arf"`
	} `yaml:"files"`
}

func SanitizeInput(input string) (string, error) {
	safePattern := regexp.MustCompile(`^[a-zA-Z0-9-_.]+$`)
	if !safePattern.MatchString(input) {
		return "", fmt.Errorf("input contains unexpected characters: %s", input)
	}
	return input, nil
}

func SanitizePath(path string) string {
	return filepath.Clean(path)
}

func ReadConfig(configFile string) (*Config, error) {
	config := &Config{}

	file, err := os.Open(configFile)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	d := yaml.NewDecoder(file)
	if err := d.Decode(&config); err != nil {
		return nil, err
	}

	// String fields to sanitize
	paths := []*string{
		&config.Files.PluginDir,
		&config.Files.Policy,
		&config.Files.Results,
		&config.Files.ARF,
	}

	for _, path := range paths {
		sanitized, err := SanitizeInput(*path)
		if err != nil {
			return nil, err
		}
		*path = sanitized
	}

	return config, nil
}

func ValidatePath(path string, shouldBeDir bool) (string, error) {
	stat, err := os.Stat(path)
	if err != nil {
		return "", err
	}

	if shouldBeDir && !stat.IsDir() {
		return "", fmt.Errorf("expected a directory, but found a file at path: %s", path)
	}
	if !shouldBeDir && stat.IsDir() {
		return "", fmt.Errorf("expected a file, but found a directory at path: %s", path)
	}

	return path, nil
}

func SanitizeAndValidatePath(path string, shouldBeDir bool) (string, error) {
	cleanPath := SanitizePath(path)
	validPath, err := ValidatePath(cleanPath, shouldBeDir)
	if err != nil {
		return "", err
	}
	return validPath, nil
}

func EnsureDirectory(path string) error {
	_, err := os.Stat(path)
	if errors.Is(err, fs.ErrNotExist) {
		err := os.MkdirAll(path, 0750)
		if err != nil {
			return fmt.Errorf("failed to create directory: %w", err)
		}
		log.Printf("Directory created: %s\n", path)
	} else if err != nil {
		return fmt.Errorf("error checking directory: %w", err)
	}

	return nil
}

func EnsureWorkspace(cfg *Config) (map[string]string, error) {
	workspace, err := SanitizeAndValidatePath(cfg.Files.Workspace, true)
	if err != nil {
		return nil, err
	}

	directories := map[string]string{
		"workspace":  workspace,
		"pluginDir":  SanitizePath(workspace + "/" + cfg.Files.PluginDir),
		"policyDir":  SanitizePath(workspace + "/" + cfg.Files.PluginDir + "/policy"),
		"resultsDir": SanitizePath(workspace + "/" + cfg.Files.PluginDir + "/results"),
	}

	for key, dir := range directories {
		if err := EnsureDirectory(dir); err != nil {
			return nil, fmt.Errorf("failed to ensure directory %s (%s): %w", dir, key, err)
		}
	}

	return directories, nil
}

func DefineFilesPaths(cfg *Config) (map[string]string, error) {
	directories, err := EnsureWorkspace(cfg)
	if err != nil {
		return nil, err
	}

	files := map[string]string{
		"datastream": SanitizePath(cfg.Files.Datastream),
		"policy":     SanitizePath(directories["policyDir"] + "/" + cfg.Files.Policy),
		"results":    SanitizePath(directories["resultsDir"] + "/" + cfg.Files.Results),
		"arf":        SanitizePath(directories["resultsDir"] + "/" + cfg.Files.ARF),
	}

	return files, nil
}
