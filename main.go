package main

import (
	"fmt"
	"log"
	"os"
	"path/filepath"

	hplugin "github.com/hashicorp/go-plugin"
	"github.com/oscal-compass/compliance-to-policy-go/v2/plugin"

	"github.com/marcusburghardt/openscap-prototype/config"
	"github.com/marcusburghardt/openscap-prototype/server"
)

func parseFlags() (string, error) {
	exePath, err := os.Executable()
	if err != nil {
		return "", err
	}

	// Get the directory of the executable
	exeDir := filepath.Dir(exePath)
	configPath := filepath.Join(exeDir, "oscap-config.yml")

	// Construct the full path to the file
	configFile, err := config.SanitizeAndValidatePath(configPath, false)
	if err != nil {
		return "", err
	}

	return configFile, nil
}

func initializeConfig() (*config.Config, error) {
	configFile, err := parseFlags()
	if err != nil {
		return nil, fmt.Errorf("error parsing flags: %w", err)
	}

	config, err := config.ReadConfig(configFile)
	if err != nil {
		return nil, fmt.Errorf("error reading config from %s: %w", configFile, err)
	}

	return config, nil
}

func main() {
	cfg, err := initializeConfig()
	if err != nil {
		log.Fatalf("Failed to initialize config: %v", err)
	}

	openSCAPPlugin := server.New(cfg)
	pluginByType := map[string]hplugin.Plugin{
		plugin.PVPPluginName:        &plugin.PVPPlugin{Impl: openSCAPPlugin},
		plugin.GenerationPluginName: &plugin.GeneratorPlugin{Impl: openSCAPPlugin},
	}
	plugin.Register(pluginByType)
}
