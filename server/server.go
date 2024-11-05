package server

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/antchfx/xmlquery"
	"github.com/oscal-compass/compliance-to-policy-go/v2/policy"
	"os"
	"path/filepath"
	"time"

	"github.com/ComplianceAsCode/compliance-operator/pkg/utils"
	"github.com/oscal-compass/compliance-to-policy-go/v2/oscal/observations"
	"github.com/oscal-compass/compliance-to-policy-go/v2/oscal/rules"

	"github.com/marcusburghardt/openscap-prototype/config"
	"github.com/marcusburghardt/openscap-prototype/scan"
)

var _ policy.Provider = &PluginServer{}

type PluginServer struct {
	Config *config.Config
}

func New(cfg *config.Config) PluginServer {
	return PluginServer{Config: cfg}
}

func (s PluginServer) GetSchema() ([]byte, error) {
	//TODO implement me
	panic("implement me")
}

func (s PluginServer) UpdateConfiguration(message json.RawMessage) error {
	//TODO implement me
	panic("implement me")
}

func (s PluginServer) Generate(policy rules.Policy) error {
	//TODO implement me
	panic("implement me")
}

func (s PluginServer) GetResults() (observations.PVPResult, error) {
	fmt.Println("I have been scanned")
	pvpResults := observations.PVPResult{
		ObservationsByCheck: make([]*observations.ObservationByCheck, 0),
	}
	_, err := scan.ScanSystem(s.Config, "cis")
	if err != nil {
		return observations.PVPResult{}, err
	}

	openscapFiles, err := config.DefineFilesPaths(s.Config)
	if err != nil {
		return observations.PVPResult{}, err
	}
	arfFile, ok := openscapFiles["arf"]
	if !ok {
		return observations.PVPResult{}, errors.New("ARF file location not defined")
	}

	// get some results here
	file, err := os.Open(filepath.Clean(arfFile))
	if err != nil {
		return observations.PVPResult{}, err
	}
	defer file.Close()

	xmlnode, err := utils.ParseContent(bufio.NewReader(file))
	if err != nil {
		return observations.PVPResult{}, err
	}
	results := xmlnode.SelectElements("//rule-result")
	for i := range results {
		result := results[i]
		ruleIDRef := result.SelectAttr("idref")

		mappedResult, err := mapResultStatus(result)
		if err != nil {
			return observations.PVPResult{}, err
		}
		observation := &observations.ObservationByCheck{
			Title:     ruleIDRef,
			Methods:   []string{"AUTOMATED"},
			Collected: time.Now(),
			CheckID:   "mycheck",
			Subjects: []*observations.Subject{
				&observations.Subject{
					Title:       "My Comp",
					Type:        "component",
					ResourceID:  ruleIDRef,
					EvaluatedOn: time.Now(),
					Result:      mappedResult,
					Reason:      "my reason",
				},
			},
		}
		pvpResults.ObservationsByCheck = append(pvpResults.ObservationsByCheck, observation)
	}

	return pvpResults, nil
}

func mapResultStatus(result *xmlquery.Node) (observations.Result, error) {
	resultEl := result.SelectElement("result")
	if resultEl == nil {
		return observations.ResultInvalid, errors.New("result node has no 'result' attribute")
	}
	switch resultEl.InnerText() {
	case "pass", "fixed":
		return observations.ResultPass, nil
	case "fail":
		return observations.ResultFail, nil
	case "notselected", "notapplicable":
		return observations.ResultError, nil
	case "error", "unknown":
		return observations.ResultError, nil
	}

	return observations.ResultInvalid, fmt.Errorf("couldn't match %s ", resultEl.InnerText())
}
