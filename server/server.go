package server

import (
	"bufio"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/ComplianceAsCode/compliance-operator/pkg/utils"
	"github.com/ComplianceAsCode/compliance-operator/pkg/xccdf"
	"github.com/antchfx/xmlquery"
	"github.com/oscal-compass/compliance-to-policy-go/v2/providers"

	"github.com/marcusburghardt/openscap-prototype/config"
	"github.com/marcusburghardt/openscap-prototype/scan"
)

var _ providers.PolicyProvider = (*PluginServer)(nil)
var _ providers.GenerationProvider = (*PluginServer)(nil)

const ovalCheckType = "http://oval.mitre.org/XMLSchema/oval-definitions-5"

type PluginServer struct {
	Config *config.Config
}

func New(cfg *config.Config) PluginServer {
	return PluginServer{Config: cfg}
}

func (s PluginServer) GetSchema() ([]byte, error) {
	fmt.Println("Get schema")
	return nil, nil
}

func (s PluginServer) UpdateConfiguration(message json.RawMessage) error {
	fmt.Println("Updating configuration")
	return nil
}

func (s PluginServer) Generate(policy providers.Policy) error {
	tailoringXML, err := policyToXML(policy, s.Config)
	if err != nil {
		return err
	}

	openscapFiles, err := config.DefineFilesPaths(s.Config)
	if err != nil {
		return err
	}
	policyPath := openscapFiles["policy"]
	dst, err := os.Create(policyPath)
	if err != nil {
		return err
	}
	defer dst.Close()
	if _, err := dst.WriteString(tailoringXML); err != nil {
		return err
	}
	return nil
}

func (s PluginServer) GetResults() (providers.PVPResult, error) {
	fmt.Println("I have been scanned")
	pvpResults := providers.PVPResult{
		ObservationsByCheck: make([]providers.ObservationByCheck, 0),
	}
	_, err := scan.ScanSystem(s.Config, "cis")
	if err != nil {
		return providers.PVPResult{}, err
	}

	openscapFiles, err := config.DefineFilesPaths(s.Config)
	if err != nil {
		return providers.PVPResult{}, err
	}
	arfFile, ok := openscapFiles["arf"]
	if !ok {
		return providers.PVPResult{}, errors.New("ARF file location not defined")
	}

	// get some results here
	file, err := os.Open(filepath.Clean(arfFile))
	if err != nil {
		return providers.PVPResult{}, err
	}
	defer file.Close()

	xmlnode, err := utils.ParseContent(bufio.NewReader(file))
	if err != nil {
		return providers.PVPResult{}, err
	}

	ruleTable := newRuleHashTable(xmlnode)
	results := xmlnode.SelectElements("//rule-result")
	for i := range results {
		result := results[i]
		ruleIDRef := result.SelectAttr("idref")

		rule, ok := ruleTable[ruleIDRef]
		if !ok {
			continue
		}

		var ovalRefEl *xmlquery.Node
		for _, check := range rule.SelectElements("//xccdf-1.2:check") {
			if check.SelectAttr("system") == ovalCheckType {
				ovalRefEl = check.SelectElement("xccdf-1.2:check-content-ref")
				break
			}
		}
		if ovalRefEl == nil {
			continue
		}
		ovalCheckName := strings.TrimSpace(ovalRefEl.SelectAttr("name"))

		mappedResult, err := mapResultStatus(result)
		if err != nil {
			return providers.PVPResult{}, err
		}
		observation := providers.ObservationByCheck{
			Title:     ruleIDRef,
			Methods:   []string{"AUTOMATED"},
			Collected: time.Now(),
			CheckID:   ovalCheckName,
			Subjects: []providers.Subject{
				{
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

func mapResultStatus(result *xmlquery.Node) (providers.Result, error) {
	resultEl := result.SelectElement("result")
	if resultEl == nil {
		return providers.ResultInvalid, errors.New("result node has no 'result' attribute")
	}
	switch resultEl.InnerText() {
	case "pass", "fixed":
		return providers.ResultPass, nil
	case "fail":
		return providers.ResultFail, nil
	case "notselected", "notapplicable":
		return providers.ResultError, nil
	case "error", "unknown":
		return providers.ResultError, nil
	}

	return providers.ResultInvalid, fmt.Errorf("couldn't match %s ", resultEl.InnerText())
}

func policyToXML(tp providers.Policy, config *config.Config) (string, error) {
	tailoring := xccdf.TailoringElement{
		XMLNamespaceURI: xccdf.XCCDFURI,
		ID:              getTailoringID(),
		Version: xccdf.VersionElement{
			Time:  time.Now().Format(time.RFC3339),
			Value: "1",
		},
		Benchmark: xccdf.BenchmarkElement{
			Href: config.Files.Datastream,
		},
		Profile: xccdf.ProfileElement{
			ID: GetXCCDFProfileID(),
			Title: &xccdf.TitleOrDescriptionElement{
				Value: "example",
			},
			Selections: getSelections(tp),
			Values:     getValuesFromVariables(tp),
		},
	}

	output, err := xml.MarshalIndent(tailoring, "", "  ")
	if err != nil {
		return "", err
	}
	return xccdf.XMLHeader + "\n" + string(output), nil
}

func getSelections(tp providers.Policy) []xccdf.SelectElement {
	selections := []xccdf.SelectElement{}
	for _, rule := range tp.RuleSets {
		selections = append(selections, xccdf.SelectElement{
			IDRef:    rule.Rule.ID,
			Selected: true,
		})
	}
	// Disable all else?
	return selections
}

func getValuesFromVariables(tp providers.Policy) []xccdf.SetValueElement {
	values := []xccdf.SetValueElement{}
	for _, parameter := range tp.Parameters {
		values = append(values, xccdf.SetValueElement{
			IDRef: parameter.ID,
			Value: parameter.Value,
		})
	}

	return values
}

// GetXCCDFProfileID gets a profile xccdf ID from the TailoredProfile object
func GetXCCDFProfileID() string {
	return fmt.Sprintf("xccdf_%s_profile_%s", xccdf.XCCDFNamespace, "my-tailoring-profile")
}

func getTailoringID() string {
	return fmt.Sprintf("xccdf_%s_tailoring_%s", xccdf.XCCDFNamespace, "my-tailoring-profile")
}

// Getting rule information
// Copied from https://github.com/ComplianceAsCode/compliance-operator/blob/fed54b4b761374578016d79d97bcb7636bf9d920/pkg/utils/parse_arf_result.go#L170

func newRuleHashTable(dsDom *xmlquery.Node) NodeByIdHashTable {
	return newHashTableFromRootAndQuery(dsDom, "//ds:component/xccdf-1.2:Benchmark", "//xccdf-1.2:Rule")
}

func newHashTableFromRootAndQuery(dsDom *xmlquery.Node, root, query string) NodeByIdHashTable {
	benchmarkDom := dsDom.SelectElement(root)
	rules := benchmarkDom.SelectElements(query)
	return newByIdHashTable(rules)
}

type NodeByIdHashTable map[string]*xmlquery.Node
type nodeByIdHashVariablesTable map[string][]string

func newByIdHashTable(nodes []*xmlquery.Node) NodeByIdHashTable {
	table := make(NodeByIdHashTable)
	for i := range nodes {
		ruleDefinition := nodes[i]
		ruleId := ruleDefinition.SelectAttr("id")

		table[ruleId] = ruleDefinition
	}

	return table
}
