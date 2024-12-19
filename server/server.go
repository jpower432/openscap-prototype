package server

import (
	"bufio"
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
	"github.com/oscal-compass/compliance-to-policy-go/v2/policy"

	"github.com/marcusburghardt/openscap-prototype/config"
	"github.com/marcusburghardt/openscap-prototype/scan"
)

var _ policy.Provider = (*PluginServer)(nil)

const ovalCheckType = "http://oval.mitre.org/XMLSchema/oval-definitions-5"

type PluginServer struct {
	Config *config.Config
}

func New(cfg *config.Config) PluginServer {
	return PluginServer{Config: cfg}
}

func (s PluginServer) Generate(policy policy.Policy) error {
	fmt.Println("Generating a tailoring file")
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

func (s PluginServer) GetResults(_ policy.Policy) (policy.PVPResult, error) {
	fmt.Println("I am being scanned by OpenSCAP")
	pvpResults := policy.PVPResult{}
	_, err := scan.ScanSystem(s.Config)
	if err != nil {
		return policy.PVPResult{}, err
	}

	openscapFiles, err := config.DefineFilesPaths(s.Config)
	if err != nil {
		return policy.PVPResult{}, err
	}
	arfFile, ok := openscapFiles["arf"]
	if !ok {
		return policy.PVPResult{}, errors.New("ARF file location not defined")
	}

	// get some results here
	file, err := os.Open(filepath.Clean(arfFile))
	if err != nil {
		return policy.PVPResult{}, err
	}
	defer file.Close()

	xmlnode, err := utils.ParseContent(bufio.NewReader(file))
	if err != nil {
		return policy.PVPResult{}, err
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
			return policy.PVPResult{}, err
		}
		observation := policy.ObservationByCheck{
			Title:     ruleIDRef,
			Methods:   []string{"AUTOMATED"},
			Collected: time.Now(),
			CheckID:   ovalCheckName,
			Subjects: []policy.Subject{
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

func mapResultStatus(result *xmlquery.Node) (policy.Result, error) {
	resultEl := result.SelectElement("result")
	if resultEl == nil {
		return policy.ResultInvalid, errors.New("result node has no 'result' attribute")
	}
	switch resultEl.InnerText() {
	case "pass", "fixed":
		return policy.ResultPass, nil
	case "fail":
		return policy.ResultFail, nil
	case "notselected", "notapplicable":
		return policy.ResultError, nil
	case "error", "unknown":
		return policy.ResultError, nil
	}

	return policy.ResultInvalid, fmt.Errorf("couldn't match %s ", resultEl.InnerText())
}

func policyToXML(tp policy.Policy, config *config.Config) (string, error) {
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

func getSelections(tp policy.Policy) []xccdf.SelectElement {
	var selections []xccdf.SelectElement
	for _, rule := range tp {
		selections = append(selections, xccdf.SelectElement{
			IDRef:    rule.Rule.ID,
			Selected: true,
		})
	}
	// Disable all else?
	return selections
}

func getValuesFromVariables(tp policy.Policy) []xccdf.SetValueElement {
	var values []xccdf.SetValueElement
	if len(tp) != 0 {
		for _, rule := range tp {
			if rule.Rule.Parameter == nil {
				continue
			}

			values = append(values, xccdf.SetValueElement{
				IDRef: rule.Rule.Parameter.ID,
				Value: rule.Rule.Parameter.Value,
			})
		}
		return values
	}

	return nil
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
