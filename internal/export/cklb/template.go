package cklb

import (
	"encoding/json"
	"fmt"
	"io"
	"os"

	stigexport "github.com/Exonical/stigctl/internal/export"
	"github.com/Exonical/stigctl/internal/id"
	"github.com/Exonical/stigctl/internal/results"
)

func Load(r io.Reader) (Document, error) {
	var doc Document
	if err := json.NewDecoder(r).Decode(&doc); err != nil {
		return Document{}, fmt.Errorf("decode CKLB: %w", err)
	}
	if doc.CKLBVersion == "" {
		doc.CKLBVersion = "1.0"
	}
	if doc.CKLBVersion != "1.0" {
		return Document{}, fmt.Errorf("unsupported CKLB version %q", doc.CKLBVersion)
	}
	return doc, nil
}

func LoadFile(path string) (Document, error) {
	file, err := os.Open(path)
	if err != nil {
		return Document{}, fmt.Errorf("open CKLB template: %w", err)
	}
	defer file.Close()
	return Load(file)
}

func Overlay(template Document, req stigexport.Request) (Document, error) {
	checklistID, err := id.UUIDv4()
	if err != nil {
		return Document{}, err
	}

	resultByVuln := make(map[string]results.Result, len(req.Results))
	for _, result := range req.Results {
		resultByVuln[result.VulnID] = result
	}

	template.ID = checklistID
	template.Title = title(req)
	template.Active = true
	template.Mode = 2
	template.HasPath = false
	template.CKLBVersion = "1.0"
	template.TargetData = TargetData{
		TargetType:     "Computing",
		HostName:       req.Target.Hostname,
		IPAddress:      req.Target.IPAddress,
		MACAddress:     req.Target.MACAddress,
		FQDN:           req.Target.FQDN,
		Comments:       req.Target.Comments,
		Role:           role(req.Target.Role),
		IsWebDatabase:  false,
		TechnologyArea: "",
		WebDBSite:      "",
		WebDBInstance:  "",
		Classification: nil,
	}

	for stigIndex := range template.STIGs {
		for ruleIndex := range template.STIGs[stigIndex].Rules {
			rule := &template.STIGs[stigIndex].Rules[ruleIndex]
			result, ok := resultByVuln[rule.GroupID]
			if !ok {
				result, ok = resultByVuln[rule.GroupIDSrc]
			}
			if !ok {
				rule.Status = "not_reviewed"
				rule.Comments = ""
				rule.FindingDetails = ""
				continue
			}
			rule.Status = status(result.Status)
			rule.Comments = result.Comments
			rule.FindingDetails = result.FindingDetails
		}
	}

	return template, nil
}

func Write(w io.Writer, doc Document) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(doc); err != nil {
		return fmt.Errorf("encode CKLB: %w", err)
	}
	return nil
}


func SanitizeTemplate(doc Document, title string) (Document, error) {
	checklistID, err := id.UUIDv4()
	if err != nil {
		return Document{}, err
	}
	doc.ID = checklistID
	doc.Title = title
	doc.Active = true
	doc.Mode = 2
	doc.HasPath = false
	doc.CKLBVersion = "1.0"
	doc.TargetData = TargetData{
		TargetType:     "Computing",
		Role:           "None",
		TechnologyArea: "",
	}

	for stigIndex := range doc.STIGs {
		for ruleIndex := range doc.STIGs[stigIndex].Rules {
			rule := &doc.STIGs[stigIndex].Rules[ruleIndex]
			rule.Status = "not_reviewed"
			rule.Comments = ""
			rule.FindingDetails = ""
			rule.Overrides = map[string]any{}
		}
	}
	return doc, nil
}
