package cklb

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strings"

	stigexport "github.com/Exonical/stigctl/internal/export"
	"github.com/Exonical/stigctl/internal/id"
	"github.com/Exonical/stigctl/internal/results"
)

type Exporter struct{}

func (Exporter) Export(_ context.Context, w io.Writer, req stigexport.Request) error {
	checklistID, err := id.UUIDv4()
	if err != nil {
		return err
	}
	stigUUID, err := id.UUIDv4()
	if err != nil {
		return err
	}

	resultByVuln := make(map[string]results.Result, len(req.Results))
	for _, result := range req.Results {
		resultByVuln[result.VulnID] = result
	}

	stig := STIG{
		STIGName:    req.Benchmark.Title,
		DisplayName: displayName(req.Benchmark.Title),
		STIGID:      req.Benchmark.ID,
		ReleaseInfo: req.Benchmark.ReleaseInfo,
		Version:     req.Benchmark.Version,
		UUID:        stigUUID,
		Size:        len(req.Benchmark.Rules),
		Rules:       make([]Rule, 0, len(req.Benchmark.Rules)),
	}
	if len(req.Benchmark.Rules) > 0 {
		stig.ReferenceIdentifier = req.Benchmark.Rules[0].ReferenceID
	}

	for _, source := range req.Benchmark.Rules {
		ruleUUID, err := id.UUIDv4()
		if err != nil {
			return err
		}
		result, ok := resultByVuln[source.VulnID]
		if !ok {
			result = results.Result{
				VulnID: source.VulnID,
				RuleID: source.RuleID,
				Title:  source.Title,
				Status: results.StatusManual,
			}
		}

		stig.Rules = append(stig.Rules, Rule{
			GroupIDSrc:         source.VulnID,
			GroupTree:          []GroupTree{{ID: source.VulnID, Title: source.GroupTreeTitle, Description: "<GroupDescription></GroupDescription>"}},
			GroupID:            source.VulnID,
			Severity:           normalizeSeverity(source.Severity),
			GroupTitle:         source.GroupTitle,
			RuleIDSrc:          source.RuleIDSrc,
			RuleID:             source.RuleID,
			RuleVersion:        source.RuleVersion,
			RuleTitle:          source.Title,
			FixText:            source.FixText,
			Weight:             source.Weight,
			CheckContent:       source.CheckContent,
			CheckContentRef:    CheckContentRef{Href: source.CheckRefHref, Name: source.CheckRefName},
			Classification:     "Unclassified",
			Discussion:         source.Discussion,
			FalsePositives:     source.FalsePositives,
			FalseNegatives:     source.FalseNegatives,
			Documentable:       source.Documentable,
			SecurityOverrideGuidance: source.SecurityOverrideGuidance,
			PotentialImpacts:   source.PotentialImpacts,
			ThirdPartyTools:    source.ThirdPartyTools,
			IAControls:         source.IAControls,
			Responsibility:     source.Responsibility,
			Mitigations:        source.Mitigations,
			MitigationControl:  source.MitigationControl,
			LegacyIDs:          source.LegacyIDs,
			CCIs:               source.CCIs,
			ReferenceIdentifier: source.ReferenceID,
			UUID:               ruleUUID,
			STIGUUID:           stigUUID,
			Status:             status(result.Status),
			Overrides:          map[string]any{},
			Comments:           result.Comments,
			FindingDetails:     result.FindingDetails,
			SRGID:              source.GroupTreeTitle,
		})
	}

	doc := Document{
		Title:  title(req),
		ID:     checklistID,
		STIGs:  []STIG{stig},
		Active: true,
		Mode:   2,
		HasPath: false,
		TargetData: TargetData{
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
		},
		CKLBVersion: "1.0",
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(doc); err != nil {
		return fmt.Errorf("encode CKLB: %w", err)
	}
	return nil
}

func status(s results.Status) string {
	switch s {
	case results.StatusPass:
		return "not_a_finding"
	case results.StatusFail, results.StatusException:
		return "open"
	case results.StatusNotApplicable:
		return "not_applicable"
	default:
		return "not_reviewed"
	}
}

func normalizeSeverity(s string) string {
	switch strings.ToLower(s) {
	case "high", "medium", "low":
		return strings.ToLower(s)
	default:
		return "unknown"
	}
}

func role(value string) string {
	if value == "" {
		return "None"
	}
	return value
}

func title(req stigexport.Request) string {
	if req.Target.Hostname == "" {
		return req.Baseline
	}
	return req.Target.Hostname + " - " + req.Baseline
}


func displayName(title string) string {
	const suffix = " Security Technical Implementation Guide"
	if strings.HasSuffix(title, suffix) {
		return strings.TrimSuffix(title, suffix)
	}
	return title
}
