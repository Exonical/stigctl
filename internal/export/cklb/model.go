package cklb

type Document struct {
	Title       string     `json:"title"`
	ID          string     `json:"id"`
	STIGs       []STIG     `json:"stigs"`
	Active      bool       `json:"active"`
	Mode        int        `json:"mode"`
	HasPath     bool       `json:"has_path"`
	TargetData  TargetData `json:"target_data"`
	CKLBVersion string     `json:"cklb_version"`
}

type TargetData struct {
	TargetType     string  `json:"target_type"`
	HostName       string  `json:"host_name"`
	IPAddress      string  `json:"ip_address"`
	MACAddress     string  `json:"mac_address"`
	FQDN           string  `json:"fqdn"`
	Comments       string  `json:"comments"`
	Role           string  `json:"role"`
	IsWebDatabase  bool    `json:"is_web_database"`
	TechnologyArea string  `json:"technology_area"`
	WebDBSite      string  `json:"web_db_site"`
	WebDBInstance  string  `json:"web_db_instance"`
	Classification *string `json:"classification"`
}

type STIG struct {
	STIGName            string `json:"stig_name"`
	DisplayName         string `json:"display_name"`
	STIGID              string `json:"stig_id"`
	ReleaseInfo         string `json:"release_info"`
	Version             string `json:"version"`
	UUID                string `json:"uuid"`
	ReferenceIdentifier string `json:"reference_identifier"`
	Size                int    `json:"size"`
	Rules               []Rule `json:"rules"`
}

type Rule struct {
	GroupIDSrc               string          `json:"group_id_src"`
	GroupTree                []GroupTree     `json:"group_tree"`
	GroupID                  string          `json:"group_id"`
	Severity                 string          `json:"severity"`
	GroupTitle               string          `json:"group_title"`
	RuleIDSrc                string          `json:"rule_id_src"`
	RuleID                   string          `json:"rule_id"`
	RuleVersion              string          `json:"rule_version"`
	RuleTitle                string          `json:"rule_title"`
	FixText                  string          `json:"fix_text"`
	Weight                   string          `json:"weight"`
	CheckContent             string          `json:"check_content"`
	CheckContentRef          CheckContentRef `json:"check_content_ref"`
	Classification           string          `json:"classification"`
	Discussion               string          `json:"discussion"`
	FalsePositives           string          `json:"false_positives"`
	FalseNegatives           string          `json:"false_negatives"`
	Documentable             string          `json:"documentable"`
	SecurityOverrideGuidance string          `json:"security_override_guidance"`
	PotentialImpacts         string          `json:"potential_impacts"`
	ThirdPartyTools          string          `json:"third_party_tools"`
	IAControls               string          `json:"ia_controls"`
	Responsibility           string          `json:"responsibility"`
	Mitigations              string          `json:"mitigations"`
	MitigationControl        string          `json:"mitigation_control"`
	LegacyIDs                []string        `json:"legacy_ids"`
	CCIs                     []string        `json:"ccis"`
	ReferenceIdentifier      string          `json:"reference_identifier"`
	UUID                     string          `json:"uuid"`
	STIGUUID                 string          `json:"stig_uuid"`
	Status                   string          `json:"status"`
	Overrides                map[string]any  `json:"overrides"`
	Comments                 string          `json:"comments"`
	FindingDetails           string          `json:"finding_details"`
}

type CheckContentRef struct {
	Href string `json:"href"`
	Name string `json:"name"`
}

type GroupTree struct {
	ID          string `json:"id"`
	Title       string `json:"title"`
	Description string `json:"description"`
}
