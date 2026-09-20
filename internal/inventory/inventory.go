package inventory

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

const Version = 1

var safeName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*$`)

type Document struct {
	Version  int      `yaml:"version"`
	Defaults Defaults `yaml:"defaults"`
	Hosts    []Host   `yaml:"hosts"`
}

type Defaults struct {
	User           string `yaml:"user"`
	Port           int    `yaml:"port"`
	IdentityFile   string `yaml:"identity_file"`
	KnownHostsFile string `yaml:"known_hosts_file"`
	Sudo           bool   `yaml:"sudo"`
	Profile        string `yaml:"profile"`
	ConnectTimeout string `yaml:"connect_timeout"`
	ScanTimeout    string `yaml:"scan_timeout"`
}

type Host struct {
	Name           string `yaml:"name"`
	Address        string `yaml:"address"`
	User           string `yaml:"user"`
	Port           int    `yaml:"port"`
	IdentityFile   string `yaml:"identity_file"`
	KnownHostsFile string `yaml:"known_hosts_file"`
	Sudo           *bool  `yaml:"sudo"`
	Profile        string `yaml:"profile"`
	Hostname       string `yaml:"hostname"`
	IPAddress      string `yaml:"ip_address"`
	MACAddress     string `yaml:"mac_address"`
	FQDN           string `yaml:"fqdn"`
	Role           string `yaml:"role"`
	Comments       string `yaml:"comments"`
	ConnectTimeout string `yaml:"connect_timeout"`
	ScanTimeout    string `yaml:"scan_timeout"`
}

type Target struct {
	Name           string
	Address        string
	User           string
	Port           int
	IdentityFile   string
	KnownHostsFile string
	Sudo           bool
	Profile        string
	Hostname       string
	IPAddress      string
	MACAddress     string
	FQDN           string
	Role           string
	Comments       string
	ConnectTimeout time.Duration
	ScanTimeout    time.Duration
}

func Load(path string) ([]Target, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read inventory: %w", err)
	}
	var doc Document
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true)
	if err := decoder.Decode(&doc); err != nil {
		return nil, fmt.Errorf("parse inventory: %w", err)
	}
	if doc.Version != Version {
		return nil, fmt.Errorf("inventory version must be %d", Version)
	}
	if len(doc.Hosts) == 0 {
		return nil, fmt.Errorf("inventory contains no hosts")
	}

	seen := make(map[string]struct{}, len(doc.Hosts))
	targets := make([]Target, 0, len(doc.Hosts))
	for i, host := range doc.Hosts {
		target, err := merge(doc.Defaults, host)
		if err != nil {
			return nil, err
		}
		if err := validateTarget(target); err != nil {
			return nil, fmt.Errorf("inventory host %d: %w", i+1, err)
		}
		nameKey := strings.ToLower(target.Name)
		if _, ok := seen[nameKey]; ok {
			return nil, fmt.Errorf("inventory host %d: duplicate name %q", i+1, target.Name)
		}
		seen[nameKey] = struct{}{}
		targets = append(targets, target)
	}
	return targets, nil
}

func merge(defaults Defaults, host Host) (Target, error) {
	connectTimeout, err := parseTimeout(host.Name, "connect_timeout", first(host.ConnectTimeout, defaults.ConnectTimeout))
	if err != nil {
		return Target{}, err
	}
	scanTimeout, err := parseTimeout(host.Name, "scan_timeout", first(host.ScanTimeout, defaults.ScanTimeout))
	if err != nil {
		return Target{}, err
	}

	port := host.Port
	if port == 0 {
		port = defaults.Port
	}
	if port == 0 {
		port = 22
	}
	user := first(host.User, defaults.User)
	profile := first(host.Profile, defaults.Profile)
	role := host.Role
	if role == "" {
		role = "None"
	}
	sudo := defaults.Sudo
	if host.Sudo != nil {
		sudo = *host.Sudo
	}
	return Target{
		Name: host.Name, Address: host.Address, User: user, Port: port,
		IdentityFile:   expandHome(first(host.IdentityFile, defaults.IdentityFile)),
		KnownHostsFile: expandHome(first(host.KnownHostsFile, defaults.KnownHostsFile)),
		Sudo:           sudo, Profile: profile, Hostname: host.Hostname,
		IPAddress: host.IPAddress, MACAddress: host.MACAddress, FQDN: host.FQDN,
		Role: role, Comments: host.Comments,
		ConnectTimeout: connectTimeout, ScanTimeout: scanTimeout,
	}, nil
}

func parseTimeout(host, field, value string) (time.Duration, error) {
	if value == "" {
		return 0, nil
	}
	duration, err := time.ParseDuration(value)
	if err != nil || duration < 0 {
		return 0, fmt.Errorf("host %s: invalid %s %q", host, field, value)
	}
	return duration, nil
}

func validateTarget(target Target) error {
	if !safeName.MatchString(target.Name) {
		return fmt.Errorf("name %q must contain only letters, numbers, dot, underscore, or dash", target.Name)
	}
	if target.Address == "" || strings.HasPrefix(target.Address, "-") || strings.ContainsAny(target.Address, " \t\r\n") {
		return fmt.Errorf("invalid address %q", target.Address)
	}
	if target.User == "" || strings.HasPrefix(target.User, "-") || strings.ContainsAny(target.User, "@ \t\r\n") {
		return fmt.Errorf("invalid SSH user %q", target.User)
	}
	if target.Port < 1 || target.Port > 65535 {
		return fmt.Errorf("invalid SSH port %d", target.Port)
	}
	if target.Profile != "" && !safeName.MatchString(target.Profile) {
		return fmt.Errorf("invalid profile %q", target.Profile)
	}
	return nil
}

func first(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}

func expandHome(path string) string {
	if path == "~" || strings.HasPrefix(path, "~/") {
		if home, err := os.UserHomeDir(); err == nil {
			return filepath.Join(home, strings.TrimPrefix(path, "~/"))
		}
	}
	return path
}
