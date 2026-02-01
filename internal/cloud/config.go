package cloud

import (
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

// Config represents cloud provider configuration
type Config struct {
	Enabled  bool              `yaml:"enabled"`
	Provider string            `yaml:"provider"` // "aws", "gcp", "azure", "none"
	Settings map[string]string `yaml:"settings"` // Provider-specific settings
}

// AWSSettings contains AWS-specific configuration
type AWSSettings struct {
	Region   string
	Profile  string
	KMSKeyID string // Optional: Custom KMS key for shared secrets
}

// GetConfig loads cloud configuration from ~/.keyopol/cloud-config.yaml
func GetConfig() (*Config, error) {
	configPath, err := getConfigPath()
	if err != nil {
		return nil, err
	}

	// If config doesn't exist, return disabled config
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		return &Config{
			Enabled:  false,
			Provider: "none",
			Settings: make(map[string]string),
		}, nil
	}

	data, err := os.ReadFile(configPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read config: %w", err)
	}

	var config Config
	if err := yaml.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("failed to parse config: %w", err)
	}

	return &config, nil
}

// SaveConfig writes cloud configuration to disk
func SaveConfig(config *Config) error {
	configPath, err := getConfigPath()
	if err != nil {
		return err
	}

	// Ensure config directory exists
	configDir := filepath.Dir(configPath)
	if err := os.MkdirAll(configDir, 0755); err != nil {
		return fmt.Errorf("failed to create config directory: %w", err)
	}

	data, err := yaml.Marshal(config)
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}

	if err := os.WriteFile(configPath, data, 0600); err != nil {
		return fmt.Errorf("failed to write config: %w", err)
	}

	return nil
}

// EnableAWS enables AWS cloud provider with given settings
func EnableAWS(region, profile, kmsKeyID string) error {
	if region == "" {
		region = "us-east-1" // Default region
	}

	config := &Config{
		Enabled:  true,
		Provider: "aws",
		Settings: map[string]string{
			"region":   region,
			"profile":  profile,
			"kmsKeyID": kmsKeyID,
		},
	}

	return SaveConfig(config)
}

// DisableCloud disables cloud sync
func DisableCloud() error {
	config := &Config{
		Enabled:  false,
		Provider: "none",
		Settings: make(map[string]string),
	}

	return SaveConfig(config)
}

// IsCloudEnabled checks if cloud sync is enabled
func IsCloudEnabled() bool {
	config, err := GetConfig()
	if err != nil {
		return false
	}
	return config.Enabled
}

// GetAWSSettings extracts AWS-specific settings from config
func GetAWSSettings(config *Config) (*AWSSettings, error) {
	if config.Provider != "aws" {
		return nil, fmt.Errorf("config is not for AWS provider")
	}

	settings := &AWSSettings{
		Region:   config.Settings["region"],
		Profile:  config.Settings["profile"],
		KMSKeyID: config.Settings["kmsKeyID"],
	}

	if settings.Region == "" {
		settings.Region = "us-east-1"
	}

	return settings, nil
}

func getConfigPath() (string, error) {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("failed to get home directory: %w", err)
	}

	return filepath.Join(homeDir, ".keyopol", "cloud-config.yaml"), nil
}
