package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
)

// defaultAPIURL is used when no api_url is configured and WARDEN_API_URL is
// not set.
const defaultAPIURL = "http://localhost:8080"

// config is the on-disk CLI configuration. It is persisted as YAML in the
// user's config directory and lets the user avoid passing --api and -u on
// every invocation.
type config struct {
	APIURL      string `yaml:"api_url"`
	DefaultUser string `yaml:"default_user"`
}

// configDir returns the directory holding the CLI configuration, falling back
// to the OS user config directory if unavailable.
func configDir() (string, error) {
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", fmt.Errorf("cannot determine config directory: %w", err)
	}
	return filepath.Join(dir, "ssh-warden"), nil
}

// configPath returns the absolute path of the config file.
func configPath() (string, error) {
	dir, err := configDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "config.yaml"), nil
}

// defaultConfig returns a config populated with environment-driven defaults:
// the home API URL, and the current OS user as the default user if available.
func defaultConfig() config {
	return config{
		APIURL:      defaultAPIURL,
		DefaultUser: osUsername(),
	}
}

// osUsername returns the current OS username from $USER or $USERNAME, or an
// empty string when neither is set.
func osUsername() string {
	if u := os.Getenv("USER"); u != "" {
		return u
	}
	return os.Getenv("USERNAME")
}

// loadConfig reads the config file, returning a merged view: values from the
// file override defaults, and missing files fall back to defaults.
func loadConfig() (config, error) {
	cfg := defaultConfig()

	path, err := configPath()
	if err != nil {
		return cfg, err
	}

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return cfg, nil
		}
		return cfg, fmt.Errorf("cannot read config %s: %w", path, err)
	}

	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return cfg, fmt.Errorf("cannot parse config %s: %w", path, err)
	}
	return cfg, nil
}

// saveConfig ensures the parent directory exists (with restrictive
// permissions) and writes the config to disk as YAML.
func saveConfig(cfg config) error {
	path, err := configPath()
	if err != nil {
		return err
	}

	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("cannot create config directory %s: %w", dir, err)
	}

	data, err := yaml.Marshal(cfg)
	if err != nil {
		return fmt.Errorf("cannot serialize config: %w", err)
	}

	if err := os.WriteFile(path, data, 0o600); err != nil {
		return fmt.Errorf("cannot write config %s: %w", path, err)
	}
	return nil
}

// resolveAPIURL determines the effective API URL by priority: explicit --api
// flag, then WARDEN_API_URL, then config file, then the default.
func resolveAPIURL() (string, error) {
	if apiURL != "" {
		return apiURL, nil
	}
	if env := os.Getenv("WARDEN_API_URL"); env != "" {
		return env, nil
	}
	cfg, err := loadConfig()
	if err != nil {
		return "", err
	}
	if cfg.APIURL != "" {
		return cfg.APIURL, nil
	}
	return defaultAPIURL, nil
}

// resolveUsername determines the effective username by priority: explicit
// flag value, then config default_user, then the OS user. It returns an error
// with guidance when no source provides a value.
func resolveUsername(flagValue string) (string, error) {
	if flagValue != "" {
		return flagValue, nil
	}

	cfg, err := loadConfig()
	if err != nil {
		return "", err
	}
	if cfg.DefaultUser != "" {
		return cfg.DefaultUser, nil
	}
	if u := osUsername(); u != "" {
		return u, nil
	}

	return "", fmt.Errorf("no username provided: set it with -u/--user or run 'warden config set default_user <name>'")
}

// newConfigCmd builds the "warden config" command group with its subcommands,
// "config set" and "config show".
func newConfigCmd() *cobra.Command {
	configCmd := &cobra.Command{
		Use:   "config",
		Short: "Manage local CLI configuration",
	}

	setCmd := &cobra.Command{
		Use:   "set <key> <value>",
		Short: "Set a configuration value (api_url, default_user)",
		Args:  cobra.ExactArgs(2),
		RunE:  runConfigSet,
	}

	showCmd := &cobra.Command{
		Use:   "show",
		Short: "Show the current configuration and active config file",
		Args:  cobra.NoArgs,
		RunE:  runConfigShow,
	}

	configCmd.AddCommand(setCmd, showCmd)
	return configCmd
}

// runConfigSet updates a single configuration key and persists it.
func runConfigSet(cmd *cobra.Command, args []string) error {
	key, value := args[0], args[1]

	cfg, err := loadConfig()
	if err != nil {
		return err
	}

	switch key {
	case "api_url":
		cfg.APIURL = value
	case "default_user":
		cfg.DefaultUser = value
	default:
		return fmt.Errorf("unknown config key %q (valid: api_url, default_user)", key)
	}

	if err := saveConfig(cfg); err != nil {
		return err
	}

	fmt.Printf("Set %s = %s\n", key, value)
	return nil
}

// runConfigShow prints the effective configuration and the active file path.
func runConfigShow(cmd *cobra.Command, args []string) error {
	path, err := configPath()
	if err != nil {
		return err
	}

	cfg, err := loadConfig()
	if err != nil {
		return err
	}

	fmt.Printf("Config file    : %s\n", path)
	fmt.Printf("api_url        : %s\n", cfg.APIURL)
	fmt.Printf("default_user   : %s\n", cfg.DefaultUser)
	return nil
}
