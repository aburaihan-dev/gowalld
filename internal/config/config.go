// Package config loads gowalld's optional settings file. It exists so a
// devops team can set fleet-wide defaults (preferred backend, backup
// location, whether confirmation prompts are required) once instead of
// repeating flags on every invocation.
package config

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/viper"

	"github.com/aburaihan-dev/gowalld/internal/backup"
)

// Config is gowalld's settings, layered flags > env (GOWALLD_*) > --config
// path > /etc/gowalld/config.yaml (merged with ~/.config/gowalld/config.yaml
// for cosmetic overrides) > these defaults. Load only applies the
// env/file/default layers; the caller (cli package) applies flags on top for
// any value the user actually passed.
type Config struct {
	Backend         string `mapstructure:"backend"`
	DefaultZone     string `mapstructure:"default_zone"`
	BackupDir       string `mapstructure:"backup_dir"`
	OutputFormat    string `mapstructure:"output_format"`
	Confirm         bool   `mapstructure:"confirm"`
	SSHLockoutGuard bool   `mapstructure:"ssh_lockout_guard"`
}

func defaults() Config {
	return Config{
		BackupDir:       backup.DefaultDir,
		OutputFormat:    "table",
		Confirm:         true,
		SSHLockoutGuard: true,
	}
}

// Load resolves Config from (in ascending precedence) built-in defaults, the
// system config file, the user config file, and GOWALLD_* environment
// variables. If explicitPath is set (from --config), it is read instead of
// the system/user files, with no merging.
func Load(explicitPath string) (*Config, error) {
	v := viper.New()
	v.SetConfigType("yaml")

	d := defaults()
	v.SetDefault("backend", d.Backend)
	v.SetDefault("default_zone", d.DefaultZone)
	v.SetDefault("backup_dir", d.BackupDir)
	v.SetDefault("output_format", d.OutputFormat)
	v.SetDefault("confirm", d.Confirm)
	v.SetDefault("ssh_lockout_guard", d.SSHLockoutGuard)

	v.SetEnvPrefix("GOWALLD")
	v.AutomaticEnv()

	if err := readConfigFiles(v, explicitPath); err != nil {
		return nil, err
	}

	var cfg Config
	if err := v.Unmarshal(&cfg); err != nil {
		return nil, fmt.Errorf("parsing config: %w", err)
	}
	return &cfg, nil
}

func readConfigFiles(v *viper.Viper, explicitPath string) error {
	if explicitPath != "" {
		v.SetConfigFile(explicitPath)
		if err := v.ReadInConfig(); err != nil {
			return fmt.Errorf("reading config %q: %w", explicitPath, err)
		}
		return nil
	}

	v.SetConfigName("config")
	v.AddConfigPath("/etc/gowalld")
	if err := v.ReadInConfig(); err != nil {
		if !isNotFound(err) {
			return fmt.Errorf("reading /etc/gowalld/config.yaml: %w", err)
		}
	}

	home, err := os.UserHomeDir()
	if err != nil {
		return nil
	}
	userPath := filepath.Join(home, ".config", "gowalld", "config.yaml")
	if _, statErr := os.Stat(userPath); statErr != nil {
		return nil
	}
	v.SetConfigFile(userPath)
	if err := v.MergeInConfig(); err != nil {
		return fmt.Errorf("reading %q: %w", userPath, err)
	}
	return nil
}

func isNotFound(err error) bool {
	_, ok := err.(viper.ConfigFileNotFoundError)
	return ok
}
