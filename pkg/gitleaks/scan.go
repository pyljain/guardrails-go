package gitleaks

import (
	"fmt"
	"strings"

	"github.com/spf13/viper"
	"github.com/zricethezav/gitleaks/v8/config"
	"github.com/zricethezav/gitleaks/v8/detect"
)

func loadDefaultConfig() (*config.Config, error) {
	v := viper.New()
	v.SetConfigType("toml")
	err := v.ReadConfig(strings.NewReader(config.DefaultConfig))
	if err != nil {
		return nil, err
	}

	var vc config.ViperConfig
	if err := v.Unmarshal(&vc); err != nil {
		return nil, err
	}

	cfg, err := vc.Translate()
	if err != nil {
		return nil, err
	}

	return &cfg, nil
}

func Scan(content string) error {
	cfg, err := loadDefaultConfig()
	if err != nil {
		return err
	}

	detector := detect.NewDetector(*cfg)
	leaks := detector.DetectString(content)

	if len(leaks) == 0 {
		return nil
	}

	var leakDetails = ""

	for _, leak := range leaks {
		leakDetails += fmt.Sprintf("Description: %s, Leak: %s\n", leak.Description, leak.Secret)
	}

	return fmt.Errorf(leakDetails)
}
