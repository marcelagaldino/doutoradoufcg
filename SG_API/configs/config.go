package configs

import (
	"github.com/spf13/viper"
)

var cfg *APIConfig

type APIConfig struct {
	Port string
	ModulePath string
}

func Load() error {
	viper.SetConfigName("config")
	viper.SetConfigType("toml")
	viper.AddConfigPath(".")

	err := viper.ReadInConfig()
	if err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			return err
		}
	}

	cfg = new(APIConfig)
	cfg.Port = viper.GetString("api.port")
	cfg.ModulePath = viper.GetString("module.path")

	return nil
}

func GetAPIPort() string {
	return cfg.Port
}

func GetModulePath() string {
	return cfg.ModulePath
}
