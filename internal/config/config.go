package config

import (
	"log"
	"os"
	"time"

	"github.com/ilyakaznacheev/cleanenv"
)

type Config struct {
	MongodbInfo string `yaml:"mongodb_info" env-default:"127.0.0.1:27017"`
	HttpServer  string `yaml:"http_server" env-default:"127.0.0.1:8080"`
	AuthInfo    `yaml:"auth_info"`
}

type AuthInfo struct {
	SecretPath string `yaml:"secret_path" env-required:"true"`
	Secret     []byte
	TokenTTL   time.Duration `yaml:"token_ttl" env-default:"5m"`
}

func MustLoad() *Config {
	configPath := "C:/Users/Leonid/Desktop/auth/config/config.yaml"

	// check if file exists
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		log.Fatalf("config file does not exist: %s", configPath)
	}

	var cfg Config

	if err := cleanenv.ReadConfig(configPath, &cfg); err != nil {
		log.Fatalf("cannot read config: %s", err)
	}

	// check if oauth secret file exists
	if _, err := os.Stat(cfg.AuthInfo.SecretPath); os.IsNotExist(err) {
		log.Fatalf("oauth secret file does not exist: %s", cfg.AuthInfo.SecretPath)
	}

	secret, err := os.ReadFile(cfg.AuthInfo.SecretPath)
	if err != nil {
		log.Fatalf("failed to read secret key: %s", err)
	}

	cfg.Secret = secret

	return &cfg
}
