package config

import (
	"errors"
	"log/slog"
	"strings"

	"github.com/go-playground/validator/v10"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
)

type Engine string

const (
	Iptables Engine = "iptables"
	Nftables Engine = "nftables"
)

type ServerConfig struct {
	ListenPort int    `mapstructure:"port" validate:"required"`
	Host       string `mapstructure:"host" validate:"required"`
}

type Config struct {
	Web    ServerConfig `mapstructure:"web" validate:"required"`
	Log    Log          `mapstructure:"log" validate:"required"`
	Engine Engine       `mapstructure:"engine" validate:"required,oneof=iptables nftables"`
}

type LogLevel string

const (
	Debug LogLevel = "debug"
	Info  LogLevel = "info"
	Warn  LogLevel = "warn"
	Error LogLevel = "error"
)

type LogFormat string

const (
	HumanReadable LogFormat = "human-readable"
	Json          LogFormat = "json"
)

type Log struct {
	Level LogLevel `mapstructure:"level" validate:"required,oneof=debug info warn error"`
	// Format LogFormat `mapstructure:"format" validate:"required,oneof=human-readable json"`
}

func GetConfig(logger *slog.Logger) (*Config, error) {
	pflag.Int("web.port", 9234, "Port to run the application on")
	pflag.String("web.host", "localhost", "Host for the application")
	pflag.String("engine", "iptables", "Firewall engine to use (iptables, nftables)")
	pflag.String("log.level", "info", "Log level (debug, info, warn, error)")
	// pflag.String("log.format", "human-readable", "Log format (human-readable, json)")

	pflag.Parse()
	v := viper.New()

	v.SetDefault("web.port", 9234)
	v.SetDefault("web.host", "localhost")
	v.SetDefault("engine", "iptables")
	v.SetDefault("log.level", "info")
	// v.SetDefault("log.format", "human-readable")

	v.SetConfigName("config")
	v.SetConfigType("yaml")
	v.AddConfigPath(".")

	if err := v.ReadInConfig(); err != nil {
		logger.Error("Error reading config file", slog.String("error", err.Error()))
		return nil, err
	}

	v.AutomaticEnv()
	v.SetEnvPrefix("NF_EXPORTER")
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))

	v.BindPFlags(pflag.CommandLine)

	var config Config
	if err := v.Unmarshal(&config); err != nil {
		logger.Error("Unable to decode into struct", slog.String("error", err.Error()))
		return nil, err
	}

	validate := validator.New()
	var failed bool = false
	if err := validate.Struct(config); err != nil {
		if _, ok := err.(*validator.InvalidValidationError); ok {
			logger.Error("Validation error", slog.String("error", err.Error()))
			failed = true
		}

		for _, err := range err.(validator.ValidationErrors) {
			logger.Warn("Validation failed on", slog.String("field", err.Field()), slog.String("tag", err.Tag()), slog.String("error", err.Error()))
			failed = true
		}

		if failed {
			return nil, errors.New("config validation failed")
		}
	}

	return &config, nil
}
