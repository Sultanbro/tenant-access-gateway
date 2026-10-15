package main

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/Sultanbro/tenant-access-gateway/internal/auth"
	"github.com/Sultanbro/tenant-access-gateway/internal/gateway"
	"github.com/Sultanbro/tenant-access-gateway/internal/policy"
	"github.com/golang-jwt/jwt/v5"
)

func readConfig(path string) (policy.Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return policy.Config{}, err
	}
	if len(data) > 1<<20 {
		return policy.Config{}, errors.New("policy exceeds 1 MiB")
	}
	c, err := policy.Decode(data)
	if err != nil {
		return c, err
	}
	for name, service := range c.Services {
		if override := os.Getenv("UPSTREAM_" + strings.ToUpper(name)); override != "" {
			service.Upstream = override
			c.Services[name] = service
		}
	}
	return c, nil
}
func run() error {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	slog.SetDefault(logger)
	configPath := os.Getenv("POLICY_FILE")
	if configPath == "" {
		configPath = "config/policy.json"
	}
	config, err := readConfig(configPath)
	if err != nil {
		return err
	}
	data, err := os.ReadFile(os.Getenv("JWT_PUBLIC_KEY_FILE"))
	if err != nil {
		return err
	}
	key, err := jwt.ParseRSAPublicKeyFromPEM(data)
	if err != nil {
		return err
	}
	var keyStrings map[string]string
	if err := json.Unmarshal([]byte(os.Getenv("UPSTREAM_KEYS_JSON")), &keyStrings); err != nil {
		return err
	}
	keys := make(map[string][]byte)
	for name, value := range keyStrings {
		keys[name] = []byte(value)
	}
	g, err := gateway.New(config, auth.Verifier{PublicKey: key, Issuer: os.Getenv("JWT_ISSUER"), Audience: os.Getenv("JWT_AUDIENCE")}, keys, logger)
	if err != nil {
		return err
	}
	defer g.Close()
	if len(os.Args) > 1 && os.Args[1] == "check" {
		return json.NewEncoder(os.Stdout).Encode(map[string]string{"policy": config.Version, "status": "valid"})
	}
	address := os.Getenv("LISTEN_ADDR")
	if address == "" {
		address = "127.0.0.1:8085"
	}
	server := &http.Server{Addr: address, Handler: g, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 10 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 16 << 10}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, os.Interrupt)
	defer stop()
	reload := make(chan os.Signal, 1)
	signal.Notify(reload, syscall.SIGHUP)
	defer signal.Stop(reload)
	result := make(chan error, 1)
	go func() { logger.Info("listening", "address", address); result <- server.ListenAndServe() }()
	for {
		select {
		case <-reload:
			config, err := readConfig(configPath)
			if err == nil {
				err = g.Reload(config)
			}
			if err != nil {
				logger.Error("policy reload rejected; previous policy remains active", "error", err)
			} else {
				logger.Info("policy reloaded", "version", config.Version)
			}
		case err := <-result:
			if errors.Is(err, http.ErrServerClosed) {
				return nil
			}
			return err
		case <-ctx.Done():
			deadline, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			return server.Shutdown(deadline)
		}
	}
}
func main() {
	if err := run(); err != nil {
		slog.Error("gateway stopped", "error", err)
		os.Exit(1)
	}
}
