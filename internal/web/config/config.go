package config

import "os"

const defaultListenAddr = ":8080"

type Config struct {
	ListenAddr string
}

func Load() Config {
	listenAddr := os.Getenv("WEB_LISTEN_ADDR")
	if listenAddr == "" {
		listenAddr = defaultListenAddr
	}

	return Config{ListenAddr: listenAddr}
}
