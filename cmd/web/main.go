package main

import (
	"log"

	_ "github.com/jimmicro/version"
	"github.com/jimyag/template-repository/internal/web/api"
	"github.com/jimyag/template-repository/internal/web/config"
)

func main() {
	cfg := config.Load()
	if err := api.NewRouter().Run(cfg.ListenAddr); err != nil {
		log.Fatal(err)
	}
}
