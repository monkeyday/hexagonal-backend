package main

import (
	"os"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"sc/cmd/auth/config"
	"sc/cmd/auth/dependencies"
	"sc/cmd/auth/wire"
	webHandler "sc/handler/web"

	"github.com/rs/zerolog/log"
)

func main() {
	defer func() {
		if err := recover(); err != nil {
			log.Error().
				Interface("panic error", err).
				Str("stack", string(debug.Stack())).
				Msg("Executing main failed")
			// A failed boot must report failure: exiting 0 here would make
			// orchestrators treat a crashed startup as a clean shutdown.
			os.Exit(1)
		}
	}()

	cfg := config.Load(entryPath())
	deps := dependencies.NewDeps(cfg)
	mods := buildModules(cfg, deps)

	if err := webHandler.Start(mods, webHandler.Args{
		Server:  cfg.Server,
		Cleanup: deps.Cleanup,
		Cache:   deps.Cache,
	}); err != nil {
		log.Error().Err(err).Msg("auth server stopped with error")
		os.Exit(1)
	}
}

func entryPath() string {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		log.Error().Msg("Failed to get entry path")
		panic("Failed to get root")
	}
	return filepath.Dir(file)
}

func buildModules(cfg *config.Settings, deps dependencies.Deps) []webHandler.HTTPModule {
	return []webHandler.HTTPModule{
		wire.Auth(cfg, deps),
	}
}
