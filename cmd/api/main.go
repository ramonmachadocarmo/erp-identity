package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"erp/pkg/config"
	"erp/pkg/httpserver"
	"erp/pkg/postgres"
	"erp/pkg/redisx"
	httpadapter "erp/services/identity-service/internal/adapters/http"
	pgadapter "erp/services/identity-service/internal/adapters/postgres"
	redisadapter "erp/services/identity-service/internal/adapters/redis"
	"erp/services/identity-service/internal/application"
	"erp/services/identity-service/migrations"
)

func main() {
	cfg := config.Load()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	pool, err := postgres.Connect(ctx, cfg.Postgres.DSN())
	if err != nil {
		log.Fatal(err)
	}
	defer pool.Close()
	if err := postgres.Migrate(ctx, pool, migrations.FS, "."); err != nil {
		log.Fatal(err)
	}

	rdb := redisx.Connect(cfg.Redis.Addr(), cfg.Redis.Password)
	defer rdb.Close()

	roleRepo := pgadapter.NewRoleRepo(pool)
	roles := application.NewRoleService(roleRepo)
	auth := application.NewAuthService(
		pgadapter.NewUserRepo(pool), roles, pgadapter.NewSessionRepo(pool),
		redisadapter.NewSessionStore(rdb), cfg.JWTSecret, cfg.JWTIssuer, lifetimesFromEnv(),
	)
	if err := auth.SeedAdmin(ctx, cfg.MasterAdminPassword); err != nil {
		log.Fatal(err)
	}

	engine := httpserver.New(cfg.ServiceName)
	httpadapter.New(auth, roles).RegisterRoutes(engine, httpserver.JWT(cfg.JWTSecret, cfg.JWTIssuer))

	srv := &http.Server{Addr: ":" + cfg.HTTPPort, Handler: engine}
	go func() {
		log.Printf("%s listening on %s", cfg.ServiceName, srv.Addr)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatal(err)
		}
	}()
	<-ctx.Done()
	shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = srv.Shutdown(shutdown)
}

// lifetimesFromEnv reads the token clocks: ACCESS_TOKEN_TTL (default 5m), REFRESH_TOKEN_TTL
// (default 8h, renewed on every refresh) and SESSION_MAX_TTL (default 12h, hard cap from login).
func lifetimesFromEnv() application.Lifetimes {
	return application.Lifetimes{
		Access:     durationEnv("ACCESS_TOKEN_TTL", 5*time.Minute),
		Refresh:    durationEnv("REFRESH_TOKEN_TTL", 8*time.Hour),
		SessionMax: durationEnv("SESSION_MAX_TTL", 12*time.Hour),
	}
}

func durationEnv(key string, def time.Duration) time.Duration {
	if v := os.Getenv(key); v != "" {
		if d, err := time.ParseDuration(v); err == nil && d > 0 {
			return d
		}
		log.Printf("invalid %s=%q, using %s", key, v, def)
	}
	return def
}
