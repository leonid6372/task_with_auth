package main

import (
	"context"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"auth/internal/config"
	mainPage "auth/internal/http-server/handlers/main_page"
	"auth/internal/lib/auth"
	"auth/internal/lib/logger/sl"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

func main() {
	cfg := config.MustLoad()

	log := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))

	ctx := context.Background()

	client, err := mongo.Connect(ctx, options.Client().ApplyURI("mongodb://"+cfg.MongodbInfo))
	if err != nil {
		log.Error("failed to connect to mongoDB", sl.Err(err))
		os.Exit(1)
	}

	defer func() {
		if err := client.Disconnect(ctx); err != nil {
			log.Info("mongoDB client closed")
		}
	}()

	storage := client.Database("auth").Collection("refresh_token")

	authorizer := auth.NewAuthorizer(
		cfg.Secret,
		cfg.TokenTTL,
	)

	router := chi.NewRouter()

	router.Use(middleware.RequestID) // Добавляет request_id в каждый запрос, для трейсинга
	router.Use(middleware.Logger)    // Логирование всех запросов
	router.Use(middleware.Recoverer) // Если где-то внутри сервера (обработчика запроса) произойдет паника, приложение не должно упасть
	router.Use(middleware.URLFormat) // Парсер URLов поступающих запросов

	//Secured API group
	router.Group(func(r chi.Router) {
		// Use Authorize middleware
		r.Use(authorizer.Authorize(ctx, log, storage))
		r.Get("/main_page", mainPage.New())
	})

	// Public API group
	router.Group(func(r chi.Router) {
		r.Post("/log_in", authorizer.LogIn(ctx, log, storage))
		r.Post("/refresh", authorizer.Refresh(ctx, log, storage))
	})

	log.Info("starting server", slog.String("address", cfg.HttpServer))

	done := make(chan os.Signal, 1)
	signal.Notify(done, os.Interrupt, syscall.SIGINT, syscall.SIGTERM)

	srv := &http.Server{
		Addr:    cfg.HttpServer,
		Handler: router,
	}

	go func() {
		if err := http.ListenAndServe(cfg.HttpServer, router); err != nil {
			log.Error("failed to start server", sl.Err(err))
		}
	}()

	log.Info("server started")

	<-done
	log.Info("stopping server")

	// Time to correct finish server's operations
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := srv.Shutdown(ctx); err != nil {
		log.Error("failed to stop server", sl.Err(err))

		return
	}

	log.Info("server stopped")
}
