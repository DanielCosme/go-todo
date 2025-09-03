package main

import (
	"fmt"
	"log/slog"
	"net/http"
	"os"
)

func main() {
	port := 3000

	s := http.Server{
		Addr:    fmt.Sprintf(":%d", port),
		Handler: nil,
	}

	slog.Info("Starting HTTP Server", "port", port)
	if err := s.ListenAndServe(); err != nil {
		slog.Error(err.Error())
		os.Exit(1)
	}
}
