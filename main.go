package main

import (
	"flag"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"
)

func main() {
	configPath := flag.String("c", "config.yaml", "Path to configuration file")
	verbose := flag.Bool("v", false, "Enable verbose logging")
	flag.Parse()

	config, err := LoadConfig(*configPath)
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	// Set initial log behavior based on config before creating daemon
	logLevel := strings.ToLower(config.LogLevel)
	if logLevel == "" {
		logLevel = "normal"
	}
	if *verbose {
		logLevel = "verbose"
	}

	// Only log startup in non-silent mode
	if logLevel != "silent" {
		log.Printf("Starting radvan-go with log level: %s", logLevel)
	}

	daemon := NewRADaemon(config, *verbose)
	if err := daemon.Start(); err != nil {
		log.Fatalf("Failed to start daemon: %v", err)
	}

	// Wait for interrupt signal
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	<-sigChan

	if logLevel != "silent" {
		log.Println("Shutting down...")
	}
	daemon.Stop()
}
