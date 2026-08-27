package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	_ "net/http/pprof"

	"github.com/dmachard/go-dnscollector/v2/pkg/config"
	"github.com/dmachard/go-dnscollector/v2/pkg/pipeline"
	"github.com/dmachard/go-dnscollector/v2/telemetry"
	"github.com/dmachard/go-dnscollector/v2/workers"
	"github.com/dmachard/go-logger"
	"github.com/natefinch/lumberjack"
	"github.com/prometheus/common/version"
)

func showVersion() {
	fmt.Println(version.Version)
}

func printUsage() {
	fmt.Printf("Usage of %s:\n", os.Args[0])
	fmt.Println("  -config string")
	fmt.Println("        path to config file (default \"./config.yml\")")
	fmt.Println("  -version")
	fmt.Println("        Show version")
	fmt.Println("  -test-config")
	fmt.Println("        Test config file")
}

func InitLogger(logger *logger.Logger, cfg *config.Config) {
	// redirect app logs to file ?
	if len(cfg.Global.Trace.Filename) > 0 {
		logger.SetOutput(&lumberjack.Logger{
			Filename:   cfg.Global.Trace.Filename,
			MaxSize:    cfg.Global.Trace.MaxSize,
			MaxBackups: cfg.Global.Trace.MaxBackups,
		})
	}

	// enable the verbose mode ?
	logger.SetVerbose(cfg.Global.Trace.Verbose)
}

func createPIDFile(pidFilePath string) (string, error) {
	if _, err := os.Stat(pidFilePath); err == nil {
		pidBytes, err := os.ReadFile(pidFilePath)
		if err != nil {
			return "", fmt.Errorf("failed to read PID file: %w", err)
		}

		pid, err := strconv.Atoi(string(pidBytes))
		if err != nil {
			return "", fmt.Errorf("invalid PID in PID file: %w", err)
		}

		if process, err := os.FindProcess(pid); err == nil {
			if err := process.Signal(syscall.Signal(0)); err == nil {
				return "", fmt.Errorf("process with PID %d is already running", pid)
			}
		}
	}

	pid := os.Getpid()
	pidStr := strconv.Itoa(pid)
	err := os.WriteFile(pidFilePath, []byte(pidStr), 0644)
	if err != nil {
		return "", fmt.Errorf("failed to write PID file: %w", err)
	}
	return pidStr, nil
}

func removePIDFile(cfg *config.Config) {
	if cfg.Global.PidFile != "" {
		os.Remove(cfg.Global.PidFile)
	}
}

func main() {
	args := os.Args[1:] // Ignore the first argument (the program name)

	verFlag := false
	configPath := "./config.yml"
	testFlag := false

	// Server for pprof
	// go func() {
	// 	fmt.Println(http.ListenAndServe("localhost:9999", nil))
	// }()

	// no more use embedded golang flags...
	// external lib like tcpassembly can set some unneeded flags too...
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "-version", "-v":
			verFlag = true
		case "-config", "-c":
			if i+1 < len(args) {
				configPath = args[i+1]
				i++ // Skip the next argument
			} else {
				fmt.Println("Missing argument for -config")
				os.Exit(1)
			}
		case "-help", "-h":
			printUsage()
			os.Exit(0)
		case "-test-config":
			testFlag = true
		default:
			if strings.HasPrefix(args[i], "-") {
				printUsage()
				os.Exit(1)
			}
		}
	}

	if verFlag {
		showVersion()
		os.Exit(0)
	}

	done := make(chan bool)

	// create logger
	logger := logger.New(true)

	// load config
	cfg, err := config.LoadConfig(configPath)
	if err != nil {
		fmt.Printf("main - config error: %v\n", err)
		os.Exit(1)
	}

	// If PID file is specified in the config, create it
	if cfg.Global.PidFile != "" {
		pid, err := createPIDFile(cfg.Global.PidFile)
		if err != nil {
			fmt.Printf("main - PID file error: %v\n", err)
			os.Exit(1)
		}
		logger.Info("main - write pid=%s to file=%s", pid, cfg.Global.PidFile)
	}

	// init logger
	InitLogger(logger, cfg)
	logger.Info("main - version=%s revision=%s", version.Version, version.Revision)

	// // telemetry
	if cfg.Global.Telemetry.Enabled {
		if cfg.Global.Telemetry.SockPath != "" {
			logger.Info("main - telemetry enabled on unix socket: %s", cfg.Global.Telemetry.SockPath)
		} else {
			logger.Info("main - telemetry enabled on local address: %s", cfg.Global.Telemetry.WebListen)
		}
	}
	promServer, metrics, errTelemetry := telemetry.InitTelemetryServer(cfg, logger)

	// init active collectors and loggers
	mapLoggers := make(map[string]workers.Worker)
	mapCollectors := make(map[string]workers.Worker)

	// or pipeline ?
	if pipeline.IsPipelinesEnabled(cfg) {
		logger.Info("main - running in pipeline mode")
		err := pipeline.InitPipelines(mapLoggers, mapCollectors, cfg, logger, metrics)
		if err != nil {
			logger.Error("main - %s", err.Error())
			removePIDFile(cfg)
			os.Exit(1)
		}
	}

	// Handle Ctrl-C with SIG TERM and SIGHUP
	sigTerm := make(chan os.Signal, 1)
	sigHUP := make(chan os.Signal, 1)

	signal.Notify(sigTerm, os.Interrupt, syscall.SIGTERM)
	signal.Notify(sigHUP, syscall.SIGHUP)

	go func() {
		for {
			select {
			case err := <-errTelemetry:
				logger.Error("main - unable to start telemetry: %v", err)
				removePIDFile(cfg)
				os.Exit(1)

			case <-sigHUP:
				logger.Warning("main - SIGHUP received")

				// read config
				err := config.ReloadConfig(configPath, cfg)
				if err != nil {
					logger.Error("main - reload config error:  %v", err)
					removePIDFile(cfg)
					os.Exit(1)
				}

				// reload
				InitLogger(logger, cfg)
				if pipeline.IsPipelinesEnabled(cfg) {
					pipeline.ReloadPipelines(mapLoggers, mapCollectors, cfg, logger)
				}

			case <-sigTerm:
				logger.Warning("main - exiting...")

				// Create a timeout-bounded context for graceful shutdown (10s)
				shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)

				// Gracefully stop all pipeline workers (collectors first, then loggers)
				pipeline.StopPipelines(shutdownCtx, mapCollectors, mapLoggers, logger)

				// gracefully shutdown the HTTP server
				if cfg.Global.Telemetry.Enabled {
					logger.Info("main - telemetry is stopping")
					metrics.Stop()

					if err := promServer.Shutdown(shutdownCtx); err != nil {
						logger.Error("main - telemetry error shutting down http server - %s", err.Error())
					}

					logger.Info("main - telemetry stopped")
				}

				shutdownCancel()

				// unblock main function
				done <- true

			}
		}
	}()

	if testFlag {
		// We've parsed the config and are ready to start, so the config is good enough
		logger.Info("main - config OK!")
		removePIDFile(cfg)
		os.Exit(0)
	}

	// run all workers in background
	for _, l := range mapLoggers {
		go l.StartCollect()
	}
	for _, c := range mapCollectors {
		go c.StartCollect()
	}

	// block main
	<-done

	removePIDFile(cfg)
	logger.Info("main - stopped")
}
