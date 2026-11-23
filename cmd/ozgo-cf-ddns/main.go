// Command ozgo-cf-ddns keeps Cloudflare DNS records pointed at this host.
//
//	ozgo-cf-ddns              run the agent (configured through environment variables)
//	ozgo-cf-ddns healthcheck  query the local /healthz endpoint; exit 0 when healthy
//	ozgo-cf-ddns version      print the version
package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"
	_ "time/tzdata" // honour TZ in minimal images

	"github.com/notolac/ozgo-cf-ddns/internal/agent"
	"github.com/notolac/ozgo-cf-ddns/internal/config"
	"github.com/notolac/ozgo-cf-ddns/internal/web"
)

// version is set at build time with -ldflags "-X main.version=...".
var version = "dev"

func main() {
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "healthcheck":
			os.Exit(healthcheck())
		case "version", "--version", "-v":
			fmt.Println(version)
			return
		default:
			fmt.Fprintf(os.Stderr, "usage: %s [healthcheck|version]\n", os.Args[0])
			os.Exit(2)
		}
	}
	os.Exit(run())
}

func newLogger(format string, level slog.Level) *slog.Logger {
	opts := &slog.HandlerOptions{Level: level}
	if format == "json" {
		return slog.New(slog.NewJSONHandler(os.Stdout, opts))
	}
	return slog.New(slog.NewTextHandler(os.Stdout, opts))
}

func run() int {
	cfg, err := config.Load(os.Environ())
	if err != nil {
		log := newLogger("text", slog.LevelInfo)
		for _, line := range strings.Split(err.Error(), "\n") {
			log.Error("invalid configuration", "error", line)
		}
		return 1
	}
	log := newLogger(cfg.LogFormat, cfg.LogLevel)
	slog.SetDefault(log)
	for _, w := range cfg.Warnings {
		log.Warn(w)
	}
	log.Info("starting", "version", version, "records", len(cfg.Records), "schedule", cfg.Schedule.String())
	for _, r := range cfg.Records {
		log.Info("record configured", "name", r.Name, "record", r.FQDN(), "type", r.Type,
			"proxied", r.Proxied, "source", string(r.Source), "credentials", r.Credentials,
			"delete_on_stop", r.DeleteOnStop)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	a := agent.New(cfg, agent.Options{Version: version, Logger: log})

	var srv *http.Server
	if cfg.Web.Enabled {
		srv = &http.Server{
			Addr:              ":" + strconv.Itoa(cfg.Web.Port),
			Handler:           web.Handler(a.Status(), web.Options{User: cfg.Web.User, Password: cfg.Web.Password, Logger: log}),
			ReadHeaderTimeout: 5 * time.Second,
			ReadTimeout:       10 * time.Second,
			WriteTimeout:      10 * time.Second,
			IdleTimeout:       60 * time.Second,
		}
		ln, err := net.Listen("tcp", srv.Addr)
		if err != nil {
			log.Error("web interface cannot listen", "addr", srv.Addr, "error", err.Error())
			return 1
		}
		log.Info("web interface listening", "addr", srv.Addr, "basic_auth", cfg.Web.User != "")
		go func() {
			if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
				log.Error("web interface stopped", "error", err.Error())
			}
		}()
	}

	a.Run(ctx)

	if srv != nil {
		sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(sctx)
	}
	log.Info("stopped")
	return 0
}

// healthcheck is used by the Docker HEALTHCHECK. It reads only WEB_ENABLED and
// WEB_PORT, so it works without the rest of the configuration.
func healthcheck() int {
	if v := os.Getenv("WEB_ENABLED"); v != "" {
		if b, err := strconv.ParseBool(v); err == nil && !b {
			fmt.Println("web interface disabled; health check skipped")
			return 0
		}
	}
	port := 8080
	if v := os.Getenv("WEB_PORT"); v != "" {
		p, err := strconv.Atoi(v)
		if err != nil || p < 1 || p > 65535 {
			fmt.Println("invalid WEB_PORT")
			return 1
		}
		port = p
	}
	// Always loopback; only the port comes from the environment.
	u := url.URL{Scheme: "http", Host: net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), Path: "/healthz"}
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get(u.String()) // #nosec G704 -- fixed loopback host, validated port
	if err != nil {
		fmt.Println(err)
		return 1
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
	fmt.Print(string(body))
	if resp.StatusCode != http.StatusOK {
		return 1
	}
	return 0
}
