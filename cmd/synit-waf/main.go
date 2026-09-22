package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/caddyserver/certmagic"
	"github.com/libdns/cloudflare"
	"github.com/synit-io/synit-waf/internal/waf"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "FATAL: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	defaultConfigPath := "/etc/waf/config.yml"
	if envPath := os.Getenv("EDGE_WAF_CONFIG"); envPath != "" {
		defaultConfigPath = envPath
	}
	listenAddr := ":80"
	if envAddr := os.Getenv("EDGE_WAF_ADDR"); envAddr != "" {
		listenAddr = envAddr
	}
	configPath := flag.String("config", defaultConfigPath, "Path to configuration file")
	validateOnly := flag.Bool("validate-config", false, "Validate config and exit")
	showVersion := flag.Bool("version", false, "Show version and exit")
	flag.Parse()

	if *showVersion {
		fmt.Printf("Synit WAF %s\n", waf.Version)
		return nil
	}

	// Errors are returned, never raised with os.Exit or Fatalf, so the
	// deferred cleanup below always runs.
	cfg, err := waf.LoadConfig(*configPath)
	if err != nil {
		return fmt.Errorf("could not load configuration: %w", err)
	}
	if *validateOnly {
		fmt.Println("Configuration is valid")
		return nil
	}
	if err := waf.SetupLogging(cfg); err != nil {
		return fmt.Errorf("configure logging: %w", err)
	}
	defer func() {
		if err := waf.CloseLogging(); err != nil {
			fmt.Fprintf(os.Stderr, "close logging: %v\n", err)
		}
	}()

	if !cfg.GlobalSettings.ACME.Enabled && listenAddr == cfg.GlobalSettings.AdminAddress {
		return fmt.Errorf("public and admin listeners must use different addresses: %s", listenAddr)
	}

	registry := waf.NewWAFRegistry()
	proxyHandler := waf.NewProxyHandler(registry)
	if err := registry.Reload(*configPath, proxyHandler); err != nil {
		return fmt.Errorf("load initial configuration: %w", err)
	}
	defer func() {
		if err := proxyHandler.Close(); err != nil {
			waf.ErrorLog.Errorf("close proxy runtime: %v", err)
		}
	}()

	runCtx, cancelRun := context.WithCancel(context.Background())
	defer cancelRun()
	go waf.WatchConfig(runCtx, registry, *configPath, proxyHandler)

	readTimeout := cfg.GlobalSettings.ReadTimeout
	if readTimeout == 0 {
		readTimeout = 15 * time.Second
	}
	idleTimeout := cfg.GlobalSettings.IdleTimeout
	if idleTimeout == 0 {
		idleTimeout = 60 * time.Second
	}
	newServer := func(addr string, handler http.Handler) *http.Server {
		return &http.Server{
			Addr:              addr,
			Handler:           handler,
			ReadHeaderTimeout: 5 * time.Second,
			ReadTimeout:       readTimeout,
			WriteTimeout:      cfg.GlobalSettings.WriteTimeout,
			IdleTimeout:       idleTimeout,
			MaxHeaderBytes:    64 << 10,
			ErrorLog:          waf.NewLogrusStandardLogger(waf.ErrorLog),
		}
	}

	publicHandler := waf.NewPublicHTTPHandler(proxyHandler)
	adminServer := newServer(cfg.GlobalSettings.AdminAddress, waf.NewAdminHTTPHandler(proxyHandler))
	servers := []*http.Server{adminServer}
	serverErrors := make(chan error, 3)
	serve := func(name string, server *http.Server, listener net.Listener, tlsEnabled bool) {
		go func() {
			var err error
			if tlsEnabled {
				err = server.ServeTLS(listener, "", "")
			} else {
				err = server.Serve(listener)
			}
			if err != nil && !errors.Is(err, http.ErrServerClosed) {
				serverErrors <- fmt.Errorf("%s server: %w", name, err)
			}
		}()
	}

	if cfg.GlobalSettings.ACME.Enabled {
		configureACME(cfg)
		magic := certmagic.NewDefault()
		domains := registry.GetDomains()
		if err := magic.ManageSync(runCtx, domains); err != nil {
			return fmt.Errorf("manage TLS certificates: %w", err)
		}
		// Tenants added by a later reload get certificates in the background.
		registry.SetDomainManager(func(_ context.Context, added []string) error {
			return magic.ManageAsync(runCtx, added)
		})

		dataServer := newServer(fmt.Sprintf(":%d", certmagic.HTTPSPort), publicHandler)
		dataServer.TLSConfig = magic.TLSConfig()
		challengeServer := newServer(fmt.Sprintf(":%d", certmagic.HTTPPort), acmeHTTPHandler(magic, registry.HasTenant))
		dataListener, err := net.Listen("tcp", dataServer.Addr)
		if err != nil {
			return fmt.Errorf("bind HTTPS listener %s: %w", dataServer.Addr, err)
		}
		challengeListener, err := net.Listen("tcp", challengeServer.Addr)
		if err != nil {
			_ = dataListener.Close()
			return fmt.Errorf("bind ACME HTTP listener %s: %w", challengeServer.Addr, err)
		}
		servers = append(servers, dataServer, challengeServer)
		waf.ErrorLog.Infof("HTTPS listener on %s for domains %v", dataServer.Addr, domains)
		serve("https", dataServer, dataListener, true)
		serve("acme-http", challengeServer, challengeListener, false)
	} else {
		dataServer := newServer(listenAddr, publicHandler)
		dataListener, err := net.Listen("tcp", dataServer.Addr)
		if err != nil {
			return fmt.Errorf("bind public listener %s: %w", dataServer.Addr, err)
		}
		servers = append(servers, dataServer)
		waf.ErrorLog.Infof("Public listener on %s", dataServer.Addr)
		serve("public", dataServer, dataListener, false)
	}
	adminListener, err := net.Listen("tcp", adminServer.Addr)
	if err != nil {
		for _, server := range servers[1:] {
			_ = server.Close()
		}
		return fmt.Errorf("bind admin listener %s: %w", adminServer.Addr, err)
	}
	waf.ErrorLog.Infof("Admin listener on %s", adminServer.Addr)
	serve("admin", adminServer, adminListener, false)

	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGINT, syscall.SIGTERM)
	defer signal.Stop(signals)
	var runtimeErr error
	select {
	case sig := <-signals:
		waf.ErrorLog.Infof("Shutting down after %s", sig)
	case err := <-serverErrors:
		waf.ErrorLog.Errorf("Server failed: %v", err)
		runtimeErr = err
	}
	cancelRun()

	shutdownCtx, cancelShutdown := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancelShutdown()
	var shutdownErrors []error
	for _, server := range servers {
		if err := server.Shutdown(shutdownCtx); err != nil {
			shutdownErrors = append(shutdownErrors, fmt.Errorf("shutdown %s: %w", server.Addr, err))
		}
	}
	if err := errors.Join(shutdownErrors...); err != nil {
		waf.ErrorLog.Errorf("Graceful shutdown incomplete: %v", err)
		if runtimeErr == nil {
			runtimeErr = err
		}
	}
	return runtimeErr
}

func configureACME(cfg waf.AppConfig) {
	certmagic.DefaultACME.Email = cfg.GlobalSettings.ACME.Email
	// Config validation requires acme.agree_tos. Without Agreed, certmagic
	// asks on stdin during account registration, which fails in a container.
	certmagic.DefaultACME.Agreed = cfg.GlobalSettings.ACME.AgreeTOS
	if cfg.GlobalSettings.ACME.Staging {
		certmagic.DefaultACME.CA = certmagic.LetsEncryptStagingCA
	}
	if cfg.GlobalSettings.ACME.StoragePath != "" {
		certmagic.Default.Storage = &certmagic.FileStorage{Path: cfg.GlobalSettings.ACME.StoragePath}
	}
	if strings.EqualFold(strings.TrimSpace(cfg.GlobalSettings.ACME.DNSProvider), "cloudflare") {
		certmagic.DefaultACME.DNS01Solver = &certmagic.DNS01Solver{
			DNSProvider: &cloudflare.Provider{APIToken: cfg.GlobalSettings.ACME.DNSToken},
		}
	}
}

// acmeHTTPHandler answers ACME HTTP-01 challenges on the plain HTTP port and
// redirects everything else to HTTPS. Only configured tenant hosts are
// redirected: reflecting an arbitrary Host header would turn the listener
// into an open redirect.
func acmeHTTPHandler(magic *certmagic.Config, isTenant func(host string) bool) http.Handler {
	redirect := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host := r.Host
		if parsedHost, _, err := net.SplitHostPort(r.Host); err == nil {
			host = parsedHost
		}
		if !isTenant(host) {
			http.Error(w, "Not Found", http.StatusNotFound)
			return
		}
		http.Redirect(w, r, "https://"+host+r.URL.RequestURI(), http.StatusPermanentRedirect) // #nosec G710 -- host is a configured tenant, checked above
	})
	if len(magic.Issuers) > 0 {
		if issuer, ok := magic.Issuers[0].(*certmagic.ACMEIssuer); ok {
			return issuer.HTTPChallengeHandler(redirect)
		}
	}
	return redirect
}
