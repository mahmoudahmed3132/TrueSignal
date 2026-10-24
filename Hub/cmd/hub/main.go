package main

import (
	"context"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/truesignal/hub/internal/api"
	"github.com/truesignal/hub/internal/catalog"
	"github.com/truesignal/hub/internal/models"
	"github.com/truesignal/hub/internal/services/auth"
	composesvc "github.com/truesignal/hub/internal/services/compose"
	"github.com/truesignal/hub/internal/services/config"
	"github.com/truesignal/hub/internal/services/event"
	"github.com/truesignal/hub/internal/services/honeytoken"
	"github.com/truesignal/hub/internal/services/node"
	"github.com/truesignal/hub/internal/services/notify"
	"github.com/truesignal/hub/internal/services/sensor"
	"github.com/truesignal/hub/internal/services/siem"
	"github.com/truesignal/hub/internal/services/statemonitor"
	"github.com/truesignal/hub/internal/services/updater"
	"github.com/truesignal/hub/internal/services/websocket"
	"github.com/truesignal/hub/internal/store"
)

const HubAPIVersion = 1

// loadConfigSafe is a helper to fetch DB configs without panicking on empty/missing rows
// auditLogger writes administrative actions to the Hub log and forwards them
// to the SIEM.
type auditLogger struct{ siem *siem.Service }

func (a auditLogger) Audit(action, path string, status int, actorIP string) {
	log.Printf("[AUDIT] %s status=%d ip=%s", action, status, actorIP)
	a.siem.QueueAudit(siem.AuditRecord{Time: time.Now().UTC(), Action: action, Path: path, Status: status, ActorIP: actorIP})
}

func loadConfigSafe(s *store.SQLiteStore, key string, fallback string) string {
	val, err := s.GetConfigValue(key)
	if err != nil || val == "" {
		return fallback
	}
	return val
}

func main() {
	log.Printf("Starting TrueSignal Hub v%s initialization...\n", models.HubVersion)

	cfg := config.Load()

	dbStore, err := store.NewStore(cfg.DBPath)
	if err != nil {
		log.Fatalf("[FATAL] Failed to initialize database: %v", err)
	}
	defer dbStore.DB.Close()

	// 1. Establish Root Context for all background workers
	rootCtx, rootCancel := context.WithCancel(context.Background())
	defer rootCancel()

	wsService := websocket.NewService()
	authService := auth.NewService(dbStore, cfg.DashboardPassword, auth.SessionPolicy{TTL: cfg.SessionTTL, Idle: cfg.SessionIdle})

	catalogService := catalog.NewService(dbStore, wsService)

	nodeSvc := node.NewService(dbStore, wsService, catalogService, authService)
	siemService := siem.NewService(nodeSvc, siem.Options{PEN: cfg.SyslogPEN, CAFile: cfg.SIEMCAFile})
	notifyService := notify.NewService(nodeSvc)
	eventSvc := event.NewService(dbStore, wsService, siemService, notifyService)
	honeytokenSvc := honeytoken.NewService(dbStore)
	eventSvc.SetHoneytokenMatcher(honeytokenSvc)
	sensorSvc := sensor.NewService(dbStore, wsService, eventSvc)
	configService := config.NewService(dbStore, authService, siemService, notifyService, cfg.DashboardPassword, cfg.Version)
	composeService := composesvc.NewService(dbStore, catalogService)
	composeService.AllowUnpinnedImages(cfg.AllowUnpinnedImages)
	composeService.SetHoneytokens(honeytokenSvc)
	if cfg.AllowUnpinnedImages {
		log.Println("[WARNING] TS_ALLOW_UNPINNED_IMAGES=true: sensor images are not required to be digest-pinned. Do not use in production.")
	}
	monitorService := statemonitor.NewStateMonitor(dbStore.DB, wsService, eventSvc)

	// Browsers may open the dashboard WebSocket only from the Hub's own origin.
	if cfg.IsDevelopment() {
		wsService.SetOriginPolicy(func(*http.Request) bool { return true })
	} else {
		wsService.SetOriginPolicy(websocket.SameOrigin(func() []string {
			endpoint := loadConfigSafe(dbStore, "hub_endpoint", "")
			if u, err := url.Parse(endpoint); err == nil && u.Host != "" {
				return []string{u.Host}
			}
			return nil
		}, cfg.TrustProxy))
	}

	authHandler := api.NewAuthHandler(authService, cfg)
	nodeHandler := api.NewNodeHandler(nodeSvc)
	sensorHandler := api.NewSensorHandler(sensorSvc, composeService)
	eventsHandler := api.NewEventHandler(eventSvc, cfg)
	analyticsHandler := api.NewAnalyticsHandler(dbStore)
	updaterSvc := updater.NewService(configService, catalogService)
	configHandler := api.NewConfigHandler(configService, cfg, updaterSvc)
	composeHandler := api.NewComposeHandler(composeService)

	r, err := api.SetupRouter(api.RouterConfig{
		Nodes:             nodeHandler,
		Sensors:           sensorHandler,
		Auth:              authHandler,
		Events:            eventsHandler,
		Analytics:         analyticsHandler,
		Config:            configHandler,
		Compose:           composeHandler,
		Honeytokens:       api.NewHoneytokenHandler(honeytokenSvc),
		WSService:         wsService,
		SessionValidator:  authService,
		NodeAuthenticator: authService,
		Auditor:           auditLogger{siem: siemService},
		TrustProxy:        cfg.TrustProxy,
	})
	if err != nil {
		log.Fatalf("[FATAL] Router setup failed: %v", err)
	}

	if token := configService.EnsureSetupToken(); token != "" {
		log.Printf("[SETUP] Hub is not initialised. One-time setup token: %s", token)
		log.Printf("[SETUP] Enter it on the setup page to create the admin account.")
	}

	// 1. Start External Workers
	go wsService.StartChartSyncBroadcaster(rootCtx)
	go authService.StartWorkers(rootCtx)
	go siemService.StartWorker(rootCtx)
	go notifyService.StartWorker(rootCtx)
	go nodeSvc.StartWorker(rootCtx)
	go monitorService.Start(rootCtx)

	// 2. Load Runtime Configurations Safely
	isArmed := loadConfigSafe(dbStore, "is_armed", "true") == "true"
	webhookType := loadConfigSafe(dbStore, "webhook_type", "ntfy")
	webhookURL := loadConfigSafe(dbStore, "webhook_url", "")
	webhookEvents := loadConfigSafe(dbStore, "webhook_events", "[]")
	notifyService.UpdateConfig(isArmed, webhookType, webhookURL, webhookEvents)

	siemService.UpdateConfig(siem.Output{
		Address:  loadConfigSafe(dbStore, "siem_address", ""),
		Protocol: loadConfigSafe(dbStore, "siem_protocol", "tcp"),
		Format:   loadConfigSafe(dbStore, "siem_format", siem.FormatRFC5424),
		Token:    loadConfigSafe(dbStore, "siem_token", ""),
	})

	go eventSvc.StartRetentionWorker(rootCtx)

	// 4. Start HTTP Server
	// ReadHeaderTimeout/IdleTimeout bound slow or idle clients (slowloris).
	// No ReadTimeout/WriteTimeout: the dashboard WebSocket is long-lived.
	server := &http.Server{
		Addr:              ":" + cfg.Port,
		Handler:           r,
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    1 << 20,
	}

	go func() {
		log.Printf("[*] Server listening on port %s\n", cfg.Port)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("[FATAL] Server failed to start: %v", err)
		}
	}()

	// 5. Graceful Shutdown Handling
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGTERM, syscall.SIGINT)

	<-sigChan
	log.Println("\n[*] Received shutdown signal. Initiating graceful shutdown...")

	// 1. Signal all background workers to stop accepting new work and begin draining
	rootCancel()

	// 2. Shut down the HTTP server (stops taking new HTTP requests)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := server.Shutdown(ctx); err != nil {
		log.Printf("[!] Server forced to shut down: %v\n", err)
	}

	// 3. Wait for critical telemetry pipelines to flush
	// We wait for them concurrently to speed up the shutdown process.
	// Since both services have hard internal 5-second drain timeouts,
	// this is guaranteed to never hang the system indefinitely.
	log.Println("[*] Waiting for SIEM and Notification workers to flush remaining events...")

	var shutdownWg sync.WaitGroup

	shutdownWg.Add(1)
	go func() {
		defer shutdownWg.Done()
		siemService.Wait()
	}()

	shutdownWg.Add(1)
	go func() {
		defer shutdownWg.Done()
		notifyService.Wait()
	}()

	// Block until both services confirm their WaitGroups are zero
	shutdownWg.Wait()

	log.Println("[*] Graceful shutdown complete. Goodbye!")
}
