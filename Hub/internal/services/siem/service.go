package siem

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"log"
	"math"
	"os"

	// codeql[go/insecure-randomness] Non-cryptographic use case.
	// nosemgrep: go.lang.security.audit.crypto.math_random.math-random-used
	"math/rand"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/truesignal/hub/internal/attack"
	"github.com/truesignal/hub/internal/models"
)

const (
	MaxRetriesPerEvent = 10

	// DefaultPEN is the RFC 5612 documentation Private Enterprise Number.
	// Operators should configure their own registered PEN (TS_SYSLOG_PEN).
	DefaultPEN = "32473"

	syslogHostname = "truesignal"
	syslogAppName  = "truesignalSensor"
	maxSDValueLen  = 1024
)

// ============================================================================
// 1. SHARED CLASSIFIER (Pure Network Truth Layer)
// ============================================================================

type NetworkFact struct {
	IsError     bool
	IsTransient bool
	Err         error
}

// classify inspects raw socket/dialer errors to determine system state.
func classify(err error) NetworkFact {
	if err == nil {
		return NetworkFact{IsError: false, IsTransient: false, Err: nil}
	}

	fact := NetworkFact{
		IsError:     true,
		IsTransient: true, // Default raw network errors (timeouts, refusions) to transient
		Err:         err,
	}

	// Check for known terminal configuration anomalies
	errStr := err.Error()
	if strings.Contains(errStr, "unknown network") ||
		strings.Contains(errStr, "invalid argument") {
		fact.IsTransient = false
	}

	return fact
}

// ============================================================================
// 2. POLICY INTERPRETER (Domain-Specific Security Logging Rules)
// ============================================================================

type SiemAction string

const (
	SiemSuccess SiemAction = "success"
	SiemRetry   SiemAction = "retry"
	SiemDrop    SiemAction = "drop"
)

func (s *Service) siemPolicy(fact NetworkFact, attempt int) (SiemAction, time.Duration) {
	if !fact.IsError {
		return SiemSuccess, 0
	}
	if !fact.IsTransient {
		return SiemDrop, 0
	}

	// Calculate robust exponential backoff + jitter for transient network drops
	base := 2.0
	maxDelay := 60.0
	delay := base * math.Pow(2, float64(attempt))
	if delay > maxDelay {
		delay = maxDelay
	}
	jitter := (s.rng.Float64() * 0.2) - 0.1
	finalDelay := time.Duration((delay + (delay * jitter)) * float64(time.Second))

	return SiemRetry, finalDelay
}

// ============================================================================
// SERVICE CORE & CONFIGURATION
// ============================================================================

type NodeService interface {
	GetNodeDetails(nodeID string) (*models.Node, error)
}

// AuditRecord is an administrative action forwarded to the SIEM so that
// changes which can blind the platform (whitelists, silencing, disarming,
// deletions) leave a trail outside the Hub.
type AuditRecord struct {
	Time    time.Time `json:"timestamp"`
	Action  string    `json:"action"`
	Path    string    `json:"path"`
	Status  int       `json:"status"`
	ActorIP string    `json:"actor_ip"`
}

// Options tunes message identity and transport security.
type Options struct {
	PEN    string // IANA Private Enterprise Number for SD-IDs
	CAFile string // optional PEM bundle for TLS verification
}

// Output is the SIEM destination. Protocol tcp|udp|tls streams lines in
// Format rfc5424 (default) or ecs (NDJSON); elastic|logscale POST ECS JSON
// over HTTPS to Address with Token.
type Output struct {
	Address  string
	Protocol string
	Format   string
	Token    string
}

const (
	FormatRFC5424 = "rfc5424"
	FormatECS     = "ecs"
)

type queueItem struct {
	event      *models.Event
	audit      *AuditRecord
	honeytoken *models.Honeytoken
}

type Service struct {
	eventQueue  chan queueItem
	out         Output
	pen         string
	tlsConfig   *tls.Config
	rng         *rand.Rand
	mu          sync.RWMutex
	wg          sync.WaitGroup
	isDraining  atomic.Bool
	nodeService NodeService
	httpClient  *http.Client
}

func NewService(nodeService NodeService, opts ...Options) *Service {
	o := Options{PEN: DefaultPEN}
	if len(opts) > 0 {
		if opts[0].PEN != "" {
			o.PEN = opts[0].PEN
		}
		o.CAFile = opts[0].CAFile
	}
	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12}
	if o.CAFile != "" {
		if pem, err := os.ReadFile(o.CAFile); err != nil {
			log.Printf("[WARNING] SIEM CA file %s unreadable: %v (using system roots)", o.CAFile, err)
		} else {
			pool := x509.NewCertPool()
			if pool.AppendCertsFromPEM(pem) {
				tlsCfg.RootCAs = pool
			} else {
				log.Printf("[WARNING] SIEM CA file %s contains no certificates (using system roots)", o.CAFile)
			}
		}
	}
	return &Service{
		eventQueue: make(chan queueItem, 5000),
		pen:        o.PEN,
		tlsConfig:  tlsCfg,
		// codeql[go/insecure-randomness] Non-cryptographic use case.
		// nosemgrep: go.lang.security.audit.crypto.math_random.math-random-used
		rng:         rand.New(rand.NewSource(time.Now().UnixNano())),
		nodeService: nodeService,
		httpClient: &http.Client{
			Timeout:   15 * time.Second,
			Transport: &http.Transport{TLSClientConfig: tlsCfg, Proxy: http.ProxyFromEnvironment},
			// A redirect would resend the token to wherever it points.
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
	}
}

func (s *Service) UpdateConfig(o Output) {
	s.mu.Lock()
	defer s.mu.Unlock()
	o.Address = strings.TrimSpace(o.Address)
	o.Token = strings.TrimSpace(o.Token)
	o.Protocol = strings.ToLower(strings.TrimSpace(o.Protocol))
	if o.Protocol == "" {
		o.Protocol = "tcp"
	}
	o.Format = strings.ToLower(o.Format)
	if o.Format != FormatECS {
		o.Format = FormatRFC5424
	}
	s.out = o
}

func (s *Service) output() Output {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.out
}

func (s *Service) enqueue(item queueItem) {
	if s.isDraining.Load() {
		return
	}

	select {
	case s.eventQueue <- item:
	default:
		log.Println("[!] SIEM Pipeline saturated. Bounded queue full, dropping event.")
	}
}

func (s *Service) QueueEvent(event models.Event) {
	s.enqueue(queueItem{event: &event})
}

// QueueHoneytoken forwards a honeytoken inventory record (username and where
// it is planted; never the secret) so the SIEM can watch for the planted
// usernames on real systems.
func (s *Service) QueueHoneytoken(h models.Honeytoken) {
	h.Secret = ""
	s.enqueue(queueItem{honeytoken: &h})
}

// QueueAudit forwards an administrative action record.
func (s *Service) QueueAudit(rec AuditRecord) {
	s.enqueue(queueItem{audit: &rec})
}

// ============================================================================
// WORKER ENGINE (Persistent Streams + Non-Stalling Cooldowns)
// ============================================================================

// streamSession encapsulates the active connection state for a single worker goroutine.
// By binding methods to this struct, we eliminate pointer indirection and parameter bloat.
// not safe for concurrent access.
type streamSession struct {
	conn                 net.Conn
	currentAddr          string
	currentProto         string
	nextReconnectAttempt time.Time
	service              *Service
}

// close cleanly tears down the connection
func (sess *streamSession) close() {
	if sess.conn != nil {
		sess.conn.Close()
		sess.conn = nil
	}
}

func (s *Service) StartWorker(ctx context.Context) {
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		log.Println("[SIEM] Worker started.")

		// Initialize the stateful session object
		sess := &streamSession{
			service: s,
		}
		defer sess.close()

		for {
			select {
			case <-ctx.Done():
				log.Println("[SIEM] Shutdown signal received. Flushing pipeline...")
				s.drainQueue(sess.conn)
				return

			case item := <-s.eventQueue:
				if out := s.output(); IsHTTPProtocol(out.Protocol) {
					sess.close()
					if out.Address != "" {
						s.processHTTPWithRetry(ctx, out, item)
					}
					continue
				}
				sess.processWithRetry(ctx, s.format(item))
			}
		}
	}()
}

// dial opens the configured transport. "tls" is TCP with TLS 1.2+ and
// certificate verification (system roots or TS_SIEM_CA_FILE).
func (s *Service) dial(proto, addr string) (net.Conn, error) {
	if proto != "tls" {
		return net.DialTimeout(proto, addr, 5*time.Second)
	}
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	cfg := s.tlsConfig.Clone()
	cfg.ServerName = host
	return tls.DialWithDialer(&net.Dialer{Timeout: 5 * time.Second}, "tcp", addr, cfg)
}

func (sess *streamSession) processWithRetry(ctx context.Context, msg string) {
	for attempt := 0; attempt < MaxRetriesPerEvent; attempt++ {
		out := sess.service.output()
		addr, proto := out.Address, out.Protocol

		if addr == "" || IsHTTPProtocol(proto) {
			return // Exporter explicitly disabled via configuration
		}

		// Handle Stream Synchronization/Instantiation cleanly
		if sess.conn == nil || addr != sess.currentAddr || proto != sess.currentProto {
			// Prevent aggressive dial storms against a dead receiver
			if time.Now().Before(sess.nextReconnectAttempt) {
				// Cooldown active: wait out the balance using a precise context-aware timer
				t := time.NewTimer(time.Until(sess.nextReconnectAttempt))
				select {
				case <-t.C:
				case <-ctx.Done():
					t.Stop()
					return
				}
			}

			sess.close()
			dialConn, err := sess.service.dial(proto, addr)
			fact := classify(err)

			if fact.IsError {
				log.Printf("[!] SIEM Stream connection failed (%s://%s): %v", proto, addr, err)
				sess.nextReconnectAttempt = time.Now().Add(2 * time.Second) // 2-second suppression cooldown

				action, delay := sess.service.siemPolicy(fact, attempt)
				if action == SiemDrop {
					log.Printf("[-] Terminal configuration error. Dropping log stream position.")
					return
				}

				// Backoff and retry dialing for the exact same event log position
				if sess.service.sleepContext(ctx, delay) {
					return
				}
				continue
			}

			sess.conn = dialConn
			sess.currentAddr, sess.currentProto = addr, proto
		}

		// Stream Writing Phase
		sess.conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
		_, writeErr := sess.conn.Write([]byte(msg + "\n"))
		fact := classify(writeErr)
		action, delay := sess.service.siemPolicy(fact, attempt)

		switch action {
		case SiemSuccess:
			return // Log exported successfully. Advance queue position.
		case SiemDrop:
			log.Printf("[-] Terminal failure encountered on write. Discarding position.")
			sess.close()
			return
		case SiemRetry:
			log.Printf("[!] SIEM stream disconnected mid-write: %v. Retrying connection structure in %v...", writeErr, delay)
			sess.close() // Kill connection to trigger a fresh dial sequence on next iteration
			if sess.service.sleepContext(ctx, delay) {
				return
			}
		}
	}

	log.Printf("[-] Telemetry record exceeded critical retry budget (%d). Discarding to prevent local pipeline freeze.", MaxRetriesPerEvent)
}

// ============================================================================
// CLEAN SHUTDOWN FLUSH ENGINE
// ============================================================================

func (s *Service) drainQueue(conn net.Conn) {
	s.isDraining.Store(true)

	// Best-effort 5-second deadline to push remaining in-flight memory to disk/wire
	timeout := time.After(5 * time.Second)
	count := 0

	for {
		select {
		case <-timeout:
			log.Printf("[SIEM] Flush cutoff reached. Aborted %d buffered telemetry items.", len(s.eventQueue))
			log.Println("[SIEM] Worker stopped.")
			return
		case item := <-s.eventQueue:
			if out := s.output(); IsHTTPProtocol(out.Protocol) && out.Address != "" {
				ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
				if !s.sendHTTP(ctx, out.Protocol, out.Address, out.Token, s.ecsDoc(item)).IsError {
					count++
				}
				cancel()
			} else if conn != nil {
				msg := s.format(item)
				conn.SetWriteDeadline(time.Now().Add(1 * time.Second))
				if _, err := conn.Write([]byte(msg + "\n")); err == nil {
					count++
				}
			}
		default:
			log.Printf("[SIEM] Telemetry stream fully synchronized. Flushed %d remaining logs.", count)
			log.Println("[SIEM] Worker stopped.")
			return
		}
	}
}

// ============================================================================
// FORMATTERS (RFC 5424)
// ============================================================================

func (s *Service) format(item queueItem) string {
	if s.output().Format == FormatECS {
		line, _ := json.Marshal(s.ecsDoc(item))
		return string(line)
	}
	if item.audit != nil {
		return s.formatAudit(*item.audit)
	}
	if item.honeytoken != nil {
		return s.formatHoneytoken(*item.honeytoken)
	}
	return s.formatSyslog(*item.event)
}

// escapeSDValue applies RFC 5424 §6.3.3 PARAM-VALUE escaping (", \ and ]).
// Control characters are replaced so that attacker-supplied values cannot
// break newline framing or inject fake records.
func escapeSDValue(v string) string {
	v = strings.ToValidUTF8(v, "?")
	if len(v) > maxSDValueLen {
		v = v[:maxSDValueLen]
	}
	var b strings.Builder
	b.Grow(len(v))
	for _, r := range v {
		switch {
		case r == '"' || r == '\\' || r == ']':
			b.WriteByte('\\')
			b.WriteRune(r)
		case r < 0x20 || r == 0x7f:
			b.WriteByte(' ')
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

func structuredData(id string, params [][2]string) string {
	var b strings.Builder
	b.WriteString("[")
	b.WriteString(id)
	for _, kv := range params {
		b.WriteString(" ")
		b.WriteString(kv[0])
		b.WriteString(`="`)
		b.WriteString(escapeSDValue(kv[1]))
		b.WriteString(`"`)
	}
	b.WriteString("]")
	return b.String()
}

func eventTime(ts string) time.Time {
	if ts != "" {
		if t, err := time.Parse(time.RFC3339, ts); err == nil {
			return t
		}
	}
	return time.Now()
}

// formatSyslog renders one event as an RFC 5424 line:
//
//	<PRI>1 TIMESTAMP truesignal truesignalSensor - EVENT [truesignal@PEN ...] {json}
//
// The structured data carries the triage fields; the MSG is the full event as
// single-line JSON, which SIEM parsers (Elastic json processor, LogScale
// parseJson) can consume without custom grok.
func (s *Service) formatSyslog(event models.Event) string {
	priority := syslogPriority(event.Severity)
	timestamp := eventTime(event.Timestamp).UTC().Format(time.RFC3339Nano)

	detailsJSON := event.Details
	if len(detailsJSON) == 0 || !json.Valid(detailsJSON) {
		detailsJSON = []byte("{}")
	}

	nodeAlias := s.nodeAlias(event.NodeID)

	// ATT&CK: always present, empty when the trigger is unmapped, so the
	// parameter positions never shift.
	var mitreTechnique, mitreTactic string
	var mitre any
	var assetName, assetCriticality string
	var sourceAsset any
	if event.SourceAsset != nil {
		assetName, assetCriticality, sourceAsset = event.SourceAsset.Name, event.SourceAsset.Criticality, event.SourceAsset
	}
	if m, ok := attack.For(event.EventTrigger); ok {
		mitreTechnique, mitreTactic, mitre = m.Primary.ID, m.Primary.TacticIDs(), m
	}

	sd := structuredData("truesignal@"+s.pen, [][2]string{
		{"event_id", fmt.Sprint(event.ID)},
		{"trigger", event.EventTrigger},
		{"severity", event.Severity},
		{"source", event.Source},
		{"target", event.Target},
		{"node", nodeAlias},
		{"node_id", event.NodeID},
		{"sensor", event.SensorID},
		{"whitelisted", fmt.Sprint(event.Whitelisted)},
		{"known_scanner", fmt.Sprint(event.KnownScanner)},
		{"mitre_technique", mitreTechnique},
		{"mitre_tactic", mitreTactic},
		{"source_asset", assetName},
		{"source_asset_criticality", assetCriticality},
	})

	body, _ := json.Marshal(map[string]any{
		"event_id":      event.ID,
		"timestamp":     event.Timestamp,
		"node_id":       event.NodeID,
		"node":          nodeAlias,
		"sensor_id":     event.SensorID,
		"trigger":       event.EventTrigger,
		"severity":      event.Severity,
		"source":        event.Source,
		"target":        event.Target,
		"whitelisted":   event.Whitelisted,
		"known_scanner": event.KnownScanner,
		"attack":        mitre,
		"source_asset":  sourceAsset,
		"details":       json.RawMessage(detailsJSON),
	})

	return fmt.Sprintf("<%d>1 %s %s %s - EVENT %s %s",
		priority, timestamp, syslogHostname, syslogAppName, sd, body)
}

// nodeAlias resolves a node ID to its display alias, falling back to the ID.
func (s *Service) nodeAlias(nodeID string) string {
	if s.nodeService != nil {
		if n, err := s.nodeService.GetNodeDetails(nodeID); err == nil && n != nil && n.Alias != "" {
			return n.Alias
		}
	}
	return nodeID
}

// formatAudit renders an administrative action. Facility local0, severity
// notice (5).
func (s *Service) formatAudit(rec AuditRecord) string {
	if rec.Time.IsZero() {
		rec.Time = time.Now()
	}
	sd := structuredData("truesignal-audit@"+s.pen, [][2]string{
		{"action", rec.Action},
		{"path", rec.Path},
		{"status", fmt.Sprint(rec.Status)},
		{"actor_ip", rec.ActorIP},
	})
	body, _ := json.Marshal(rec)
	return fmt.Sprintf("<%d>1 %s %s %s - AUDIT %s %s",
		16*8+5, rec.Time.UTC().Format(time.RFC3339Nano), syslogHostname, syslogAppName, sd, body)
}

// formatHoneytoken renders a honeytoken inventory record. Facility local0,
// severity informational (6), MSGID HONEYTOKEN.
func (s *Service) formatHoneytoken(h models.Honeytoken) string {
	sd := structuredData("truesignal-honeytoken@"+s.pen, [][2]string{
		{"honeytoken_id", h.ID},
		{"username", h.Username},
		{"planted_node_id", h.NodeID},
		{"planted_sensor_id", h.SensorID},
		{"status", "active"},
	})
	body, _ := json.Marshal(honeytokenRecord(h))
	return fmt.Sprintf("<%d>1 %s %s %s - HONEYTOKEN %s %s",
		16*8+6, time.Now().UTC().Format(time.RFC3339Nano), syslogHostname, syslogAppName, sd, body)
}

// honeytokenRecord is the published shape of a honeytoken. It lists fields
// explicitly so the secret can never be serialised.
func honeytokenRecord(h models.Honeytoken) map[string]any {
	return map[string]any{
		"honeytoken_id":     h.ID,
		"username":          h.Username,
		"planted_node_id":   h.NodeID,
		"planted_sensor_id": h.SensorID,
		"created_at":        h.CreatedAt,
		"status":            "active",
	}
}

func syslogPriority(severity string) int {
	facility := 16 * 8 // local0
	switch severity {
	case "critical":
		return facility + 2
	case "high":
		return facility + 3
	case "medium":
		return facility + 4
	case "low":
		return facility + 5
	default:
		return facility + 6 // info
	}
}

// helper to clean up select-block boilerplate across retry systems
func (s *Service) sleepContext(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	select {
	case <-t.C:
		return false
	case <-ctx.Done():
		t.Stop()
		return true
	}
}

func (s *Service) Wait() {
	s.wg.Wait()
}
