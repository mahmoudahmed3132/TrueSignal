package siem

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"time"
)

// HTTP outputs. Both send ECS documents over HTTPS:
//
//   - elastic: POST <address>/_bulk where address is the cluster URL plus the
//     target data stream, e.g. https://es.example:9200/logs-truesignal-default.
//     Each document is a `create` action (required for data streams).
//     Authorization: ApiKey <encoded API key>.
//   - logscale: POST <address> where address is the HEC endpoint, e.g.
//     https://cloud.us.humio.com/api/v1/ingest/hec. Authorization: Bearer
//     <ingest token>.
//
// Events are sent one per request: deception alerts are low volume, and
// per-event delivery keeps the retry position exact.

const (
	ProtocolElastic  = "elastic"
	ProtocolLogScale = "logscale"

	maxHTTPResponse = 64 << 10
)

// IsHTTPProtocol reports whether protocol is an HTTP output.
func IsHTTPProtocol(protocol string) bool {
	return protocol == ProtocolElastic || protocol == ProtocolLogScale
}

// httpRequestBody builds the request body for one document.
func httpRequestBody(protocol string, doc map[string]any) ([]byte, string, error) {
	docJSON, err := json.Marshal(doc)
	if err != nil {
		return nil, "", err
	}
	switch protocol {
	case ProtocolElastic:
		var b bytes.Buffer
		b.WriteString(`{"create":{}}` + "\n")
		b.Write(docJSON)
		b.WriteByte('\n')
		return b.Bytes(), "application/x-ndjson", nil
	default: // logscale (HEC)
		ts, _ := time.Parse(time.RFC3339Nano, fmt.Sprint(doc["@timestamp"]))
		host := ""
		if h, ok := doc["host"].(map[string]any); ok {
			host = fmt.Sprint(h["name"])
		}
		body, err := json.Marshal(map[string]any{
			"time":       float64(ts.UnixNano()) / 1e9,
			"host":       host,
			"source":     "truesignal-hub",
			"sourcetype": "truesignal",
			"event":      json.RawMessage(docJSON),
		})
		return body, "application/json", err
	}
}

func httpEndpoint(protocol, address string) string {
	if protocol == ProtocolElastic {
		return strings.TrimRight(address, "/") + "/_bulk"
	}
	return address
}

func authHeader(protocol, token string) string {
	if token == "" {
		return ""
	}
	if protocol == ProtocolElastic {
		return "ApiKey " + token
	}
	return "Bearer " + token
}

// sendHTTP delivers one document and classifies the outcome. Network errors,
// 5xx and 429 are transient; other non-2xx responses and Elastic per-item
// errors are terminal for that document (a retry would fail the same way).
func (s *Service) sendHTTP(ctx context.Context, protocol, address, token string, doc map[string]any) NetworkFact {
	body, contentType, err := httpRequestBody(protocol, doc)
	if err != nil {
		return NetworkFact{IsError: true, Err: err}
	}
	reqCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(reqCtx, http.MethodPost, httpEndpoint(protocol, address), bytes.NewReader(body))
	if err != nil {
		return NetworkFact{IsError: true, Err: err}
	}
	req.Header.Set("Content-Type", contentType)
	req.Header.Set("User-Agent", "TrueSignal-Hub")
	if h := authHeader(protocol, token); h != "" {
		req.Header.Set("Authorization", h)
	}

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return NetworkFact{IsError: true, IsTransient: true, Err: err}
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, maxHTTPResponse))

	switch {
	case resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500:
		return NetworkFact{IsError: true, IsTransient: true, Err: fmt.Errorf("HTTP %d", resp.StatusCode)}
	case resp.StatusCode < 200 || resp.StatusCode > 299:
		return NetworkFact{IsError: true, Err: fmt.Errorf("HTTP %d: %s", resp.StatusCode, snippet(respBody))}
	}

	if protocol == ProtocolElastic {
		var bulk struct {
			Errors bool `json:"errors"`
			Items  []map[string]struct {
				Status int             `json:"status"`
				Error  json.RawMessage `json:"error"`
			} `json:"items"`
		}
		if json.Unmarshal(respBody, &bulk) == nil && bulk.Errors {
			for _, item := range bulk.Items {
				for _, r := range item {
					if r.Status == http.StatusTooManyRequests {
						return NetworkFact{IsError: true, IsTransient: true, Err: fmt.Errorf("bulk item HTTP 429")}
					}
					return NetworkFact{IsError: true, Err: fmt.Errorf("bulk item HTTP %d: %s", r.Status, snippet(r.Error))}
				}
			}
			return NetworkFact{IsError: true, Err: fmt.Errorf("bulk request reported errors")}
		}
	}
	return NetworkFact{}
}

func snippet(b []byte) string {
	s := strings.TrimSpace(string(b))
	if len(s) > 300 {
		s = s[:300] + "..."
	}
	return s
}

// processHTTPWithRetry sends one queue item with the shared backoff policy.
func (s *Service) processHTTPWithRetry(ctx context.Context, out Output, item queueItem) {
	doc := s.ecsDoc(item)
	for attempt := 0; attempt < MaxRetriesPerEvent; attempt++ {
		fact := s.sendHTTP(ctx, out.Protocol, out.Address, out.Token, doc)
		action, delay := s.siemPolicy(fact, attempt)
		switch action {
		case SiemSuccess:
			return
		case SiemDrop:
			log.Printf("[-] SIEM %s output rejected the record: %v. Dropping it.", out.Protocol, fact.Err)
			return
		case SiemRetry:
			log.Printf("[!] SIEM %s output failed: %v. Retrying in %v...", out.Protocol, fact.Err, delay)
			if s.sleepContext(ctx, delay) {
				return
			}
			// Pick up a configuration change made while backing off.
			out = s.output()
			if out.Address == "" || !IsHTTPProtocol(out.Protocol) {
				return
			}
		}
	}
	log.Printf("[-] Telemetry record exceeded critical retry budget (%d). Discarding to prevent local pipeline freeze.", MaxRetriesPerEvent)
}
