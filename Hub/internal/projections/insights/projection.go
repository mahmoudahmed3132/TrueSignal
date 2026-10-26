package insights

import (
	"context"
	"fmt"
	"time"

	"github.com/truesignal/hub/internal/models"
	"github.com/truesignal/hub/internal/store"
)

type ProjectionStore interface {
	GetEvents(isArchived int, nodeID, sensorID string) ([]models.Event, error)
	ListDeployedSensors(nodeID, sensorID string) ([]store.DeployedSensor, error)
	ListHoneytokens() ([]models.Honeytoken, error)
}

type Projector struct {
	Store ProjectionStore
}

func NewProjector(s ProjectionStore) *Projector {
	return &Projector{Store: s}
}

// Since resolves a dashboard timeframe to its cut-off; zero means all time.
func Since(timeframe string, now time.Time) (string, time.Time) {
	switch timeframe {
	case "24H":
		return timeframe, now.Add(-24 * time.Hour)
	case "7D":
		return timeframe, now.Add(-7 * 24 * time.Hour)
	case "30D":
		return timeframe, now.Add(-30 * 24 * time.Hour)
	default:
		return "alltime", time.Time{}
	}
}

func (p *Projector) BuildInsightsProjection(ctx context.Context, timeframe, nodeID, sensorID string, viewingArchive int) (*InsightsDTO, error) {
	timeframe, since := Since(timeframe, time.Now().UTC())

	events, err := p.Store.GetEvents(viewingArchive, nodeID, sensorID)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch events for insights: %w", err)
	}
	decoys, err := p.Store.ListDeployedSensors(nodeID, sensorID)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch deployed sensors for insights: %w", err)
	}
	all, err := p.Store.ListHoneytokens()
	if err != nil {
		return nil, fmt.Errorf("failed to fetch honeytokens for insights: %w", err)
	}
	tokens := all[:0]
	for _, h := range all {
		if (nodeID == "" || h.NodeID == nodeID) && (sensorID == "" || h.SensorID == sensorID) {
			tokens = append(tokens, h)
		}
	}

	return Calculate(events, decoys, tokens, timeframe, since), nil
}
