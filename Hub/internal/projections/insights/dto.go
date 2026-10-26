package insights

// InsightsDTO is the read-model behind the dashboard's decoy coverage
// widgets: what is deployed, what attackers touched, and from how many
// sources. Hub liveness events are not attacker activity and are excluded.
type InsightsDTO struct {
	Timeframe          string     `json:"timeframe"`
	Events             int        `json:"events"`
	CriticalEvents     int        `json:"criticalEvents"`
	UniqueSources      int        `json:"uniqueSources"`
	DecoysDeployed     int        `json:"decoysDeployed"`
	DecoysTouched      int        `json:"decoysTouched"`
	DecoyTypesDeployed int        `json:"decoyTypesDeployed"`
	HoneytokensTotal   int        `json:"honeytokensTotal"`
	HoneytokensUsed    int        `json:"honeytokensUsed"`
	ByType             []TypeStat `json:"byType"`
}

// TypeStat aggregates one decoy type (sensor ID) across nodes.
type TypeStat struct {
	SensorID      string `json:"sensorId"`
	Events        int    `json:"events"`
	UniqueSources int    `json:"uniqueSources"`
	Deployed      int    `json:"deployed"`
	Touched       int    `json:"touched"`
}
