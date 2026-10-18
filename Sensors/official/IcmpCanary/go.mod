module github.com/truesignal/sensors/icmpcanary

go 1.25.0

replace github.com/truesignal/sdk-go => ../../../SDKs/go-truesignal

require (
	github.com/truesignal/sdk-go v0.0.0-00010101000000-000000000000
	golang.org/x/net v0.57.0
)

require golang.org/x/sys v0.47.0 // indirect
