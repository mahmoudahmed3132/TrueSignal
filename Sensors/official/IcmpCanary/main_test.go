package main

import (
	"testing"
	"time"
)

func TestThrottleAggregates(t *testing.T) {
	th := newThrottle(time.Minute)
	t0 := time.Unix(0, 0)
	if ok, _ := th.allow("a", t0); !ok {
		t.Fatal("first packet must emit")
	}
	for i := 1; i <= 5; i++ {
		if ok, _ := th.allow("a", t0.Add(time.Duration(i)*time.Second)); ok {
			t.Fatal("packets within cooldown must be suppressed")
		}
	}
	if ok, _ := th.allow("b", t0.Add(time.Second)); !ok {
		t.Fatal("other sources are independent")
	}
	ok, n := th.allow("a", t0.Add(2*time.Minute))
	if !ok || n != 5 {
		t.Fatalf("after cooldown expect emit with 5 suppressed, got ok=%v n=%d", ok, n)
	}
}

func TestThrottleDisabled(t *testing.T) {
	th := newThrottle(0)
	for i := 0; i < 3; i++ {
		if ok, _ := th.allow("a", time.Unix(0, 0)); !ok {
			t.Fatal("cooldown 0 must emit every packet")
		}
	}
}
