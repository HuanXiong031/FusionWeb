package common

import "testing"

func TestNormalizeScanHostsDeduplicatesAndTrims(t *testing.T) {
	hosts := normalizeScanHosts([]string{" 192.0.2.1 ", "192.0.2.1", "", "198.51.100.10"})
	if len(hosts) != 2 {
		t.Fatalf("expected 2 hosts, got %d", len(hosts))
	}
	if hosts[0] != "192.0.2.1" || hosts[1] != "198.51.100.10" {
		t.Fatalf("unexpected hosts: %#v", hosts)
	}
}

func TestNormalizeExplicitPortTargetsDeduplicates(t *testing.T) {
	targets := normalizeExplicitPortTargets([]string{
		"192.0.2.1:80",
		"192.0.2.1:80",
		"[2001:db8::1]:443",
		"[2001:db8::1]:443",
		"bad-target",
	})
	if len(targets) != 2 {
		t.Fatalf("expected 2 targets, got %d", len(targets))
	}
	if targets[0].ip != "192.0.2.1" || targets[0].port != 80 {
		t.Fatalf("unexpected first target: %#v", targets[0])
	}
	if targets[1].ip != "2001:db8::1" || targets[1].port != 443 {
		t.Fatalf("unexpected second target: %#v", targets[1])
	}
}

func TestMultiplyTaskCountSaturates(t *testing.T) {
	if got := multiplyTaskCount(1000, 65535); got != 65535000 {
		t.Fatalf("expected 65535000, got %d", got)
	}
	if got := multiplyTaskCount(1<<30, 1<<30); got <= 0 {
		t.Fatalf("expected saturated positive value, got %d", got)
	}
}

func TestNormalizePortScanThreadsRespectsTotal(t *testing.T) {
	if got := normalizePortScanThreads(100, 10, 0); got != 10 {
		t.Fatalf("expected threads to be capped by total, got %d", got)
	}
}

func TestNormalizePortScanThreadsReservesFileDescriptors(t *testing.T) {
	if got := normalizePortScanThreads(512, 65535000, 256); got != 128 {
		t.Fatalf("expected threads to reserve file descriptors, got %d", got)
	}
}

func TestNormalizePortScanThreadsAppliesPlatformSafeCap(t *testing.T) {
	if got := normalizePortScanThreads(1000, 65535000, 0); got != 512 {
		t.Fatalf("expected threads to use platform safe cap, got %d", got)
	}
}
