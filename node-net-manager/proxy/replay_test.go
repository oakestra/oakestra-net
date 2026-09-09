package proxy

import (
	"NetManager/TableEntryCache"
	"NetManager/proxy/iputils"
	"NetManager/resolver"
	"bytes"
	"net/netip"
	"sync"
	"testing"
	"time"
)

// resolvingEnv reports a Service IP as unresolved until release is called,
// mimicking the window in which the real Environment is waiting on an MQTT
// table query.
type resolvingEnv struct {
	mu       sync.Mutex
	table    TableEntryCache.TableManager
	pending  map[netip.Addr]chan struct{}
	resolved map[netip.Addr]bool
	lookups  map[netip.Addr]int
}

func newResolvingEnv(entries ...TableEntryCache.TableEntry) *resolvingEnv {
	e := &resolvingEnv{
		table:    TableEntryCache.NewTableManager(),
		pending:  make(map[netip.Addr]chan struct{}),
		resolved: make(map[netip.Addr]bool),
		lookups:  make(map[netip.Addr]int),
	}
	for _, entry := range entries {
		if err := e.table.Add(entry); err != nil {
			panic(err)
		}
	}
	return e
}

func (e *resolvingEnv) GetTableEntryByServiceIP(addr netip.Addr) resolver.ServiceLookup {
	e.mu.Lock()
	e.lookups[addr]++
	resolved := e.resolved[addr]
	if !resolved {
		done, ok := e.pending[addr]
		if !ok {
			done = make(chan struct{})
			e.pending[addr] = done
		}
		e.mu.Unlock()
		return resolver.ServiceLookup{Resolving: done}
	}
	e.mu.Unlock()

	entries, generation := e.table.SearchByServiceIP(addr)
	return resolver.ServiceLookup{Entries: entries, Generation: generation}
}

func (e *resolvingEnv) GetInstanceIP(addr netip.Addr, version uint8) (netip.Addr, bool) {
	return e.table.SearchInstanceIPByNsIP(addr, version)
}

func (e *resolvingEnv) TableGeneration() uint64 {
	return e.table.Generation()
}

// release completes the resolution attempt for addr. succeed=false models an
// attempt that finished without finding anything.
func (e *resolvingEnv) release(addr netip.Addr, succeed bool) {
	e.mu.Lock()
	e.resolved[addr] = succeed
	done := e.pending[addr]
	delete(e.pending, addr)
	e.mu.Unlock()
	if done != nil {
		close(done)
	}
}

func (d *Datapath) queuedFor(vip netip.Addr) int {
	d.replayLock.Lock()
	defer d.replayLock.Unlock()
	if queue, ok := d.replays[vip]; ok {
		return len(queue.packets)
	}
	return 0
}

func (d *Datapath) replayState() (queues int, bytes int) {
	d.replayLock.Lock()
	defer d.replayLock.Unlock()
	return len(d.replays), d.replayBytes
}

// waitFor polls until cond holds, so tests never depend on a fixed sleep.
func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

// coldDatapath is a Datapath whose target service is not resolved yet. Its
// replay goroutine's output is captured by a recordingSink rather than sent
// anywhere real, since these tests only care about what the datapath decided
// to do with each queued packet, not about actual socket I/O.
func coldDatapath(t *testing.T) (*Datapath, *recordingSink, *resolvingEnv) {
	t.Helper()
	resolving := newResolvingEnv(replayFixtureEntries()...)
	sink := &recordingSink{}
	dp := NewDatapath(resolving, mustAddr(nodeAIP), fixtureIPv4Prefix, fixtureIPv6Prefix, sink)
	return dp, sink, resolving
}

// replayFixtureEntries mirrors the standard fixture table but is inserted
// into resolvingEnv's own table, which starts every ServiceIP off unresolved
// until release is called.
func replayFixtureEntries() []TableEntryCache.TableEntry {
	server := tableEntry("serverapp", nodeBIP, serverNsIP, serverNsIPv6,
		serverVIP, serverVIPv6, serverInstIP, serverInstIPv6)
	other := tableEntry("otherapp", nodeCIP, otherNsIP, otherNsIPv6,
		otherVIP, otherVIPv6, otherInstIP, otherInstIPv6)
	return []TableEntryCache.TableEntry{fixtureEntries[0], server, other}
}

// datagramPayload returns the UDP payload of a forwarded IPv4 packet.
func datagramPayload(t *testing.T, wire []byte) string {
	t.Helper()
	if len(wire) < 28 {
		t.Fatalf("packet too short to hold a UDP payload: %d bytes", len(wire))
	}
	return string(wire[28:])
}

// TestReplayPreservesOrder checks that packets queued behind one unresolved
// Service IP replay in the order they arrived.
func TestReplayPreservesOrder(t *testing.T) {
	dp, sink, resolving := coldDatapath(t)
	vip := mustAddr(serverVIP)

	const datagrams = 16
	payloads := make([]string, datagrams)
	for i := range payloads {
		payloads[i] = string(rune('a'+i)) + "-datagram"
		dp.Handle(Outgoing, buildUDPv4(t, clientNsIP, serverVIP, 40000, 53, []byte(payloads[i])))
	}

	if got := dp.queuedFor(vip); got != datagrams {
		t.Fatalf("queued %d packets; want %d", got, datagrams)
	}
	// One queue for the Service IP, not one per packet.
	if queues, _ := dp.replayState(); queues != 1 {
		t.Fatalf("%d replay queues for a single Service IP; want 1", queues)
	}

	resolving.release(vip, true)

	waitFor(t, "the replay queue to be released", func() bool {
		queues, bytes := dp.replayState()
		return queues == 0 && bytes == 0
	})

	actions := sink.drain()
	if len(actions) != datagrams {
		t.Fatalf("replay emitted %d actions; want %d", len(actions), datagrams)
	}
	for i, want := range payloads {
		if actions[i].Kind != ActionForward {
			t.Fatalf("datagram %d emitted as kind %v; want ActionForward", i, actions[i].Kind)
		}
		if got := datagramPayload(t, actions[i].Packet); got != want {
			t.Fatalf("datagram %d was %q; want %q - replay reordered the queue", i, got, want)
		}
	}
}

// TestReplaySeparateVIPsResolveIndependently checks that one Service IP
// resolving does not flush packets waiting on another.
func TestReplaySeparateVIPsResolveIndependently(t *testing.T) {
	dp, sink, resolving := coldDatapath(t)

	dp.Handle(Outgoing, buildUDPv4(t, clientNsIP, serverVIP, 40000, 53, []byte("for-server")))
	dp.Handle(Outgoing, buildUDPv4(t, clientNsIP, otherVIP, 40000, 53, []byte("for-other")))

	if queues, _ := dp.replayState(); queues != 2 {
		t.Fatalf("%d replay queues; want one per Service IP", queues)
	}

	resolving.release(mustAddr(serverVIP), true)

	waitFor(t, "only the resolved Service IP's queue to drain", func() bool {
		queues, _ := dp.replayState()
		return queues == 1
	})

	actions := sink.drain()
	if len(actions) != 1 {
		t.Fatalf("replay emitted %d actions; want 1", len(actions))
	}
	if got := datagramPayload(t, actions[0].Packet); got != "for-server" {
		t.Errorf("forwarded %q; want the resolved Service IP's datagram", got)
	}
	if got := dp.queuedFor(mustAddr(otherVIP)); got != 1 {
		t.Errorf("the unresolved Service IP has %d packets queued; want 1", got)
	}
}

// TestReplayQueueBounded checks that the queue is capped, and that the cap
// counts packets actually retained rather than pooled 64KiB buffers.
func TestReplayQueueBounded(t *testing.T) {
	dp, _, _ := coldDatapath(t)

	for i := 0; i < maxReplayPacketsPerVIP*3; i++ {
		dp.Handle(Outgoing, buildUDPv4(t, clientNsIP, serverVIP, 40000, 53, []byte("x")))
	}

	if got := dp.queuedFor(mustAddr(serverVIP)); got != maxReplayPacketsPerVIP {
		t.Errorf("queued %d packets; want the cap of %d", got, maxReplayPacketsPerVIP)
	}
	_, bytes := dp.replayState()
	if bytes > maxReplayBytes {
		t.Errorf("retained %d bytes; cap is %d", bytes, maxReplayBytes)
	}
	// Retention is proportional to the packets held, not to the 64KiB read
	// buffer they arrived in.
	if bytes > maxReplayPacketsPerVIP*2048 {
		t.Errorf("retained %d bytes for %d small packets; retention should track packet length",
			bytes, maxReplayPacketsPerVIP)
	}
}

// TestReplayFailedResolutionReleasesQueue checks that an attempt finishing
// without resolving anything drops its queue rather than re-queueing it
// forever.
func TestReplayFailedResolutionReleasesQueue(t *testing.T) {
	dp, _, resolving := coldDatapath(t)

	for i := 0; i < 4; i++ {
		dp.Handle(Outgoing, buildUDPv4(t, clientNsIP, serverVIP, 40000, 53, []byte("x")))
	}
	resolving.release(mustAddr(serverVIP), false)

	waitFor(t, "the failed queue to be released", func() bool {
		queues, bytes := dp.replayState()
		return queues == 0 && bytes == 0
	})
}

// TestReplayHoldsLaterFragmentsOfAColdDatagram checks that both fragments of
// a datagram sent to an unresolved Service IP queue for replay, not just the
// first.
func TestReplayHoldsLaterFragmentsOfAColdDatagram(t *testing.T) {
	dp, sink, resolving := coldDatapath(t)
	vip := mustAddr(serverVIP)

	wire := buildUDPv4(t, clientNsIP, serverVIP, 40000, 53, largePayload(2000))
	first, later := fragmentIPv4(t, wire, 1024)
	laterPayloadBefore := append([]byte(nil), later[20:]...)

	dp.Handle(Outgoing, first)
	dp.Handle(Outgoing, later)

	if got := dp.queuedFor(vip); got != 2 {
		t.Fatalf("%d packets queued behind the unresolved Service IP; want both fragments", got)
	}

	resolving.release(vip, true)

	waitFor(t, "the replay queue to be released", func() bool {
		queues, bytes := dp.replayState()
		return queues == 0 && bytes == 0
	})

	actions := sink.drain()
	if len(actions) != 2 {
		t.Fatalf("replay emitted %d actions; want 2", len(actions))
	}
	if actions[0].Kind != ActionForward || actions[1].Kind != ActionForward {
		t.Fatalf("replay actions = %v, %v; want both ActionForward", actions[0].Kind, actions[1].Kind)
	}

	gotFirst := parseTestPacket(t, actions[0].Packet)
	if !gotFirst.IsFirstFragment() {
		t.Fatal("the first fragment must replay before the rest")
	}
	gotLater, ok := iputils.Parse(actions[1].Packet)
	if !ok {
		t.Fatal("the later fragment was never forwarded")
	}
	if gotLater.IsFirstFragment() {
		t.Fatal("expected the later fragment second")
	}

	// Both must be addressed identically, or the far end cannot reassemble
	// them into one datagram.
	if gotLater.SrcIP() != gotFirst.SrcIP() || gotLater.DstIP() != gotFirst.DstIP() {
		t.Errorf("fragments forwarded as %s -> %s and %s -> %s; they must match",
			gotFirst.SrcIP(), gotFirst.DstIP(), gotLater.SrcIP(), gotLater.DstIP())
	}
	if gotFirst.SrcIP() != mustAddr(clientInstIP) || gotFirst.DstIP() != mustAddr(serverNsIP) {
		t.Errorf("translated to %s -> %s; want %s -> %s",
			gotFirst.SrcIP(), gotFirst.DstIP(), clientInstIP, serverNsIP)
	}
	if got := ipv4HeaderChecksum(gotLater.Bytes()[:20]); got != 0 {
		t.Errorf("later fragment header checksum does not verify (residual %#04x)", got)
	}
	if !bytes.Equal(gotLater.Bytes()[20:], laterPayloadBefore) {
		t.Error("later fragment payload was modified")
	}
}

// TestLaterFragmentNeverStartsAResolution covers the fact that a later fragment carries no
// transport ports, so it cannot drive a route lookup of its own. With nothing
// already waiting on its destination there is no first fragment for it to stay
// consistent with, and it must simply be dropped.
func TestLaterFragmentNeverStartsAResolution(t *testing.T) {
	dp, _, _ := coldDatapath(t)

	wire := buildUDPv4(t, clientNsIP, serverVIP, 40000, 53, largePayload(2000))
	_, later := fragmentIPv4(t, wire, 1024)

	dp.Handle(Outgoing, later)

	if queues, bytes := dp.replayState(); queues != 0 || bytes != 0 {
		t.Errorf("a lone later fragment created %d replay queues holding %d bytes; want none",
			queues, bytes)
	}
}

// TestReplayFragmentQueueRespectsBounds checks that fragments queue through
// the same bounded FIFO as everything else, so a flood cannot grow it without
// limit.
func TestReplayFragmentQueueRespectsBounds(t *testing.T) {
	dp, _, _ := coldDatapath(t)

	wire := buildUDPv4(t, clientNsIP, serverVIP, 40000, 53, largePayload(2000))
	first, later := fragmentIPv4(t, wire, 1024)

	dp.Handle(Outgoing, first)
	for range maxReplayPacketsPerVIP * 3 {
		dp.Handle(Outgoing, append([]byte(nil), later...))
	}

	if got := dp.queuedFor(mustAddr(serverVIP)); got != maxReplayPacketsPerVIP {
		t.Errorf("queued %d packets; want the cap of %d", got, maxReplayPacketsPerVIP)
	}
	if _, bytes := dp.replayState(); bytes > maxReplayBytes {
		t.Errorf("retained %d bytes; cap is %d", bytes, maxReplayBytes)
	}
}
