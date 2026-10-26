package resolver

import (
	"NetManager/TableEntryCache"
	"NetManager/mqtt"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// Regression tests for issue #248: a crash-looping job could leave its local
// instance without a translation table entry, after which every packet it
// sent into the overlay was dropped until the job happened to go idle.

const refreshJob = "app.ns.svc.svcns"

type fakeDeployments struct {
	mu    sync.Mutex
	nsIPs map[string][]netip.Addr
}

func (f *fakeDeployments) IsServiceDeployed(job string) bool {
	return len(f.NamespaceIPs(job)) > 0
}

func (f *fakeDeployments) NamespaceIPs(job string) []netip.Addr {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.nsIPs[job]
}

func (f *fakeDeployments) deploy(job string, addrs ...string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.nsIPs == nil {
		f.nsIPs = make(map[string][]netip.Addr)
	}
	for _, a := range addrs {
		f.nsIPs[job] = append(f.nsIPs[job], netip.MustParseAddr(a))
	}
}

func (f *fakeDeployments) undeploy(job string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.nsIPs, job)
}

func instanceEntry(job string, instance int, nodeIP, nsip, nsipv6, instanceIP string) TableEntryCache.TableEntry {
	entry := resolvableEntry(job, "10.30.0.1")
	entry.Instancenumber = instance
	entry.Nodeip = net.ParseIP(nodeIP)
	entry.Nsip = net.ParseIP(nsip)
	entry.Nsipv6 = net.ParseIP(nsipv6)
	entry.ServiceIP = append(entry.ServiceIP, TableEntryCache.ServiceIP{
		IpType:  TableEntryCache.InstanceNumber,
		Address: net.ParseIP(instanceIP),
	})
	return entry
}

// scriptedQuery answers job-name table queries from answers in order,
// repeating the last one once they run out.
type scriptedQuery struct {
	mu      sync.Mutex
	answers [][]TableEntryCache.TableEntry
	calls   atomic.Int32
}

func (s *scriptedQuery) query(string) ([]TableEntryCache.TableEntry, error) {
	s.calls.Add(1)
	s.mu.Lock()
	defer s.mu.Unlock()
	answer := s.answers[0]
	if len(s.answers) > 1 {
		s.answers = s.answers[1:]
	}
	return append([]TableEntryCache.TableEntry(nil), answer...), nil
}

func newRefreshResolver(deployments *fakeDeployments, query *scriptedQuery) *ServiceResolver {
	return &ServiceResolver{
		translationTable: TableEntryCache.NewTableManager(),
		deployments:      deployments,
		jobQuery:         query.query,
		retryMinDelay:    time.Millisecond,
		retryMaxDelay:    5 * time.Millisecond,
	}
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(time.Millisecond)
	}
}

func (r *ServiceResolver) retrying(job string) bool {
	r.retryLock.Lock()
	defer r.retryLock.Unlock()
	_, ok := r.localRetries[job]
	return ok
}

// The cluster can answer from a view that predates the instance running here.
// Installing that answer must not take the local instance's entry with it.
func TestStaleAnswerKeepsLocalInstanceEntry(t *testing.T) {
	local := instanceEntry(refreshJob, 0, "10.0.0.1", "10.19.1.2", "fc00::2", "10.30.1.2")
	remote := instanceEntry(refreshJob, 1, "10.0.0.9", "10.20.1.2", "fc00:1::2", "10.30.1.3")
	deployments := &fakeDeployments{}
	deployments.deploy(refreshJob, "10.19.1.2", "fc00::2")
	query := &scriptedQuery{answers: [][]TableEntryCache.TableEntry{
		{local, remote},
		{}, // e.g. the undeployment of a previous incarnation landed last
	}}
	r := newRefreshResolver(deployments, query)

	r.RefreshServiceTable(refreshJob)
	r.RefreshServiceTable(refreshJob)

	for _, nsip := range []string{"10.19.1.2", "fc00::2"} {
		if _, ok := r.GetInstanceIP(netip.MustParseAddr(nsip), 4); !ok {
			t.Errorf("local instance at %s lost its entry to a stale answer", nsip)
		}
	}
	// kept once, not once per address family
	if kept, _ := r.translationTable.SearchByServiceIP(netip.MustParseAddr("10.30.1.2")); len(kept) != 1 {
		t.Errorf("local instance carried over %d times; want 1", len(kept))
	}
	// only what this node is the authority on is kept
	if _, ok := r.translationTable.SearchByNsIP(netip.MustParseAddr("10.20.1.2")); ok {
		t.Error("remote instance survived an answer that no longer lists it")
	}
	if r.retrying(refreshJob) {
		t.Error("retry loop started although the local instance still has its entry")
	}
}

// When the answer has the local instance under one of its addresses but not
// the other, the answer's entry is the fresher one. Carrying ours over next to
// it would leave two entries claiming the shared address, and the namespace IP
// index would pick whichever came last: ours, with its stale instance IP.
func TestPartialAnswerForLocalInstanceWinsOverOldEntry(t *testing.T) {
	old := instanceEntry(refreshJob, 0, "10.0.0.1", "10.19.1.2", "fc00::2", "10.30.1.2")
	fresh := instanceEntry(refreshJob, 0, "10.0.0.1", "10.19.1.2", "fc00::9", "10.30.1.9")
	deployments := &fakeDeployments{}
	deployments.deploy(refreshJob, "10.19.1.2", "fc00::2")
	query := &scriptedQuery{answers: [][]TableEntryCache.TableEntry{{old}, {fresh}}}
	r := newRefreshResolver(deployments, query)
	// fc00::2 stays unanswered, so a retry loop starts; keep it from firing
	r.retryMinDelay, r.retryMaxDelay = time.Hour, time.Hour

	r.RefreshServiceTable(refreshJob)
	r.RefreshServiceTable(refreshJob)

	got, ok := r.GetInstanceIP(netip.MustParseAddr("10.19.1.2"), 4)
	if want := netip.MustParseAddr("10.30.1.9"); !ok || got != want {
		t.Errorf("instance IP for 10.19.1.2 = %v (found %v); want %v from the fresh answer", got, ok, want)
	}
	if !r.retrying(refreshJob) {
		t.Error("no retry for fc00::2, which the answer left without an entry")
	}
}

// The sequence from the issue: the deploy's own query comes back empty because
// the cluster hasn't processed our deployment report yet, and the cluster
// then has no reason to publish another update.
func TestEmptyAnswerOnDeployIsRetriedUntilLocalInstanceKnown(t *testing.T) {
	local := instanceEntry(refreshJob, 0, "10.0.0.1", "10.19.1.2", "fc00::2", "10.30.1.2")
	deployments := &fakeDeployments{}
	deployments.deploy(refreshJob, "10.19.1.2", "fc00::2")
	query := &scriptedQuery{answers: [][]TableEntryCache.TableEntry{{}, {}, {}, {local}}}
	r := newRefreshResolver(deployments, query)
	nsip := netip.MustParseAddr("10.19.1.2")

	r.RefreshServiceTable(refreshJob)
	if _, ok := r.GetInstanceIP(nsip, 4); ok {
		t.Fatal("test setup: the first answer was supposed to be empty")
	}

	waitFor(t, "the local instance's entry", func() bool {
		_, ok := r.GetInstanceIP(nsip, 4)
		return ok
	})
	waitFor(t, "the retry loop to stop", func() bool { return !r.retrying(refreshJob) })

	calls := query.calls.Load()
	time.Sleep(20 * time.Millisecond)
	if extra := query.calls.Load() - calls; extra != 0 {
		t.Errorf("%d more queries after the entry was installed", extra)
	}
	if calls != 4 {
		t.Errorf("%d queries; want 4 (one per scripted answer)", calls)
	}
}

func TestRetryStopsOnceJobIsUndeployed(t *testing.T) {
	deployments := &fakeDeployments{}
	deployments.deploy(refreshJob, "10.19.1.2")
	query := &scriptedQuery{answers: [][]TableEntryCache.TableEntry{{}}}
	r := newRefreshResolver(deployments, query)

	r.RefreshServiceTable(refreshJob)
	waitFor(t, "a retry", func() bool { return query.calls.Load() >= 2 })
	deployments.undeploy(refreshJob)
	waitFor(t, "the retry loop to stop", func() bool { return !r.retrying(refreshJob) })
}

func TestConcurrentRefreshesRunOneRetryLoop(t *testing.T) {
	deployments := &fakeDeployments{}
	deployments.deploy(refreshJob, "10.19.1.2")
	query := &scriptedQuery{answers: [][]TableEntryCache.TableEntry{{}}}
	r := newRefreshResolver(deployments, query)
	r.retryMinDelay, r.retryMaxDelay = time.Hour, time.Hour

	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r.RefreshServiceTable(refreshJob)
		}()
	}
	wg.Wait()

	r.retryLock.Lock()
	loops := len(r.localRetries)
	r.retryLock.Unlock()
	if loops != 1 {
		t.Errorf("%d retry loops for one job; want 1", loops)
	}
}

// A cluster that failed to resolve the query must not look like a job with no
// instances, or the refresh installs it and wipes the job's entries.
func TestClusterErrorIsNotAnEmptyAnswer(t *testing.T) {
	entries, err := responseParser(mqtt.TableQueryResponse{
		JobName:  refreshJob,
		QueryKey: refreshJob,
		Error:    "root service manager unreachable",
	})
	if err == nil {
		t.Fatalf("parsed an error response as %d entries", len(entries))
	}
}
