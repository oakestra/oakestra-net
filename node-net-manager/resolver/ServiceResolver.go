package resolver

import (
	"NetManager/TableEntryCache"
	"NetManager/logger"
	"NetManager/model"
	"NetManager/mqtt"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"time"
)

// ServiceLookup is the result of resolving a Service IP on the packet path.
// Entries is empty on a miss; Resolving is then a channel that closes when
// the background resolution finishes, or nil if the caller should just drop
// the packet. Generation is the table generation Entries was read under, so
// a cached route tagged with the same generation is still current.
type ServiceLookup struct {
	Entries    []TableEntryCache.TableEntry
	Generation uint64
	Resolving  <-chan struct{}
}

// Resolver takes netip.Addr rather than net.IP because the packet parser
// already produces netip.Addr, and converting back would allocate per packet.
type Resolver interface {
	// GetTableEntryByServiceIP starts a background resolution on a miss
	// instead of blocking (see resolveServiceIPOnce).
	GetTableEntryByServiceIP(addr netip.Addr) ServiceLookup
	// GetInstanceIP resolves just the instance address, not the whole table
	// entry, since copying a TableEntry per packet dominated the outgoing path.
	GetInstanceIP(addr netip.Addr, version uint8) (netip.Addr, bool)
	// TableGeneration lets the datapath tell whether a cached route is still
	// current without consulting the table itself.
	TableGeneration() uint64
}

// LocalDeployments decouples the MQTT interest bookkeeping below from the
// host/namespace management that actually tracks deployments.
type LocalDeployments interface {
	IsServiceDeployed(job string) bool
	// NamespaceIPs lists the namespace addresses of job's instances running
	// on this node. The node is the authority on these: the cluster only
	// learns them from our deployment reports, so its answers can lag behind.
	NamespaceIPs(job string) []netip.Addr
}

// ServiceResolver resolves Service IPs, Namespace IPs and Instance IPs on the
// packet path against the local translation table, kicking off background MQTT
// table queries on a miss.
type ServiceResolver struct {
	translationTable TableEntryCache.TableManager
	deployments      LocalDeployments
	// guards pendingResolves and failedServiceIPs, both lazily created
	resolveLock      sync.Mutex
	pendingResolves  map[netip.Addr]chan struct{} // ServiceIP -> closed when its in-flight resolution finishes
	failedServiceIPs map[netip.Addr]time.Time     // ServiceIP -> when resolution last failed
	// nil selects the real MQTT round trip; tests substitute a stub
	tableQuery func(netip.Addr) ([]TableEntryCache.TableEntry, error)
	// nil registers through MQTT; tests substitute a recorder instead
	interestRegistrar func(string)
	// nil selects the real MQTT round trip; tests substitute a stub
	jobQuery func(string) ([]TableEntryCache.TableEntry, error)
	// guards localRetries, lazily created: jobs with a retry loop running
	retryLock    sync.Mutex
	localRetries map[string]struct{}
	// zero selects localRetryMinDelay/localRetryMaxDelay; tests shorten them
	retryMinDelay, retryMaxDelay time.Duration
}

// New builds a ServiceResolver. deployments may be nil in tests that don't exercise MQTT interest bookkeeping.
func New(deployments LocalDeployments) *ServiceResolver {
	return &ServiceResolver{
		translationTable: TableEntryCache.NewTableManager(),
		deployments:      deployments,
	}
}

// IsServiceDeployed lets ServiceResolver satisfy mqtt's interest-registration
// interface directly; reports false rather than panicking if deployments is nil.
func (r *ServiceResolver) IsServiceDeployed(job string) bool {
	if r.deployments == nil {
		return false
	}
	return r.deployments.IsServiceDeployed(job)
}

// GetTableEntriesOnNode performs a search in the local ServiceCache for entries with the NodeIp of this node
func (r *ServiceResolver) GetTableEntriesOnNode() []TableEntryCache.TableEntry {
	ip := net.ParseIP(model.NetConfig.NodePublicAddress)
	return r.translationTable.SearchByNodeIp(ip)
}

// rate-limits retries against a ServiceIP that just failed to resolve, so a
// sustained stream of packets to an unresolvable VIP doesn't start a fresh
// MQTT round trip on every packet
const negativeResolveCacheTTL = 2 * time.Second

// caps in-flight table queries; each blocks up to 5s on MQTT, so an unbounded
// scan of the (large, especially in IPv6) proxy subnetwork would otherwise
// spawn one goroutine and broker request per destination
const maxConcurrentResolves = 32

// caps the negative cache so a scan can't grow it without bound
const maxFailedServiceIPs = 1024

// GetTableEntryByServiceIP searches the local table for addr. On a miss it
// starts resolution in the background instead of blocking here, because this
// runs on the single outgoing-packet goroutine and resolution needs an MQTT
// round trip. The returned channel signals completion so the caller can hold
// the packet and retry.
func (r *ServiceResolver) GetTableEntryByServiceIP(addr netip.Addr) ServiceLookup {
	table, generation := r.translationTable.SearchByServiceIP(addr)
	if len(table) > 0 {
		table[0].Touch() // keep the job's MQTT interest from expiring
		return ServiceLookup{Entries: table, Generation: generation}
	}
	return ServiceLookup{Resolving: r.resolveServiceIPOnce(addr)}
}

// resolveServiceIPOnce starts background resolution for key and returns a
// channel closed once it finishes. Returns nil (caller should drop the
// packet) if a recent attempt already failed or too many are in flight.
func (r *ServiceResolver) resolveServiceIPOnce(key netip.Addr) <-chan struct{} {
	r.resolveLock.Lock()

	if done, ok := r.pendingResolves[key]; ok {
		r.resolveLock.Unlock()
		return done
	}

	if failedAt, ok := r.failedServiceIPs[key]; ok {
		if time.Since(failedAt) < negativeResolveCacheTTL {
			r.resolveLock.Unlock()
			return nil
		}
	}

	if len(r.pendingResolves) >= maxConcurrentResolves {
		r.resolveLock.Unlock()
		return nil
	}

	if r.pendingResolves == nil {
		r.pendingResolves = make(map[netip.Addr]chan struct{})
	}
	done := make(chan struct{})
	r.pendingResolves[key] = done
	r.resolveLock.Unlock()

	go func() {
		err := r.resolveServiceIP(key)

		r.resolveLock.Lock()
		delete(r.pendingResolves, key)
		if err != nil {
			r.rememberFailureLocked(key)
		} else {
			delete(r.failedServiceIPs, key)
		}
		r.resolveLock.Unlock()

		close(done)
	}()

	return done
}

// rememberFailureLocked records a failed resolution, sweeping expired entries
// first and dropping the map wholesale if it's still full afterwards.
func (r *ServiceResolver) rememberFailureLocked(key netip.Addr) {
	if r.failedServiceIPs == nil {
		r.failedServiceIPs = make(map[netip.Addr]time.Time)
	}

	if len(r.failedServiceIPs) >= maxFailedServiceIPs {
		now := time.Now()
		for k, failedAt := range r.failedServiceIPs {
			if now.Sub(failedAt) >= negativeResolveCacheTTL {
				delete(r.failedServiceIPs, k)
			}
		}
		if len(r.failedServiceIPs) >= maxFailedServiceIPs {
			r.failedServiceIPs = make(map[netip.Addr]time.Time)
		}
	}

	r.failedServiceIPs[key] = time.Now()
}

// resolveServiceIP performs the blocking table query and populates the
// translation table. Must only run off the packet path. Every failure to
// resolve addr must be returned as an error, not just logged: the caller
// uses it to decide whether to arm the negative cache.
func (r *ServiceResolver) resolveServiceIP(addr netip.Addr) error {
	entryList, err := r.queryTable(addr)
	if err != nil {
		return err
	}
	if len(entryList) < 1 {
		return fmt.Errorf("table query for %s returned no instances", addr)
	}

	// validate before touching the table: ReplaceJobEntries displaces
	// whatever holds the claimed namespace IPs, so install-then-reject would
	// take a working route down with it
	jobName := entryList[0].JobName
	for i := range entryList {
		if entryList[i].JobName != jobName {
			return fmt.Errorf("table query for %s returned entries for both %s and %s",
				addr, jobName, entryList[i].JobName)
		}
	}

	// a well-formed response can still resolve the wrong address for this job
	if !resolvesServiceIP(entryList, addr) {
		return fmt.Errorf("table query for %s resolved job %s but not that address", addr, jobName)
	}

	if err := r.translationTable.ReplaceJobEntries(jobName, entryList); err != nil {
		return err
	}

	r.registerInterest(jobName)
	r.registerInterest(addr.String()) // avoid re-querying this address too
	return nil
}

func (r *ServiceResolver) registerInterest(target string) {
	if r.interestRegistrar != nil {
		r.interestRegistrar(target)
		return
	}
	mqtt.MqttRegisterInterest(target, r)
}

// resolvesServiceIP reports whether any entry actually advertises addr as one
// of its Service IPs.
func resolvesServiceIP(entries []TableEntryCache.TableEntry, addr netip.Addr) bool {
	for i := range entries {
		for _, sip := range entries[i].ServiceIP {
			if a, ok := TableEntryCache.AddrFromIP(sip.Address); ok && a == addr {
				return true
			}
			if a, ok := TableEntryCache.AddrFromIP(sip.Address_v6); ok && a == addr {
				return true
			}
		}
	}
	return false
}

func (r *ServiceResolver) queryTable(addr netip.Addr) ([]TableEntryCache.TableEntry, error) {
	if r.tableQuery != nil {
		return r.tableQuery(addr)
	}
	return tableQueryByIP(addr)
}

// GetInstanceIP Given a NamespaceIP finds the instance address identifying that
// service instance, in the requested address family. This search is local
// because RefreshServiceTable keeps an entry for every locally deployed
// instance (see retryMissingLocalInstances).
func (r *ServiceResolver) GetInstanceIP(addr netip.Addr, version uint8) (netip.Addr, bool) {
	return r.translationTable.SearchInstanceIPByNsIP(addr, version)
}

// TableGeneration returns the translation table's current generation. Takes
// no lock since it runs on every packet; see TableManager.Generation.
func (r *ServiceResolver) TableGeneration() uint64 {
	return r.translationTable.Generation()
}

// RefreshServiceTable force a table query refresh for a service. If an
// instance running on this node is still left without an entry, it keeps
// retrying in the background.
func (r *ServiceResolver) RefreshServiceTable(jobname string) {
	r.refreshJob(jobname)
	r.retryMissingLocalInstances(jobname)
}

func (r *ServiceResolver) refreshJob(jobname string) {
	logger.DebugLogger().Printf("Requested table query refresh for %s", jobname)
	entryList, err := r.queryJob(jobname)
	if err != nil {
		logger.DebugLogger().Printf("Table query refresh for %s failed: %v", jobname, err)
		return
	}
	entryList = r.keepLocalInstances(jobname, entryList)
	if err := r.translationTable.ReplaceJobEntries(jobname, entryList); err != nil {
		logger.ErrorLogger().Println(err)
	}
}

func (r *ServiceResolver) queryJob(jobname string) ([]TableEntryCache.TableEntry, error) {
	if r.jobQuery != nil {
		return r.jobQuery(jobname)
	}
	return tableQueryByJobName(jobname, true)
}

func (r *ServiceResolver) localNamespaceIPs(job string) []netip.Addr {
	if r.deployments == nil {
		return nil
	}
	return r.deployments.NamespaceIPs(job)
}

// keepLocalInstances carries over the current entry of every local instance
// of job that answer leaves out. During deploy/undeploy churn the cluster can
// answer from a view that predates the instance running here (e.g. it applies
// the undeployment of the previous incarnation after our new deployment
// report), and installing that as-is would cut the instance off the overlay:
// the outgoing path drops every packet whose source has no entry.
func (r *ServiceResolver) keepLocalInstances(job string, answer []TableEntryCache.TableEntry) []TableEntryCache.TableEntry {
	for _, addr := range r.localNamespaceIPs(job) {
		if hasNamespaceIP(answer, addr) {
			continue
		}
		current, ok := r.translationTable.SearchByNsIP(addr)
		if !ok || current.JobName != job {
			continue
		}
		// the answer may list this instance under its other address; that
		// entry is fresher, and keeping ours too would shadow it in the
		// namespace IP index
		if sharesNamespaceIP(answer, current) {
			continue
		}
		answer = append(answer, current)
	}
	return answer
}

func hasNamespaceIP(entries []TableEntryCache.TableEntry, addr netip.Addr) bool {
	for i := range entries {
		if a, ok := TableEntryCache.AddrFromIP(entries[i].Nsip); ok && a == addr {
			return true
		}
		if a, ok := TableEntryCache.AddrFromIP(entries[i].Nsipv6); ok && a == addr {
			return true
		}
	}
	return false
}

func sharesNamespaceIP(entries []TableEntryCache.TableEntry, entry TableEntryCache.TableEntry) bool {
	for _, ip := range []net.IP{entry.Nsip, entry.Nsipv6} {
		if addr, ok := TableEntryCache.AddrFromIP(ip); ok && hasNamespaceIP(entries, addr) {
			return true
		}
	}
	return false
}

func (r *ServiceResolver) missingLocalInstance(job string) bool {
	for _, addr := range r.localNamespaceIPs(job) {
		if entry, ok := r.translationTable.SearchByNsIP(addr); !ok || entry.JobName != job {
			return true
		}
	}
	return false
}

const (
	localRetryMinDelay = time.Second
	localRetryMaxDelay = 30 * time.Second
	// the first query on a deploy usually beats our deployment report to the
	// cluster, so shorter gaps only get a debug line
	localRetryErrorAfter = 30 * time.Second
)

// retryMissingLocalInstances keeps re-querying job, backing off, for as long
// as one of its instances running here has no table entry. Nothing else would
// re-query: the cluster only publishes updates_available when its own view
// changes.
func (r *ServiceResolver) retryMissingLocalInstances(job string) {
	r.retryLock.Lock()
	defer r.retryLock.Unlock()
	if _, running := r.localRetries[job]; running || !r.missingLocalInstance(job) {
		return
	}
	if r.localRetries == nil {
		r.localRetries = make(map[string]struct{})
	}
	r.localRetries[job] = struct{}{}
	go r.retryLoop(job)
}

func (r *ServiceResolver) retryLoop(job string) {
	delay, maxDelay := r.retryMinDelay, r.retryMaxDelay
	if delay <= 0 || maxDelay <= 0 {
		delay, maxDelay = localRetryMinDelay, localRetryMaxDelay
	}
	start := time.Now()
	for {
		log := logger.DebugLogger()
		if time.Since(start) >= localRetryErrorAfter {
			log = logger.ErrorLogger()
		}
		log.Printf("%s runs on this node but has no table entry for %v, re-querying in %v",
			job, time.Since(start).Round(time.Second), delay)
		time.Sleep(delay)
		r.refreshJob(job)

		// the exit check and the deregistration share the lock with
		// retryMissingLocalInstances, so a refresh that finds the entry
		// missing right after we saw it present still starts a new loop
		r.retryLock.Lock()
		if !r.missingLocalInstance(job) {
			delete(r.localRetries, job)
			r.retryLock.Unlock()
			return
		}
		r.retryLock.Unlock()
		delay = min(2*delay, maxDelay)
	}
}

func (r *ServiceResolver) RemoveServiceEntries(jobname string) {
	err := r.translationTable.RemoveByJobName(jobname)
	if err != nil {
		logger.ErrorLogger().Printf("CRITICAL-ERROR: %v", err)
	}
}

// RemoveNsIPEntry removes the translation table entry that owns ip. Used by
// the container/unikernel teardown paths.
func (r *ServiceResolver) RemoveNsIPEntry(ip net.IP) error {
	return r.translationTable.RemoveByNsip(ip)
}
