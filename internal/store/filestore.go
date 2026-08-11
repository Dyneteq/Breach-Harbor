package store

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

// DefaultMaxQueueEntries bounds the on-disk upload queue so a
// standalone agent (which never drains it — nothing is enrolled to
// drain it to) can run indefinitely without unbounded disk growth.
const DefaultMaxQueueEntries = 10000

// FileStore is the AgentStore implementation: an offenders.json file,
// a queue.ndjson file, and a PID lock file, all under one data
// directory. Every mutation is written via write-to-temp-then-rename
// so a crash mid-write never corrupts the previous good state.
type FileStore struct {
	dir             string
	maxQueueEntries int

	mu        sync.Mutex
	offenders map[string]Offender // keyed by ip.String()
	queue     []Observation
	lockFile  *os.File
}

// Open acquires the data directory's lock and loads existing state. A
// second agent started against the same --data-dir fails fast here
// with a clear message rather than silently corrupting state.
func Open(dataDir string) (*FileStore, error) {
	if err := os.MkdirAll(dataDir, 0o755); err != nil {
		return nil, fmt.Errorf("create data directory %s: %w", dataDir, err)
	}
	lf, err := acquireLock(filepath.Join(dataDir, "agent.lock"))
	if err != nil {
		return nil, err
	}
	fs := &FileStore{
		dir:             dataDir,
		maxQueueEntries: DefaultMaxQueueEntries,
		offenders:       make(map[string]Offender),
		lockFile:        lf,
	}
	if err := fs.loadOffenders(); err != nil {
		fs.releaseLock()
		return nil, err
	}
	if err := fs.loadQueue(); err != nil {
		fs.releaseLock()
		return nil, err
	}
	return fs, nil
}

// acquireLock creates dataDir/agent.lock exclusively. On contention it
// checks whether the PID recorded in the existing lock is still
// alive; a dead PID's lock is treated as stale and removed, then
// retried once. A live PID's lock fails fast rather than being
// silently stolen.
func acquireLock(path string) (*os.File, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o644)
	if err == nil {
		writePID(f)
		return f, nil
	}
	if !os.IsExist(err) {
		return nil, fmt.Errorf("create lock file %s: %w", path, err)
	}

	if data, rerr := os.ReadFile(path); rerr == nil {
		if pid, perr := strconv.Atoi(strings.TrimSpace(string(data))); perr == nil && pid > 0 && processAlive(pid) {
			return nil, fmt.Errorf("another breachharbor agent (pid %d) already holds the lock at %s — stop it first, or remove the lock file if you're sure it's gone", pid, path)
		}
	}

	// Stale lock (owning process is gone): remove and retry once.
	if rerr := os.Remove(path); rerr != nil && !os.IsNotExist(rerr) {
		return nil, fmt.Errorf("stale lock at %s could not be removed: %w", path, rerr)
	}
	f, err = os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o644)
	if err != nil {
		return nil, fmt.Errorf("lock at %s still contended after removing a stale entry: %w", path, err)
	}
	writePID(f)
	return f, nil
}

func writePID(f *os.File) {
	fmt.Fprintf(f, "%d\n", os.Getpid())
	_ = f.Sync()
}

// processAlive reports whether pid is a live process, using the
// standard POSIX "signal 0" liveness probe (delivers nothing, just
// checks permission/existence).
func processAlive(pid int) bool {
	proc, err := os.FindProcess(pid)
	if err != nil {
		return false
	}
	return proc.Signal(syscall.Signal(0)) == nil
}

func (fs *FileStore) releaseLock() {
	if fs.lockFile == nil {
		return
	}
	path := fs.lockFile.Name()
	fs.lockFile.Close()
	os.Remove(path)
	fs.lockFile = nil
}

// Close releases the lock. Offender/queue state is already durable on
// disk (every mutation is written through immediately), so Close has
// nothing else to flush.
func (fs *FileStore) Close() error {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	fs.releaseLock()
	return nil
}

// --- offenders ---

type offendersFile struct {
	Offenders []Offender `json:"offenders"`
}

func (fs *FileStore) offendersPath() string { return filepath.Join(fs.dir, "offenders.json") }

func (fs *FileStore) loadOffenders() error {
	data, err := os.ReadFile(fs.offendersPath())
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("read %s: %w", fs.offendersPath(), err)
	}
	var of offendersFile
	if err := json.Unmarshal(data, &of); err != nil {
		return fmt.Errorf("corrupt offenders file %s: %w", fs.offendersPath(), err)
	}
	for _, o := range of.Offenders {
		fs.offenders[o.IP.String()] = o
	}
	return nil
}

func (fs *FileStore) saveOffendersLocked() error {
	list := make([]Offender, 0, len(fs.offenders))
	for _, o := range fs.offenders {
		list = append(list, o)
	}
	sort.Slice(list, func(i, j int) bool { return list[i].IP.String() < list[j].IP.String() })
	return atomicWriteJSON(fs.offendersPath(), offendersFile{Offenders: list})
}

func (fs *FileStore) GetOffender(ip netip.Addr) (Offender, bool, error) {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	o, ok := fs.offenders[ip.String()]
	return o, ok, nil
}

func (fs *FileStore) PutOffender(o Offender) error {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	fs.offenders[o.IP.String()] = o
	return fs.saveOffendersLocked()
}

func (fs *FileStore) ListOffenders() ([]Offender, error) {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	list := make([]Offender, 0, len(fs.offenders))
	for _, o := range fs.offenders {
		list = append(list, o)
	}
	sort.Slice(list, func(i, j int) bool {
		if list[i].Score != list[j].Score {
			return list[i].Score > list[j].Score
		}
		return list[i].IP.String() < list[j].IP.String()
	})
	return list, nil
}

func (fs *FileStore) DeleteOffender(ip netip.Addr) error {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	delete(fs.offenders, ip.String())
	return fs.saveOffendersLocked()
}

// --- queue ---

func (fs *FileStore) queuePath() string { return filepath.Join(fs.dir, "queue.ndjson") }

func (fs *FileStore) loadQueue() error {
	data, err := os.ReadFile(fs.queuePath())
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("read %s: %w", fs.queuePath(), err)
	}
	for _, line := range strings.Split(strings.TrimRight(string(data), "\n"), "\n") {
		if line == "" {
			continue
		}
		var obs Observation
		if err := json.Unmarshal([]byte(line), &obs); err != nil {
			// Skip a corrupt line rather than fail the whole load —
			// an interrupted write should cost at most one entry.
			continue
		}
		fs.queue = append(fs.queue, obs)
	}
	return nil
}

func (fs *FileStore) saveQueueLocked() error {
	var b strings.Builder
	for _, obs := range fs.queue {
		data, err := json.Marshal(obs)
		if err != nil {
			return err
		}
		b.Write(data)
		b.WriteByte('\n')
	}
	tmp := fs.queuePath() + ".tmp"
	if err := os.WriteFile(tmp, []byte(b.String()), 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, fs.queuePath())
}

func (fs *FileStore) Enqueue(obs Observation) error {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	if obs.ID == "" {
		obs.ID = newObservationID()
	}
	if obs.Time.IsZero() {
		obs.Time = time.Now()
	}
	fs.queue = append(fs.queue, obs)
	if len(fs.queue) > fs.maxQueueEntries {
		drop := len(fs.queue) - fs.maxQueueEntries
		fs.queue = fs.queue[drop:]
	}
	return fs.saveQueueLocked()
}

func (fs *FileStore) Dequeue(max int) ([]Observation, error) {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	n := max
	if n <= 0 || n > len(fs.queue) {
		n = len(fs.queue)
	}
	out := make([]Observation, n)
	copy(out, fs.queue[:n])
	return out, nil
}

func (fs *FileStore) Ack(ids []string) error {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	ack := make(map[string]bool, len(ids))
	for _, id := range ids {
		ack[id] = true
	}
	kept := fs.queue[:0]
	for _, obs := range fs.queue {
		if !ack[obs.ID] {
			kept = append(kept, obs)
		}
	}
	fs.queue = kept
	return fs.saveQueueLocked()
}

func (fs *FileStore) QueueDepth() (int, error) {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	return len(fs.queue), nil
}

func newObservationID() string {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return fmt.Sprintf("obs-%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(b[:])
}

func atomicWriteJSON(path string, v any) error {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

var _ AgentStore = (*FileStore)(nil)
