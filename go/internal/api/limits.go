package api

import (
	"context"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/lab517/noo-relay/internal/limit"
)

// Abuse limits: who may register, how fast anyone may try passwords, how much
// bcrypt runs at once, and how much one account may store.
//
// Status codes, all carrying the usual {"detail": ...} body:
//   403 registration is closed
//   429 too many attempts; Retry-After says when to try again
//   503 too many password checks in flight; retry shortly
//   507 a storage limit — quota, stream count, or server disk
// None of them ever applies to /auth/refresh: the client drops its tokens
// when a refresh fails, so throttling it would log devices out.

// Login backoff per username: five failures are free, then each further one
// doubles the wait from 1 s, up to 5 min; an hour without failures forgets.
const (
	loginFreeFailures = 5
	loginBackoffBase  = time.Second
	loginBackoffMax   = 5 * time.Minute
	loginBackoffReset = time.Hour
)

// hashWait is how long a request may queue for a bcrypt slot before 503.
const hashWait = 10 * time.Second

type limits struct {
	authRate  *limit.Rate
	login     *limit.Backoff
	hashSlots chan struct{}
	trusted   []netip.Prefix
}

func newLimits(authPerMinute, hashes int, trusted []netip.Prefix) *limits {
	return &limits{
		authRate:  limit.NewRate(authPerMinute),
		login:     limit.NewBackoff(loginFreeFailures, loginBackoffBase, loginBackoffMax, loginBackoffReset),
		hashSlots: make(chan struct{}, hashes),
		trusted:   trusted,
	}
}

// clientIP is the address a request is rate-limited under.
//
// The TCP peer, unless it is a trusted proxy: then X-Forwarded-For is walked
// from the right — the end the proxies appended to — to the first address
// that is not itself trusted. Everything left of that is client-supplied and
// could say anything. IPv6 clients are grouped by /64, the smallest block a
// single subscriber is normally given, or rotating addresses would evade it.
func (l *limits) clientIP(r *http.Request) netip.Addr {
	peer := addrOf(r.RemoteAddr)
	if !peer.IsValid() || !l.isTrusted(peer) {
		return group(peer)
	}
	hops := strings.Split(strings.Join(r.Header.Values("X-Forwarded-For"), ","), ",")
	for i := len(hops) - 1; i >= 0; i-- {
		addr, err := netip.ParseAddr(strings.TrimSpace(hops[i]))
		if err != nil {
			break // garbage: stop at the last address a proxy vouched for
		}
		addr = addr.Unmap()
		if !l.isTrusted(addr) {
			return group(addr)
		}
		peer = addr
	}
	return group(peer)
}

func (l *limits) isTrusted(addr netip.Addr) bool {
	for _, p := range l.trusted {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}

func addrOf(remote string) netip.Addr {
	host, _, err := net.SplitHostPort(remote)
	if err != nil {
		host = remote
	}
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return netip.Addr{}
	}
	return addr.Unmap()
}

func group(addr netip.Addr) netip.Addr {
	if addr.Is6() {
		p, _ := addr.Prefix(64)
		return p.Addr()
	}
	return addr
}

// allowAuth spends one of the client IP's login/register attempts.
func (s *Server) allowAuth(w http.ResponseWriter, r *http.Request) bool {
	ok, wait := s.limits.authRate.Allow(s.limits.clientIP(r).String(), time.Now())
	if !ok {
		writeTooMany(w, wait)
	}
	return ok
}

// acquireHash waits for a bcrypt slot. The caller must call the release func.
func (s *Server) acquireHash(w http.ResponseWriter, r *http.Request) (func(), bool) {
	ctx, cancel := context.WithTimeout(r.Context(), hashWait)
	defer cancel()
	select {
	case s.limits.hashSlots <- struct{}{}:
		return func() { <-s.limits.hashSlots }, true
	case <-ctx.Done():
		w.Header().Set("Retry-After", "5")
		writeError(w, http.StatusServiceUnavailable, "Server busy; retry shortly")
		return nil, false
	}
}

func writeTooMany(w http.ResponseWriter, wait time.Duration) {
	secs := int64((wait + time.Second - 1) / time.Second)
	if secs < 1 {
		secs = 1
	}
	w.Header().Set("Retry-After", strconv.FormatInt(secs, 10))
	writeError(w, http.StatusTooManyRequests,
		"Too many attempts; retry in "+strconv.FormatInt(secs, 10)+" seconds")
}

// checkPacketStorage applies the storage limits to one packet upload. They
// apply only to new data — the next counter of a stream. An already-held
// slot is a no-op and a gap is a 409, neither of which stores anything, so
// both pass through untouched: a client must always be able to re-send
// what the relay holds, however full the account.
//
// A snapshot is credited with what its coverage frees, or an account at its
// quota could never compact its way back under it. The checks and the insert
// are not atomic, so two concurrent uploads may overshoot a quota by one
// packet each; the quota is a bound on abuse, not an accounting ledger.
func (s *Server) checkPacketStorage(w http.ResponseWriter, r *http.Request, userID int64, origin string, counter int64, size int64, covers map[string]int64) bool {
	ctx := r.Context()
	mark, err := s.store.StreamMark(ctx, userID, origin)
	if err != nil {
		writeServerError(w, r, err)
		return false
	}
	if counter != mark+1 {
		return true
	}

	if !s.checkDisk(w, r, size) {
		return false
	}

	if mark == 0 && s.cfg.MaxStreamsPerUser > 0 {
		streams, err := s.store.StreamCount(ctx, userID)
		if err != nil {
			writeServerError(w, r, err)
			return false
		}
		if streams >= s.cfg.MaxStreamsPerUser {
			writeError(w, http.StatusInsufficientStorage,
				"Too many device streams: the limit is "+strconv.FormatInt(s.cfg.MaxStreamsPerUser, 10))
			return false
		}
	}

	var freed int64
	if covers != nil && s.cfg.UserQuotaBytes > 0 {
		if freed, err = s.store.CoveredBytes(ctx, userID, covers, origin, counter); err != nil {
			writeServerError(w, r, err)
			return false
		}
	}
	return s.checkQuota(w, r, userID, size-freed)
}

// checkBlobStorage applies the limits to a blob upload; a blob already held
// stores nothing and always passes.
func (s *Server) checkBlobStorage(w http.ResponseWriter, r *http.Request, userID int64, blobID string, size int64) bool {
	if s.cfg.MinFreeDiskBytes == 0 && s.cfg.UserQuotaBytes == 0 {
		return true
	}
	held, err := s.store.HasBlob(r.Context(), userID, blobID)
	if err != nil {
		writeServerError(w, r, err)
		return false
	}
	if held {
		return true
	}
	return s.checkDisk(w, r, size) && s.checkQuota(w, r, userID, size)
}

func (s *Server) checkDisk(w http.ResponseWriter, r *http.Request, size int64) bool {
	if s.cfg.MinFreeDiskBytes == 0 {
		return true
	}
	free, err := s.store.FreeBytes()
	if err != nil {
		writeServerError(w, r, err)
		return false
	}
	if free >= 0 && free-size < s.cfg.MinFreeDiskBytes {
		writeError(w, http.StatusInsufficientStorage, "The server is out of storage space")
		return false
	}
	return true
}

// checkQuota admits growth of delta bytes (negative for a net shrink).
func (s *Server) checkQuota(w http.ResponseWriter, r *http.Request, userID int64, delta int64) bool {
	if s.cfg.UserQuotaBytes == 0 || delta <= 0 {
		return true
	}
	used, err := s.store.UserStorageBytes(r.Context(), userID)
	if err != nil {
		writeServerError(w, r, err)
		return false
	}
	if used+delta > s.cfg.UserQuotaBytes {
		writeError(w, http.StatusInsufficientStorage,
			"Storage quota exceeded: using "+strconv.FormatInt(used, 10)+
				" of "+strconv.FormatInt(s.cfg.UserQuotaBytes, 10)+" bytes")
		return false
	}
	return true
}
