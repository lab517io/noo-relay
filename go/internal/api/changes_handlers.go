package api

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"

	"github.com/lab517/noo-relay/internal/store"
)

// Packet identity travels in headers so the body can stay raw ciphertext.
const (
	headerOriginDevice = "X-Noo-Origin-Device"
	headerCounter      = "X-Noo-Counter"
	// Compaction: the uploader declares which packets this one supersedes,
	// as JSON {device_id: counter} (docs/P2P_SYNC_COMPACTION.md §4.3). Out of
	// band because the relay cannot read the payload it describes.
	headerSnapshotCovers = "X-Noo-Snapshot-Covers"
	// The attachment blobs a packet references, comma-separated content ids
	// (docs/P2P_SYNC.md §3.5). Out of band for the same reason as coverage:
	// the relay must know what a packet keeps alive without reading it.
	headerBlobs = "X-Noo-Blobs"
)

type vectorResponse struct {
	Vectors map[string]int64 `json:"vectors"`
}

type uploadResponse struct {
	Stored bool `json:"stored"`
	// Present only when the upload carried a coverage declaration.
	Pruned *store.PruneResult `json:"pruned,omitempty"`
}

// packetResponse carries the payload base64-encoded: pulls return JSON, while
// uploads take the raw bytes. The asymmetry is deliberate and part of the
// wire contract.
type packetResponse struct {
	OriginDeviceID string `json:"origin_device_id"`
	Counter        int64  `json:"counter"`
	Payload        []byte `json:"payload"`
	StoredAt       string `json:"stored_at"`
}

type pullResponse struct {
	Changes []packetResponse `json:"changes"`
	HasMore bool             `json:"has_more"`
}

func (s *Server) getVector(w http.ResponseWriter, r *http.Request) {
	vector, err := s.store.UserVector(r.Context(), callerFrom(r.Context()).UserID)
	if err != nil {
		writeServerError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, vectorResponse{Vectors: vector})
}

// uploadPacket stores one packet under its (origin device, counter) identity.
//
// The uploader is not required to be the origin device: clients also carry
// packets for their user's other devices (gossip). The relay never inspects
// payloads — clients verify origin via the AEAD AAD.
//
// Insertion rule (docs/P2P_SYNC.md §5.2): a packet is accepted only as the
// next contiguous counter of its device's stream. An already-held slot is a
// no-op (200) — expected when a packet reaches the relay via more than one
// path; a counter beyond the next one is a protocol violation (409).
func (s *Server) uploadPacket(w http.ResponseWriter, r *http.Request) {
	origin := r.Header.Get(headerOriginDevice)
	if origin == "" {
		writeError(w, statusValidation, "Field required: "+headerOriginDevice+" header")
		return
	}
	rawCounter := r.Header.Get(headerCounter)
	if rawCounter == "" {
		writeError(w, statusValidation, "Field required: "+headerCounter+" header")
		return
	}
	counter, err := strconv.ParseInt(rawCounter, 10, 64)
	if err != nil {
		writeError(w, statusValidation, headerCounter+" must be an integer")
		return
	}

	// covers stays nil when the header is absent, and is non-nil (possibly
	// empty) when the upload declared coverage — which is what decides both
	// the is_snapshot flag and whether the response carries a pruned object.
	// A literal "null" unmarshals without error and would leave it nil, so a
	// declaration that says nothing is rejected rather than silently dropped.
	var covers map[string]int64
	if raw := r.Header.Get(headerSnapshotCovers); raw != "" {
		if err := json.Unmarshal([]byte(raw), &covers); err != nil || covers == nil {
			writeError(w, statusValidation,
				"Invalid "+headerSnapshotCovers+": expected JSON object of device_id -> counter")
			return
		}
	}

	// Reject an oversized upload by Content-Length before buffering the body.
	// MaxBytesReader below still guards a chunked or absent Content-Length.
	if r.ContentLength > s.cfg.MaxPayloadSize {
		writeError(w, http.StatusRequestEntityTooLarge, s.tooLargeDetail())
		return
	}

	payload, err := io.ReadAll(http.MaxBytesReader(w, r.Body, s.cfg.MaxPayloadSize))
	if err != nil {
		var toolarge *http.MaxBytesError
		if errors.As(err, &toolarge) {
			writeError(w, http.StatusRequestEntityTooLarge, s.tooLargeDetail())
			return
		}
		writeError(w, http.StatusBadRequest, "Could not read request body")
		return
	}
	if len(payload) == 0 {
		writeError(w, http.StatusBadRequest, "Empty payload")
		return
	}
	// Checked after the identity headers so a malformed counter is a
	// validation error, while a well-formed but invalid one is a 400.
	if counter < 1 {
		writeError(w, http.StatusBadRequest, "Counter must be a positive integer")
		return
	}

	userID := callerFrom(r.Context()).UserID

	// Declared blobs must already be here: "stored packet ⇒ its blobs are
	// stored" is what makes a reference in a pulled packet resolvable, and
	// what makes collecting undeclared blobs safe.
	blobIDs, ok := parseBlobHeader(r.Header.Get(headerBlobs))
	if !ok {
		writeError(w, statusValidation, "Invalid "+headerBlobs+": expected comma-separated sha256 hex ids")
		return
	}
	if len(blobIDs) > 0 {
		missing, err := s.store.MissingBlobs(r.Context(), userID, blobIDs)
		if err != nil {
			writeServerError(w, r, err)
			return
		}
		if len(missing) > 0 {
			writeError(w, http.StatusConflict, "Missing blobs: "+strings.Join(missing, ","))
			return
		}
	}

	if !s.checkPacketStorage(w, r, userID, origin, counter, int64(len(payload)), covers) {
		return
	}

	inserted, held, err := s.store.InsertPacket(r.Context(), userID, origin, counter, payload, covers != nil, blobIDs)
	if err != nil {
		writeServerError(w, r, err)
		return
	}
	if !inserted && counter > held {
		writeError(w, http.StatusConflict,
			"Non-contiguous counter "+strconv.FormatInt(counter, 10)+
				"; next expected "+strconv.FormatInt(held+1, 10))
		return
	}

	// The prune runs for an already-held slot too, so a client whose 201 was
	// lost in transit reclaims the space on its retry instead of never.
	var pruned *store.PruneResult
	if covers != nil {
		result, err := s.store.PruneCovered(r.Context(), userID, covers, origin, counter)
		if err != nil {
			writeServerError(w, r, err)
			return
		}
		pruned = &result
	}

	if inserted {
		// 201 tells the client the slot was newly filled.
		writeJSON(w, http.StatusCreated, uploadResponse{Stored: true, Pruned: pruned})
		return
	}
	// Already held: a no-op, not an error.
	writeJSON(w, http.StatusOK, uploadResponse{Stored: false, Pruned: pruned})
}

// maxHashRange caps how many counters one hash query may span, so a client
// cannot ask the relay to read a whole stream in one request. Clients check a
// recent window, not the entire history.
const maxHashRange = 500

// getStreamHashes answers what the relay holds under one device's packet
// identities: {counter: sha256-hex} over an inclusive counter range
// (docs/P2P_SYNC.md §3.3).
//
// The slot rule treats an already-held identity as a duplicate, which is right
// until a device restored from a backup re-issues counters it has already
// published — then two different packets wear one identity and the collision
// is invisible. Hashes let a client verify that the relay's copy of *its own*
// stream is the stream it thinks it published.
//
// This discloses nothing the exchange does not: they are hashes of ciphertext
// the caller may already pull, scoped to the caller's own account.
func (s *Server) getStreamHashes(w http.ResponseWriter, r *http.Request) {
	device := r.URL.Query().Get("device")
	if device == "" {
		writeError(w, statusValidation, "Field required: device")
		return
	}
	from, err := strconv.ParseInt(r.URL.Query().Get("from"), 10, 64)
	if err != nil || from < 1 {
		writeError(w, http.StatusBadRequest, "from must be a positive integer")
		return
	}
	to, err := strconv.ParseInt(r.URL.Query().Get("to"), 10, 64)
	if err != nil || to < from {
		writeError(w, http.StatusBadRequest, "to must be an integer >= from")
		return
	}
	if to-from > maxHashRange {
		to = from + maxHashRange
	}

	hashes, err := s.store.StreamHashes(
		r.Context(), callerFrom(r.Context()).UserID, device, from, to)
	if err != nil {
		writeServerError(w, r, err)
		return
	}
	// JSON object keys are strings, so counters go out as text. Absent
	// counters mean "not stored" (never fetched, or pruned) — not zero.
	out := make(map[string]string, len(hashes))
	for counter, hash := range hashes {
		out[strconv.FormatInt(counter, 10)] = hash
	}
	writeJSON(w, http.StatusOK, hashesResponse{Hashes: out})
}

type hashesResponse struct {
	Hashes map[string]string `json:"hashes"`
}

// parseBlobHeader splits the X-Noo-Blobs declaration. Absent → no blobs;
// anything that is not a well-formed id → not ok.
func parseBlobHeader(raw string) ([]string, bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, true
	}
	parts := strings.Split(raw, ",")
	ids := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if !isBlobID(p) {
			return nil, false
		}
		ids = append(ids, p)
	}
	return ids, true
}

// getUsage reports what this account occupies on the relay. Sizes only — the
// payloads stay opaque, and nothing here describes their contents.
func (s *Server) getUsage(w http.ResponseWriter, r *http.Request) {
	usage, err := s.store.UserUsage(r.Context(), callerFrom(r.Context()).UserID)
	if err != nil {
		writeServerError(w, r, err)
		return
	}
	usage.QuotaBytes = s.cfg.UserQuotaBytes
	writeJSON(w, http.StatusOK, usage)
}

func (s *Server) tooLargeDetail() string {
	return "Payload exceeds maximum size of " + strconv.FormatInt(s.cfg.MaxPayloadSize, 10) + " bytes"
}

// pullPageBytes bounds the payload bytes in one pull page. The JSON body is
// about 4/3 of this after base64. A single packet over the budget is still
// served, alone — see store.Pull.
const pullPageBytes = 16 << 20

// pullPackets is the v2 pull: everything the relay holds above the requester's
// vector. "have" is a URL-encoded JSON object {device_id: counter}.
func (s *Server) pullPackets(w http.ResponseWriter, r *http.Request) {
	have := map[string]int64{}
	if raw := r.URL.Query().Get("have"); raw != "" {
		if err := json.Unmarshal([]byte(raw), &have); err != nil {
			writeError(w, http.StatusBadRequest,
				"Invalid 'have' vector: expected JSON object of device_id -> counter")
			return
		}
	}

	limit := 100
	if raw := r.URL.Query().Get("limit"); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil || parsed < 1 || parsed > 1000 {
			writeError(w, statusValidation, "limit must be an integer between 1 and 1000")
			return
		}
		limit = parsed
	}

	packets, hasMore, err := s.store.Pull(r.Context(), callerFrom(r.Context()).UserID, have, limit, pullPageBytes)
	if err != nil {
		writeServerError(w, r, err)
		return
	}

	changes := make([]packetResponse, 0, len(packets))
	for _, p := range packets {
		changes = append(changes, packetResponse{
			OriginDeviceID: p.OriginDeviceID,
			Counter:        p.Counter,
			Payload:        p.Payload,
			StoredAt:       p.StoredAt,
		})
	}
	writeJSON(w, http.StatusOK, pullResponse{Changes: changes, HasMore: hasMore})
}
