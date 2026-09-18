package api

import (
	"errors"
	"io"
	"net/http"
	"regexp"
	"strconv"
)

// Attachment blob store (docs/P2P_SYNC.md §3.5). A blob is an encrypted
// attachment stored once per account under its content id; packets name it
// instead of carrying it. Same zero-knowledge stance as packets: the relay
// stores and serves bytes it cannot read, keyed by a hash a client computed.

var blobIDPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)

func isBlobID(id string) bool { return blobIDPattern.MatchString(id) }

// putBlob stores one blob. Idempotent: an id already held answers 200 and
// the body is discarded — a blob's bytes are fixed by its id, so there is
// nothing a second copy could change.
func (s *Server) putBlob(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("blob_id")
	if !isBlobID(id) {
		writeError(w, statusValidation, "Invalid blob id: expected 64 hex characters")
		return
	}
	if r.ContentLength > s.cfg.MaxBlobSize {
		writeError(w, http.StatusRequestEntityTooLarge, s.blobTooLargeDetail())
		return
	}
	payload, err := io.ReadAll(http.MaxBytesReader(w, r.Body, s.cfg.MaxBlobSize))
	if err != nil {
		var toolarge *http.MaxBytesError
		if errors.As(err, &toolarge) {
			writeError(w, http.StatusRequestEntityTooLarge, s.blobTooLargeDetail())
			return
		}
		writeError(w, http.StatusBadRequest, "Could not read request body")
		return
	}
	if len(payload) == 0 {
		writeError(w, http.StatusBadRequest, "Empty blob")
		return
	}

	userID := callerFrom(r.Context()).UserID
	if !s.checkBlobStorage(w, r, userID, id, int64(len(payload))) {
		return
	}
	inserted, err := s.store.PutBlob(r.Context(), userID, id, payload)
	if err != nil {
		writeServerError(w, r, err)
		return
	}
	if inserted {
		writeJSON(w, http.StatusCreated, map[string]bool{"stored": true})
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"stored": false})
}

// getBlob serves one blob as raw bytes. A HEAD lands here too (Go's mux
// routes HEAD to the GET handler) and gets the status without the body —
// which is how a client asks "do you have this?" before uploading.
func (s *Server) getBlob(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("blob_id")
	if !isBlobID(id) {
		writeError(w, statusValidation, "Invalid blob id: expected 64 hex characters")
		return
	}
	userID := callerFrom(r.Context()).UserID

	if r.Method == http.MethodHead {
		held, err := s.store.HasBlob(r.Context(), userID, id)
		if err != nil {
			writeServerError(w, r, err)
			return
		}
		if !held {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.WriteHeader(http.StatusOK)
		return
	}

	payload, err := s.store.GetBlob(r.Context(), userID, id)
	if err != nil {
		writeServerError(w, r, err)
		return
	}
	if payload == nil {
		writeError(w, http.StatusNotFound, "Blob not found")
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Length", strconv.Itoa(len(payload)))
	w.WriteHeader(http.StatusOK)
	w.Write(payload)
}

func (s *Server) blobTooLargeDetail() string {
	return "Blob exceeds maximum size of " + strconv.FormatInt(s.cfg.MaxBlobSize, 10) + " bytes"
}
