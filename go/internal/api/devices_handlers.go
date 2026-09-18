package api

import (
	"net/http"

	"github.com/lab517/noo-relay/internal/store"
)

type deviceRegisterRequest struct {
	DeviceID   string `json:"device_id"`
	DeviceName string `json:"device_name"`
	Platform   string `json:"platform"`
}

func (s *Server) listDevices(w http.ResponseWriter, r *http.Request) {
	devices, err := s.store.ListDevices(r.Context(), callerFrom(r.Context()).UserID)
	if err != nil {
		writeServerError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, devices)
}

func (s *Server) registerDevice(w http.ResponseWriter, r *http.Request) {
	var body deviceRegisterRequest
	if !decodeJSON(w, r, &body) {
		return
	}
	if !validateFields(w,
		fieldRule{name: "device_id", value: body.DeviceID, required: true},
		fieldRule{name: "device_name", value: body.DeviceName, required: true},
	) {
		return
	}

	now := store.Now()
	created, err := s.store.InsertDevice(r.Context(), callerFrom(r.Context()).UserID,
		body.DeviceID, body.DeviceName, body.Platform, now)
	if err != nil {
		writeServerError(w, r, err)
		return
	}
	if !created {
		writeError(w, http.StatusConflict, "Device already registered")
		return
	}

	writeJSON(w, http.StatusCreated, store.Device{
		DeviceID:   body.DeviceID,
		DeviceName: body.DeviceName,
		Platform:   body.Platform,
		CreatedAt:  now,
		LastSeen:   now,
	})
}

// deleteDevice removes another of the user's devices, which also revokes that
// device's tokens — requireUser and refresh both re-check the row's existence.
func (s *Server) deleteDevice(w http.ResponseWriter, r *http.Request) {
	caller := callerFrom(r.Context())
	deviceID := r.PathValue("device_id")

	// Deleting the device you are authenticated as would revoke the very
	// token making the request.
	if deviceID == caller.DeviceID {
		writeError(w, http.StatusBadRequest, "Cannot delete the currently authenticated device")
		return
	}

	deleted, err := s.store.DeleteDevice(r.Context(), caller.UserID, deviceID)
	if err != nil {
		writeServerError(w, r, err)
		return
	}
	if !deleted {
		writeError(w, http.StatusNotFound, "Device not found")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
