package hub

import (
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// logSafe strips line breaks from a value that came from a request. slog
// already quotes values, this keeps log lines intact for any handler.
func logSafe(s string) string {
	return strings.NewReplacer("\n", "", "\r", "").Replace(s)
}

// Handler accepts signed reports from sidecars (POST /api/sync).
func Handler(store *Store, key []byte, log *slog.Logger) http.Handler {
	if log == nil {
		log = slog.Default()
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.Header().Set("Allow", http.MethodPost)
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, MaxBody))
		if err != nil {
			var tooBig *http.MaxBytesError
			if errors.As(err, &tooBig) {
				http.Error(w, "report too large", http.StatusRequestEntityTooLarge)
				return
			}
			http.Error(w, "cannot read report", http.StatusBadRequest)
			return
		}

		ts, err := strconv.ParseInt(r.Header.Get(HeaderTimestamp), 10, 64)
		if err != nil || !Verify(key, ts, body, r.Header.Get(HeaderSignature)) {
			log.Warn("sync report rejected: bad signature", "remote", r.RemoteAddr)
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		// Checked after the signature, so an unsigned request learns nothing.
		if skew := time.Duration(store.now().UnixMilli()-ts) * time.Millisecond; skew > MaxSkew || skew < -MaxSkew {
			log.Warn("sync report rejected: clock skew", "remote", r.RemoteAddr, "skew", skew.Round(time.Second).String())
			http.Error(w, "timestamp outside the accepted window", http.StatusUnauthorized)
			return
		}

		var rep Report
		if err := json.Unmarshal(body, &rep); err != nil {
			http.Error(w, "invalid JSON", http.StatusBadRequest)
			return
		}
		isNew, err := store.Accept(rep, ts)
		switch {
		case err == nil:
		case errors.Is(err, ErrReplay):
			http.Error(w, err.Error(), http.StatusConflict)
			return
		case errors.Is(err, ErrConflict):
			log.Warn("sync report rejected", "instance", logSafe(rep.Instance), "error", logSafe(err.Error()))
			http.Error(w, err.Error(), http.StatusConflict)
			return
		case errors.Is(err, ErrTooManyPeers):
			log.Warn("sync report rejected", "instance", logSafe(rep.Instance), "error", logSafe(err.Error()))
			http.Error(w, err.Error(), http.StatusTooManyRequests)
			return
		default:
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if isNew {
			log.Info("sidecar connected", "instance", logSafe(rep.Instance), "version", logSafe(rep.Status.Version),
				"records", len(rep.Status.Records))
		}
		w.WriteHeader(http.StatusNoContent)
	})
}
