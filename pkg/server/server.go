package server

import (
	"encoding/json"
	"fmt"
	"guardrails/pkg/gitleaks"
	"guardrails/pkg/utils"
	"io"
	"math/rand/v2"
	"net/http"

	"go.uber.org/zap"
	"golang.org/x/sync/errgroup"
)

type Server struct {
	logger *zap.Logger
}

func New(logger *zap.Logger) *Server {
	return &Server{
		logger: logger,
	}
}

func (s *Server) Start(port int) error {

	http.HandleFunc("/api/v1/safety", s.safety)

	err := http.ListenAndServe(fmt.Sprintf(":%d", port), nil)
	if err != nil {
		return err
	}

	return nil
}

func (s *Server) safety(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	reqBytes, err := io.ReadAll(r.Body)
	if err != nil {
		s.logger.Error("Error in reading request body at /safety", zap.Error(err))
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	rb := safetyRequest{}
	err = json.Unmarshal(reqBytes, &rb)
	if err != nil {
		s.logger.Error("Error in unmarshalling request body at /safety", zap.Error(err))
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	// Check use case ID data classification allowance [NOT IMPLEMENTED HERE]
	// Chunk request body
	eg, _ := errgroup.WithContext(r.Context())
	for _, chunk := range utils.Chunk(rb.Content) {

		// Spin up go routines and make callouts to Lakera
		eg.Go(func() error {
			// Make callout to Lakera [NOT IMPLEMENTED HERE]

			// logging
			s.logger.Info("Sending chunk to Lakera", zap.String("chunk", chunk))

			// Static response returned
			if rand.IntN(5) == 0 {
				return fmt.Errorf("found Prompt injection")
			}

			return nil
		})
	}

	// Spin up another go routine for Gitleaks checks
	eg.Go(func() error {
		return gitleaks.Scan(rb.Content)
	})

	err = eg.Wait()
	var resp safetyResponse
	if err != nil {
		s.logger.Error("Leaks found", zap.Error(err))
		w.WriteHeader(http.StatusNotAcceptable)
		resp = safetyResponse{
			Status: "Error",
			Detail: err.Error(),
		}
	} else {
		signedPayload, err := utils.SignContent(rb.Content)
		if err != nil {
			s.logger.Error("Unable to sign content", zap.Error(err))
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		resp = safetyResponse{
			Status: "Success",
			Detail: signedPayload,
		}
	}

	respBytes, err := json.Marshal(resp)
	if err != nil {
		s.logger.Error("Unable to construct response", zap.Error(err))
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.Write(respBytes)
}

type safetyRequest struct {
	Content string `json:"content"`
}

type safetyResponse struct {
	Status string `json:"status"`
	Detail string `json:"detail"`
}
