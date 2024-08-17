package main

import (
	"guardrails/pkg/server"
	"log"
	"os"

	"go.uber.org/zap"
)

func main() {
	logger, err := zap.NewDevelopment()
	if err != nil {
		log.Printf("Unable to instantiate logger: %s", err)
		os.Exit(-1)
	}

	defer logger.Sync()

	svr := server.New(logger)
	err = svr.Start(8090)
	if err != nil {
		logger.Error("Unable to start server", zap.Error(err))
		os.Exit(-1)
	}

}
