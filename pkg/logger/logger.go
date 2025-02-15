package logger

import (
	"os"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

// InitLogger configures zerolog according to the desired format and level.
func InitLogger(logFormat string, verbose bool) {
	// Establece el formato de tiempo.
	zerolog.TimeFieldFormat = time.RFC3339

	if logFormat == "json" {
		log.Logger = log.Output(os.Stdout)
	} else {
		// Use a console writer for friendly output.
		consoleWriter := zerolog.ConsoleWriter{
			Out:        os.Stdout,
			TimeFormat: time.RFC3339,
		}
		log.Logger = log.Output(consoleWriter)
	}

	// Configure global level.
	if verbose {
		zerolog.SetGlobalLevel(zerolog.DebugLevel)
	} else {
		zerolog.SetGlobalLevel(zerolog.InfoLevel)
	}
}
