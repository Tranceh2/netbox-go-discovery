package logger

import (
	"github.com/rs/zerolog"
)

// ZerologCronLogger is an adapter to use zerolog with cron.
type ZerologCronLogger struct {
	Logger zerolog.Logger
}

// Printf implements the interface required by cron.
func (z *ZerologCronLogger) Printf(format string, v ...interface{}) {
	// Puedes ajustar el nivel de log según prefieras.
	z.Logger.Info().Msgf(format, v...)
}
