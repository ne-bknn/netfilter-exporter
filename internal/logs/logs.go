package logs

import (
	"log/slog"
	"os"
)

func GetLogger() *slog.Logger {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	return logger
}
