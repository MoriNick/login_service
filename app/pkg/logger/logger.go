package logger

import (
	"os"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

type Logger struct {
	*zap.Logger
}

var log *zap.Logger

func GetLogger() *Logger {
	return &Logger{log}
}

// Rewrite log instance with nop core. Use for tests.
func GetStubLogger() *Logger {
	nop := zap.WrapCore(func(zapcore.Core) zapcore.Core {
		return zapcore.NewNopCore()
	})
	log = log.WithOptions(nop)
	return &Logger{log}
}

var logLevel = map[string]zapcore.Level{
	"ERROR": zapcore.ErrorLevel,
	"INFO":  zapcore.InfoLevel,
}

func init() {
	config := zap.NewDevelopmentConfig()
	if level, ok := logLevel[os.Getenv("LOG_LEVEL")]; ok {
		config.Level.SetLevel(level)
	}

	log, _ = config.Build()
}

func (l *Logger) String(key, value string) zap.Field {
	return zap.String(key, value)
}

func (l *Logger) Int(key string, value int) zap.Field {
	return zap.Int(key, value)
}
