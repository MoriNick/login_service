package user

import (
	"errors"
	"log/slog"
	us "login/internals/services/user"
)

func parseServiceError(l *slog.Logger, reqId string, err error) (*logErrorType, string) {
	var errMessage string
	var se *us.ServiceError
	if errors.As(err, &se) {
		if se.Err != nil {
			errMessage = se.Err.Error()
		}

		return &logErrorType{
			log:     l,
			reqId:   reqId,
			name:    se.Name,
			message: errMessage,
		}, se.ClientMessage
	}

	return nil, ""
}
