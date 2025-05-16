package user

type ServiceError struct {
	Name          string
	ClientMessage string
	Err           error
}

func (se *ServiceError) Error() string {
	return se.ClientMessage
}

func (se *ServiceError) Unwrap() error {
	return se.Err
}

func newServiceClientError(message string) *ServiceError {
	return &ServiceError{Name: "ClientError", ClientMessage: message, Err: nil}
}

func newServiceInternalError(name string, err error) *ServiceError {
	return &ServiceError{Name: name, ClientMessage: "internal error", Err: err}
}
