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
