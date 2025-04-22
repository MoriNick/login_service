package user

import (
	"net/http"
	"strconv"
)

type serviceError struct {
	Code    int
	Message string
}

func (s *serviceError) Error() string {
	return s.Message
}

// Parse service errors to serviceError type.
// Input error must have Unwrap() method.
// Avaliable unwrapped errors: [code, message], [message, code]
func parseServiceError(err error) *serviceError {
	e, ok := err.(interface {
		Unwrap() []error
	})
	if !ok {
		return nil
	}

	errs := e.Unwrap()
	if len(errs) != 2 {
		return nil
	}

	se := &serviceError{}

	if code := validateAndParseStatusCode(errs[0].Error()); code == 0 {
		if code = validateAndParseStatusCode(errs[1].Error()); code == 0 {
			return nil
		}
		se.Code = code
		se.Message = errs[0].Error()
	} else {
		se.Code = code
		se.Message = errs[1].Error()
	}

	return se
}

func validateAndParseStatusCode(code string) int {
	codeInt, err := strconv.Atoi(code)
	if err != nil {
		return 0
	}
	if http.StatusText(codeInt) == "" {
		return 0
	}
	return codeInt
}
