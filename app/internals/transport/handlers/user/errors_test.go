package user

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestParseServiceError(t *testing.T) {
	cases := []struct {
		name      string
		inputErr  error
		expResult *serviceError
	}{
		{name: "empty_input_error", inputErr: nil, expResult: nil},
		{name: "error_without_unwrap_function", inputErr: errors.New("err"), expResult: nil},
		{
			name:      "incorrect_status_code",
			inputErr:  errors.Join(errors.New("1"), errors.New("err")),
			expResult: nil,
		},
		{
			name:      "check_variant_err_code",
			inputErr:  errors.Join(errors.New("err"), errors.New("500")),
			expResult: &serviceError{Code: 500, Message: "err"},
		},
		{
			name:      "check_variant_code_err",
			inputErr:  errors.Join(errors.New("500"), errors.New("err")),
			expResult: &serviceError{Code: 500, Message: "err"},
		},
		{
			name:      "join_return_greater_than_2_errors",
			inputErr:  errors.Join(errors.New("500"), errors.New("err"), errors.New("err2")),
			expResult: nil,
		},
		{
			name:      "join_return_less_than_2_errors",
			inputErr:  errors.Join(errors.New("500")),
			expResult: nil,
		},
	}

	for _, tCase := range cases {
		t.Run(tCase.name, func(t *testing.T) {
			serviceError := parseServiceError(tCase.inputErr)
			require.Equal(t, tCase.expResult, serviceError)
		})
	}
}
