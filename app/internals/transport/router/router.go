package router

import (
	"net/http"
)

func NewRouter() *http.ServeMux {
	return http.NewServeMux()
}
