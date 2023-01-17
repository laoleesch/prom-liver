package remote

import (
	"encoding/json"
	"fmt"

	v1 "github.com/prometheus/client_golang/api/prometheus/v1"
	"github.com/prometheus/common/model"
)

// APIResponse json
type APIResponse struct {
	Status    string       `json:"status"`
	Data      *QueryResult `json:"data,omitempty"`
	ErrorType v1.ErrorType `json:"errorType,omitempty"`
	Error     string       `json:"error,omitempty"`
	Warnings  []string     `json:"warnings,omitempty"`
}

// QueryResult contains result data for a query.
type QueryResult struct {
	Type   model.ValueType `json:"resultType"`
	Result interface{}     `json:"result"`
}

// DefaultAPIResponse return default APIResponse success empty
func DefaultAPIResponse() APIResponse {
	return APIResponse{
		Status: "success",
		Data: &QueryResult{
			Type:   model.ValNone,
			Result: []string{},
		},
	}
}

// ErrorAPIResponse return error response
func ErrorAPIResponse(t v1.ErrorType, e error) APIResponse {
	return APIResponse{
		Status:    "error",
		ErrorType: t,
		Error:     fmt.Sprintf("%v", e),
	}
}

func (r APIResponse) String() string {
	str, _ := json.Marshal(r)
	return string(str)
}
