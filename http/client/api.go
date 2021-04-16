package client

import (
	"fmt"
	"time"
)

// APIResponse ...
type APIResponse struct {
	Error *Error `json:"error,omitempty"`
}

// Error ...
type Error struct {
	Message string `json:"message,omitempty"`
	Status  int    `json:"status,omitempty"`
}

func (e Error) Error() string {
	return fmt.Sprintf("%s (%d)", e.Message, e.Status)
}

// Metadata ...
type Metadata struct {
	CreatedAt time.Time `json:"createdAt"`
	UpdatedAt time.Time `json:"updatedAt"`
}
