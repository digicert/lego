package storage

import "github.com/digicert/lego/v5/certificate"

type Certificate struct {
	*certificate.Resource

	Origin string `json:"origin,omitempty"`
}
