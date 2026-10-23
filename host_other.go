//go:build !linux && !darwin

package phpcheck

import (
	"context"
	"errors"
)

func scanHost(context.Context, []Probe) (Report, error) {
	return Report{Status: Unknown, Instances: []Instance{}}, errors.New("CheckHost requires Linux or macOS")
}
