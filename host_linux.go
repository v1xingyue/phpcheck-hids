package phpcheck

import "context"

func scanHost(ctx context.Context, probes []Probe) (Report, error) {
	return checkHost(ctx, "/proc", probes)
}
