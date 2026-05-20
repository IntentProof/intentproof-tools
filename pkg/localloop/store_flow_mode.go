package localloop

const (
	modeMinimal     = "minimal"
	modeOperational = "operational"
	modeFull        = "full"
	defaultMode     = modeOperational
)

func modeRank(mode string) int {
	switch mode {
	case modeMinimal:
		return 0
	case modeOperational:
		return 1
	case modeFull:
		return 2
	default:
		return 1
	}
}

func reduceFlowMode(modes []string) string {
	if len(modes) == 0 {
		return defaultMode
	}
	minMode := modes[0]
	minR := modeRank(minMode)
	for _, m := range modes[1:] {
		if r := modeRank(m); r < minR {
			minR = r
			minMode = m
		}
	}
	switch minMode {
	case modeMinimal, modeOperational, modeFull:
		return minMode
	default:
		return defaultMode
	}
}
