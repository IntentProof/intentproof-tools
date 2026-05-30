package bundle

import (
	"fmt"
	"io"
)

// ExplainFromReader verifies a bundle, replays policy when integrity passes,
// and returns human-readable output plus an exit code (0 pass, 1 fail).
func ExplainFromReader(r io.Reader, describe ReasonDescriber) (string, int, error) {
	b, err := Read(r)
	if err != nil {
		return "", 1, err
	}
	vr, err := VerifyBundle(b, nil)
	if err != nil {
		return "", 1, err
	}

	var replayView *verifierRunView
	if vr.Status == "pass" {
		run, replayErr := ReplayPolicy(b)
		if replayErr != nil {
			return FormatExplain(vr, b.Run, nil, describe), 1,
				fmt.Errorf("policy replay: %w", replayErr)
		}
		replayView = NewVerifierRunView(run.Status, run.Findings)
	}

	text := FormatExplain(vr, b.Run, replayView, describe)
	code := 0
	if vr.Status != "pass" {
		code = 1
	} else if replayView != nil && replayView.Status != "pass" {
		code = 1
	}
	return text, code, nil
}
