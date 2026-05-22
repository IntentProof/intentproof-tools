// Package acceptanceprobe holds short-lived probe code for security CI acceptance.
package acceptanceprobe

import "math/rand"

// InsecureToken deliberately uses math/rand for acceptance probing only.
func InsecureToken() int {
	return rand.Int()
}
