package pre

import (
	"fmt"
	"sync"
)

// ThresholdAggregator collects partial capsules and combines them once the threshold is met.
// It is safe for concurrent use.
type ThresholdAggregator struct {
	threshold int
	// collected stores partial capsules, keyed by a unique identifier of the original capsule.
	// We use the S value's string representation as the key.
	collected map[string][]*PartialCapsule
	mu        sync.Mutex
}

// NewThresholdAggregator creates a new aggregator with a given threshold.
func NewThresholdAggregator(threshold int) (*ThresholdAggregator, error) {
	if threshold <= 1 {
		return nil, fmt.Errorf("threshold must be greater than 1")
	}
	return &ThresholdAggregator{
		threshold: threshold,
		collected: make(map[string][]*PartialCapsule),
	}, nil
}

// AddPartialCapsule adds a partial capsule to the aggregator.
// If the number of collected capsules for this specific original capsule reaches the threshold,
// it combines them, returns the final capsule, and clears the collected shares.
// Otherwise, it returns a nil capsule and no error, indicating more shares are needed.
func (a *ThresholdAggregator) AddPartialCapsule(pCap *PartialCapsule) (*Capsule, error) {
	if pCap == nil || pCap.S == nil || pCap.E == nil {
		return nil, fmt.Errorf("invalid partial capsule: cannot be nil")
	}

	a.mu.Lock()
	defer a.mu.Unlock()

	key := pCap.S.String()
	for _, existingPcap := range a.collected[key] {
		if existingPcap.X.Cmp(pCap.X) == 0 {
			return nil, fmt.Errorf("duplicate partial capsule with X=%s already received", pCap.X.String())
		}
	}
	a.collected[key] = append(a.collected[key], pCap)
	if len(a.collected[key]) < a.threshold {
		return nil, nil
	}
	capsulesToCombine := a.collected[key]
	delete(a.collected, key)
	curve := capsulesToCombine[0].E.Curve
	return CombineCapsules(capsulesToCombine, curve)
}
