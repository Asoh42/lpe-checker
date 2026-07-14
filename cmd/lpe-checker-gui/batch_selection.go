package main

import "lpe-checker/internal/batch"

// selectBatchResultSubset returns selected hosts in their original scan order.
// Invalid and duplicate indices are ignored. An empty valid selection returns
// ok=false so the GUI cannot export an empty batch by mistake.
func selectBatchResultSubset(results []batch.Result, selectedIndices []int) ([]batch.Result, bool) {
	selected := make(map[int]struct{}, len(selectedIndices))
	for _, index := range selectedIndices {
		if index >= 0 && index < len(results) {
			selected[index] = struct{}{}
		}
	}
	if len(selected) == 0 {
		return nil, false
	}

	subset := make([]batch.Result, 0, len(selected))
	for index, result := range results {
		if _, ok := selected[index]; ok {
			subset = append(subset, result)
		}
	}
	return subset, true
}
