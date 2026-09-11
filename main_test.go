package main

import "testing"

func TestAutoCallCountMatchesAndroidPolicy(t *testing.T) {
	cases := map[int]int{18: 1, 27: 1, 54: 2, 81: 3, 108: 4, 126: 5}
	for workers, want := range cases {
		if got := autoCallCount(workers); got != want {
			t.Fatalf("workers=%d: got %d calls, want %d", workers, got, want)
		}
	}
}
