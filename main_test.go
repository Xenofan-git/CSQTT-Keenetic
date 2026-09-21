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

func TestDefaultsMatchOriginalCSQTT(t *testing.T) {
	var c Config
	defaults(&c)
	if c.VKHashMode != "auto_api" { t.Fatalf("VK hash mode=%q, want auto_api", c.VKHashMode) }
	if c.Obfs != "video" { t.Fatalf("obfs=%q, want video", c.Obfs) }
	if c.Fingerprint != "firefox" { t.Fatalf("fingerprint=%q, want firefox", c.Fingerprint) }
	if c.ClientIDs != "8202606,6287487" { t.Fatalf("client_ids=%q, want original pair", c.ClientIDs) }
	if c.VKAuthMode != "vkcalls" { t.Fatalf("VK auth mode=%q, want vkcalls", c.VKAuthMode) }
}


func TestVKTokenInvalidCodesAreTyped(t *testing.T) {
    for _, code := range []int{4, 5, 27, 28} {
        err := &vkTokenInvalidError{Code: code, Msg: "invalid"}
        if !isVKTokenInvalidError(err) {
            t.Fatalf("code=%d was not classified as invalid token", code)
        }
    }
    for _, code := range []int{6, 9, 15} {
        err := &vkAPIError{Code: code, Msg: "other"}
        if isVKTokenInvalidError(err) {
            t.Fatalf("code=%d was incorrectly classified as invalid token", code)
        }
    }
}

func TestManualHashRuntimeTracksUnavailableHashes(t *testing.T) {
    c := Config{VKHashes: []string{"abcdef1234567890", "1234567890abcdef", "zzzzzzzzzzzzzzzz"}}
    unavailable := map[string]bool{"1234567890abcdef": true}
    got := buildHashRuntime(c, unavailable, 27, "expired", "1234567890abcdef")
    if len(got) != 3 {
        t.Fatalf("got %d hash states, want 3", len(got))
    }
    if !got[0].Available || got[1].Available || !got[2].Available {
        t.Fatalf("unexpected availability: %+v", got)
    }
    if got[1].Code != 27 || got[1].Reason != "expired" {
        t.Fatalf("changed hash metadata not recorded: %+v", got[1])
    }
    if got[1].Hash == "1234567890abcdef" {
        t.Fatalf("runtime hash should be masked")
    }
}
