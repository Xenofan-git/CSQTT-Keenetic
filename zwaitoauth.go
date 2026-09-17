package main

import (
    "log"
    "os"
    "strings"
    "time"
)

// waitForVKOAuthToken keeps the manager alive while the web panel completes
// OAuth. The main CSQTT process otherwise exits immediately when auto_api
// starts without a token, making the login page unusable on a fresh install.
func init() {
    mode := ""
    if cfg, err := readCSQTTConfig(); err == nil {
        if v, ok := cfg["vk_hash_mode"].(string); ok {
            mode = strings.TrimSpace(v)
        }
    }
    if mode != "auto_api" {
        return
    }

    if strings.TrimSpace(os.Getenv("CSQTT_VK_ACCESS_TOKEN")) != "" {
        return
    }

    if cfg, err := readCSQTTConfig(); err == nil {
        if token, ok := cfg["vk_access_token"].(string); ok && strings.TrimSpace(token) != "" {
            return
        }
    }

    log.Printf("VK OAuth: waiting for authorization in CSQTT Web Panel")
    for {
        time.Sleep(2 * time.Second)
        cfg, err := readCSQTTConfig()
        if err != nil {
            continue
        }
        token, _ := cfg["vk_access_token"].(string)
        if strings.TrimSpace(token) != "" {
            log.Printf("VK OAuth: access token received; continuing CSQTT startup")
            return
        }
        if envToken := strings.TrimSpace(os.Getenv("CSQTT_VK_ACCESS_TOKEN")); envToken != "" {
            log.Printf("VK OAuth: access token received from environment; continuing CSQTT startup")
            return
        }
    }
}
