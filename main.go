package main

import (
    "bufio"
    "encoding/base64"
    "context"
    "crypto/rand"
    "encoding/hex"
    "encoding/json"
    "errors"
    "flag"
    "fmt"
    "io"
    "log"
    "net"
    "net/http"
    "net/url"
    "os"
    "os/exec"
    "os/signal"
    "strings"
    "syscall"
    "sync"
    "time"
    "unsafe"
)

const (
    tunDevice = "/dev/net/tun"
    tunName   = "csqtt0"
    tunMTU    = 1300
    udsName   = "csqtt_tun_uds"
    vkAPIBase = "https://api.vk.ru/method/"
    vkAPIVersion = "5.199"
)

type Config struct {
    Client        string   `json:"client"`
    Peer          string   `json:"peer"`
    Password      string   `json:"password"`
    VKHashes      []string `json:"vk_hashes"`
    Workers       int      `json:"workers"`
    Obfs          string   `json:"obfs"`
    TurnTransport string   `json:"turn_transport"`
    VKHashMode    string   `json:"vk_hash_mode"`
    VKAccessToken string   `json:"vk_access_token"`
    VKAuthMode    string   `json:"vk_auth_mode"`
    Fingerprint   string   `json:"fingerprint"`
    ClientIDs     string   `json:"client_ids"`
    DeviceID      string   `json:"device_id"`
    Generation    uint64   `json:"generation"`
    Salt          string   `json:"salt"`
    CaptchaMode   string   `json:"captcha_mode"`
    StateFile     string   `json:"state_file"`
    AllowHashRedistribution bool `json:"allow_hash_redistribution"`
    Enabled       bool     `json:"enabled"`
}

func defaults(c *Config) {
    if c.Client == "" { c.Client = "/opt/etc/csqtt/client" }
    if c.Workers == 0 { c.Workers = 18 }
    if c.Obfs == "" { c.Obfs = "video" }
    if c.TurnTransport == "" { c.TurnTransport = "udp" }
    if c.VKHashMode == "" { c.VKHashMode = "auto_api" }
    if c.VKAuthMode == "" { c.VKAuthMode = "vkcalls" }
    if c.Fingerprint == "" { c.Fingerprint = "firefox" }
    if c.CaptchaMode == "" { c.CaptchaMode = "auto" }
    if c.ClientIDs == "" { c.ClientIDs = "8202606,6287487" }
    if c.StateFile == "" { c.StateFile = "/opt/etc/csqtt/state.json" }
}

func loadConfig(path string) (Config, error) {
    b, err := os.ReadFile(path)
    if err != nil { return Config{}, err }
    var c Config
    if err := json.Unmarshal(b, &c); err != nil { return Config{}, err }
    defaults(&c)
    return c, nil
}

func createTUN(name string) (*os.File, error) {
    f, err := os.OpenFile(tunDevice, os.O_RDWR, 0)
    if err != nil { return nil, fmt.Errorf("open %s: %w", tunDevice, err) }
    var ifr struct { Name [16]byte; Flags uint16; Pad [22]byte }
    if len(name) >= len(ifr.Name) { f.Close(); return nil, fmt.Errorf("TUN name too long: %q", name) }
    copy(ifr.Name[:], name)
    ifr.Flags = syscall.IFF_TUN | syscall.IFF_NO_PI
    const tunsetiff = syscall.TUNSETIFF
    _, _, errno := syscall.Syscall(syscall.SYS_IOCTL, f.Fd(), uintptr(tunsetiff), uintptr(unsafe.Pointer(&ifr)))
    if errno != 0 { f.Close(); return nil, fmt.Errorf("TUNSETIFF %s: %w", name, errno) }
    if err := syscall.SetNonblock(int(f.Fd()), true); err != nil { f.Close(); return nil, fmt.Errorf("set nonblock: %w", err) }
    return f, nil
}

func sendFD(udsName string, tun *os.File, timeout time.Duration) error {
    fd, err := syscall.Socket(syscall.AF_UNIX, syscall.SOCK_STREAM|syscall.SOCK_CLOEXEC, 0)
    if err != nil { return fmt.Errorf("socket: %w", err) }
    defer syscall.Close(fd)
    sa := &syscall.SockaddrUnix{Name: "\x00" + udsName}
    if err := syscall.Connect(fd, sa); err != nil { return fmt.Errorf("connect @%s: %w", udsName, err) }
    oob := syscall.UnixRights(int(tun.Fd()))
    if _, err := syscall.SendmsgN(fd, []byte{1}, oob, nil, 0); err != nil { return fmt.Errorf("send TUN fd: %w", err) }
    if err := syscall.SetNonblock(fd, true); err != nil { return err }
    deadline := time.Now().Add(timeout)
    buf := make([]byte, 1)
    for time.Now().Before(deadline) {
        n, err := syscall.Read(fd, buf)
        if err == nil {
            if n == 1 && buf[0] == 1 { return nil }
            if n == 0 { return io.EOF }
            return fmt.Errorf("unexpected TUN ACK: %d/%d", n, buf[0])
        }
        if errors.Is(err, syscall.EAGAIN) || errors.Is(err, syscall.EWOULDBLOCK) { time.Sleep(25 * time.Millisecond); continue }
        return fmt.Errorf("read TUN ACK: %w", err)
    }
    return fmt.Errorf("timeout waiting for TUN ACK")
}

var ipCommand string

func resolveIPCommand() (string, error) {
    if ipCommand != "" { return ipCommand, nil }
    for _, candidate := range []string{"/opt/sbin/ip", "/opt/bin/ip", "/usr/sbin/ip", "/usr/bin/ip", "/bin/ip", "/sbin/ip"} {
        if st, err := os.Stat(candidate); err == nil && !st.IsDir() { ipCommand = candidate; return ipCommand, nil }
    }
    if p, err := exec.LookPath("ip"); err == nil { ipCommand = p; return ipCommand, nil }
    return "", fmt.Errorf("ip command not found (checked /opt/sbin/ip, /opt/bin/ip and PATH)")
}

func ip(args ...string) error {
    bin, err := resolveIPCommand()
    if err != nil { return err }
    out, err := exec.Command(bin, args...).CombinedOutput()
    if err != nil { return fmt.Errorf("%s %s: %w: %s", bin, strings.Join(args, " "), err, strings.TrimSpace(string(out))) }
    return nil
}

func configureTUN(ipaddr string) error {
    parsed := net.ParseIP(ipaddr)
    if parsed == nil || parsed.To4() == nil { return fmt.Errorf("server returned invalid IPv4 TUN address: %q", ipaddr) }
    if err := ip("link", "set", "dev", tunName, "mtu", fmt.Sprint(tunMTU)); err != nil { return err }
    if err := ip("addr", "replace", ipaddr+"/32", "dev", tunName); err != nil { return err }
    return ip("link", "set", "dev", tunName, "up")
}

type runtimeState struct { DeviceID string `json:"device_id"`; Generation uint64 `json:"generation"`; Salt string `json:"salt"` }

func randomHex(n int) (string, error) {
    b := make([]byte, n)
    if _, err := rand.Read(b); err != nil { return "", err }
    return hex.EncodeToString(b), nil
}

func loadOrCreateState(path string, c *Config) error {
    if c.DeviceID != "" && c.Generation != 0 && c.Salt != "" { return nil }
    if b, err := os.ReadFile(path); err == nil {
        var st runtimeState
        if json.Unmarshal(b, &st) == nil && st.DeviceID != "" && st.Generation != 0 && st.Salt != "" {
            c.DeviceID, c.Generation, c.Salt = st.DeviceID, st.Generation, st.Salt
            return nil
        }
    }
    deviceID, err := randomHex(16)
    if err != nil { return fmt.Errorf("generate device_id: %w", err) }
    salt, err := randomHex(16)
    if err != nil { return fmt.Errorf("generate salt: %w", err) }
    c.DeviceID, c.Generation, c.Salt = deviceID, 1, salt
    st := runtimeState{DeviceID: deviceID, Generation: 1, Salt: salt}
    b, _ := json.MarshalIndent(st, "", "  ")
    if err := os.WriteFile(path, append(b, '\n'), 0600); err != nil { return fmt.Errorf("write state: %w", err) }
    return nil
}

func autoCallCount(workers int) int {
    if workers < 9 { workers = 9 }
    if workers > 126 { workers = 126 }
    for hashes := 1; hashes <= 6; hashes++ {
        max := hashes * 27
        if max > 126 { max = 126 }
        if workers <= max { return hashes }
    }
    return 6
}

type vkStartedCall struct { CallID string; Hash string }
type vkAPIError struct { Code int `json:"error_code"`; Msg string `json:"error_msg"` }

type vkTokenInvalidError struct {
    Code int
    Msg  string
}
func (e *vkTokenInvalidError) Error() string { return fmt.Sprintf("VK token invalid: code=%d %s", e.Code, e.Msg) }
func isVKTokenInvalidError(err error) bool {
    var target *vkTokenInvalidError
    return errors.As(err, &target)
}
type vkResponse struct { Response struct { CallID string `json:"call_id"`; Hash string `json:"ok_join_link"`; Join string `json:"join_link"` } `json:"response"`; Error *vkAPIError `json:"error"` }

func extractVKHash(okJoinLink, joinLink string) (string, error) {
    candidates := []string{strings.TrimSpace(okJoinLink), strings.TrimSpace(joinLink)}
    for _, raw := range candidates {
        if raw == "" { continue }
        if u, err := url.Parse(raw); err == nil {
            if q := strings.TrimSpace(u.Query().Get("call_link")); q != "" { return q, nil }
            if q := strings.TrimSpace(u.Query().Get("join_link")); q != "" { return q, nil }
            if u.Path != "" && u.Path != "/" {
                p := strings.Trim(strings.TrimSpace(u.Path), "/")
                if p != "" && !strings.ContainsAny(p, "?=&") { return p, nil }
            }
        }
        value := strings.Trim(strings.TrimSpace(raw), "/")
        if idx := strings.IndexByte(value, '?'); idx >= 0 { value = value[:idx] }
        if value != "" && !strings.ContainsAny(value, "=&?") { return value, nil }
    }
    return "", fmt.Errorf("VK calls.start returned unusable join link/hash")
}

func vkStartCall(token string) (vkStartedCall, *vkAPIError, error) {
    form := url.Values{}
    form.Set("v", vkAPIVersion)
    req, err := http.NewRequest(http.MethodPost, vkAPIBase+"calls.start", strings.NewReader(form.Encode()))
    if err != nil { return vkStartedCall{}, nil, err }
    req.Header.Set("Authorization", "Bearer "+token)
    req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
    client := &http.Client{Timeout: 8 * time.Second}
    resp, err := client.Do(req)
    if err != nil { return vkStartedCall{}, nil, err }
    defer resp.Body.Close()
    var out vkResponse
    if err := json.NewDecoder(resp.Body).Decode(&out); err != nil { return vkStartedCall{}, nil, err }
    if out.Error != nil { return vkStartedCall{}, out.Error, nil }
    if out.Response.CallID == "" { return vkStartedCall{}, nil, fmt.Errorf("VK calls.start returned empty call_id") }
    hash, err := extractVKHash(out.Response.Hash, out.Response.Join)
    if err != nil { return vkStartedCall{}, nil, err }
    return vkStartedCall{CallID: out.Response.CallID, Hash: hash}, nil, nil
}

func finishVKCalls(token string, callIDs []string) {
    token = strings.TrimSpace(token)
    if token == "" || len(callIDs) == 0 { return }
    for _, callID := range callIDs {
        if err := vkFinishCall(token, callID); err != nil { log.Printf("VK Auto API: finish %s: %v", callID, err) }
    }
}

func clearVKAccessToken(configPath string) error {
    b, err := os.ReadFile(configPath)
    if err != nil { return err }
    var cfg map[string]any
    if err := json.Unmarshal(b, &cfg); err != nil { return err }
    delete(cfg, "vk_access_token")
    delete(cfg, "vk_user_id")
    delete(cfg, "vk_token_expires_in")
    out, err := json.MarshalIndent(cfg, "", "  ")
    if err != nil { return err }
    tmp := configPath + ".tmp"
    if err := os.WriteFile(tmp, append(out, '\n'), 0600); err != nil { return err }
    return os.Rename(tmp, configPath)
}

func vkFinishCall(token, callID string) error {
    form := url.Values{}
    form.Set("call_id", callID)
    form.Set("v", vkAPIVersion)
    req, err := http.NewRequest(http.MethodPost, vkAPIBase+"calls.forceFinish", strings.NewReader(form.Encode()))
    if err != nil { return err }
    req.Header.Set("Authorization", "Bearer "+token)
    req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
    client := &http.Client{Timeout: 8 * time.Second}
    resp, err := client.Do(req)
    if err != nil { return err }
    defer resp.Body.Close()
    var out vkResponse
    if err := json.NewDecoder(resp.Body).Decode(&out); err != nil { return err }
    if out.Error != nil { return fmt.Errorf("VK %d: %s", out.Error.Code, out.Error.Msg) }
    return nil
}

func resolveAutoAPIToken(c Config) string {
    token := strings.TrimSpace(c.VKAccessToken)
    if token == "" {
        token = strings.TrimSpace(os.Getenv("CSQTT_VK_ACCESS_TOKEN"))
    }
    if token != "" {
        return token
    }
    for _, path := range []string{"/opt/etc/csqtt/vk_token.json", "/opt/etc/csqтt/vk_token.json"} {
        b, err := os.ReadFile(path)
        if err != nil {
            continue
        }
        var saved struct {
            AccessToken string `json:"access_token"`
        }
        if json.Unmarshal(b, &saved) == nil && strings.TrimSpace(saved.AccessToken) != "" {
            return strings.TrimSpace(saved.AccessToken)
        }
    }
    return ""
}

func resolveAutoAPI(c Config) ([]string, []string, error) {
    token := resolveAutoAPIToken(c)
    if token == "" { return nil, nil, fmt.Errorf("vk_hash_mode=auto_api requires vk_access_token or CSQTT_VK_ACCESS_TOKEN") }
    count := autoCallCount(c.Workers)
    interval := 80 * time.Millisecond
    if count > 4 { interval = 202 * time.Millisecond }
    hashes := make([]string, 0, count)
    callIDs := make([]string, 0, count)
    for i := 0; i < count; i++ {
        if i > 0 { time.Sleep(interval) }
        var lastErr error
        var started vkStartedCall
        for attempt := 0; attempt < 3; attempt++ {
            call, apiErr, err := vkStartCall(token)
            if err == nil && apiErr == nil { started = call; lastErr = nil; break }
            if apiErr != nil {
                if apiErr.Code == 4 || apiErr.Code == 5 || apiErr.Code == 27 || apiErr.Code == 28 {
                    return hashes, callIDs, &vkTokenInvalidError{Code: apiErr.Code, Msg: apiErr.Msg}
                }
                lastErr = fmt.Errorf("VK API code=%d %s", apiErr.Code, apiErr.Msg)
            } else { lastErr = err }
            if attempt < 2 { time.Sleep(100 * time.Millisecond) }
        }
        if lastErr != nil { log.Printf("VK Auto API: call %d/%d failed: %v", i+1, count, lastErr); continue }
        hashes = append(hashes, started.Hash)
        callIDs = append(callIDs, started.CallID)
        log.Printf("VK Auto API: call %d/%d created", len(hashes), count)
    }
    if len(hashes) == 0 { return nil, nil, fmt.Errorf("VK Auto API created no calls") }
    return hashes, callIDs, nil
}

type vkHashRuntimeState struct {
    Hash string `json:"hash"`
    Available bool `json:"available"`
    Code int `json:"code,omitempty"`
    Reason string `json:"reason,omitempty"`
    UpdatedAt string `json:"updated_at"`
}
func maskVKHash(hash string) string {
    hash = strings.TrimSpace(hash)
    if len(hash) <= 12 { return hash }
    return hash[:6] + "…" + hash[len(hash)-4:]
}
func buildHashRuntime(c Config, unavailable map[string]bool, code int, reason, changedHash string) []vkHashRuntimeState {
    now := time.Now().UTC().Format(time.RFC3339)
    out := make([]vkHashRuntimeState, 0, len(c.VKHashes))
    for _, h := range c.VKHashes {
        item := vkHashRuntimeState{Hash: maskVKHash(h), Available: !unavailable[h], UpdatedAt: now}
        if h == changedHash { item.Code = code; item.Reason = strings.TrimSpace(reason) }
        out = append(out, item)
    }
    return out
}

func resolveAutoJSBootstrap(c Config) (string, error) {
    token := resolveAutoAPIToken(c)
    if token == "" {
        return "", fmt.Errorf("vk_hash_mode=auto_js requires VK authorization/access token")
    }
    payload, err := json.Marshal(struct {
        Token string `json:"token"`
    }{Token: token})
    if err != nil {
        return "", fmt.Errorf("encode Auto VK bootstrap: %w", err)
    }
    return base64.StdEncoding.EncodeToString(payload), nil
}

func buildClientArgs(c Config) []string {
    args := []string{"-peer", c.Peer, "-n", fmt.Sprint(c.Workers), "-tun-uds", udsName, "-vk-hash-mode", c.VKHashMode, "-obfs", c.Obfs, "-turn-transport", c.TurnTransport, "-vk-auth-mode", c.VKAuthMode, "-device-id", c.DeviceID, "-password", c.Password, "-gen", fmt.Sprint(c.Generation), "-salt", c.Salt, "-fingerprint", c.Fingerprint, "-captcha-mode", c.CaptchaMode}
    if c.ClientIDs != "" { args = append(args, "-client-ids", c.ClientIDs) }
    if c.AllowHashRedistribution { args = append(args, "-allow-hash-redistribution") }
    if len(c.VKHashes) > 0 { args = append(args, "-vk", strings.Join(c.VKHashes, ",")) }
    return args
}

type clientEvent struct {
    Kind string
    Hash string
    Code int
    Active int
    Reason string
}

func parseClientEvent(line string) (clientEvent, bool) {
    const prefix = "__CSQTT_EVENT__|"
    if !strings.HasPrefix(line, prefix) { return clientEvent{}, false }
    rest := strings.TrimPrefix(line, prefix)
    p := strings.IndexByte(rest, '|')
    if p < 0 { return clientEvent{}, false }
    var payload struct {
        Hash string `json:"hash"`
        Code int `json:"code"`
        Active int `json:"active"`
        Reason string `json:"reason"`
    }
    if err := json.Unmarshal([]byte(rest[p+1:]), &payload); err != nil { return clientEvent{}, false }
    return clientEvent{Kind: rest[:p], Hash: strings.TrimSpace(payload.Hash), Code: payload.Code, Active: payload.Active, Reason: strings.TrimSpace(payload.Reason)}, true
}

func waitForTUNCONF(lines <-chan string, timeout time.Duration) (string, error) {
    timer := time.NewTimer(timeout)
    defer timer.Stop()
    for {
        select {
        case line, ok := <-lines:
            if !ok { return "", fmt.Errorf("client stdout closed before TUNCONF") }
            if strings.Contains(line, "TUNCONF:") {
                p := strings.Index(line, "TUNCONF:")
                value := strings.TrimSpace(line[p+len("TUNCONF:"):])
                fields := strings.Split(value, ":")
                if len(fields) >= 2 && fields[0] != "" { return fields[0], nil }
            }
        case <-timer.C:
            return "", fmt.Errorf("timeout waiting for TUNCONF")
        }
    }
}

type vkRuntimeState struct {
    Authorized bool `json:"authorized"`
    Mode string `json:"mode"`
    Stage string `json:"stage"`
    CallsRequested int `json:"calls_requested"`
    CallsCreated int `json:"calls_created"`
    HashesReceived int `json:"hashes_received"`
    HashTotal int `json:"hash_total"`
    HashActive int `json:"hash_active"`
    HashUnavailable int `json:"hash_unavailable"`
    HashChanged string `json:"hash_changed,omitempty"`
    HashNotice string `json:"hash_notice,omitempty"`
    HashNoticeAt string `json:"hash_notice_at,omitempty"`
    Hashes []vkHashRuntimeState `json:"hashes,omitempty"`
    TokenInvalid bool `json:"token_invalid,omitempty"`
    TokenInvalidCode int `json:"token_invalid_code,omitempty"`
    ClientStarted bool `json:"client_started"`
    ClientRunning bool `json:"client_running"`
    Error string `json:"error,omitempty"`
    UpdatedAt string `json:"updated_at"`
}

const vkRuntimePath = "/opt/etc/csqtt/vk-runtime.json"

func writeVKRuntime(c Config, st vkRuntimeState) {
    token := strings.TrimSpace(c.VKAccessToken)
    st.Authorized = token != ""
    if st.Mode == "" { st.Mode = c.VKHashMode }
    st.UpdatedAt = time.Now().UTC().Format(time.RFC3339)
    b, err := json.MarshalIndent(st, "", "  ")
    if err != nil { return }
    tmp := vkRuntimePath + ".tmp"
    if err := os.WriteFile(tmp, append(b, '\n'), 0600); err == nil { _ = os.Rename(tmp, vkRuntimePath) }
}

func waitForManagerShutdown(ctx context.Context, reason string) {
    log.Printf("manager remains alive for web panel: %s", reason)
    <-ctx.Done()
}

var currentClientMu sync.Mutex
var currentClient *os.Process

func setCurrentClient(p *os.Process) {
    currentClientMu.Lock()
    currentClient = p
    currentClientMu.Unlock()
}

func clearCurrentClient(p *os.Process) {
    currentClientMu.Lock()
    if currentClient == p {
        currentClient = nil
    }
    currentClientMu.Unlock()
}

func stopCurrentClient() {
    currentClientMu.Lock()
    p := currentClient
    currentClientMu.Unlock()
    if p != nil {
        _ = p.Signal(syscall.SIGTERM)
    }
}

func csqttEnabled(path string) bool {
    b, err := os.ReadFile(path)
    if err != nil {
        return true
    }
    var raw struct {
        Enabled *bool `json:"enabled"`
    }
    if err := json.Unmarshal(b, &raw); err != nil || raw.Enabled == nil {
        return true
    }
    return *raw.Enabled
}

func main() {
    configPath := flag.String("config", "/opt/etc/csqtt/config.json", "config JSON")
    flag.Parse()
    log.SetFlags(log.LstdFlags | log.Lmicroseconds)
    c, err := loadConfig(*configPath)
    if err != nil { log.Fatalf("config: %v", err) }
    if c.Peer == "" || c.Password == "" { log.Fatalf("config requires peer and password") }
    if err := loadOrCreateState(c.StateFile, &c); err != nil { log.Fatalf("state: %v", err) }
    ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
    defer stop()
    managerVKHashMode := c.VKHashMode

    var autoCallIDs []string
    runtime := vkRuntimeState{Mode: c.VKHashMode, Stage: "starting"}
    if c.VKHashMode == "manual" {
        runtime.HashTotal = len(c.VKHashes)
        runtime.HashActive = len(c.VKHashes)
        runtime.Hashes = buildHashRuntime(c, map[string]bool{}, 0, "", "")
    }
    writeVKRuntime(c, runtime)
    if managerVKHashMode == "auto_api" {
        runtime.Stage = "getting_hashes"
        runtime.CallsRequested = autoCallCount(c.Workers)
        writeVKRuntime(c, runtime)
        c.VKHashes, autoCallIDs, err = resolveAutoAPI(c)
        if err != nil {
            finishVKCalls(resolveAutoAPIToken(c), autoCallIDs)
            if isVKTokenInvalidError(err) {
                var inv *vkTokenInvalidError
                if errors.As(err, &inv) {
                    runtime.TokenInvalid = true
                    runtime.TokenInvalidCode = inv.Code
                    runtime.HashNotice = fmt.Sprintf("VK токен недействителен (код %d). Требуется повторная авторизация.", inv.Code)
                    runtime.HashNoticeAt = time.Now().UTC().Format(time.RFC3339)
                }
                _ = clearVKAccessToken(*configPath)
            }
            runtime.Stage = "error"
            runtime.Error = err.Error()
            writeVKRuntime(c, runtime)
            waitForManagerShutdown(ctx, fmt.Sprintf("Auto API: %v", err))
            return
        }
        runtime.Stage = "hashes_received"
        runtime.CallsCreated = len(autoCallIDs)
        runtime.HashesReceived = len(c.VKHashes)
        writeVKRuntime(c, runtime)
        c.AllowHashRedistribution = len(autoCallIDs) < runtime.CallsRequested
        c.VKHashMode = "manual"
    } else if c.VKHashMode == "auto_js" {
        if strings.TrimSpace(resolveAutoAPIToken(c)) == "" {
            waitForManagerShutdown(ctx, "Auto VK: VK authorization/access token is required")
            return
        }
        c.VKAuthMode = "auto_js"
    } else if c.VKHashMode == "manual" && len(c.VKHashes) == 0 {
        waitForManagerShutdown(ctx, "manual vk_hash_mode requires at least one vk_hash")
        return
    }
    // Keep one TUN device across transport rebuilds. This mirrors the Android
    // TunnelManager/TunnelService recovery path while keeping the router TUN alive.
    tun, err := createTUN(tunName)
    if err != nil { log.Fatalf("TUN: %v", err) }
    defer tun.Close()
    log.Printf("TUN created: %s fd=%d mtu=%d", tunName, tun.Fd(), tunMTU)

    finishAutoCalls := func(callIDs []string) {
        finishVKCalls(resolveAutoAPIToken(c), callIDs)
    }

    unavailableManual := map[string]bool{}
    if managerVKHashMode == "manual" {
        runtime.HashTotal = len(c.VKHashes)
        runtime.HashActive = len(c.VKHashes)
        runtime.HashUnavailable = 0
        runtime.Hashes = buildHashRuntime(c, unavailableManual, 0, "", "")
        writeVKRuntime(c, runtime)
    }
    for {
        // The web panel and Keenetic's native connection switch control the same
        // persistent enabled flag. When disabled, keep the manager/web panel alive
        // but do not run the CSQTT client or keep the TUN interface up.
        if !csqttEnabled(*configPath) {
            runtime.Stage = "disabled"
            runtime.ClientRunning = false
            runtime.ClientStarted = false
            runtime.Error = ""
            writeVKRuntime(c, runtime)
            _ = ip("link", "set", "dev", tunName, "down")
            ticker := time.NewTicker(1 * time.Second)
            for !csqttEnabled(*configPath) {
                select {
                case <-ticker.C:
                case <-ctx.Done():
                    ticker.Stop()
                    return
                }
            }
            ticker.Stop()
            runtime.Stage = "starting"
            writeVKRuntime(c, runtime)
        }

        // Auto API is intentionally re-run on every recovery. The original
        // Android client uses one VK account/token and creates a fresh call set.
        if managerVKHashMode == "auto_api" {
            runtime.Mode = managerVKHashMode
            runtime.Stage = "getting_hashes"
            runtime.CallsRequested = autoCallCount(c.Workers)
            runtime.CallsCreated = 0
            runtime.HashesReceived = 0
            runtime.Error = ""
            writeVKRuntime(c, runtime)
            var callErr error
            c.VKHashes, autoCallIDs, callErr = resolveAutoAPI(c)
            if callErr != nil {
                finishAutoCalls(autoCallIDs)
                if isVKTokenInvalidError(callErr) {
                    var inv *vkTokenInvalidError
                    if errors.As(callErr, &inv) {
                        runtime.TokenInvalid = true
                        runtime.TokenInvalidCode = inv.Code
                        runtime.HashNotice = fmt.Sprintf("VK токен недействителен (код %d). Требуется повторная авторизация.", inv.Code)
                        runtime.HashNoticeAt = time.Now().UTC().Format(time.RFC3339)
                    }
                    _ = clearVKAccessToken(*configPath)
                }
                runtime.Stage = "error"
                runtime.Error = callErr.Error()
                writeVKRuntime(c, runtime)
                waitForManagerShutdown(ctx, fmt.Sprintf("Auto API: %v", callErr))
                return
            }
            runtime.Stage = "hashes_received"
            runtime.CallsCreated = len(autoCallIDs)
            runtime.HashesReceived = len(c.VKHashes)
            runtime.HashTotal = len(c.VKHashes)
            runtime.HashActive = len(c.VKHashes)
            runtime.HashUnavailable = 0
            runtime.HashNotice = ""
            runtime.HashChanged = ""
            runtime.Hashes = nil
            c.AllowHashRedistribution = len(autoCallIDs) < runtime.CallsRequested
            writeVKRuntime(c, runtime)
            c.VKHashMode = "manual"
        }

        clientConfig := c
        if managerVKHashMode == "manual" && len(unavailableManual) > 0 {
            clientConfig.VKHashes = make([]string, 0, len(c.VKHashes))
            for _, h := range c.VKHashes {
                if !unavailableManual[h] {
                    clientConfig.VKHashes = append(clientConfig.VKHashes, h)
                }
            }
            if len(clientConfig.VKHashes) == 0 {
                runtime.Stage = "error"
                runtime.Error = "all configured VK hashes are unavailable"
                runtime.HashTotal = len(c.VKHashes)
                runtime.HashActive = 0
                runtime.HashUnavailable = len(unavailableManual)
                runtime.HashNotice = "Все ручные VK хеши недоступны. Туннель остановлен — добавьте новые хеши."
                runtime.HashNoticeAt = time.Now().UTC().Format(time.RFC3339)
                runtime.Hashes = buildHashRuntime(c, unavailableManual, 0, "", "")
                writeVKRuntime(c, runtime)
                _ = ip("link", "set", "dev", tunName, "down")
                waitForManagerShutdown(ctx, runtime.Error)
                return
            }
        }
        cmd := exec.CommandContext(ctx, clientConfig.Client, buildClientArgs(clientConfig)...)
        cmd.Env = append(os.Environ(), "CSQTT_EVENTS=1")
        cmd.Stderr = os.Stderr
        clientStdin, err := cmd.StdinPipe()
        if err != nil { log.Fatalf("stdin pipe: %v", err) }
        stdout, err := cmd.StdoutPipe()
        if err != nil { clientStdin.Close(); log.Fatalf("stdout pipe: %v", err) }
        if err := cmd.Start(); err != nil {
            clientStdin.Close()
            runtime.Stage = "error"
            runtime.Error = fmt.Sprintf("start client: %v", err)
            writeVKRuntime(c, runtime)
            log.Fatalf("start client: %v", err)
        }
        setCurrentClient(cmd.Process)
        runtime.Stage = "client_started"
        runtime.ClientStarted = true
        runtime.ClientRunning = true
        writeVKRuntime(c, runtime)
        log.Printf("client started pid=%d", cmd.Process.Pid)
        clientDone := make(chan error, 1)
        go func() {
            err := cmd.Wait()
            clearCurrentClient(cmd.Process)
            clientDone <- err
        }()

        if managerVKHashMode == "auto_js" {
            bootstrap, bootstrapErr := resolveAutoJSBootstrap(c)
            if bootstrapErr != nil { _ = cmd.Process.Kill(); <-clientDone; clientStdin.Close(); log.Fatalf("Auto VK bootstrap: %v", bootstrapErr) }
            if _, writeErr := io.WriteString(clientStdin, "VK_JS_BOOTSTRAP:"+bootstrap+"\\n"); writeErr != nil { _ = cmd.Process.Kill(); <-clientDone; clientStdin.Close(); log.Fatalf("Auto VK bootstrap write: %v", writeErr) }
            log.Printf("Auto VK: bootstrap передан Rust-клиенту")
        }

        lines := make(chan string, 128)
        events := make(chan clientEvent, 64)
        clientAlerts := make(chan string, 4)
        go func() {
            defer close(lines); defer close(events); defer close(clientAlerts)
            scanner := bufio.NewScanner(stdout)
            scanner.Buffer(make([]byte, 4096), 1024*1024)
            for scanner.Scan() {
                line := scanner.Text()
                log.Printf("CLIENT %s", line)
                if managerVKHashMode == "auto_js" {
                    lower := strings.ToLower(line)
                    if strings.Contains(lower, "captcha_wait_required") ||
                        strings.Contains(lower, "captcha session rate limit reached") ||
                        strings.Contains(lower, "global lockout active") ||
                        strings.Contains(lower, "automatic captcha chain failed") ||
                        strings.Contains(lower, "manual fallback failed") {
                        select { case clientAlerts <- line: default: }
                    }
                }
                if ev, ok := parseClientEvent(line); ok { select { case events <- ev: default: } }
                select { case lines <- line: case <-ctx.Done(): return }
            }
            if err := scanner.Err(); err != nil { log.Printf("client stdout: %v", err) }
        }()

        var sent bool
        for i := 0; i < 600 && !sent; i++ {
            if err := sendFD(udsName, tun, 3*time.Second); err == nil { sent = true; log.Printf("TUN FD accepted by client"); break }
            log.Printf("waiting for client UDS")
            select {
            case err := <-clientDone:
                log.Printf("client exited before TUN FD transfer: %v", err)
                finishAutoCalls(autoCallIDs)
                waitForManagerShutdown(ctx, "client exited before TUN FD transfer")
                return
            case <-ctx.Done(): _ = cmd.Process.Kill(); <-clientDone; return
            case <-time.After(50 * time.Millisecond):
            }
        }
        if !sent { _ = cmd.Process.Kill(); <-clientDone; finishAutoCalls(autoCallIDs); waitForManagerShutdown(ctx, "could not pass TUN FD to client"); return }

        clientIP, err := waitForTUNCONF(lines, 30*time.Second)
        if err != nil {
            _ = cmd.Process.Kill(); <-clientDone; finishAutoCalls(autoCallIDs)
            runtime.ClientRunning = false; runtime.Stage = "error"; runtime.Error = err.Error(); writeVKRuntime(c, runtime)
            waitForManagerShutdown(ctx, fmt.Sprintf("TUNCONF: %v", err)); return
        }
        log.Printf("server assigned TUN IP: %s", clientIP)
        if err := configureTUN(clientIP); err != nil { _ = cmd.Process.Kill(); <-clientDone; finishAutoCalls(autoCallIDs); waitForManagerShutdown(ctx, fmt.Sprintf("configure TUN: %v", err)); return }
        log.Printf("TUN configured: %s %s/32 mtu=%d", tunName, clientIP, tunMTU)

        recovery := make(chan string, 1)
        var zeroTimer *time.Timer
        var zeroC <-chan time.Time
        activeWorkers := 0
        sessionEnded := false
        for !sessionEnded {
            select {
            case ev, ok := <-events:
                if !ok { events = nil; continue }
                switch ev.Kind {
                case "CALL_UNAVAILABLE":
                    if managerVKHashMode == "manual" && !c.AllowHashRedistribution {
                        if ev.Hash != "" { unavailableManual[ev.Hash] = true }
                        active := len(c.VKHashes) - len(unavailableManual)
                        if active < 0 { active = 0 }
                        runtime.HashTotal = len(c.VKHashes)
                        runtime.HashActive = active
                        runtime.HashUnavailable = len(unavailableManual)
                        runtime.HashChanged = maskVKHash(ev.Hash)
                        runtime.HashNotice = fmt.Sprintf("Хеш стал недоступен%s", func() string {
                            if ev.Code != 0 { return fmt.Sprintf(" · код %d", ev.Code) }
                            return ""
                        }())
                        runtime.HashNoticeAt = time.Now().UTC().Format(time.RFC3339)
                        runtime.Hashes = buildHashRuntime(c, unavailableManual, ev.Code, ev.Reason, ev.Hash)
                        writeVKRuntime(c, runtime)
                        log.Printf("VK hash unavailable in manual mode: %s code=%d active=%d/%d", ev.Hash, ev.Code, active, len(c.VKHashes))
                        if active == 0 {
                            runtime.Stage = "error"
                            runtime.Error = "all configured VK hashes are unavailable"
                            runtime.HashNotice = "Все ручные VK хеши недоступны. Туннель остановлен — добавьте новые хеши."
                            runtime.HashNoticeAt = time.Now().UTC().Format(time.RFC3339)
                            writeVKRuntime(c, runtime)
                            stopCurrentClient()
                            sessionEnded = true
                        }
                    } else if managerVKHashMode == "auto_api" || managerVKHashMode == "auto_js" {
                        runtime.HashChanged = maskVKHash(ev.Hash)
                        runtime.HashNotice = fmt.Sprintf("Автоматический VK хеш недоступен%s — получаю замену.", func() string {
                            if ev.Code != 0 { return fmt.Sprintf(" · код %d", ev.Code) }
                            return ""
                        }())
                        runtime.HashNoticeAt = time.Now().UTC().Format(time.RFC3339)
                        writeVKRuntime(c, runtime)
                        select { case recovery <- "call_unavailable": default: }
                    } else {
                        select { case recovery <- "call_unavailable": default: }
                    }
                case "ACTIVE_ZERO":
                    if zeroTimer == nil { zeroTimer = time.NewTimer(4*time.Second); zeroC = zeroTimer.C }
                case "STATS":
                    activeWorkers = ev.Active
                    if activeWorkers > 0 && zeroTimer != nil { if !zeroTimer.Stop() { select { case <-zeroTimer.C: default: } }; zeroTimer=nil; zeroC=nil }
                case "NETWORK_SUSPECT":
                    select { case recovery <- "network_suspect": default: }
                }
            case <-zeroC:
                if activeWorkers == 0 { select { case recovery <- "workers_zero_refresh": default: } }
                zeroTimer=nil; zeroC=nil
            case alert, ok := <-clientAlerts:
                if !ok { clientAlerts = nil; continue }
                runtime.Stage = "error"
                runtime.ClientRunning = false
                runtime.Error = "auto_vk_captcha_exhausted"
                runtime.HashNotice = "Авто ВК исчерпал попытки проверки CAPTCHA. Требуется ручная проверка VK."
                runtime.HashNoticeAt = time.Now().UTC().Format(time.RFC3339)
                writeVKRuntime(c, runtime)
                log.Printf("Auto VK CAPTCHA attempts exhausted: %s", alert)
                stopCurrentClient()
                sessionEnded = true
            case reason := <-recovery:
                if reason != "" { sessionEnded=true; log.Printf("transport recovery requested: %s", reason) }
            case err := <-clientDone:
                runtime.ClientRunning=false; runtime.Stage="client_stopped"
                if err != nil {
                    if runtime.Error != "auto_vk_captcha_exhausted" {
                        runtime.Error=err.Error()
                    }
                    log.Printf("client exited: %v", err)
                } else { log.Printf("client exited cleanly") }
                sessionEnded=true
            case <-ctx.Done():
                _=cmd.Process.Kill(); <-clientDone; clientStdin.Close(); finishAutoCalls(autoCallIDs); _=ip("link","set","dev",tunName,"down"); return
            }
        }
        if zeroTimer != nil { if !zeroTimer.Stop() { select { case <-zeroTimer.C: default: } } }
        select { case <-clientDone: default: _=cmd.Process.Kill(); <-clientDone }
        clientStdin.Close()
        finishAutoCalls(autoCallIDs); autoCallIDs=nil

        if managerVKHashMode == "manual" && len(unavailableManual) > 0 {
            active := len(c.VKHashes) - len(unavailableManual)
            if active <= 0 {
                runtime.Stage="error"
                runtime.Error="all configured VK hashes are unavailable"
                runtime.HashTotal=len(c.VKHashes)
                runtime.HashActive=0
                runtime.HashUnavailable=len(unavailableManual)
                runtime.HashNotice="Все ручные VK хеши недоступны. Туннель остановлен — добавьте новые хеши."
                runtime.HashNoticeAt=time.Now().UTC().Format(time.RFC3339)
                runtime.Hashes=buildHashRuntime(c, unavailableManual, 0, "", "")
                writeVKRuntime(c,runtime)
                _=ip("link","set","dev",tunName,"down")
                waitForManagerShutdown(ctx,runtime.Error)
                return
            }
        }
        runtime.Stage="restarting"; runtime.ClientRunning=false; writeVKRuntime(c,runtime)
        // Return to the top: Auto API gets a new call/hash set; Auto JS gets a
        // fresh bootstrap session; manual mode reuses only still-valid hashes.
    }
}

// Verified ARM64 Entware build path.
