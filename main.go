package main

import (
    "bufio"
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
}

func defaults(c *Config) {
    if c.Client == "" { c.Client = "/opt/etc/csqtt/client" }
    if c.Workers == 0 { c.Workers = 18 }
    if c.Obfs == "" { c.Obfs = "audio" }
    if c.TurnTransport == "" { c.TurnTransport = "udp" }
    if c.VKHashMode == "" { c.VKHashMode = "manual" }
    if c.VKAuthMode == "" { c.VKAuthMode = "vkcalls" }
    if c.Fingerprint == "" { c.Fingerprint = "chrome" }
    if c.CaptchaMode == "" { c.CaptchaMode = "auto" }
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
    if err := ip("addr", "add", ipaddr+"/32", "dev", tunName); err != nil { return err }
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
type vkResponse struct { Response struct { CallID string `json:"call_id"`; Hash string `json:"ok_join_link"`; Join string `json:"join_link"` } `json:"response"`; Error *vkAPIError `json:"error"` }

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
    hash := strings.TrimSpace(out.Response.Hash)
    if hash == "" { hash = strings.Trim(strings.TrimSpace(out.Response.Join), "/") }
    if idx := strings.LastIndex(hash, "/"); idx >= 0 { hash = hash[idx+1:] }
    if out.Response.CallID == "" || hash == "" { return vkStartedCall{}, nil, fmt.Errorf("VK calls.start returned empty call_id/hash") }
    return vkStartedCall{CallID: out.Response.CallID, Hash: hash}, nil, nil
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
                if apiErr.Code == 4 || apiErr.Code == 5 || apiErr.Code == 27 || apiErr.Code == 28 { return nil, nil, fmt.Errorf("VK token invalid: code=%d %s", apiErr.Code, apiErr.Msg) }
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

func buildClientArgs(c Config) []string {
    args := []string{"-peer", c.Peer, "-n", fmt.Sprint(c.Workers), "-tun-uds", udsName, "-vk-hash-mode", c.VKHashMode, "-obfs", c.Obfs, "-turn-transport", c.TurnTransport, "-vk-auth-mode", c.VKAuthMode, "-device-id", c.DeviceID, "-password", c.Password, "-gen", fmt.Sprint(c.Generation), "-salt", c.Salt, "-fingerprint", c.Fingerprint, "-captcha-mode", c.CaptchaMode}
    if c.ClientIDs != "" { args = append(args, "-client-ids", c.ClientIDs) }
    if len(c.VKHashes) > 0 { args = append(args, "-vk", strings.Join(c.VKHashes, ",")) }
    return args
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

func main() {
    configPath := flag.String("config", "/opt/etc/csqtt/config.json", "config JSON")
    flag.Parse()
    log.SetFlags(log.LstdFlags | log.Lmicroseconds)
    c, err := loadConfig(*configPath)
    if err != nil { log.Fatalf("config: %v", err) }
    if c.Peer == "" || c.Password == "" { log.Fatalf("config requires peer and password") }
    if err := loadOrCreateState(c.StateFile, &c); err != nil { log.Fatalf("state: %v", err) }
    var autoCallIDs []string
    if c.VKHashMode == "auto_api" {
        c.VKHashes, autoCallIDs, err = resolveAutoAPI(c)
        if err != nil { log.Fatalf("Auto API: %v", err) }
        c.VKHashMode = "manual"
    } else if c.VKHashMode == "manual" && len(c.VKHashes) == 0 {
        log.Fatalf("manual vk_hash_mode requires at least one vk_hash")
    }
    // Start the Rust client before creating the TUN FD. The upstream Android
    // client follows the same lifecycle: the Rust client first binds the persistent
    // UDS receiver, then VpnService creates the TUN and passes its FD. This avoids
    // making TUN creation part of the UDS startup race.
    ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
    defer stop()
    cmd := exec.CommandContext(ctx, c.Client, buildClientArgs(c)...)
    cmd.Env = append(os.Environ(), "CSQTT_EVENTS=1")
    cmd.Stderr = os.Stderr
    stdout, err := cmd.StdoutPipe()
    if err != nil { log.Fatalf("stdout pipe: %v", err) }
    if err := cmd.Start(); err != nil { log.Fatalf("start client: %v", err) }
    log.Printf("client started pid=%d", cmd.Process.Pid)
    clientDone := make(chan error, 1)
    go func() { clientDone <- cmd.Wait() }()
    lines := make(chan string, 128)
    go func() {
        defer close(lines)
        s := bufio.NewScanner(stdout)
        s.Buffer(make([]byte, 4096), 1024*1024)
        for s.Scan() {
            line := s.Text()
            log.Printf("CLIENT %s", line)
            select { case lines <- line: case <-ctx.Done(): return }
        }
        if err := s.Err(); err != nil { log.Printf("client stdout: %v", err) }
    }()
    // The client owns the persistent UDS receiver. Wait/retry here exactly
    // like the Android VpnService does, then pass the already-created TUN FD.
    tun, err := createTUN(tunName)
    if err != nil {
        _ = cmd.Process.Kill()
        <-clientDone
        log.Fatalf("TUN: %v", err)
    }
    defer tun.Close()
    log.Printf("TUN created: %s fd=%d mtu=%d", tunName, tun.Fd(), tunMTU)

    var sent bool
    for i := 0; i < 40 && !sent; i++ {
        if err := sendFD(udsName, tun, 3*time.Second); err == nil {
            sent = true
            log.Printf("TUN FD accepted by client")
            break
        } else {
            log.Printf("waiting for client UDS: %v", err)
            select {
            case err := <-clientDone: log.Fatalf("client exited before TUN FD transfer: %v", err)
            case <-ctx.Done(): return
            // The Rust client exits quickly if the TUN FD never arrives.
            // Retry almost immediately after a startup-time UDS refusal so we
            // can catch the listener as soon as it is bound.
            case <-time.After(10 * time.Millisecond):
            }
        }
    }
    if !sent { _ = cmd.Process.Kill(); <-clientDone; log.Fatal("could not pass TUN FD to client") }
    clientIP, err := waitForTUNCONF(lines, 30*time.Second)
    if err != nil { _ = cmd.Process.Kill(); log.Fatalf("TUNCONF: %v", err) }
    log.Printf("server assigned TUN IP: %s", clientIP)
    if err := configureTUN(clientIP); err != nil { _ = cmd.Process.Kill(); log.Fatalf("configure TUN: %v", err) }
    log.Printf("TUN configured: %s %s/32 mtu=%d", tunName, clientIP, tunMTU)
    err = <-clientDone
    if err != nil { log.Printf("client exited: %v", err) } else { log.Printf("client exited cleanly") }
    if len(autoCallIDs) > 0 {
        token := strings.TrimSpace(c.VKAccessToken)
        if token == "" { token = strings.TrimSpace(os.Getenv("CSQTT_VK_ACCESS_TOKEN")) }
        for _, callID := range autoCallIDs {
            if err := vkFinishCall(token, callID); err != nil { log.Printf("VK Auto API: finish %s: %v", callID, err) }
        }
    }
    _ = ip("link", "set", "dev", tunName, "down")
}
