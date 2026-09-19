package main

import (
    "context"
    "crypto/rand"
    "encoding/hex"
    "encoding/json"
    "fmt"
    "io"
    "net/http"
    "os"
    "os/exec"
    "path/filepath"
    "runtime"
    "strings"
    "sync"
    "time"
)

const (
    csqttDeployVersion = "v2.1.9"
    csqttDeployRawScript = "https://raw.githubusercontent.com/amurcanov/csqtt/ace21228f46f056e4a2ba734f2ecb67361d401ad/app/src/main/assets/deploy.sh"
    csqttDeployReleaseAPI = "https://api.github.com/repos/amurcanov/csqtt/releases/tags/" + csqttDeployVersion
    csqttDeployDir = "/opt/etc/csqtt/deploy"
)

type DeployRequest struct {
    Host       string `json:"host"`
    SSHPort    int    `json:"ssh_port"`
    User       string `json:"user"`
    KeyPath    string `json:"key_path"`
    Password   string `json:"password"`
    PeerPort   int    `json:"peer_port"`
    WebPort    int    `json:"web_port"`
    WebUser    string `json:"web_user"`
    WebPass    string `json:"web_pass"`
    ServerPass string `json:"server_password"`
    UseForRouter bool `json:"use_for_router"`
    Version    string `json:"version"`
}

type deployAsset struct {
    Name string `json:"name"`
    URL  string `json:"browser_download_url"`
}

type deployRelease struct {
    Assets []deployAsset `json:"assets"`
}

var deployMu sync.Mutex

func deployValidate(r DeployRequest) error {
    r.Host = strings.TrimSpace(r.Host)
    r.User = strings.TrimSpace(r.User)
    if r.Host == "" || r.User == "" {
        return fmt.Errorf("host и user обязательны")
    }
    if r.SSHPort < 1 || r.SSHPort > 65535 {
        return fmt.Errorf("неверный SSH port")
    }
    if r.PeerPort < 1 || r.PeerPort > 65535 {
        return fmt.Errorf("неверный CSQTT UDP port")
    }
    if r.WebPort < 1 || r.WebPort > 65535 {
        return fmt.Errorf("неверный CSQTT WEB port")
    }
    if r.PeerPort == r.SSHPort || r.PeerPort == r.WebPort || r.WebPort == r.SSHPort || r.PeerPort == 80 {
        return fmt.Errorf("CSQTT ports должны отличаться от SSH/WEB и HTTP: выберите другие порты")
    }
    if strings.TrimSpace(r.KeyPath) == "" && strings.TrimSpace(r.Password) == "" {
        return fmt.Errorf("укажите SSH key path или пароль")
    }
    if strings.TrimSpace(r.WebUser) == "" || strings.TrimSpace(r.WebPass) == "" {
        return fmt.Errorf("нужны WEB user и WEB password")
    }
    if strings.TrimSpace(r.ServerPass) == "" {
        return fmt.Errorf("нужен пароль CSQTT сервера")
    }
    return nil
}

func deploySSHBase(r DeployRequest) ([]string, error) {
    ssh, err := exec.LookPath("ssh")
    if err != nil {
        return nil, fmt.Errorf("ssh client не найден в Entware")
    }
    args := []string{"-o", "BatchMode=yes", "-o", "ConnectTimeout=10", "-o", "ServerAliveInterval=10", "-o", "ServerAliveCountMax=2", "-o", "StrictHostKeyChecking=accept-new"}
    if r.KeyPath != "" {
        if _, err := os.Stat(r.KeyPath); err != nil {
            return nil, fmt.Errorf("SSH key %s: %w", r.KeyPath, err)
        }
        args = append(args, "-i", r.KeyPath)
    }
    args = append(args, "-p", fmt.Sprint(r.SSHPort), r.User+"@"+r.Host)
    return []string{ssh}, nil
}

func deployRunSSH(ctx context.Context, r DeployRequest, command string) ([]byte, error) {
    bins, err := deploySSHBase(r)
    if err != nil { return nil, err }
    args := []string{}
    if r.KeyPath != "" {
        args = append(args, "-o", "BatchMode=yes", "-o", "ConnectTimeout=10", "-o", "ServerAliveInterval=10", "-o", "ServerAliveCountMax=2", "-o", "StrictHostKeyChecking=accept-new", "-i", r.KeyPath)
    } else {
        if _, err := exec.LookPath("sshpass"); err != nil {
            return nil, fmt.Errorf("sshpass не найден; для парольной авторизации установите sshpass или укажите SSH key")
        }
        args = append(args, "-o", "ConnectTimeout=10", "-o", "ServerAliveInterval=10", "-o", "ServerAliveCountMax=2", "-o", "StrictHostKeyChecking=accept-new")
    }
    args = append(args, "-p", fmt.Sprint(r.SSHPort), r.User+"@"+r.Host, command)
    cmdName := bins[0]
    var cmd *exec.Cmd
    if r.KeyPath == "" {
        cmd = exec.CommandContext(ctx, "sshpass", append([]string{"-e", cmdName}, args...)...)
        cmd.Env = append(os.Environ(), "SSHPASS="+r.Password)
    } else {
        cmd = exec.CommandContext(ctx, cmdName, args...)
    }
    out, err := cmd.CombinedOutput()
    if err != nil {
        return out, fmt.Errorf("ssh: %w: %s", err, strings.TrimSpace(string(out)))
    }
    return out, nil
}

func deployCopy(ctx context.Context, r DeployRequest, localPath, remotePath string) error {
    scp, err := exec.LookPath("scp")
    if err != nil { return fmt.Errorf("scp client не найден в Entware") }
    args := []string{"-o", "ConnectTimeout=10", "-o", "ServerAliveInterval=10", "-o", "ServerAliveCountMax=2", "-o", "StrictHostKeyChecking=accept-new"}
    if r.KeyPath != "" {
        args = append(args, "-i", r.KeyPath)
    }
    args = append(args, "-P", fmt.Sprint(r.SSHPort), localPath, r.User+"@"+r.Host+":"+remotePath)
    var cmd *exec.Cmd
    if r.KeyPath == "" {
        if _, err := exec.LookPath("sshpass"); err != nil { return fmt.Errorf("sshpass не найден для SCP") }
        cmd = exec.CommandContext(ctx, "sshpass", append([]string{"-e", scp}, args...)...)
        cmd.Env = append(os.Environ(), "SSHPASS="+r.Password)
    } else {
        cmd = exec.CommandContext(ctx, scp, args...)
    }
    out, err := cmd.CombinedOutput()
    if err != nil { return fmt.Errorf("scp: %w: %s", err, strings.TrimSpace(string(out))) }
    return nil
}

func deployDownload(ctx context.Context, url, path string) error {
    req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
    if err != nil { return err }
    req.Header.Set("User-Agent", "CSQTT-Keenetic-Deploy")
    resp, err := (&http.Client{Timeout: 5 * time.Minute}).Do(req)
    if err != nil { return err }
    defer resp.Body.Close()
    if resp.StatusCode != http.StatusOK { return fmt.Errorf("download %s: HTTP %d", url, resp.StatusCode) }
    f, err := os.OpenFile(path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
    if err != nil { return err }
    defer f.Close()
    _, err = io.Copy(f, resp.Body)
    return err
}

func deployRemoteArch(ctx context.Context, r DeployRequest) (string, error) {
    out, err := deployRunSSH(ctx, r, "uname -m")
    if err != nil { return "", err }
    arch := strings.TrimSpace(string(out))
    switch arch {
    case "x86_64", "amd64":
        return "amd64", nil
    case "aarch64", "arm64":
        return "arm64", nil
    case "armv7l", "armv7", "armhf":
        return "armv7", nil
    default:
        return "", fmt.Errorf("неподдерживаемая архитектура VPS: %s", arch)
    }
}

func deployFindAsset(ctx context.Context, version, arch string) (deployAsset, error) {
    if version == "" { version = csqttDeployVersion }
    u := "https://api.github.com/repos/amurcanov/csqtt/releases/tags/" + strings.TrimPrefix(version, "v")
    req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
    if err != nil { return deployAsset{}, err }
    req.Header.Set("Accept", "application/vnd.github+json")
    req.Header.Set("User-Agent", "CSQTT-Keenetic-Deploy")
    resp, err := (&http.Client{Timeout: 20 * time.Second}).Do(req)
    if err != nil { return deployAsset{}, err }
    defer resp.Body.Close()
    if resp.StatusCode != http.StatusOK { return deployAsset{}, fmt.Errorf("GitHub release API: HTTP %d", resp.StatusCode) }
    var rel deployRelease
    if err := json.NewDecoder(resp.Body).Decode(&rel); err != nil { return deployAsset{}, err }
    aliases := map[string][]string{
        "amd64": {"amd64", "x86_64", "x86-64"},
        "arm64": {"arm64", "aarch64"},
        "armv7": {"armv7", "armv7l", "armhf", "arm32"},
    }
    for _, a := range rel.Assets {
        n := strings.ToLower(a.Name)
        if !strings.Contains(n, "server") { continue }
        for _, alias := range aliases[arch] {
            if strings.Contains(n, alias) && (strings.HasSuffix(n, ".tar.gz") || strings.HasSuffix(n, ".tgz") || !strings.Contains(n, ".")) {
                return a, nil
            }
        }
    }
    names := make([]string, 0, len(rel.Assets))
    for _, a := range rel.Assets { names = append(names, a.Name) }
    return deployAsset{}, fmt.Errorf("не найден server asset для %s; assets: %s", arch, strings.Join(names, ", "))
}

func deployRemoteQuote(s string) string {
    return "'" + strings.ReplaceAll(s, "'", "'\\''") + "'"
}

func deployRandomHex(n int) (string, error) {
    b := make([]byte, n)
    if _, err := rand.Read(b); err != nil { return "", err }
    return hex.EncodeToString(b), nil
}

func deployServer(ctx context.Context, r DeployRequest, progress func(string)) (map[string]any, error) {
    deployMu.Lock()
    defer deployMu.Unlock()
    if err := deployValidate(r); err != nil { return nil, err }
    if r.Version == "" { r.Version = csqttDeployVersion }

    if runtime.GOOS != "linux" {
        return nil, fmt.Errorf("deploy выполняется с Linux/Entware router")
    }
    if err := os.MkdirAll(csqttDeployDir, 0700); err != nil { return nil, err }
    if progress != nil { progress("Проверка SSH и архитектуры VPS…") }
    arch, err := deployRemoteArch(ctx, r)
    if err != nil { return nil, err }
    if progress != nil { progress("VPS: " + arch + ". Поиск server release…") }
    asset, err := deployFindAsset(ctx, r.Version, arch)
    if err != nil { return nil, err }

    id, err := deployRandomHex(16)
    if err != nil { return nil, err }
    work := filepath.Join(csqttDeployDir, id)
    if err := os.MkdirAll(work, 0700); err != nil { return nil, err }
    defer os.RemoveAll(work)

    script := filepath.Join(work, "deploy.sh")
    binary := filepath.Join(work, "csqtt-server")
    envFile := filepath.Join(work, "csqtt.env")
    overrides := filepath.Join(work, "deploy-overrides.json")
    if progress != nil { progress("Загрузка deploy.sh…") }
    if err := deployDownload(ctx, csqttDeployRawScript, script); err != nil { return nil, err }
    if progress != nil { progress("Загрузка CSQTT server " + asset.Name + "…") }
    if err := deployDownload(ctx, asset.URL, binary); err != nil { return nil, err }
    _ = os.Chmod(script, 0700)
    _ = os.Chmod(binary, 0700)

    deviceID, err := deployRandomHex(16)
    if err != nil { return nil, err }
    env := fmt.Sprintf("CSQTT_WEB_USER=%s\nCSQTT_WEB_PASS=%s\n", r.WebUser, r.WebPass)
    if err := os.WriteFile(envFile, []byte(env), 0600); err != nil { return nil, err }
    override := fmt.Sprintf("{\n  \"main_password\": %s,\n  \"device_id\": %s\n}\n", deployRemoteQuote(r.ServerPass), deployRemoteQuote(deviceID))
    // The installer expects JSON strings, not shell quoting.
    override = fmt.Sprintf("{\n  \"main_password\": %s,\n  \"device_id\": %s\n}\n", jsonString(r.ServerPass), jsonString(deviceID))
    if err := os.WriteFile(overrides, []byte(override), 0600); err != nil { return nil, err }

    remoteDir := "/tmp/csqtt-keenetic-deploy"
    if progress != nil { progress("Подготовка VPS…") }
    if _, err := deployRunSSH(ctx, r, "rm -rf "+deployRemoteQuote(remoteDir)+" && mkdir -p "+deployRemoteQuote(remoteDir)); err != nil { return nil, err }
    for _, pair := range [][2]string{{script, remoteDir + "/deploy.sh"}, {binary, remoteDir + "/csqtt-server"}, {envFile, remoteDir + "/csqtt.env"}, {overrides, remoteDir + "/deploy-overrides.json"}} {
        if err := deployCopy(ctx, r, pair[0], pair[1]); err != nil { return nil, err }
    }
    cmd := fmt.Sprintf("chmod 700 %s && chmod 600 %s %s && export CSQTT_PEER_PORT=%d CSQTT_SSH_PORT=%d CSQTT_WEB_PORT=%d CSQTT_DEPLOY_MODE=systemd && cp %s /tmp/.csqtt-upload-server && cp %s /tmp/.csqtt-upload-web.env && cp %s /tmp/.csqtt-upload-overrides.json && bash %s install",
        deployRemoteQuote(remoteDir+"/deploy.sh"),
        deployRemoteQuote(remoteDir+"/csqtt.env"), deployRemoteQuote(remoteDir+"/deploy-overrides.json"),
        r.PeerPort, r.SSHPort, r.WebPort,
        deployRemoteQuote(remoteDir+"/csqtt-server"),
        deployRemoteQuote(remoteDir+"/csqtt.env"),
        deployRemoteQuote(remoteDir+"/deploy-overrides.json"),
        deployRemoteQuote(remoteDir+"/deploy.sh"))
    if progress != nil { progress("Запуск безопасного systemd deploy…") }
    out, err := deployRunSSH(ctx, r, cmd)
    if err != nil { return nil, err }
    if !strings.Contains(string(out), "CSQTT_DEPLOY_OK") {
        return nil, fmt.Errorf("deploy не подтвердил успешный запуск: %s", strings.TrimSpace(string(out)))
    }
    if r.UseForRouter {
        cfg, cfgErr := readCSQTTConfig()
        if cfgErr == nil {
            cfg["peer"] = fmt.Sprintf("%s:%d", r.Host, r.PeerPort)
            cfg["password"] = r.ServerPass
            if cfgErr = writeCSQTTConfig(cfg); cfgErr != nil {
                return nil, fmt.Errorf("сервер установлен, но не удалось переключить локальный CSQTT config: %w", cfgErr)
            }
        } else {
            return nil, fmt.Errorf("сервер установлен, но не удалось прочитать локальный CSQTT config: %w", cfgErr)
        }
        if progress != nil { progress("Локальный Keenetic client переключён на новый сервер") }
    }
    if progress != nil { progress("Сервер CSQTT успешно установлен") }
    return map[string]any{
        "ok": true, "version": r.Version, "arch": arch, "peer_port": r.PeerPort, "web_port": r.WebPort,
        "server": r.Host, "web_user": r.WebUser, "server_password": r.ServerPass,
        "use_for_router": r.UseForRouter, "asset": asset.Name,
    }, nil
}

func jsonString(s string) string {
    b, _ := json.Marshal(s)
    return string(b)
}
