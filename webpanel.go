package main

import (
    _ "embed"
    "context"
    "crypto/rand"
    "encoding/base64"
    "encoding/json"
    "fmt"
    "html/template"
    "log"
    "net"
    "net/http"
    "net/url"
    "os"
    "strconv"
    "strings"
    "time"
    "sync"
    "syscall"
)

const (
    csqttWebListen = "0.0.0.0:2001"
    vkWebAppID = "7793118"
    vkWebScope = "1073737727"
    vkWebRedirect = "https://csqtt.xenofan.netcraze.link/api/vk/token"
    vkWebVersion = "5.199"
)

//go:embed vk-auth.user.js
var vkAuthUserScript string

type vkAuthState struct {
    ExpiresAt time.Time
    ReturnURL string
}

var vkTokenMu sync.Mutex
var vkAuthStates = map[string]vkAuthState{}

func init() {
    go startCSQTTWebPanel()
}

func startCSQTTWebPanel() {
    mux := http.NewServeMux()
    mux.HandleFunc("/", csqttPanel)
    mux.HandleFunc("/vk-auth.user.js", csqttVKUserScript)
    mux.HandleFunc("/api/vk/token", csqttVKCallback)
    mux.HandleFunc("/api/vk/validate", csqttValidateVKToken)
    mux.HandleFunc("/api/vk/session", csqttVKSession)
    mux.HandleFunc("/api/vk/oauth-url", csqttVKOAuthURL)
    mux.HandleFunc("/api/vk/status", csqttVKStatus)
    mux.HandleFunc("/api/vk/mode", csqttSetVKMode)
    mux.HandleFunc("/api/tunnel/toggle", csqttTunnelToggle)
    mux.HandleFunc("/api/config", csqttConfigStatus)
    mux.HandleFunc("/api/deploy/server", csqttDeployServer)

    log.Printf("CSQTT Web Panel listening on http://%s", csqttWebListen)
    if err := http.ListenAndServe(csqttWebListen, mux); err != nil {
        log.Printf("CSQTT Web Panel stopped: %v", err)
    }
}

func vkRequestScheme(r *http.Request) string {
    if proto := strings.TrimSpace(strings.Split(r.Header.Get("X-Forwarded-Proto"), ",")[0]); strings.EqualFold(proto, "https") {
        return "https"
    } else if strings.EqualFold(proto, "http") {
        return "http"
    }
    if r.TLS != nil {
        return "https"
    }
    host := strings.TrimSpace(r.Host)
    if _, port, err := net.SplitHostPort(host); err == nil {
        if port == "2001" || port == "80" {
            return "http"
        }
        if port == "443" {
            return "https"
        }
    }
    return "https"
}

func vkCallbackURL(r *http.Request) string {
    return vkRequestScheme(r) + "://" + strings.TrimSpace(r.Host) + "/api/vk/token"
}

func vkOAuthURLFor(r *http.Request, state string) string {
    q := url.Values{}
    q.Set("client_id", vkWebAppID)
    q.Set("scope", vkWebScope)
    q.Set("redirect_uri", vkOAuthRedirect(r))
    q.Set("display", "page")
    q.Set("response_type", "token")
    q.Set("revoke", "1")
    q.Set("v", vkWebVersion)
    if strings.TrimSpace(state) != "" {
        q.Set("state", strings.TrimSpace(state))
    }
    return "https://oauth.vk.ru/authorize?" + q.Encode()
}

func vkOAuthURL() string {
    return vkOAuthURLFor(&http.Request{Host: "127.0.0.1:2001"}, "")
}

func csqttVKOAuthURL(w http.ResponseWriter, r *http.Request) {
    if r.Method != http.MethodGet {
        http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
        return
    }
    writeJSON(w, map[string]any{"ok": true, "url": vkOAuthURLFor(r, r.URL.Query().Get("state"))})
}

func vkOAuthRedirect(r *http.Request) string {
    // Primary flow: VK redirects directly to the CSQTT callback page.
    // The access_token remains in the browser URL fragment and is immediately
    // POSTed by the callback page to this same origin. No userscript/bookmarklet
    // is required.
    return vkWebRedirect
}
func csqttVKSession(w http.ResponseWriter, r *http.Request) {
    if r.Method != http.MethodGet {
        http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
        return
    }

    b := make([]byte, 24)
    if _, err := rand.Read(b); err != nil {
        http.Error(w, "cannot create auth state", http.StatusInternalServerError)
        return
    }
    nonce := base64.RawURLEncoding.EncodeToString(b)
    scheme := vkRequestScheme(r)
    callbackURL := vkCallbackURL(r)
    returnURL := scheme + "://" + strings.TrimSpace(r.Host) + "/"
    // The VK fragment is visible only on oauth.vk.ru/blank.html. Post it back
    // to the same CSQTT origin that created this short-lived state. Remote
    // KeenDNS access stays HTTPS; direct LAN access stays on port 2001.
    statePayload := callbackURL + "|" + returnURL + "|" + nonce
    state := base64.RawURLEncoding.EncodeToString([]byte(statePayload))

    vkTokenMu.Lock()
    now := time.Now()
    for k, authState := range vkAuthStates {
        if authState.ExpiresAt.Before(now) {
            delete(vkAuthStates, k)
        }
    }
    vkAuthStates[state] = vkAuthState{
        ExpiresAt: now.Add(5 * time.Minute),
        ReturnURL: returnURL,
    }
    vkTokenMu.Unlock()

    writeJSON(w, map[string]any{"ok": true, "state": state})
}

func readCSQTTConfig() (map[string]any, error) {
    path := "/opt/etc/csqtt/config.json"
    b, err := os.ReadFile(path)
    if err != nil {
        return map[string]any{}, err
    }
    var v map[string]any
    if err := json.Unmarshal(b, &v); err != nil {
        return nil, err
    }
    return v, nil
}

func writeCSQTTConfig(v map[string]any) error {
    path := "/opt/etc/csqtt/config.json"
    b, err := json.MarshalIndent(v, "", "  ")
    if err != nil {
        return err
    }
    tmp := path + ".tmp"
    if err := os.WriteFile(tmp, append(b, '\n'), 0600); err != nil {
        return err
    }
    return os.Rename(tmp, path)
}

func csqttPanel(w http.ResponseWriter, r *http.Request) {
    if r.URL.Path != "/" {
        http.NotFound(w, r)
        return
    }
    data := struct {
        OAuthURL string
    }{OAuthURL: vkOAuthURL()}
    w.Header().Set("Content-Type", "text/html; charset=utf-8")
    _ = csqttPanelTemplate.Execute(w, data)
}

func csqttVKUserScript(w http.ResponseWriter, r *http.Request) {
    if r.Method != http.MethodGet {
        http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
        return
    }
    w.Header().Set("Content-Type", "application/javascript; charset=utf-8")
    w.Header().Set("Cache-Control", "no-store")
    _, _ = w.Write([]byte(vkAuthUserScript))
}

func csqttVKCallback(w http.ResponseWriter, r *http.Request) {
    if r.Method == http.MethodGet {
        // OAuth implicit flow returns the access_token in location.hash.
        // The fragment is never sent to the server, so this tiny same-origin
        // callback page posts it back to /api/vk/token automatically.
        w.Header().Set("Content-Type", "text/html; charset=utf-8")
        w.Header().Set("Cache-Control", "no-store")
        _, _ = w.Write([]byte(vkCallbackHTML))
        return
    }
    csqttSaveVKToken(w, r)
}

func parseVKTokenInput(raw string) (token, userID string, expiresIn int64, state string, err error) {
    raw = strings.TrimSpace(raw)
    if raw == "" {
        return "", "", 0, "", fmt.Errorf("токен или URL blank.html не указан")
    }

    // Preferred format: the complete VK blank.html URL containing the token
    // in the URL fragment. We also accept a raw token for backwards compatibility.
    if u, e := url.Parse(raw); e == nil && u.Fragment != "" {
        q, e := url.ParseQuery(u.Fragment)
        if e == nil && q.Get("access_token") != "" {
            if !strings.HasSuffix(strings.ToLower(u.Path), "/blank.html") {
                return "", "", 0, "", fmt.Errorf("нужна полная ссылка VK blank.html")
            }
            token = strings.TrimSpace(q.Get("access_token"))
            userID = strings.TrimSpace(q.Get("user_id"))
            state = strings.TrimSpace(q.Get("state"))
            expiresIn, _ = strconv.ParseInt(q.Get("expires_in"), 10, 64)
            return token, userID, expiresIn, state, nil
        }
    }
    token = raw
    return token, "", 0, "", nil
}

func validateVKAccessToken(token string) (string, error) {
    token = strings.TrimSpace(token)
    if token == "" {
        return "", fmt.Errorf("пустой VK token")
    }
    q := url.Values{}
    q.Set("access_token", token)
    q.Set("v", vkWebVersion)
    req, err := http.NewRequest(http.MethodGet, "https://api.vk.com/method/users.get?"+q.Encode(), nil)
    if err != nil {
        return "", err
    }
    client := &http.Client{Timeout: 12 * time.Second}
    resp, err := client.Do(req)
    if err != nil {
        return "", fmt.Errorf("VK API недоступен: %w", err)
    }
    defer resp.Body.Close()
    var out struct {
        Response []struct {
            ID int64 `json:"id"`
        } `json:"response"`
        Error *struct {
            Code int `json:"error_code"`
            Msg  string `json:"error_msg"`
        } `json:"error"`
    }
    if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
        return "", fmt.Errorf("некорректный ответ VK API")
    }
    if out.Error != nil {
        return "", fmt.Errorf("VK token недействителен: code=%d %s", out.Error.Code, out.Error.Msg)
    }
    if len(out.Response) == 0 || out.Response[0].ID == 0 {
        return "", fmt.Errorf("VK token не прошёл проверку")
    }
    return strconv.FormatInt(out.Response[0].ID, 10), nil
}

func csqttValidateVKToken(w http.ResponseWriter, r *http.Request) {
    if r.Method != http.MethodPost {
        http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
        return
    }
    var req struct{ Token string `json:"token"` }
    if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
        http.Error(w, "invalid json", http.StatusBadRequest)
        return
    }
    userID, err := validateVKAccessToken(req.Token)
    if err != nil {
        writeJSON(w, map[string]any{"ok": true, "valid": false, "message": "Требуется обновить токен"})
        return
    }
    writeJSON(w, map[string]any{"ok": true, "valid": true, "user_id": userID})
}
func csqttSaveVKToken(w http.ResponseWriter, r *http.Request) {
    if r.Method != http.MethodPost {
        http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
        return
    }
    var req struct {
        Token string `json:"token"`
        UserID string `json:"user_id"`
        ExpiresIn int64 `json:"expires_in"`
        State string `json:"state"`
    }
    contentType := strings.ToLower(r.Header.Get("Content-Type"))
    if strings.HasPrefix(contentType, "application/x-www-form-urlencoded") || strings.HasPrefix(contentType, "multipart/form-data") {
        if err := r.ParseForm(); err != nil {
            http.Error(w, "invalid form", http.StatusBadRequest)
            return
        }
        req.Token = r.FormValue("token")
        req.UserID = r.FormValue("user_id")
        req.State = r.FormValue("state")
        req.ExpiresIn, _ = strconv.ParseInt(r.FormValue("expires_in"), 10, 64)
    } else if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
        http.Error(w, "invalid json", http.StatusBadRequest)
        return
    }

    // The UI accepts the entire blank.html URL in "token". Extract its
    // fragment here so the browser never needs to expose the token in the UI.
    token, parsedUserID, parsedExpires, parsedState, err := parseVKTokenInput(req.Token)
    if err != nil {
        http.Error(w, err.Error(), http.StatusBadRequest)
        return
    }
    if parsedUserID != "" { req.UserID = parsedUserID }
    if parsedExpires != 0 { req.ExpiresIn = parsedExpires }
    if parsedState != "" { req.State = parsedState }
    token = strings.TrimSpace(token)
    if token == "" || len(token) < 16 {
        http.Error(w, "invalid token", http.StatusBadRequest)
        return
    }

    // Validate before replacing the currently working token.
    validUserID, err := validateVKAccessToken(token)
    if err != nil {
        writeJSON(w, map[string]any{"ok": false, "valid": false, "message": "Требуется обновить токен"})
        return
    }
    if req.UserID == "" { req.UserID = validUserID }

    vkTokenMu.Lock()
    defer vkTokenMu.Unlock()

    stateKey := strings.TrimSpace(req.State)
    if stateKey != "" {
        authState, ok := vkAuthStates[stateKey]
        if !ok || authState.ExpiresAt.Before(time.Now()) {
            http.Error(w, "invalid or expired auth state", http.StatusForbidden)
            return
        }
        // Consume a state only when one was supplied. Manual URL paste is
        // still accepted for a valid token, while OAuth callbacks remain bound
        // to the short-lived state created by this panel.
        delete(vkAuthStates, stateKey)
    }

    cfg, err := readCSQTTConfig()
    if err != nil {
        http.Error(w, "cannot read config: "+err.Error(), http.StatusInternalServerError)
        return
    }
    cfg["vk_access_token"] = token
    cfg["vk_user_id"] = req.UserID
    cfg["vk_token_expires_in"] = req.ExpiresIn
    if _, ok := cfg["vk_hash_mode"]; !ok {
        cfg["vk_hash_mode"] = "auto_api"
    }
    if err := writeCSQTTConfig(cfg); err != nil {
        http.Error(w, "cannot save config: "+err.Error(), http.StatusInternalServerError)
        return
    }
    log.Printf("CSQTT Web Panel: VK access token saved for user %s", req.UserID)

    if strings.HasPrefix(contentType, "application/x-www-form-urlencoded") || strings.HasPrefix(contentType, "multipart/form-data") {
        w.Header().Set("Content-Type", "text/html; charset=utf-8")
        returnURL := "/"
        if stateKey != "" {
            // Reconstructing a return URL from the state is intentionally avoided
            // after validation; the panel origin is always the safe destination.
            returnURL = "/"
        }
        _, _ = fmt.Fprintf(w, `<!doctype html><html lang="ru"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>CSQTT VK</title><body style="font-family:system-ui;background:#111;color:#eee;text-align:center;padding:40px"><h2 style="color:#67e8a5">VK авторизация выполнена ✓</h2><p>Токен проверен и сохранён. Возвращаю в CSQTT…</p><script>setTimeout(function(){location.replace(%q)},900)</script></body></html>`, returnURL)
    } else {
        writeJSON(w, map[string]any{"ok": true, "valid": true, "user_id": req.UserID, "restart_pending": true})
    }

    go func() {
        time.Sleep(1200 * time.Millisecond)
        _ = syscall.Kill(os.Getpid(), syscall.SIGTERM)
    }()
}
func csqttSetVKMode(w http.ResponseWriter, r *http.Request) {
    if r.Method != http.MethodPost {
        http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
        return
    }
    var req struct {
        Mode   string   `json:"mode"`
        Hashes []string `json:"hashes"`
    }
    if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
        http.Error(w, "invalid json", http.StatusBadRequest)
        return
    }
    mode := strings.ToLower(strings.TrimSpace(req.Mode))
    if mode != "manual" && mode != "auto_api" && mode != "auto_js" {
        http.Error(w, "invalid mode", http.StatusBadRequest)
        return
    }
    hashes := make([]string, 0, len(req.Hashes))
    for _, hash := range req.Hashes {
        hash = strings.TrimSpace(hash)
        if hash != "" {
            hashes = append(hashes, hash)
        }
    }
    if mode == "manual" && len(hashes) == 0 {
        http.Error(w, "manual mode requires at least one hash", http.StatusBadRequest)
        return
    }

    vkTokenMu.Lock()
    defer vkTokenMu.Unlock()
    cfg, err := readCSQTTConfig()
    if err != nil {
        http.Error(w, "cannot read config: "+err.Error(), http.StatusInternalServerError)
        return
    }
    cfg["vk_hash_mode"] = mode
    if mode == "auto_js" {
        cfg["vk_auth_mode"] = "auto_js"
    } else {
        cfg["vk_auth_mode"] = "vkcalls"
    }
    cfg["vk_hashes"] = hashes
    if err := writeCSQTTConfig(cfg); err != nil {
        http.Error(w, "cannot save config: "+err.Error(), http.StatusInternalServerError)
        return
    }
    log.Printf("CSQTT Web Panel: VK hash mode changed to %s", mode)
    // Manager reads VK hash mode at process start. Restart the manager after
    // saving so a mode/hash change is applied immediately without rebooting
    // the router. The service supervisor will bring it back.
    go func() {
        time.Sleep(350 * time.Millisecond)
        _ = syscall.Kill(os.Getpid(), syscall.SIGTERM)
    }()
    writeJSON(w, map[string]any{"ok": true, "mode": mode, "restart_pending": true})
}

func csqttVKStatus(w http.ResponseWriter, r *http.Request) {
    cfg, err := readCSQTTConfig()
    if err != nil {
        writeJSON(w, map[string]any{"ok": false, "authorized": false})
        return
    }
    token, _ := cfg["vk_access_token"].(string)
    userID, _ := cfg["vk_user_id"].(string)
    tokenValid := false
    if strings.TrimSpace(token) != "" {
        if validatedID, err := validateVKAccessToken(token); err == nil {
            tokenValid = true
            if userID == "" { userID = validatedID }
        }
    }
    mode, _ := cfg["vk_hash_mode"].(string)
    runtime := map[string]any{}
    if b, err := os.ReadFile("/opt/etc/csqtt/vk-runtime.json"); err == nil {
        _ = json.Unmarshal(b, &runtime)
    }
    enabled := true
    if v, ok := cfg["enabled"].(bool); ok {
        enabled = v
    }
    writeJSON(w, map[string]any{
        "ok": true,
        "authorized": strings.TrimSpace(token) != "",
        "token_valid": tokenValid,
        "user_id": userID,
        "mode": mode,
        "enabled": enabled,
        "runtime": runtime,
        "hash_notice": runtime["hash_notice"],
        "hash_notice_at": runtime["hash_notice_at"],
    })
}

func csqttTunnelToggle(w http.ResponseWriter, r *http.Request) {
    if r.Method != http.MethodPost {
        http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
        return
    }
    var req map[string]any
    if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
        http.Error(w, "invalid json", http.StatusBadRequest)
        return
    }
    enabled, ok := req["enabled"].(bool)
    if !ok {
        http.Error(w, "enabled must be boolean", http.StatusBadRequest)
        return
    }
    vkTokenMu.Lock()
    defer vkTokenMu.Unlock()
    cfg, err := readCSQTTConfig()
    if err != nil {
        http.Error(w, "cannot read config: "+err.Error(), http.StatusInternalServerError)
        return
    }
    cfg["enabled"] = enabled
    if err := writeCSQTTConfig(cfg); err != nil {
        http.Error(w, "cannot save config: "+err.Error(), http.StatusInternalServerError)
        return
    }
    if !enabled {
        stopCurrentClient()
    }
    log.Printf("CSQTT Web Panel: tunnel enabled=%v", enabled)
    writeJSON(w, map[string]any{"ok": true, "enabled": enabled})
}

func panelClientIsPrivate(r *http.Request) bool {
    host, _, err := net.SplitHostPort(r.RemoteAddr)
    if err != nil {
        host = r.RemoteAddr
    }
    ip := net.ParseIP(host)
    return ip != nil && (ip.IsLoopback() || ip.IsPrivate())
}

func csqttDeployServer(w http.ResponseWriter, r *http.Request) {
    if !panelClientIsPrivate(r) {
        http.Error(w, "deploy доступен только из LAN/VPN", http.StatusForbidden)
        return
    }
    if r.Method != http.MethodPost {
        http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
        return
    }
    var req DeployRequest
    if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
        http.Error(w, "invalid json", http.StatusBadRequest)
        return
    }
    ctx, cancel := context.WithTimeout(r.Context(), 30*time.Minute)
    defer cancel()
    result, err := deployServer(ctx, req, func(msg string) {
        log.Printf("CSQTT Deploy: %s", msg)
    })
    if err != nil {
        log.Printf("CSQTT Deploy failed: %v", err)
        writeJSON(w, map[string]any{"ok": false, "error": err.Error()})
        return
    }
    writeJSON(w, result)
}

func csqttConfigStatus(w http.ResponseWriter, r *http.Request) {
    cfg, err := readCSQTTConfig()
    if err != nil {
        writeJSON(w, map[string]any{"ok": false, "error": err.Error()})
        return
    }
    // Never return secrets through the web API.
    delete(cfg, "vk_access_token")
    delete(cfg, "password")
    delete(cfg, "vk_hashes")
    writeJSON(w, map[string]any{"ok": true, "config": cfg})
}

func writeJSON(w http.ResponseWriter, value any) {
    w.Header().Set("Content-Type", "application/json; charset=utf-8")
    _ = json.NewEncoder(w).Encode(value)
}

var csqttPanelTemplate = template.Must(template.New("panel").Parse(`<!doctype html>
<html lang="ru"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>CSQTT-Keenetic</title>
<style>
:root{color-scheme:light;--bg:#fdfdfe;--surface:#fff;--surface2:#f2f2f4;--text:#111215;--muted:#5f6067;--blue:#1a73e8;--blueSoft:#e8f0fe;--teal:#00b8a3;--green:#4caf50;--amber:#d98200;--red:#ef5350;--line:#d7d8dd}
*{box-sizing:border-box}html,body{min-height:100%;margin:0}body{font-family:system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;background:linear-gradient(180deg,#fff 0%,#fdfdfd 58%,#f5f6f8 100%);color:var(--text);max-width:760px;margin:0 auto;padding:18px 18px 104px}
.topbar{display:flex;align-items:center;justify-content:space-between;padding:2px 6px 18px}.brand{font-size:34px;font-weight:800;letter-spacing:-2.5px;color:#1683df}.version{font-size:14px;font-weight:700;color:#3b8de0}.chat{width:36px;height:30px;border:3px solid #1683df;border-radius:9px;display:flex;align-items:center;justify-content:center;color:#1683df;font-size:15px;font-weight:900}.chat:after{content:"";position:absolute;margin:27px 0 0 13px;width:7px;height:7px;border-left:3px solid #1683df;transform:skewY(-35deg)}
.tabs{position:fixed;z-index:20;left:50%;bottom:10px;transform:translateX(-50%);width:min(716px,calc(100% - 28px));height:82px;display:flex;gap:2px;padding:5px;background:rgba(16,17,20,.97);border:1px solid rgba(120,125,135,.22);border-radius:27px;box-shadow:0 10px 34px rgba(0,0,0,.32);backdrop-filter:blur(18px)}
.tab{flex:1;min-width:0;background:transparent;color:#85878d;border:0;border-radius:21px;padding:5px 2px 6px;font-size:15px;font-weight:650;line-height:19px;display:flex;flex-direction:column;align-items:center;justify-content:center;gap:3px;white-space:nowrap}.tab.active{background:linear-gradient(145deg,#1976e8,#1764d7);color:#fff;box-shadow:0 4px 16px rgba(25,118,232,.34)}.tabIcon{width:30px;height:30px;display:flex;align-items:center;justify-content:center}.tabIcon svg{width:28px;height:28px;fill:none;stroke:currentColor;stroke-width:1.9;stroke-linecap:round;stroke-linejoin:round}.tab span:last-child{display:block}
.panelSection{display:none}.panelSection.active{display:block}.card{background:rgba(255,255,255,.98);border:1px solid rgba(80,82,90,.13);border-radius:28px;padding:20px;margin:12px 0;box-shadow:0 7px 24px rgba(0,0,0,.10)}
.powerCard{min-height:520px;display:flex;flex-direction:column;align-items:center;justify-content:center;text-align:center;padding:28px 24px}.brandLogo{width:176px;height:176px;border-radius:50%;display:flex;align-items:center;justify-content:center;background:linear-gradient(145deg,#e8f0fe,#fff);border:1px solid #e2e4e9;box-shadow:0 14px 38px rgba(0,0,0,.13);margin:8px auto 20px}.brandLogo span{font-size:96px;font-weight:800;letter-spacing:-13px;color:#1683df;transform:translateX(-5px)}
.powerState{font-size:18px;font-weight:700;margin:0 0 7px}.powerTime{font-size:17px;color:#85868d;font-weight:600}.powerBtn{width:100%;max-width:360px;font-size:17px;padding:15px 18px;border-radius:18px;margin-top:22px}.powerOn{background:var(--red)}.powerOff{background:var(--blue)}.powerWait{background:#9a9ba1}.status{font-size:17px}.muted{color:var(--muted)}.ok{color:var(--green)}.warn{color:var(--amber)}
.metricRow{display:flex;width:100%;margin-top:26px;padding:2px;background:var(--surface2);border:1px solid rgba(80,82,90,.10);border-radius:18px}.metric{flex:1;text-align:center;padding:11px 5px}.metric+.metric{border-left:1px solid rgba(80,82,90,.14)}.metricTitle{font-size:11px;color:#777980}.metricValue{font-size:14px;font-weight:600;margin-top:3px;color:#34353a}
h1{font-size:22px;line-height:28px;margin:4px 4px 14px;font-weight:700}.sectionTitle{font-size:22px;font-weight:700;margin:2px 0 14px}h2{font-size:21px}
button{background:linear-gradient(135deg,#1976d2,#1565d8);color:#fff;border:0;border-radius:14px;padding:12px 18px;font-weight:700;cursor:pointer;transition:transform .18s ease,box-shadow .18s ease,filter .18s ease;box-shadow:0 5px 14px rgba(21,101,216,.22)}button:hover{transform:translateY(-1px);box-shadow:0 8px 20px rgba(21,101,216,.30);filter:brightness(1.04)}button:active{transform:scale(.97)}button.secondary{background:var(--surface2);color:#444}
input,textarea{width:100%;box-sizing:border-box;background:#fff;color:#222;border:1px solid #d4d8df;border-radius:14px;padding:13px 14px;margin:8px 0;transition:border-color .2s,box-shadow .2s}input:focus,textarea:focus{outline:none;border-color:#1976d2;box-shadow:0 0 0 4px rgba(25,118,210,.12)}small{color:#777}.row{display:flex;gap:10px;flex-wrap:wrap}code{word-break:break-all;color:#1769aa}
details{background:#f7f7f8;border-radius:15px;padding:10px 12px}summary{font-weight:650;cursor:pointer}
@media(prefers-color-scheme:dark){:root{color-scheme:dark;--bg:#09090a;--surface:#121214;--surface2:#202024;--text:#fafafa;--muted:#c9c9cf;--blue:#1565d8;--blueSoft:#173b72;--line:#35353a}body{background:radial-gradient(circle at 50% 12%,#14151a 0,#09090a 45%)}.topbar .brand{color:#4aa0ff}.version{color:#8ab4f8}.chat{border-color:#4aa0ff;color:#4aa0ff}.card{background:rgba(18,18,20,.96);border-color:rgba(140,140,148,.18);box-shadow:0 5px 24px rgba(0,0,0,.25)}.tabs{background:rgba(16,17,20,.97);border-color:rgba(140,140,148,.24)}.tab{color:#8d8f96}.tab.active{color:#fff}.brandLogo{background:radial-gradient(circle at 35% 30%,#173b72,#121214);border-color:#35353a}.brandLogo span{color:#4aa0ff}.metricRow,details{background:#202024}.metricTitle{color:#9c9da4}.metricValue{color:#e7e7eb}button.secondary{background:#202024;color:#ddd}input,textarea{background:#0d0d0f;color:#eee;border-color:#35353a}}
@media(max-width:560px){body{padding:10px 10px 112px}.topbar{padding-bottom:12px}.brand{font-size:31px}.tabs{width:calc(100% - 14px);bottom:8px;height:82px}.tab{font-size:13px;line-height:17px}.tabIcon{width:29px;height:29px}.tabIcon svg{width:27px;height:27px}.powerCard{min-height:500px;padding:24px 16px}.brandLogo{width:148px;height:148px}.brandLogo span{font-size:80px}}
.card{animation:cardIn .38s ease both}.panelSection.active .card:nth-child(2){animation-delay:.05s}.panelSection.active .card:nth-child(3){animation-delay:.1s}.tabs{box-shadow:0 8px 28px rgba(0,0,0,.10);backdrop-filter:blur(12px)}.tab{transition:color .2s,background .2s,transform .2s}.tab:hover{transform:translateY(-1px)}.powerCard{overflow:hidden;position:relative}.powerCard:before{content:"";position:absolute;width:260px;height:260px;border-radius:50%;background:radial-gradient(circle,rgba(25,118,210,.16),transparent 68%);top:25px;left:50%;transform:translateX(-50%);animation:pulseGlow 3.2s ease-in-out infinite}.brandLogo{animation:logoFloat 3.5s ease-in-out infinite}.brandLogo span{animation:logoShine 2.8s ease-in-out infinite}.tokenManual{background:transparent!important;border:0!important;box-shadow:none!important;padding:0!important;margin-top:18px!important}.tokenAlert{backdrop-filter:blur(7px);animation:fadeIn .2s ease}.tokenAlert.show .tokenAlertBox{animation:modalIn .28s cubic-bezier(.2,.8,.2,1)}.tokenAlertBox{border:1px solid rgba(211,47,47,.18)}.hashManager{margin-top:18px;border:1px solid rgba(80,82,90,.14);border-radius:22px;padding:16px;background:linear-gradient(180deg,rgba(247,249,252,.96),rgba(239,242,247,.82));overflow:hidden}.hashSummary{display:grid;grid-template-columns:repeat(3,1fr);gap:8px;margin-bottom:13px}.hashPill{border-radius:16px;padding:10px 8px;text-align:center;background:#fff;border:1px solid rgba(80,82,90,.11);box-shadow:0 3px 10px rgba(0,0,0,.05);transition:transform .22s ease,box-shadow .22s ease}.hashPill:hover{transform:translateY(-1px);box-shadow:0 7px 16px rgba(0,0,0,.08)}.hashPillValue{display:block;font-size:21px;font-weight:800;line-height:24px}.hashPillLabel{display:block;font-size:11px;color:#777980;margin-top:3px}.hashPill.active .hashPillValue{color:#19a463}.hashPill.dead .hashPillValue{color:#d32f2f}.hashPill.total .hashPillValue{color:#1976d2}.hashList{display:grid;gap:8px;margin:12px 0 15px}.hashItem{display:flex;align-items:center;gap:10px;padding:11px 12px;border-radius:16px;background:rgba(255,255,255,.86);border:1px solid rgba(80,82,90,.11);animation:hashIn .35s cubic-bezier(.2,.8,.2,1) both}.hashItem.dead{border-color:rgba(211,47,47,.24);background:linear-gradient(90deg,rgba(211,47,47,.08),rgba(255,255,255,.88))}.hashDot{width:9px;height:9px;border-radius:50%;flex:0 0 auto;background:#19a463;box-shadow:0 0 0 5px rgba(25,164,99,.10);animation:hashPulse 2s ease-in-out infinite}.hashItem.dead .hashDot{background:#d32f2f;box-shadow:0 0 0 5px rgba(211,47,47,.10);animation:hashDeadPulse 1.5s ease-in-out infinite}.hashText{font:600 13px ui-monospace,SFMono-Regular,Consolas,monospace;word-break:break-all;flex:1}.hashStatus{font-size:12px;font-weight:700;color:#19a463;white-space:nowrap}.hashItem.dead .hashStatus{color:#d32f2f}.hashEmpty{padding:15px;border:1px dashed #c8ccd4;border-radius:16px;text-align:center;color:#7b7f88;font-size:13px}.hashNotice{display:flex;gap:11px;align-items:flex-start;padding:13px 14px;border-radius:17px;margin:12px 0;background:linear-gradient(90deg,rgba(255,179,0,.12),rgba(255,255,255,.6));border:1px solid rgba(217,130,0,.2);animation:noticeIn .35s cubic-bezier(.2,.8,.2,1)}.hashNotice.danger{background:linear-gradient(90deg,rgba(211,47,47,.12),rgba(255,255,255,.6));border-color:rgba(211,47,47,.24)}.hashNoticeIcon{font-size:22px;line-height:1}.hashNoticeTitle{font-weight:800}.hashNoticeText{font-size:13px;color:#666a73;margin-top:3px;line-height:1.4}.hashEditorLabel{display:flex;justify-content:space-between;gap:8px;align-items:center}.hashCounter{font-size:12px;color:#7c8088}.hashHelp{font-size:12px;color:#777980;margin:4px 0 0;line-height:1.4}.hashSaveRow{display:flex;align-items:center;gap:10px;margin-top:10px}.hashSaveRow button{flex:1}.hashSaveState{font-size:12px;color:#6d717a}.vkActionModal{position:fixed;inset:0;z-index:150;display:flex;align-items:center;justify-content:center;padding:20px;background:rgba(5,7,12,.58);backdrop-filter:blur(10px);animation:fadeIn .2s ease}.vkActionModalBox{width:min(520px,100%);background:rgba(255,255,255,.98);color:var(--text);border:1px solid rgba(80,82,90,.14);border-radius:28px;padding:26px 22px 20px;box-shadow:0 22px 70px rgba(0,0,0,.35);animation:modalIn .28s cubic-bezier(.2,.8,.2,1)}.vkActionModalIcon{width:58px;height:58px;border-radius:19px;display:flex;align-items:center;justify-content:center;margin:0 0 15px;background:linear-gradient(145deg,#e8f0fe,#dce9ff);color:#1976d2;font-size:29px;box-shadow:0 8px 22px rgba(25,118,210,.18)}.vkActionModalBox.danger .vkActionModalIcon{background:rgba(211,47,47,.10);color:#d32f2f}.vkActionModalTitle{font-size:22px;font-weight:800;margin:0 0 9px}.vkActionModalText{font-size:15px;line-height:1.5;color:var(--muted);margin:0 0 20px}.vkActionModalActions{display:flex;gap:10px;flex-wrap:wrap}.vkActionModalActions button{flex:1;min-width:150px}.vkActionModalBox.danger{border-color:rgba(211,47,47,.22)}@media(prefers-color-scheme:dark){.vkActionModal{background:rgba(0,0,0,.68)}.vkActionModalBox{background:rgba(20,21,25,.98);border-color:rgba(140,140,148,.18)}.vkActionModalIcon{background:rgba(30,70,130,.28);color:#7fb2ff}.vkActionModalBox.danger .vkActionModalIcon{background:rgba(211,47,47,.14);color:#ff7777}}.hashToast{position:fixed;z-index:100;left:50%;top:16px;transform:translateX(-50%) translateY(-18px);width:min(620px,calc(100% - 28px));padding:13px 15px;border-radius:18px;background:rgba(20,22,27,.96);color:#fff;box-shadow:0 12px 38px rgba(0,0,0,.28);border:1px solid rgba(255,255,255,.12);opacity:0;pointer-events:none;transition:opacity .25s ease,transform .3s cubic-bezier(.2,.8,.2,1);display:flex;gap:11px;align-items:flex-start}.hashToast.show{opacity:1;transform:translateX(-50%) translateY(0)}.hashToast.danger{border-color:rgba(255,100,100,.35)}.hashToastIcon{font-size:22px}.hashToastTitle{font-weight:800}.hashToastText{font-size:13px;color:#c7cad0;margin-top:2px;line-height:1.35}
@media(prefers-color-scheme:dark){.hashManager{background:linear-gradient(180deg,rgba(30,31,35,.96),rgba(25,26,30,.9));border-color:rgba(140,140,148,.18)}.hashPill,.hashItem{background:rgba(28,29,33,.9);border-color:rgba(140,140,148,.16)}.hashItem.dead{background:linear-gradient(90deg,rgba(211,47,47,.12),rgba(28,29,33,.9))}.hashNotice{background:linear-gradient(90deg,rgba(255,179,0,.10),rgba(28,29,33,.75))}.hashNotice.danger{background:linear-gradient(90deg,rgba(211,47,47,.13),rgba(28,29,33,.75))}.hashToast{background:rgba(20,22,27,.97)}}
@keyframes hashIn{from{opacity:0;transform:translateX(-7px) scale(.985)}to{opacity:1;transform:none}}@keyframes hashPulse{0%,100%{opacity:1;transform:scale(1)}50%{opacity:.55;transform:scale(.86)}}@keyframes hashDeadPulse{0%,100%{opacity:1}50%{opacity:.45}}@keyframes noticeIn{from{opacity:0;transform:translateY(8px)}to{opacity:1;transform:none}}.tokenAlertTitle:before{content:"";display:inline-block;width:10px;height:10px;border-radius:50%;background:#d32f2f;margin-right:9px;box-shadow:0 0 0 5px rgba(211,47,47,.12);animation:alertPulse 1.5s infinite}.tokenAlertActions button{min-width:150px}.tokenAlertActions button.secondary{box-shadow:none;background:#edf0f4;color:#333}.vkTokenInput{}#vkTokenInput{display:block;width:100%;min-width:100%;min-height:56px;font-family:ui-monospace,SFMono-Regular,Consolas,monospace;font-size:14px;padding:15px 16px}.status{transition:all .25s ease}.ok{color:#19a463!important}.warn{color:#d97706!important}@keyframes cardIn{from{opacity:0;transform:translateY(8px)}to{opacity:1;transform:none}}@keyframes fadeIn{from{opacity:0}to{opacity:1}}@keyframes modalIn{from{opacity:0;transform:translateY(18px) scale(.97)}to{opacity:1;transform:none}}@keyframes logoFloat{0%,100%{transform:translateY(0)}50%{transform:translateY(-5px)}}@keyframes logoShine{0%,100%{filter:brightness(1)}50%{filter:brightness(1.18)}}@keyframes pulseGlow{0%,100%{opacity:.55;transform:translateX(-50%) scale(1)}50%{opacity:1;transform:translateX(-50%) scale(1.12)}}@keyframes alertPulse{0%,100%{opacity:1}50%{opacity:.45}}@media(prefers-reduced-motion:reduce){*,*:before,*:after{animation:none!important;transition:none!important}}</style></head><body>
<div class="topbar"><div class="brand">CSQTT</div><div class="version">v2.2.0by amurcanov</div><div class="chat">•••</div></div><nav class="tabs" aria-label="Навигация">
<button class="tab active" data-section="sec-connect"><span class="tabIcon"><svg viewBox="0 0 24 24"><path d="M12 3v9"/><path d="M7.05 5.05a8 8 0 1 0 9.9 0"/></svg></span><span>Подкл.</span></button>
<button class="tab" data-section="sec-vk"><span class="tabIcon"><svg viewBox="0 0 24 24"><circle cx="7" cy="12" r="3"/><path d="M10 12h11"/><path d="M18 12v3"/><path d="M15 12v2"/></svg></span><span>Туннель</span></button>
<button class="tab" data-section="sec-deploy"><span class="tabIcon"><svg viewBox="0 0 24 24"><path d="M4 14.5h16"/><path d="M5 10.5h14"/><path d="M8 18.5h8"/><path d="M6 6.5h12"/></svg></span><span>Деплой</span></button>
<button class="tab" data-section="sec-settings"><span class="tabIcon"><svg viewBox="0 0 24 24"><path d="M4 6h16"/><path d="M4 12h16"/><path d="M4 18h10"/></svg></span><span>Исключ.</span></button>
<button class="tab" data-section="sec-logs"><span class="tabIcon"><svg viewBox="0 0 24 24"><rect x="4" y="4" width="16" height="16" rx="2"/><path d="m9 9 3 3-3 3"/><path d="M13 15h3"/></svg></span><span>Логи</span></button>
<button class="tab" data-section="sec-info"><span class="tabIcon"><svg viewBox="0 0 24 24"><circle cx="12" cy="12" r="9"/><path d="M12 10v6"/><path d="M12 7h.01"/></svg></span><span>Инфо</span></button>
</nav>
<div id="sec-connect" class="panelSection active">
<div class="card powerCard">
<div id="brandLogo" class="brandLogo"><span>C</span></div>
<div id="powerState" class="powerState muted">Отключено</div>
<div id="powerTime" class="powerTime">00:00:00</div>
<button id="powerBtn" class="powerBtn powerOff" data-enabled="false">Подключить</button>
<div id="powerMsg" class="muted" style="margin-top:10px"></div>
<div class="metricRow"><div class="metric"><div class="metricTitle">Маскировка</div><div id="mObfs" class="metricValue">—</div></div><div class="metric"><div class="metricTitle">Хеши</div><div id="mHash" class="metricValue">—</div></div><div class="metric"><div class="metricTitle">Режим кредов</div><div id="mMode" class="metricValue">—</div></div></div>
</div></div>
<div id="sec-vk" class="panelSection">
<div class="card"><div class="status">VK: <span id="vk" class="warn">проверка…</span></div><div id="uid" class="muted"></div><div id="autoState" class="muted" style="margin-top:10px"></div></div>
<div class="card">
<h2>Авторизация VK</h2>
<p class="muted">VK-приложение 7793118 требует штатный redirect <code>https://oauth.vk.ru/blank.html</code>. После входа VK помещает access_token во фрагмент URL. После авторизации на странице VK скопируй полную ссылку из адресной строки и вернись в раздел авторизации. Вставь ссылку в поле ниже — CSQTT сам извлечёт и проверит access_token.</p>
<div class="row"><button type="button" id="vkLogin">🔐 Войти через VK</button><button class="secondary" onclick="refresh()">Обновить</button></div>
<div id="msg" class="muted"></div>
<div class="tokenManual card" style="margin:14px 0 0;padding:16px;background:#f7f8fa">
<label for="vkTokenInput"><b>Действующий токен</b></label>
<input id="vkTokenInput" type="text" autocomplete="off" autocapitalize="none" spellcheck="false" placeholder="Вставь всю ссылку https://oauth.vk.ru/blank.html#access_token=…">
<div class="row"><button type="button" id="saveVKToken">Сохранить токен</button></div>
<div id="tokenMsg" class="muted"></div>
</div>
<div style="margin-top:14px">
  <details>
    <summary>🧩 Резервный способ — скрипт VK</summary>
    <p class="muted"><b>Сценарий:</b> войти в VK → на странице blank.html запустить кнопку «CSQTT VK» → скопировать ссылку страницы → нажать «Раздел авторизации» → вставить ссылку в поле выше.</p>
    <button type="button" onclick="copyVKBookmarklet()">📋 Скопировать кнопку «CSQTT VK»</button>
    <textarea id="vkBookmarklet" readonly rows="4" style="width:100%;box-sizing:border-box;background:#101010;color:#9ecbff;border:1px solid #444;border-radius:10px;padding:11px;margin-top:10px"></textarea>
    <small>Основной вход теперь работает без этого скрипта. Этот вариант оставлен только как резервный для старого redirect VK.</small>
    <p class="muted" style="margin-top:10px">🔒 Токен не показывается и не копируется вручную. Скрипт берёт его из URL-фрагмента VK, проверяет CSQTT state и отправляет только на callback твоей панели.</p>
  </details>
</div>
</div>
</div><div id="sec-deploy" class="panelSection"><div class="card">
<h2>🚀 Deploy CSQTT Server</h2>
<p class="muted">Отдельный сервер для Keenetic. Существующий Android endpoint не трогаем. По умолчанию Keenetic использует UDP <b>46010</b>, WEB-панель сервера — TCP <b>46012</b>.</p>
<div class="row"><div style="flex:1;min-width:220px"><label>VPS host</label><input id="dHost" value="72.56.81.131"></div><div style="width:110px"><label>SSH port</label><input id="dSSH" type="number" value="22"></div></div>
<div class="row"><div style="flex:1;min-width:180px"><label>SSH user</label><input id="dUser" value="root"></div><div style="flex:1;min-width:180px"><label>SSH key на Keenetic</label><input id="dKey" placeholder="/opt/etc/dropbear/id_ed25519"></div></div>
<label>SSH password <small>(если key не используется; нужен sshpass)</small></label><input id="dPassword" type="password" autocomplete="off">
<div class="row"><div style="flex:1;min-width:180px"><label>CSQTT UDP port</label><input id="dPeer" type="number" value="46010"></div><div style="flex:1;min-width:180px"><label>Server WEB port</label><input id="dWeb" type="number" value="46012"></div></div>
<div class="row"><div style="flex:1;min-width:180px"><label>WEB user</label><input id="dWebUser" value="admin"></div><div style="flex:1;min-width:180px"><label>WEB password</label><input id="dWebPass" type="password" autocomplete="new-password"></div></div>
<label>Пароль CSQTT для клиентов</label><input id="dServerPass" type="password" autocomplete="new-password">
<label><input id="dUse" type="checkbox" checked> После успешного deploy переключить этот Keenetic client на новый сервер</label>
<div class="row"><button onclick="deployServer()">🚀 Deploy / Redeploy</button></div>
<pre id="deployMsg" class="muted" style="white-space:pre-wrap"></pre>
</div>
<div id="sec-settings" class="panelSection"><div class="card">
<h2>Hash режим</h2>
<p class="muted">Один авторизованный VK аккаунт используется для обоих автоматических режимов.</p>
<label><input type="radio" name="hashMode" value="manual" onchange="modeChanged()"> Ручной — вставить VK hashes</label>
<label><input type="radio" name="hashMode" value="auto_api" onchange="modeChanged()"> Авто API — calls.start</label>
<label><input type="radio" name="hashMode" value="auto_js" onchange="modeChanged()"> Авто ВК — VK Calls / vchat</label>
<div id="manualHashes" style="display:none" class="hashManager">
  <div class="hashSummary">
    <div class="hashPill active"><span id="hashActiveCount" class="hashPillValue">0</span><span class="hashPillLabel">активны</span></div>
    <div class="hashPill dead"><span id="hashDeadCount" class="hashPillValue">0</span><span class="hashPillLabel">недоступны</span></div>
    <div class="hashPill total"><span id="hashTotalCount" class="hashPillValue">0</span><span class="hashPillLabel">всего</span></div>
  </div>
  <div id="hashNotice" class="hashNotice" style="display:none"></div>
  <div id="hashList" class="hashList"></div>
  <div class="hashEditorLabel"><label for="hashes"><b>Ручные VK hashes</b></label><span id="hashCounter" class="hashCounter">0 / 6</span></div>
  <textarea id="hashes" rows="6" placeholder="Вставь по одному VK hash на строку"></textarea>
  <div class="hashHelp">Один хеш может перестать работать. Он будет отмечен как недоступный, а остальные продолжат работать. Если недоступны все — туннель остановится и панель покажет уведомление.</div>
  <div class="hashSaveRow"><button onclick="saveMode()">💾 Сохранить хеши и режим</button><span id="hashSaveState" class="hashSaveState"></span></div>
</div>
<div class="row"><button onclick="saveMode()">Сохранить режим</button></div>
<div id="modeMsg" class="muted"></div>
</div></div>
<div id="sec-logs" class="panelSection"><div class="card"><h2>📜 Логи</h2><p class="muted">Вкладка подготовлена. Подключение журнала добавим отдельно.</p></div></div>
<div id="sec-info" class="panelSection"><div class="card"><h2>ℹ️ Информация</h2><p class="muted">CSQTT-Keenetic · ARM64/aarch64 · Entware</p><p class="muted">Панель: 2001 · TUN: csqtt0</p></div></div>
<script>
document.querySelectorAll('.tab').forEach(function(btn){btn.onclick=function(){document.querySelectorAll('.tab').forEach(function(x){x.classList.remove('active')});document.querySelectorAll('.panelSection').forEach(function(x){x.classList.remove('active')});btn.classList.add('active');document.getElementById(btn.dataset.section).classList.add('active')}});
let powerSince=0;
function fmtTime(ms){let s=Math.floor(ms/1000),h=Math.floor(s/3600);s%=3600;let m=Math.floor(s/60);s%=60;return String(h).padStart(2,'0')+':'+String(m).padStart(2,'0')+':'+String(s).padStart(2,'0')}
document.getElementById('powerBtn').onclick=async function(){const b=this,target=b.dataset.enabled!=='true';b.disabled=true;b.className='powerBtn powerWait';b.textContent=target?'⏳ ПОДКЛЮЧЕНИЕ…':'⏳ ОТКЛЮЧЕНИЕ…';try{const r=await fetch('/api/tunnel/toggle',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({enabled:target})});const x=await r.json();if(!r.ok||!x.ok)throw new Error(x.error||'ошибка');document.getElementById('powerMsg').textContent=target?'Запускаю CSQTT…':'Останавливаю CSQTT…'}catch(e){document.getElementById('powerMsg').textContent='Ошибка: '+e.message}setTimeout(refresh,500);setTimeout(refresh,1500);b.disabled=false};
document.getElementById('vkLogin').addEventListener('click', async function(){
  const msg=document.getElementById('msg');
  try{
    const r=await fetch('/api/vk/session');
    const x=await r.json();
    if(!x.ok || !x.state) throw new Error(x.error||'Сеанс авторизации не создан');
    const u=await fetch('/api/vk/oauth-url?state='+encodeURIComponent(x.state)).then(r=>r.json());
    if(!u.ok || !u.url) throw new Error(u.error||'VK OAuth URL не создан');
    msg.textContent='Открываю VK… После авторизации скрипт на blank.html автоматически вернёт token в CSQTT.';
    window.location.href=u.url;
  }catch(e){
    msg.textContent='Не удалось запустить VK: '+e.message;
  }
});
function showVKTokenModal(){
  let m=document.getElementById('vkTokenModal');
  if(!m){
    m=document.createElement('div');
    m.id='vkTokenModal';
    m.className='vkActionModal';
    m.innerHTML='<div class="vkActionModalBox danger"><div class="vkActionModalIcon">⚠️</div><h2 class="vkActionModalTitle">Требуется обновить токен</h2><p class="vkActionModalText">Текущий VK токен не проходит проверку. Авторизуйся заново, чтобы CSQTT снова мог получать VK hashes.</p><div class="vkActionModalActions"><button type="button" id="modalVKLogin">🔐 Авторизоваться через VK</button><button type="button" class="secondary" id="modalClose">Позже</button></div></div>';
    document.body.appendChild(m);
    document.getElementById('modalClose').onclick=()=>m.remove();
    document.getElementById('modalVKLogin').onclick=()=>{m.remove();document.getElementById('vkLogin').click()};
  }
}
let vkActionModalKey='';
function showVKActionModal(x,rt){
  const mode=String(x.mode||'');
  const autoApiNeedsAuth=mode==='auto_api' && (!x.token_valid || !!rt.token_invalid);
  const autoVkCaptchaExhausted=mode==='auto_js' && rt.error==='auto_vk_captcha_exhausted';
  if(!autoApiNeedsAuth && !autoVkCaptchaExhausted){
    const old=document.getElementById('vkActionModal');
    if(old) old.remove();
    vkActionModalKey='';
    return;
  }
  const stamp=String(rt.hash_notice_at||rt.updated_at||rt.error||'');
  const key=mode+'|'+(autoVkCaptchaExhausted?'captcha-exhausted':'auth-required')+'|'+stamp;
  if(vkActionModalKey===key && document.getElementById('vkActionModal')) return;
  vkActionModalKey=key;
  const autoVk=autoVkCaptchaExhausted;
  const title=autoVk?'Авто ВК требует ручной проверки':'Авторизация VK требуется';
  const text=autoVk
    ?'Автоматическая цепочка проверки CAPTCHA исчерпала доступные попытки. Для продолжения нужно пройти VK вручную. После успешной авторизации CSQTT сможет повторить запуск.'
    :'Режим «Авто API» не может продолжить работу без действующей авторизации VK. Открой авторизацию VK и заверши вход.';
  let m=document.getElementById('vkActionModal');
  if(!m){m=document.createElement('div');m.id='vkActionModal';document.body.appendChild(m)}
  m.className='vkActionModal';
  m.innerHTML='<div class="vkActionModalBox '+(autoVk?'danger':'')+'"><div class="vkActionModalIcon">'+(autoVk?'🧩':'🔐')+'</div><h2 class="vkActionModalTitle">'+title+'</h2><p class="vkActionModalText">'+text+'</p><div class="vkActionModalActions"><button type="button" id="vkActionLogin">🔐 Авторизоваться через VK</button><button type="button" class="secondary" id="vkActionLater">Позже</button></div></div>';
  document.getElementById('vkActionLater').onclick=()=>m.remove();
  document.getElementById('vkActionLogin').onclick=()=>{m.remove();document.getElementById('vkLogin').click()};
}
async function saveVKToken(){
  const input=document.getElementById('vkTokenInput'), msg=document.getElementById('tokenMsg');
  const raw=input.value.trim();
  if(!raw){msg.textContent='Вставь полную ссылку VK blank.html.';return}  msg.textContent='Проверяю токен…';
  try{
    const r=await fetch('/api/vk/token',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({token:raw})});
    const x=await r.json().catch(()=>({}));
    if(!r.ok||!x.ok){
      msg.textContent=x.message||'Требуется обновить токен';
      return;
    }
    input.value='';
    msg.textContent='✅ Токен проверен и сохранён. CSQTT перезапускается…';
    setTimeout(refresh,1500);
  }catch(e){msg.textContent='Ошибка: '+e.message}
}
document.getElementById('saveVKToken').onclick=saveVKToken;

async function deployServer(){
  const msg=document.getElementById('deployMsg');
  msg.textContent='⏳ Подготовка deploy…\nЭто может занять несколько минут.';
  const body={
    host:document.getElementById('dHost').value.trim(),
    ssh_port:Number(document.getElementById('dSSH').value),
    user:document.getElementById('dUser').value.trim(),
    key_path:document.getElementById('dKey').value.trim(),
    password:document.getElementById('dPassword').value,
    peer_port:Number(document.getElementById('dPeer').value),
    web_port:Number(document.getElementById('dWeb').value),
    web_user:document.getElementById('dWebUser').value.trim(),
    web_pass:document.getElementById('dWebPass').value,
    server_password:document.getElementById('dServerPass').value,
    use_for_router:document.getElementById('dUse').checked,
    version:'v2.1.9'
  };
  let r;
  try{
    r=await fetch('/api/deploy/server',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});
    const x=await r.json();
    msg.textContent=x.ok
      ? '✅ DEPLOY УСПЕШЕН\nVPS: '+x.server+'\nArch: '+x.arch+'\nUDP: '+x.peer_port+'\nWEB: '+x.web_port+'\nAsset: '+x.asset
      : '❌ Ошибка: '+(x.error||'unknown');
  }catch(e){ msg.textContent='❌ Ошибка соединения с панелью: '+e; }
}

function updateVKBookmarklet(){
  const out=document.getElementById('vkBookmarklet');
  if(!out) return;
  const code="javascript:(()=>{try{const p=new URLSearchParams(location.hash.slice(1)),t=p.get('access_token')||'',s=p.get('state')||'';if(!t)throw Error('VK не вернул access_token');if(!s)throw Error('нет state CSQTT');let d=s.replace(/-/g,'+').replace(/_/g,'/');while(d.length%4)d+='=';const raw=new TextDecoder().decode(Uint8Array.from(atob(d),c=>c.charCodeAt(0))),i=raw.indexOf('|'),cb=raw.slice(0,i),panel=cb.replace(/\\/api\\/vk\\/token$/,'')+'#vk';if(!/^https?:\\/\\/[^|]+\\/api\\/vk\\/token$/i.test(cb))throw Error('неверный CSQTT callback');document.documentElement.innerHTML='<head><meta name=\\\"viewport\\\" content=\\\"width=device-width,initial-scale=1\\\"><title>CSQTT VK</title><style>*{box-sizing:border-box}body{margin:0;min-height:100vh;font-family:system-ui,-apple-system,BlinkMacSystemFont,Segoe UI,sans-serif;background:radial-gradient(circle at 50% 0,#182338 0,#0b0d12 42%,#07080b 100%);color:#fff;padding:22px}.box{max-width:560px;margin:5vh auto 0;background:rgba(20,23,30,.96);border:1px solid rgba(255,255,255,.12);border-radius:30px;padding:34px 24px 28px;box-shadow:0 18px 55px rgba(0,0,0,.45);text-align:center}.vk{width:76px;height:76px;margin:0 auto 18px;border-radius:24px;background:#1976e8;display:flex;align-items:center;justify-content:center;color:#fff;font-size:39px;font-weight:850;box-shadow:0 10px 28px rgba(25,118,232,.34)}.check{width:58px;height:58px;margin:4px auto 17px;border-radius:50%;background:rgba(40,200,120,.14);color:#35d58b;display:flex;align-items:center;justify-content:center;font-size:34px}.title{font-size:26px;font-weight:800;margin:0 0 10px}.text{font-size:16px;line-height:1.5;color:#b9bec9;margin:0 auto 22px;max-width:470px}.hint{font-size:14px;color:#858c99;margin:0 0 12px}.url{background:#0b0d12;border:1px solid #343a46;border-radius:14px;padding:13px;text-align:left;font:13px ui-monospace,SFMono-Regular,Consolas,monospace;color:#9ecbff;word-break:break-all;max-height:92px;overflow:hidden}.btn{display:block;width:100%;border:0;border-radius:17px;padding:15px 18px;margin-top:16px;background:linear-gradient(135deg,#1976e8,#1565d8);color:#fff;font-size:16px;font-weight:750;box-shadow:0 7px 18px rgba(25,118,232,.28)}.copy{display:block;width:100%;border:1px solid #3a4250;border-radius:17px;padding:13px 18px;margin-top:10px;background:#20252e;color:#fff;font-size:15px;font-weight:700}</style></head><body><main class=box><div class=vk>VK</div><div class=check>✓</div><h1 class=title>Авторизация успешна!</h1><p class=text>Токен VK получен. Скопируйте ссылку этой страницы, затем вернитесь в CSQTT и вставьте её в раздел авторизации.</p><p class=hint>Полная ссылка этой страницы:</p><div class=url id=url></div><button class=copy id=copy>Копировать ссылку</button><button class=btn id=back>Раздел авторизации</button></main><script>document.getElementById(\\\"url\\\").textContent=location.href;document.getElementById(\\\"copy\\\").onclick=async()=>{try{await navigator.clipboard.writeText(location.href);document.getElementById(\\\"copy\\\").textContent=\\\"✓ Ссылка скопирована\\\"}catch(e){document.getElementById(\\\"copy\\\").textContent=\\\"Выделите ссылку в адресной строке\\\"}};</script></body>';out.value=code;
}
async function copyVKBookmarklet(){
  updateVKBookmarklet();
  const out=document.getElementById('vkBookmarklet');
  try{
    await navigator.clipboard.writeText(out.value);
    document.getElementById('msg').textContent='✅ Код кнопки скопирован. Создай/отредактируй закладку «CSQTT VK» и вставь его в поле URL.';
  }catch(e){
    out.focus();out.select();document.execCommand('copy');
    document.getElementById('msg').textContent='✅ Код кнопки выделен. Скопируй его и вставь в URL закладки «CSQTT VK».';
  }
}
async function refresh(){
  updateVKBookmarklet();
  let r=await fetch('/api/vk/status');let x=await r.json();
  document.getElementById('vk').textContent=x.token_valid?'🟢 Авторизован':'🔴 Не авторизован';
  document.getElementById('vk').className=x.token_valid?'ok':'warn';
  if(!x.token_valid && x.mode==='manual') showVKTokenModal();
  document.getElementById('uid').textContent=x.user_id?'VK ID: '+x.user_id:'';
  const rt=x.runtime||{};
  showVKActionModal(x,rt);
  const enabled=x.enabled!==false;
  const running=!!rt.client_running;
  const pb=document.getElementById('powerBtn'),ps=document.getElementById('powerState');
  if(running){ps.textContent='Подключено';ps.className='powerState ok';pb.textContent='Отключить';pb.className='powerBtn powerOn';pb.dataset.enabled='true';if(!powerSince)powerSince=Date.now()}
  else if(!enabled){ps.textContent='Отключено';ps.className='powerState muted';pb.textContent='Подключить';pb.className='powerBtn powerOff';pb.dataset.enabled='false';powerSince=0}
  else{const stage=rt.stage||'idle';const waiting=['starting','getting_hashes','hashes_received','restarting','client_started'].includes(stage);ps.textContent=waiting?'Подключение…':'Отключено';ps.className=waiting?'powerState warn':'powerState muted';pb.textContent='Подключить';pb.className='powerBtn powerOff';pb.dataset.enabled='false';powerSince=0}
  document.getElementById('powerTime').textContent=powerSince?fmtTime(Date.now()-powerSince):'00:00:00';
  const cfg=await fetch('/api/config',{cache:'no-store'}).then(r=>r.json()).catch(()=>({config:{}}));
  const cc=cfg.config||{};
  document.getElementById('mObfs').textContent=cc.obfs||'—';
  document.getElementById('mHash').textContent=x.mode==='manual'?(rt.hashes_received||'Ручные'):'Авто';
  document.getElementById('mMode').textContent=x.mode==='auto_api'?'Авто API':x.mode==='auto_js'?'Авто ВК':'Ручной';
  const labels={starting:'Запуск manager…',getting_hashes:'Получаю VK hashes…',hashes_received:'Hashes получены',client_started:'Запускаю CSQTT…',client_stopped:'CSQTT остановлен',idle:'Ожидание',error:'Ошибка'};
  let st=labels[rt.stage]||rt.stage||'Ожидание';
  if(rt.stage==='getting_hashes' && rt.calls_requested) st+=' ('+Number(rt.calls_created||0)+'/'+Number(rt.calls_requested)+')';
  if(rt.stage==='hashes_received') st+=': '+Number(rt.hashes_received||0);
  if(rt.client_started) st+=' ✓';
  if(rt.error) st+=' — '+rt.error;
  document.getElementById('autoState').textContent='Auto VK: '+st;
  renderHashRuntime(rt);
  renderHashNotice(rt);
  showHashToast(rt);
  document.querySelectorAll('input[name=hashMode]').forEach(e=>e.checked=e.value===x.mode);
  modeChanged();
}
function maskHashForUI(v){return String(v||'').trim()}
function renderHashRuntime(rt){
  const total=Number(rt.hash_total||0), active=Number(rt.hash_active||0), dead=Number(rt.hash_unavailable||Math.max(0,total-active));
  const ac=document.getElementById('hashActiveCount'),dc=document.getElementById('hashDeadCount'),tc=document.getElementById('hashTotalCount');
  if(ac)ac.textContent=active; if(dc)dc.textContent=dead; if(tc)tc.textContent=total;
  const list=document.getElementById('hashList'); if(!list)return;
  const hashes=Array.isArray(rt.hashes)?rt.hashes:[];
  if(!hashes.length){list.innerHTML='<div class="hashEmpty">Пока нет данных о хешах. Добавь ручные хеши ниже и сохрани режим.</div>';return}
  list.innerHTML=hashes.map((h,i)=>'<div class="hashItem '+(h.available?'':'dead')+'" style="animation-delay:'+Math.min(i*45,360)+'ms"><span class="hashDot"></span><span class="hashText">'+escapeHTML(h.hash||'hash')+'</span><span class="hashStatus">'+(h.available?'АКТИВЕН':'ОТКЛЮЧЁН')+'</span></div>').join('');
}
function escapeHTML(v){return String(v).replace(/[&<>"']/g,function(c){return ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'})[c]})}
let hashToastTimer=0;
function showHashToast(rt){
  const notice=String(rt.hash_notice||'').trim(); if(!notice)return;
  const stamp=String(rt.hash_notice_at||''); if(!stamp)return;
  const key='csqtt_hash_notice_seen';
  let seen=''; try{seen=localStorage.getItem(key)||''}catch(e){}
  if(seen===stamp)return;
  let t=document.getElementById('hashToast');
  if(!t){t=document.createElement('div');t.id='hashToast';t.className='hashToast';document.body.appendChild(t)}
  const danger=Number(rt.hash_active||0)===0||rt.error==='all configured VK hashes are unavailable'||rt.token_invalid;
  t.className='hashToast '+(danger?'danger':'');
  t.innerHTML='<span class="hashToastIcon">'+(danger?'⛔':'⚠️')+'</span><div><div class="hashToastTitle">'+(danger?'Изменение VK хешей':'Статус VK хешей изменился')+'</div><div class="hashToastText">'+escapeHTML(notice)+'</div></div>';
  requestAnimationFrame(()=>t.classList.add('show'));
  clearTimeout(hashToastTimer); hashToastTimer=setTimeout(()=>t.classList.remove('show'),6500);
  try{localStorage.setItem(key,stamp)}catch(e){}
}
function renderHashNotice(rt){
  const box=document.getElementById('hashNotice'); if(!box)return;
  const notice=String(rt.hash_notice||'').trim();
  if(!notice){box.style.display='none';box.innerHTML='';return}
  const danger=Number(rt.hash_active||0)===0||rt.error==='all configured VK hashes are unavailable'||rt.token_invalid;
  box.className='hashNotice '+(danger?'danger':'');
  box.style.display='flex';
  box.innerHTML='<span class="hashNoticeIcon">'+(danger?'⛔':'⚠️')+'</span><div><div class="hashNoticeTitle">'+(danger?'Туннель требует внимания':'Изменение статуса хешей')+'</div><div class="hashNoticeText">'+escapeHTML(notice)+'</div></div>';
}
function updateHashCounter(){
  const el=document.getElementById('hashCounter'); const input=document.getElementById('hashes'); if(!el||!input)return;
  const n=input.value.split(/\r?\n/).map(x=>x.trim()).filter(Boolean).length;
  el.textContent=n+' / 6';
}
function modeChanged(){
  let m=document.querySelector('input[name=hashMode]:checked')?.value||'auto_api';
  document.getElementById('manualHashes').style.display=m==='manual'?'block':'none';
  if(m==='manual'){updateHashCounter(); const input=document.getElementById('hashes'); if(input&&!input.dataset.bound){input.addEventListener('input',updateHashCounter);input.dataset.bound='1'}}
}
async function saveMode(){
  let mode=document.querySelector('input[name=hashMode]:checked')?.value||'auto_api';
  let hashes=mode==='manual'?document.getElementById('hashes').value.split(/\\r?\\n/).map(x=>x.trim()).filter(Boolean):[];
  let r=await fetch('/api/vk/mode',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({mode:mode,hashes:hashes})});
  let x=await r.json();
  document.getElementById('modeMsg').textContent=x.ok?'Режим сохранён: '+x.mode+(x.restart_pending?' · перезапускаю manager…':''):'Ошибка: '+(x.error||'unknown');
  const hs=document.getElementById('hashSaveState'); if(hs&&x.ok)hs.textContent='✓ Сохранено';
  if(x.ok)setTimeout(refresh,900);
}
refresh();
</script></body></html>`))

var _ = fmt.Sprintf

const vkCallbackHTML = `<!doctype html><html lang="ru"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>CSQTT VK</title><style>body{font-family:system-ui,sans-serif;background:#111;color:#eee;max-width:640px;margin:40px auto;padding:24px}.ok{color:#67e8a5}.err{color:#ff7777}</style></head><body><h2 id="title">VK авторизация</h2><p id="msg">Получаю access token…</p><script>(async function(){const msg=document.getElementById('msg');try{const p=new URLSearchParams(location.hash.replace(/^#/,''));const token=p.get('access_token')||'';const userId=p.get('user_id')||'';const expires=p.get('expires_in')||'0';const state=p.get('state')||'';const error=p.get('error');if(error)throw new Error(error+(p.get('error_description')?': '+p.get('error_description'):''));if(!token)throw new Error('VK не вернул access_token. Проверь redirect_uri в настройках VK приложения.');msg.textContent='Token получен. Передаю его в CSQTT…';const r=await fetch(location.pathname,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({token:token,user_id:userId,expires_in:Number(expires)||0,state:state})});const x=await r.json().catch(()=>({}));if(!r.ok||!x.ok)throw new Error(x.error||('HTTP '+r.status));document.getElementById('title').className='ok';document.getElementById('title').textContent='VK авторизация успешна ✓';msg.textContent='Token сохранён. CSQTT перезапускается и получает VK hashes автоматически.';}catch(e){document.getElementById('title').className='err';msg.className='err';msg.textContent='Ошибка: '+e.message;}})();</script></body></html>`;