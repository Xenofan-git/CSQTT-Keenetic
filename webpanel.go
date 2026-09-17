package main

import (
    "crypto/rand"
    "encoding/base64"
    "encoding/json"
    "fmt"
    "html/template"
    "log"
    "net/http"
    "net/url"
    "os"
    "strings"
    "sync"
    "time"
)

const (
    csqttWebListen = "0.0.0.0:2001"
    vkWebAppID = "7793118"
    vkWebScope = "1073737727"
    vkWebVersion = "5.199"
    vkOAuthStateCookie = "csqtt_vk_oauth_state"
)

var vkTokenMu sync.Mutex
var vkHTTPClient = &http.Client{Timeout: 8 * time.Second}

func init() { go startCSQTTWebPanel() }

func startCSQTTWebPanel() {
    mux := http.NewServeMux()
    mux.HandleFunc("/", csqttPanel)
    mux.HandleFunc("/oauth/vk/callback", csqttVKCallback)
    mux.HandleFunc("/api/vk/token", csqttSaveVKToken)
    mux.HandleFunc("/api/vk/status", csqttVKStatus)
    mux.HandleFunc("/api/config", csqttConfigStatus)
    log.Printf("CSQTT Web Panel listening on http://%s", csqttWebListen)
    if err := http.ListenAndServe(csqttWebListen, securityHeaders(mux)); err != nil {
        log.Printf("CSQTT Web Panel stopped: %v", err)
    }
}

func securityHeaders(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        w.Header().Set("Cache-Control", "no-store")
        w.Header().Set("Referrer-Policy", "no-referrer")
        w.Header().Set("X-Content-Type-Options", "nosniff")
        next.ServeHTTP(w, r)
    })
}

func newOAuthState() (string, error) {
    b := make([]byte, 32)
    if _, err := rand.Read(b); err != nil { return "", err }
    return base64.RawURLEncoding.EncodeToString(b), nil
}

func setOAuthStateCookie(w http.ResponseWriter, r *http.Request, state string) {
    secure := r.TLS != nil
    http.SetCookie(w, &http.Cookie{Name: vkOAuthStateCookie, Value: state, Path: "/oauth/vk/callback", HttpOnly: true, SameSite: http.SameSiteLaxMode, Secure: secure, MaxAge: 600})
}

func vkRedirectURI() (string, error) {
    v := strings.TrimSpace(os.Getenv("CSQTT_VK_REDIRECT_URI"))
    if v == "" {
        return "", fmt.Errorf("CSQTT_VK_REDIRECT_URI is not configured")
    }
    u, err := url.Parse(v)
    if err != nil || u.Scheme == "" || u.Host == "" || u.Path != "/oauth/vk/callback" || u.RawQuery != "" || u.Fragment != "" {
        return "", fmt.Errorf("invalid CSQTT_VK_REDIRECT_URI")
    }
    if u.Scheme != "https" && u.Scheme != "http" {
        return "", fmt.Errorf("CSQTT_VK_REDIRECT_URI must use http or https")
    }
    return v, nil
}

func vkOAuthURL(state string) (string, error) {
    redirectURI, err := vkRedirectURI()
    if err != nil { return "", err }
    q := url.Values{}
    q.Set("client_id", vkWebAppID)
    q.Set("scope", vkWebScope)
    q.Set("redirect_uri", redirectURI)
    q.Set("display", "page")
    q.Set("response_type", "token")
    q.Set("revoke", "1")
    q.Set("v", vkWebVersion)
    q.Set("state", state)
    return "https://oauth.vk.ru/authorize?" + q.Encode(), nil
}

func readCSQTTConfig() (map[string]any, error) {
    path := "/opt/etc/csqtt/config.json"
    b, err := os.ReadFile(path)
    if err != nil { return map[string]any{}, err }
    var v map[string]any
    if err := json.Unmarshal(b, &v); err != nil { return nil, err }
    return v, nil
}

func writeCSQTTConfig(v map[string]any) error {
    path := "/opt/etc/csqtt/config.json"
    b, err := json.MarshalIndent(v, "", "  ")
    if err != nil { return err }
    tmp := path + ".tmp"
    if err := os.WriteFile(tmp, append(b, '\n'), 0600); err != nil { return err }
    return os.Rename(tmp, path)
}

func csqttPanel(w http.ResponseWriter, r *http.Request) {
    if r.URL.Path != "/" { http.NotFound(w, r); return }
    state, err := newOAuthState()
    if err != nil { http.Error(w, "cannot create OAuth state", http.StatusInternalServerError); return }
    oauthURL, err := vkOAuthURL(state)
    if err != nil {
        http.Error(w, "VK OAuth redirect URI is not configured", http.StatusServiceUnavailable)
        return
    }
    setOAuthStateCookie(w, r, state)
    data := struct { OAuthURL string }{OAuthURL: oauthURL}
    w.Header().Set("Content-Type", "text/html; charset=utf-8")
    _ = csqttPanelTemplate.Execute(w, data)
}

func csqttVKCallback(w http.ResponseWriter, r *http.Request) {
    if r.URL.Path != "/oauth/vk/callback" { http.NotFound(w, r); return }
    w.Header().Set("Content-Type", "text/html; charset=utf-8")
    _, _ = w.Write([]byte(`<!doctype html><html lang="ru"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>VK — CSQTT</title></head><body style="font-family:system-ui;max-width:600px;margin:40px auto;padding:20px;background:#111;color:#eee"><h2 id="s">Получаю токен VK…</h2><p id="m">Окно можно закрыть после завершения.</p><script>
(async()=>{const p=new URLSearchParams(location.hash.replace(/^#/,''));const token=p.get('access_token')||'';const user_id=p.get('user_id')||'';const expires_in=Number(p.get('expires_in')||0);const state=p.get('state')||'';const err=p.get('error');if(err||!token){document.getElementById('s').textContent='Авторизация VK не завершена';document.getElementById('m').textContent=err||'Токен не получен';return}document.getElementById('s').textContent='Проверяю токен через VK…';try{const r=await fetch('/api/vk/token',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({token,user_id,expires_in,state}),cache:'no-store'});const x=await r.json();if(!x.ok)throw new Error(x.error||'Ошибка сохранения');document.getElementById('s').textContent='🟢 VK авторизация завершена';document.getElementById('m').textContent='Токен автоматически проверен и сохранён на Keenetic. Возвращаюсь в панель…';history.replaceState(null,'',location.pathname);setTimeout(()=>location.href='/',1200)}catch(e){document.getElementById('s').textContent='Ошибка VK авторизации';document.getElementById('m').textContent=e.message}})();
</script></body></html>`))
}

func validateVKToken(token string) (string, error) {
    q := url.Values{}
    q.Set("access_token", token)
    q.Set("v", vkWebVersion)
    req, err := http.NewRequest(http.MethodGet, "https://api.vk.ru/method/users.get?"+q.Encode(), nil)
    if err != nil { return "", err }
    req.Header.Set("Accept", "application/json")
    resp, err := vkHTTPClient.Do(req)
    if err != nil { return "", fmt.Errorf("VK API request failed") }
    defer resp.Body.Close()
    if resp.StatusCode != http.StatusOK { return "", fmt.Errorf("VK API returned HTTP %d", resp.StatusCode) }
    var result struct { Response []struct { ID int64 `json:"id"` } `json:"response"`; Error *struct { Code int `json:"error_code"` } `json:"error"` }
    if err := json.NewDecoder(resp.Body).Decode(&result); err != nil { return "", fmt.Errorf("invalid VK API response") }
    if result.Error != nil { return "", fmt.Errorf("VK token rejected (code %d)", result.Error.Code) }
    if len(result.Response) == 0 || result.Response[0].ID <= 0 { return "", fmt.Errorf("VK API did not return a user") }
    return fmt.Sprintf("%d", result.Response[0].ID), nil
}

func csqttSaveVKToken(w http.ResponseWriter, r *http.Request) {
    if r.Method != http.MethodPost { http.Error(w, "method not allowed", http.StatusMethodNotAllowed); return }
    r.Body = http.MaxBytesReader(w, r.Body, 16*1024)
    var req struct { Token string `json:"token"`; UserID string `json:"user_id"`; ExpiresIn int64 `json:"expires_in"`; State string `json:"state"` }
    if err := json.NewDecoder(r.Body).Decode(&req); err != nil { http.Error(w, "invalid json", http.StatusBadRequest); return }
    token := strings.TrimSpace(req.Token)
    if token == "" || len(token) < 16 || len(token) > 4096 || req.ExpiresIn < 0 { http.Error(w, "invalid token data", http.StatusBadRequest); return }
    cookie, err := r.Cookie(vkOAuthStateCookie)
    if err != nil || cookie.Value == "" || req.State == "" || !secureStringEqual(cookie.Value, req.State) { http.Error(w, "invalid OAuth state", http.StatusForbidden); return }
    vkTokenMu.Lock(); defer vkTokenMu.Unlock()
    vkUserID, err := validateVKToken(token)
    if err != nil { http.Error(w, err.Error(), http.StatusUnauthorized); return }
    cfg, err := readCSQTTConfig()
    if err != nil { http.Error(w, "cannot read config: "+err.Error(), http.StatusInternalServerError); return }
    cfg["vk_access_token"] = token
    cfg["vk_user_id"] = vkUserID
    cfg["vk_token_expires_in"] = req.ExpiresIn
    cfg["vk_hash_mode"] = "auto_api"
    if err := writeCSQTTConfig(cfg); err != nil { http.Error(w, "cannot save config: "+err.Error(), http.StatusInternalServerError); return }
    http.SetCookie(w, &http.Cookie{Name: vkOAuthStateCookie, Value: "", Path: "/oauth/vk/callback", HttpOnly: true, SameSite: http.SameSiteLaxMode, Secure: r.TLS != nil, MaxAge: -1})
    log.Printf("CSQTT Web Panel: VK access token validated and saved for user %s", vkUserID)
    writeJSON(w, map[string]any{"ok": true, "user_id": vkUserID})
}

func secureStringEqual(a, b string) bool {
    if len(a) != len(b) { return false }
    var diff byte
    for i := range a { diff |= a[i] ^ b[i] }
    return diff == 0
}

func csqttVKStatus(w http.ResponseWriter, r *http.Request) {
    cfg, err := readCSQTTConfig()
    if err != nil { writeJSON(w, map[string]any{"ok": false, "authorized": false}); return }
    token, _ := cfg["vk_access_token"].(string); userID, _ := cfg["vk_user_id"].(string); mode, _ := cfg["vk_hash_mode"].(string); expires, _ := cfg["vk_token_expires_in"].(float64)
    writeJSON(w, map[string]any{"ok": true, "authorized": strings.TrimSpace(token) != "", "user_id": userID, "mode": mode, "expires_in": int64(expires)})
}

func csqttConfigStatus(w http.ResponseWriter, r *http.Request) {
    cfg, err := readCSQTTConfig()
    if err != nil { writeJSON(w, map[string]any{"ok": false, "error": err.Error()}); return }
    delete(cfg, "vk_access_token"); delete(cfg, "password"); delete(cfg, "vk_hashes")
    writeJSON(w, map[string]any{"ok": true, "config": cfg})
}

func writeJSON(w http.ResponseWriter, value any) { w.Header().Set("Content-Type", "application/json; charset=utf-8"); _ = json.NewEncoder(w).Encode(value) }

var csqttPanelTemplate = template.Must(template.New("panel").Parse(`<!doctype html><html lang="ru"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>CSQTT-Keenetic</title><style>body{font-family:system-ui,-apple-system,sans-serif;background:#111;color:#eee;max-width:760px;margin:0 auto;padding:24px}.card{background:#1c1c1c;border:1px solid #333;border-radius:16px;padding:20px;margin:14px 0}button{background:#4f7cff;color:#fff;border:0;border-radius:10px;padding:11px 16px;font-weight:600;cursor:pointer}.secondary{background:#333}.status{font-size:18px}.muted{color:#aaa}.ok{color:#67e8a5}.warn{color:#ffd166}.row{display:flex;gap:10px;flex-wrap:wrap}</style></head><body><h1>CSQTT-Keenetic</h1><div class="card"><div class="status">VK: <span id="vk" class="warn">проверка…</span></div><div id="uid" class="muted"></div><div id="expiry" class="muted"></div></div><div class="card"><h2>Авторизация VK</h2><p class="muted">Нажми «Войти через VK». Авторизация откроется в новом окне. После входа VK автоматически вернёт токен прямо в эту панель — копировать URL или токен не нужно.</p><div class="row"><button onclick="window.open({{printf "%q" .OAuthURL}},'_blank','noopener')">Войти через VK</button><button class="secondary" onclick="refresh()">Обновить</button></div><div id="msg" class="muted"></div></div><div class="card"><h2>Hash режим</h2><div>Сейчас: <b id="mode">—</b></div><p class="muted">После успешной авторизации используется auto_api.</p></div><script>async function refresh(){try{let r=await fetch('/api/vk/status',{cache:'no-store'}),x=await r.json();document.getElementById('vk').textContent=x.authorized?'🟢 Авторизован':'🔴 Не авторизован';document.getElementById('vk').className=x.authorized?'ok':'warn';document.getElementById('uid').textContent=x.user_id?'VK ID: '+x.user_id:'';document.getElementById('mode').textContent=x.mode||'—';document.getElementById('expiry').textContent=x.authorized?(x.expires_in===0?'Токен: без срока действия':'Срок токена: '+x.expires_in+' сек.') : ''}catch(e){document.getElementById('msg').textContent='Не удалось получить статус'}}refresh();</script></body></html>`))

var _ = fmt.Sprintf
