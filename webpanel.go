package main

import (
    "encoding/json"
    "fmt"
    "html/template"
    "log"
    "net/http"
    "net/url"
    "os"
    "strings"
    "sync"
)

const (
    csqttWebListen = "0.0.0.0:2001"
    vkWebAppID = "7793118"
    vkWebScope = "1073737727"
    vkWebRedirect = "https://oauth.vk.ru/blank.html"
    vkWebVersion = "5.199"
)

var vkTokenMu sync.Mutex

func init() {
    go startCSQTTWebPanel()
}

func startCSQTTWebPanel() {
    mux := http.NewServeMux()
    mux.HandleFunc("/", csqttPanel)
    mux.HandleFunc("/api/vk/token", csqttSaveVKToken)
    mux.HandleFunc("/api/vk/status", csqttVKStatus)
    mux.HandleFunc("/api/vk/mode", csqttSetVKMode)
    mux.HandleFunc("/api/config", csqttConfigStatus)

    log.Printf("CSQTT Web Panel listening on http://%s", csqttWebListen)
    if err := http.ListenAndServe(csqttWebListen, mux); err != nil {
        log.Printf("CSQTT Web Panel stopped: %v", err)
    }
}

func vkOAuthURL() string {
    q := url.Values{}
    q.Set("client_id", vkWebAppID)
    q.Set("scope", vkWebScope)
    q.Set("redirect_uri", vkWebRedirect)
    q.Set("display", "page")
    q.Set("response_type", "token")
    q.Set("revoke", "1")
    q.Set("v", vkWebVersion)
    return "https://oauth.vk.ru/authorize?" + q.Encode()
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

func csqttSaveVKToken(w http.ResponseWriter, r *http.Request) {
    if r.Method != http.MethodPost {
        http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
        return
    }
    var req struct {
        Token string `json:"token"`
        UserID string `json:"user_id"`
        ExpiresIn int64 `json:"expires_in"`
    }
    if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
        http.Error(w, "invalid json", http.StatusBadRequest)
        return
    }
    token := strings.TrimSpace(req.Token)
    if token == "" || len(token) < 16 {
        http.Error(w, "invalid token", http.StatusBadRequest)
        return
    }

    vkTokenMu.Lock()
    defer vkTokenMu.Unlock()
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
    writeJSON(w, map[string]any{"ok": true, "user_id": req.UserID})
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
    writeJSON(w, map[string]any{"ok": true, "mode": mode})
}

func csqttVKStatus(w http.ResponseWriter, r *http.Request) {
    cfg, err := readCSQTTConfig()
    if err != nil {
        writeJSON(w, map[string]any{"ok": false, "authorized": false})
        return
    }
    token, _ := cfg["vk_access_token"].(string)
    userID, _ := cfg["vk_user_id"].(string)
    mode, _ := cfg["vk_hash_mode"].(string)
    writeJSON(w, map[string]any{
        "ok": true,
        "authorized": strings.TrimSpace(token) != "",
        "user_id": userID,
        "mode": mode,
    })
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
body{font-family:system-ui,-apple-system,sans-serif;background:#111;color:#eee;max-width:760px;margin:0 auto;padding:24px}
.card{background:#1c1c1c;border:1px solid #333;border-radius:16px;padding:20px;margin:14px 0}
button{background:#4f7cff;color:#fff;border:0;border-radius:10px;padding:11px 16px;font-weight:600;cursor:pointer}
button.secondary{background:#333}.status{font-size:18px}.muted{color:#aaa}.ok{color:#67e8a5}.warn{color:#ffd166}
input{width:100%;box-sizing:border-box;background:#101010;color:#eee;border:1px solid #444;border-radius:10px;padding:11px;margin:8px 0}
small{color:#999}.row{display:flex;gap:10px;flex-wrap:wrap}
code{word-break:break-all;color:#9ecbff}
</style></head><body>
<h1>CSQTT-Keenetic</h1>
<div class="card"><div class="status">VK: <span id="vk" class="warn">проверка…</span></div><div id="uid" class="muted"></div></div>
<div class="card">
<h2>Авторизация VK</h2>
<p class="muted">Открой VK, войди в аккаунт и после перенаправления на blank.html вставь полный URL ниже. Токен будет извлечён браузером и передан на Keenetic; сам токен интерфейс не показывает.</p>
<div class="row"><button onclick="window.open({{printf "%q" .OAuthURL}},'_blank','noopener')">Открыть VK</button></div>
<label>URL после авторизации VK</label>
<input id="oauthUrl" placeholder="https://oauth.vk.ru/blank.html#access_token=…">
<div class="row"><button onclick="importOAuth()">Получить и сохранить токен</button><button class="secondary" onclick="refresh()">Обновить</button></div>
<div id="msg" class="muted"></div>
</div>
<div class="card">
<h2>Hash режим</h2>
<p class="muted">Один авторизованный VK аккаунт используется для обоих автоматических режимов.</p>
<label><input type="radio" name="hashMode" value="manual" onchange="modeChanged()"> Ручной — вставить VK hashes</label>
<label><input type="radio" name="hashMode" value="auto_api" onchange="modeChanged()"> Авто API — calls.start</label>
<label><input type="radio" name="hashMode" value="auto_js" onchange="modeChanged()"> Авто ВК — VK Calls / vchat</label>
<div id="manualHashes" style="display:none">
  <label>VK hashes (по одному на строку)</label>
  <textarea id="hashes" rows="6" style="width:100%;box-sizing:border-box;background:#101010;color:#eee;border:1px solid #444;border-radius:10px;padding:11px"></textarea>
</div>
<div class="row"><button onclick="saveMode()">Сохранить режим</button></div>
<div id="modeMsg" class="muted"></div>
</div>
<script>
async function refresh(){
  let r=await fetch('/api/vk/status');let x=await r.json();
  document.getElementById('vk').textContent=x.authorized?'🟢 Авторизован':'🔴 Не авторизован';
  document.getElementById('vk').className=x.authorized?'ok':'warn';
  document.getElementById('uid').textContent=x.user_id?'VK ID: '+x.user_id:'';
  document.querySelectorAll('input[name=hashMode]').forEach(e=>e.checked=e.value===x.mode);
  modeChanged();
}
function modeChanged(){
  let m=document.querySelector('input[name=hashMode]:checked')?.value||'auto_api';
  document.getElementById('manualHashes').style.display=m==='manual'?'block':'none';
}
function parseToken(s){try{let u=new URL(s);let p=new URLSearchParams(u.hash.replace(/^#/ ,''));return {token:p.get('access_token')||'',user_id:p.get('user_id')||'',expires_in:Number(p.get('expires_in')||0)}}catch(e){let p=new URLSearchParams((s.split('#')[1]||'').replace(/^#/ ,''));return {token:p.get('access_token')||'',user_id:p.get('user_id')||'',expires_in:Number(p.get('expires_in')||0)}}}
async function importOAuth(){let v=parseToken(document.getElementById('oauthUrl').value.trim());if(!v.token){document.getElementById('msg').textContent='Не найден access_token в URL';return}let r=await fetch('/api/vk/token',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(v)});let x=await r.json();document.getElementById('msg').textContent=x.ok?'Токен сохранён. Теперь можно выбрать Auto API или Auto ВК.':'Ошибка: '+(x.error||'unknown');if(x.ok)refresh()}
async function saveMode(){
  let mode=document.querySelector('input[name=hashMode]:checked')?.value||'auto_api';
  let hashes=mode==='manual'?document.getElementById('hashes').value.split(/\\r?\\n/).map(x=>x.trim()).filter(Boolean):[];
  let r=await fetch('/api/vk/mode',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({mode:mode,hashes:hashes})});
  let x=await r.json();
  document.getElementById('modeMsg').textContent=x.ok?'Режим сохранён: '+x.mode:'Ошибка: '+(x.error||'unknown');
  if(x.ok)refresh();
}
refresh();
</script></body></html>`))

var _ = fmt.Sprintf
