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
    vkWebRedirect = "https://oauth.vk.ru/blank.html"
    vkWebVersion = "5.199"
)

//go:embed vk-auth.user.js
var vkAuthUserScript string

var vkTokenMu sync.Mutex
var vkAuthStates = map[string]time.Time{}

func init() {
    go startCSQTTWebPanel()
}

func startCSQTTWebPanel() {
    mux := http.NewServeMux()
    mux.HandleFunc("/", csqttPanel)
    mux.HandleFunc("/vk-auth.user.js", csqttVKUserScript)
    mux.HandleFunc("/api/vk/token", csqttVKCallback)
    mux.HandleFunc("/api/vk/session", csqttVKSession)
    mux.HandleFunc("/api/vk/oauth-url", csqttVKOAuthURL)
    mux.HandleFunc("/api/vk/status", csqttVKStatus)
    mux.HandleFunc("/api/vk/mode", csqttSetVKMode)
    mux.HandleFunc("/api/config", csqttConfigStatus)
    mux.HandleFunc("/api/deploy/server", csqttDeployServer)

    log.Printf("CSQTT Web Panel listening on http://%s", csqttWebListen)
    if err := http.ListenAndServe(csqttWebListen, mux); err != nil {
        log.Printf("CSQTT Web Panel stopped: %v", err)
    }
}

func vkCallbackURL(r *http.Request) string {
    scheme := "http"
    if strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https") || r.TLS != nil {
        scheme = "https"
    }
    return scheme + "://" + strings.TrimSpace(r.Host) + "/api/vk/token"
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
    // VK application 7793118 uses the registered blank.html redirect.
    // The access_token is returned in the URL fragment and captured by the
    // browser userscript running on oauth.vk.ru/blank.html.
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
    scheme := "http"
    if strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https") || r.TLS != nil {
        scheme = "https"
    }
    statePayload := scheme + "://" + strings.TrimSpace(r.Host) + "|" + nonce
    state := base64.RawURLEncoding.EncodeToString([]byte(statePayload))

    vkTokenMu.Lock()
    now := time.Now()
    for k, expiry := range vkAuthStates {
        if expiry.Before(now) {
            delete(vkAuthStates, k)
        }
    }
    vkAuthStates[state] = now.Add(5 * time.Minute)
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
        w.Header().Set("Content-Type", "text/html; charset=utf-8")
        _, _ = w.Write([]byte(vkCallbackHTML))
        return
    }
    csqttSaveVKToken(w, r)
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
    token := strings.TrimSpace(req.Token)
    if token == "" || len(token) < 16 {
        http.Error(w, "invalid token", http.StatusBadRequest)
        return
    }

    vkTokenMu.Lock()
    defer vkTokenMu.Unlock()

    if req.State != "" {
        expiry, ok := vkAuthStates[strings.TrimSpace(req.State)]
        if !ok || expiry.Before(time.Now()) {
            http.Error(w, "invalid or expired auth state", http.StatusForbidden)
            return
        }
        delete(vkAuthStates, strings.TrimSpace(req.State))
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
    writeJSON(w, map[string]any{"ok": true, "user_id": req.UserID, "restart_pending": true})

    // The web panel lives in the manager process. Restart it after the response so
    // the freshly saved token is consumed immediately by the normal startup path.
    go func() {
        time.Sleep(700 * time.Millisecond)
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
    runtime := map[string]any{}
    if b, err := os.ReadFile("/opt/etc/csqtt/vk-runtime.json"); err == nil {
        _ = json.Unmarshal(b, &runtime)
    }
    writeJSON(w, map[string]any{
        "ok": true,
        "authorized": strings.TrimSpace(token) != "",
        "user_id": userID,
        "mode": mode,
        "runtime": runtime,
    })
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
body{font-family:system-ui,-apple-system,sans-serif;background:#111;color:#eee;max-width:760px;margin:0 auto;padding:24px}
.card{background:#1c1c1c;border:1px solid #333;border-radius:16px;padding:20px;margin:14px 0}
button{background:#4f7cff;color:#fff;border:0;border-radius:10px;padding:11px 16px;font-weight:600;cursor:pointer}
button.secondary{background:#333}.status{font-size:18px}.muted{color:#aaa}.ok{color:#67e8a5}.warn{color:#ffd166}
input{width:100%;box-sizing:border-box;background:#101010;color:#eee;border:1px solid #444;border-radius:10px;padding:11px;margin:8px 0}
small{color:#999}.row{display:flex;gap:10px;flex-wrap:wrap}
code{word-break:break-all;color:#9ecbff}
</style></head><body>
<h1>CSQTT-Keenetic</h1>
<div class="card"><div class="status">VK: <span id="vk" class="warn">проверка…</span></div><div id="uid" class="muted"></div><div id="autoState" class="muted" style="margin-top:10px"></div></div>
<div class="card">
<h2>Авторизация VK</h2>
<p class="muted">VK-приложение 7793118 требует штатный redirect <code>https://oauth.vk.ru/blank.html</code>. После входа VK помещает access_token во фрагмент URL. Браузерный скрипт забирает его и передаёт в CSQTT — APK не нужен.</p>
<div class="row"><button type="button" id="vkLogin">🔐 Войти через VK</button><button class="secondary" onclick="refresh()">Обновить</button></div>
<div id="msg" class="muted"></div>
<div style="margin-top:14px">
  <details>
    <summary>🧩 Скрипт автоматического получения токена v1.2</summary>
    <p class="muted">Firefox Android: установи Violentmonkey и открой userscript ниже. Chrome Android: сохрани bookmarklet в закладку и запускай его из адресной строки на странице VK.</p>
    <a href="/vk-auth.user.js" target="_blank">📥 Открыть userscript</a>
    <textarea id="vkBookmarklet" readonly rows="4" style="width:100%;box-sizing:border-box;background:#101010;color:#9ecbff;border:1px solid #444;border-radius:10px;padding:11px;margin-top:10px"></textarea>
    <small>Bookmarklet: скопируй код в URL закладки с именем «CSQTT VK».</small>
  </details>
</div>
</div>
<div class="card">
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
  const code="javascript:(()=>{const p=new URLSearchParams(location.hash.slice(1));const t=p.get('access_token');const u=p.get('user_id')||'';const e=p.get('expires_in')||'0';const s=p.get('state')||'';if(!t||!s){alert('CSQTT VK: token/state не найден');return;}let d=s.replace(/-/g,'+').replace(/_/g,'/');while(d.length%4)d+='=';let raw='';try{raw=decodeURIComponent(escape(atob(d)))}catch(_){alert('CSQTT VK: неверный state');return;}const i=raw.indexOf('|');const panel=raw.slice(0,i);if(!panel){alert('CSQTT VK: panel URL не найден');return;}const f=document.createElement('form');f.method='POST';f.action=panel+'/api/vk/token';[['token',t],['user_id',u],['expires_in',e],['state',s]].forEach(([n,v])=>{const x=document.createElement('input');x.type='hidden';x.name=n;x.value=v;f.appendChild(x)});document.documentElement.appendChild(f);f.submit();})();";
  out.value=code;
}
async function refresh(){
  updateVKBookmarklet();
  let r=await fetch('/api/vk/status');let x=await r.json();
  document.getElementById('vk').textContent=x.authorized?'🟢 Авторизован':'🔴 Не авторизован';
  document.getElementById('vk').className=x.authorized?'ok':'warn';
  document.getElementById('uid').textContent=x.user_id?'VK ID: '+x.user_id:'';
  const rt=x.runtime||{};
  const labels={starting:'Запуск manager…',getting_hashes:'Получаю VK hashes…',hashes_received:'Hashes получены',client_started:'Запускаю CSQTT…',client_stopped:'CSQTT остановлен',idle:'Ожидание',error:'Ошибка'};
  let st=labels[rt.stage]||rt.stage||'Ожидание';
  if(rt.stage==='getting_hashes' && rt.calls_requested) st+=' ('+Number(rt.calls_created||0)+'/'+Number(rt.calls_requested)+')';
  if(rt.stage==='hashes_received') st+=': '+Number(rt.hashes_received||0);
  if(rt.client_started) st+=' ✓';
  if(rt.error) st+=' — '+rt.error;
  document.getElementById('autoState').textContent='Auto VK: '+st;
  document.querySelectorAll('input[name=hashMode]').forEach(e=>e.checked=e.value===x.mode);
  modeChanged();
}
function modeChanged(){
  let m=document.querySelector('input[name=hashMode]:checked')?.value||'auto_api';
  document.getElementById('manualHashes').style.display=m==='manual'?'block':'none';
}
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

const vkCallbackHTML = `<!doctype html><html lang="ru"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>CSQTT VK</title><style>body{font-family:system-ui,sans-serif;background:#111;color:#eee;max-width:640px;margin:40px auto;padding:24px}.ok{color:#67e8a5}.err{color:#ff7777}</style></head><body><h2 id="title">VK авторизация</h2><p id="msg">Получаю access token…</p><script>(async function(){const msg=document.getElementById('msg');try{const p=new URLSearchParams(location.hash.replace(/^#/,''));const token=p.get('access_token')||'';const userId=p.get('user_id')||'';const expires=p.get('expires_in')||'0';const state=p.get('state')||'';const error=p.get('error');if(error)throw new Error(error+(p.get('error_description')?': '+p.get('error_description'):''));if(!token)throw new Error('VK не вернул access_token. Проверь redirect_uri в настройках VK приложения.');msg.textContent='Token получен. Передаю его в CSQTT…';const r=await fetch(location.pathname,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({token:token,user_id:userId,expires_in:Number(expires)||0,state:state})});const x=await r.json().catch(()=>({}));if(!r.ok||!x.ok)throw new Error(x.error||('HTTP '+r.status));document.getElementById('title').className='ok';document.getElementById('title').textContent='VK авторизация успешна ✓';msg.textContent='Token сохранён. CSQTT перезапускается и получает VK hashes автоматически.';}catch(e){document.getElementById('title').className='err';msg.className='err';msg.textContent='Ошибка: '+e.message;}})();</script></body></html>`;