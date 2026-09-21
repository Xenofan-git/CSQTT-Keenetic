package main

import (
  "crypto/rand"
  "encoding/hex"
  "encoding/json"
  "errors"
  "fmt"
  "io"
  "log"
  "net/http"
  "net/url"
  "os"
  "path/filepath"
  "strings"
  "sync"
  "time"
)

const (
  defaultAddr = "0.0.0.0:18081"
  defaultClientID = "7793118"
  defaultScope = "1073737727"
  defaultAPIVer = "5.199"
)

type Config struct {
  ListenAddr string
  RedirectURI string
  ClientID string
  Scope string
  APIVersion string
  StateTTL time.Duration
  DataFile string
}

type StoredToken struct {
  AccessToken string
  UserID string
  ExpiresIn int64
  UpdatedAt time.Time
}

type App struct {
  cfg Config
  mu sync.Mutex
  states map[string]time.Time
  tokenMu sync.Mutex
  token StoredToken
}

func getenv(key, fallback string) string {
  if v := strings.TrimSpace(os.Getenv(key)); v != "" { return v }
  return fallback
}

func newState() (string, error) {
  b := make([]byte, 24)
  if _, err := rand.Read(b); err != nil { return "", err }
  return hex.EncodeToString(b), nil
}

func (a *App) oauthURL(state string) (string, error) {
  if a.cfg.RedirectURI == "" { return "", errors.New("VK_REDIRECT_URI is not configured") }
  q := url.Values{}
  q.Set("client_id", a.cfg.ClientID)
  q.Set("display", "mobile")
  q.Set("redirect_uri", a.cfg.RedirectURI)
  q.Set("response_type", "token")
  q.Set("scope", a.cfg.Scope)
  q.Set("v", a.cfg.APIVersion)
  q.Set("revoke", "1")
  q.Set("state", state)
  return "https://oauth.vk.ru/authorize?" + q.Encode(), nil
}

func (a *App) saveToken(t StoredToken) error {
  a.tokenMu.Lock()
  defer a.tokenMu.Unlock()
  if err := os.MkdirAll(filepath.Dir(a.cfg.DataFile), 0700); err != nil { return err }
  tmp := a.cfg.DataFile + ".tmp"
  b, err := json.MarshalIndent(t, "", "  ")
  if err != nil { return err }
  if err = os.WriteFile(tmp, b, 0600); err != nil { return err }
  if err = os.Rename(tmp, a.cfg.DataFile); err != nil { return err }
  a.token = t
  return nil
}

func (a *App) loadToken() {
  b, err := os.ReadFile(a.cfg.DataFile)
  if err != nil { return }
  var t StoredToken
  if json.Unmarshal(b, &t) == nil {
    a.tokenMu.Lock()
    a.token = t
    a.tokenMu.Unlock()
  }
}

func (a *App) validState(state string) bool {
  a.mu.Lock()
  defer a.mu.Unlock()
  t, ok := a.states[state]
  if !ok { return false }
  delete(a.states, state)
  return time.Since(t) <= a.cfg.StateTTL
}

func (a *App) start(w http.ResponseWriter, r *http.Request) {
  if r.Method != http.MethodGet { http.Error(w, "method not allowed", 405); return }
  state, err := newState()
  if err != nil { http.Error(w, "state generation failed", 500); return }
  a.mu.Lock()
  a.states[state] = time.Now()
  a.mu.Unlock()
  u, err := a.oauthURL(state)
  if err != nil { http.Error(w, err.Error(), 500); return }
  http.Redirect(w, r, u, http.StatusFound)
}

func (a *App) callback(w http.ResponseWriter, r *http.Request) {
  w.Header().Set("Content-Type", "text/html; charset=utf-8")
  const html = `<!doctype html><meta name="viewport" content="width=device-width,initial-scale=1">
<title>CSQTT VK authorization</title>
<body><p id="s">Получение результата VK...</p>
<script>
(async()=>{
 const s=document.getElementById('s');
 const p=new URLSearchParams(location.hash.replace(/^#/,''));
 const token=p.get('access_token'),state=p.get('state'),uid=p.get('user_id'),exp=p.get('expires_in');
 if(!token){s.textContent='VK не вернул access_token. Авторизация не завершена.';return}
 try{
   const body=new URLSearchParams({access_token:token,state:state||'',user_id:uid||'',expires_in:exp||''});
   const r=await fetch('/api/vk/token',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body});
   const j=await r.json();
   if(!r.ok) throw new Error(j.error||'token rejected');
   s.textContent='VK авторизация завершена. Возвращаемся в панель...';
   location.replace('/api/vk/status');
 }catch(e){s.textContent='Ошибка: '+e.message}
})();
</script></body>`
  io.WriteString(w, html)
}

func (a *App) tokenHandler(w http.ResponseWriter, r *http.Request) {
  if r.Method != http.MethodPost { http.Error(w, "method not allowed", 405); return }
  if err := r.ParseForm(); err != nil { http.Error(w, "bad form", 400); return }
  token := strings.TrimSpace(r.Form.Get("access_token"))
  state := strings.TrimSpace(r.Form.Get("state"))
  if len(token) < 20 { http.Error(w, "invalid access_token", 400); return }
  if state == "" || !a.validState(state) { http.Error(w, "invalid or expired state", 403); return }
  t := StoredToken{AccessToken: token, UserID: strings.TrimSpace(r.Form.Get("user_id")), UpdatedAt: time.Now().UTC()}
  if v := strings.TrimSpace(r.Form.Get("expires_in")); v != "" { fmt.Sscan(v, &t.ExpiresIn) }
  if err := a.saveToken(t); err != nil { http.Error(w, "token storage failed", 500); return }
  writeJSON(w, map[string]any{"ok": true, "user_id": t.UserID, "updated_at": t.UpdatedAt})
}

func (a *App) status(w http.ResponseWriter, r *http.Request) {
  if r.Method != http.MethodGet { http.Error(w, "method not allowed", 405); return }
  a.tokenMu.Lock()
  t := a.token
  a.tokenMu.Unlock()
  writeJSON(w, map[string]any{"ok": t.AccessToken != "", "user_id": t.UserID, "updated_at": t.UpdatedAt, "expires_in": t.ExpiresIn})
}

func (a *App) health(w http.ResponseWriter, r *http.Request) {
  a.tokenMu.Lock()
  ok := a.token.AccessToken != ""
  a.tokenMu.Unlock()
  writeJSON(w, map[string]any{"service": "vk-auth", "healthy": true, "token_present": ok})
}

func writeJSON(w http.ResponseWriter, v any) {
  w.Header().Set("Content-Type", "application/json; charset=utf-8")
  _ = json.NewEncoder(w).Encode(v)
}

func main() {
  cfg := Config{
    ListenAddr: getenv("VK_AUTH_LISTEN", defaultAddr),
    RedirectURI: strings.TrimSpace(os.Getenv("VK_REDIRECT_URI")),
    ClientID: getenv("VK_CLIENT_ID", defaultClientID),
    Scope: getenv("VK_OAUTH_SCOPE", defaultScope),
    APIVersion: getenv("VK_API_VERSION", defaultAPIVer),
    StateTTL: 10 * time.Minute,
    DataFile: getenv("VK_TOKEN_FILE", "/opt/etc/csqtt/vk-token.json"),
  }
  app := &App{cfg: cfg, states: make(map[string]time.Time)}
  app.loadToken()
  mux := http.NewServeMux()
  mux.HandleFunc("/api/vk/start", app.start)
  mux.HandleFunc("/api/vk/callback", app.callback)
  mux.HandleFunc("/api/vk/token", app.tokenHandler)
  mux.HandleFunc("/api/vk/status", app.status)
  mux.HandleFunc("/healthz", app.health)
  log.Printf("vk-auth listening on %s", cfg.ListenAddr)
  if err := http.ListenAndServe(cfg.ListenAddr, mux); err != nil { log.Fatal(err) }
}
