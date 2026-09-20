#include <glib.h>
#include <wpe/webkit.h>
#include <stdio.h>
#include <string.h>
static GMainLoop *loop;
static void inspect_uri(WebKitWebView *view) {
    const char *uri = webkit_web_view_get_uri(view);
    if (!uri) return;
    const char *hash = strchr(uri, '#');
    if (!hash) return;
    hash++;
    if (!strstr(hash, "access_token=")) return;
    g_print("CSQTT_VK_OAUTH_URI=%s\n", uri);
    g_print("CSQTT_VK_OAUTH_HASH=%s\n", hash);
    g_main_loop_quit(loop);
}
static void load_changed(WebKitWebView *view, WebKitLoadEvent event, gpointer) {
    if (event == WEBKIT_LOAD_COMMITTED || event == WEBKIT_LOAD_FINISHED) inspect_uri(view);
}
int main(int argc, char **argv) {
    if (argc < 2) { fprintf(stderr, "usage: vk-oauth <oauth-url>\n"); return 2; }
    g_setenv("WPE_PLATFORM", "headless", TRUE);
    loop = g_main_loop_new(NULL, FALSE);
    WebKitWebContext *context = webkit_web_context_new_ephemeral();
    WebKitWebView *view = WEBKIT_WEB_VIEW(g_object_new(WEBKIT_TYPE_WEB_VIEW, "web-context", context, NULL));
    g_signal_connect(view, "load-changed", G_CALLBACK(load_changed), NULL);
    webkit_web_view_load_uri(view, argv[1]);
    g_main_loop_run(loop);
    g_object_unref(view); g_object_unref(context); g_main_loop_unref(loop);
    return 0;
}
