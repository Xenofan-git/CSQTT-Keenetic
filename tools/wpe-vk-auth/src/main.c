#include <wpe/webkit.h>
#include <jsc/jsc.h>
#include <glib.h>
#include <stdio.h>
#include <string.h>

typedef struct {
    GMainLoop *loop;
    WebKitWebView *view;
    guint timeout_id;
} App;

static gboolean timeout_cb(gpointer data)
{
    App *app = data;
    g_printerr("wpe-vk-auth: timeout waiting for page result\n");
    g_main_loop_quit(app->loop);
    return G_SOURCE_REMOVE;
}

static void javascript_finished(GObject *object, GAsyncResult *result, gpointer user_data)
{
    App *app = user_data;
    GError *error = NULL;
    WebKitJavascriptResult *js_result;
    JSCValue *value;
    gchar *text;

    js_result = webkit_web_view_evaluate_javascript_finish(
        WEBKIT_WEB_VIEW(object), result, &error);

    if (!js_result) {
        g_printerr("wpe-vk-auth: JavaScript evaluation failed: %s\n",
                   error ? error->message : "unknown error");
        g_clear_error(&error);
        g_main_loop_quit(app->loop);
        return;
    }

    value = webkit_javascript_result_get_js_value(js_result);
    text = jsc_value_to_string(value);

    /* Never print a real VK token. This probe only verifies fragment access. */
    if (text && strstr(text, "access_token="))
        g_print("WPE_VK_PROBE=access_token_detected\n");
    else
        g_print("WPE_VK_PROBE=%s\n", text ? text : "");

    g_free(text);
    webkit_javascript_result_unref(js_result);
    g_main_loop_quit(app->loop);
}

static void load_changed(WebKitWebView *view, WebKitLoadEvent event, gpointer data)
{
    App *app = data;

    if (event != WEBKIT_LOAD_FINISHED)
        return;

    /*
     * URL fragments are not sent to the HTTP server. Reading location.href
     * from page JavaScript is therefore the important capability for VK OAuth.
     */
    const char *script = "(function(){return window.location.href;})()";

    webkit_web_view_evaluate_javascript(
        view, script, -1, NULL, NULL, NULL, javascript_finished, app);
}

int main(int argc, char **argv)
{
    const char *uri = argc > 1 ? argv[1] : "https://wpewebkit.org/";
    const char *platform = g_getenv("WPE_PLATFORM");

    if (!platform || !*platform)
        g_setenv("WPE_PLATFORM", "headless", TRUE);

    App app = {0};
    app.loop = g_main_loop_new(NULL, FALSE);

    WebKitSettings *settings = webkit_settings_new();
    webkit_settings_set_enable_javascript(settings, TRUE);
    webkit_settings_set_enable_webgl(settings, FALSE);
    webkit_settings_set_enable_media_stream(settings, FALSE);

    app.view = WEBKIT_WEB_VIEW(g_object_new(
        WEBKIT_TYPE_WEB_VIEW,
        "settings", settings,
        NULL));

    g_signal_connect(app.view, "load-changed",
                     G_CALLBACK(load_changed), &app);

    g_print("wpe-vk-auth: WPE_PLATFORM=%s\n", g_getenv("WPE_PLATFORM"));
    g_print("wpe-vk-auth: loading %s\n", uri);

    app.timeout_id = g_timeout_add_seconds(60, timeout_cb, &app);
    webkit_web_view_load_uri(app.view, uri);

    g_main_loop_run(app.loop);

    if (app.timeout_id)
        g_source_remove(app.timeout_id);
    g_clear_object(&app.view);
    g_clear_object(&settings);
    g_main_loop_unref(app.loop);
    return 0;
}
