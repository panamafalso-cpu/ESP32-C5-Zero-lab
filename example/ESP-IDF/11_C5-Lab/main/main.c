#include <stdio.h>
#include <string.h>

#include "nvs_flash.h"
#include "esp_event.h"
#include "esp_http_server.h"
#include "esp_log.h"
#include "esp_netif.h"
#include "esp_wifi.h"

#define LAB_AP_SSID     "C5-Lab"
#define LAB_AP_PASSWORD "notforfun"
#define LAB_AP_CHANNEL  1
#define LAB_AP_MAX_CONN 4

static const char *TAG = "C5-LAB";

static const char INDEX_HTML[] =
"<!doctype html><html><head>"
"<meta name='viewport' content='width=device-width,initial-scale=1'>"
"<title>C5-Lab</title>"
"<style>"
"body{font-family:system-ui;margin:0;background:#0b1020;color:#eef2ff}"
".wrap{max-width:700px;margin:auto;padding:24px}"
".card{background:#151d33;border:1px solid #2c3857;border-radius:16px;padding:20px;margin:14px 0}"
"h1{margin-top:0}.sub{color:#aeb9d6}"
"button{width:100%;padding:14px;margin:6px 0;border:0;border-radius:10px;"
"background:#263657;color:#fff;font-size:16px}"
"button:disabled{opacity:.55}.ok{color:#68e0a0}"
"</style></head><body><div class='wrap'>"
"<div class='card'><h1>ESP32-C5 C5-Lab</h1>"
"<div class='sub'>Local laboratory interface</div></div>"
"<div class='card'><h2>Status</h2><p class='ok'>AP: C5-Lab</p>"
"<p>Address: 192.168.4.1</p><p>Security: WPA2-PSK</p></div>"
"<div class='card'><h2>Wi-Fi</h2>"
"<button disabled>Wi-Fi Scan — next module</button>"
"<button disabled>Passive Sniffer — next module</button>"
"<button disabled>EAPOL Monitor — next module</button>"
"<button disabled>Deauth Monitor — next module</button></div>"
"<div class='card'><h2>Bluetooth LE</h2>"
"<button disabled>BLE Scan — next module</button></div>"
"<div class='card'><h2>Device</h2>"
"<button onclick='info()'>Device Info</button><pre id='out'></pre></div>"
"</div><script>"
"async function info(){const r=await fetch('/api/info');"
"document.getElementById('out').textContent=await r.text();}"
"</script></body></html>";

static esp_err_t index_get(httpd_req_t *req)
{
    httpd_resp_set_type(req, "text/html; charset=utf-8");
    return httpd_resp_send(req, INDEX_HTML, HTTPD_RESP_USE_STRLEN);
}

static esp_err_t info_get(httpd_req_t *req)
{
    uint8_t mac[6] = {0};
    esp_wifi_get_mac(WIFI_IF_AP, mac);

    char body[256];
    snprintf(body, sizeof(body),
             "C5-Lab\\nSSID: %s\\nChannel: %d\\nAP MAC: %02X:%02X:%02X:%02X:%02X:%02X\\nIP: 192.168.4.1",
             LAB_AP_SSID, LAB_AP_CHANNEL,
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);

    httpd_resp_set_type(req, "text/plain; charset=utf-8");
    return httpd_resp_send(req, body, HTTPD_RESP_USE_STRLEN);
}

static httpd_handle_t start_web_server(void)
{
    httpd_config_t config = HTTPD_DEFAULT_CONFIG();
    config.server_port = 80;
    config.max_uri_handlers = 8;

    httpd_handle_t server = NULL;
    if (httpd_start(&server, &config) != ESP_OK) {
        ESP_LOGE(TAG, "Failed to start HTTP server");
        return NULL;
    }

    const httpd_uri_t index_uri = {
        .uri = "/",
        .method = HTTP_GET,
        .handler = index_get,
        .user_ctx = NULL
    };

    const httpd_uri_t info_uri = {
        .uri = "/api/info",
        .method = HTTP_GET,
        .handler = info_get,
        .user_ctx = NULL
    };

    httpd_register_uri_handler(server, &index_uri);
    httpd_register_uri_handler(server, &info_uri);

    return server;
}

static void wifi_event_handler(void *arg, esp_event_base_t base,
                               int32_t event_id, void *event_data)
{
    if (event_id == WIFI_EVENT_AP_STACONNECTED) {
        const wifi_event_ap_staconnected_t *event =
            (const wifi_event_ap_staconnected_t *)event_data;
        ESP_LOGI(TAG, "Station connected: " MACSTR, MAC2STR(event->mac));
    } else if (event_id == WIFI_EVENT_AP_STADISCONNECTED) {
        const wifi_event_ap_stadisconnected_t *event =
            (const wifi_event_ap_stadisconnected_t *)event_data;
        ESP_LOGI(TAG, "Station disconnected: " MACSTR, MAC2STR(event->mac));
    }
}

void app_main(void)
{
    esp_err_t ret = nvs_flash_init();
    if (ret == ESP_ERR_NVS_NO_FREE_PAGES ||
        ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_ERROR_CHECK(nvs_flash_erase());
        ESP_ERROR_CHECK(nvs_flash_init());
    } else {
        ESP_ERROR_CHECK(ret);
    }

    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());
    ESP_ERROR_CHECK(esp_netif_create_default_wifi_ap());

    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&cfg));

    ESP_ERROR_CHECK(esp_event_handler_register(
        WIFI_EVENT, ESP_EVENT_ANY_ID, &wifi_event_handler, NULL));

    wifi_config_t ap_config = {
        .ap = {
            .ssid = LAB_AP_SSID,
            .password = LAB_AP_PASSWORD,
            .ssid_len = sizeof(LAB_AP_SSID) - 1,
            .channel = LAB_AP_CHANNEL,
            .max_connection = LAB_AP_MAX_CONN,
            .authmode = WIFI_AUTH_WPA2_PSK,
            .pmf_cfg = {
                .required = false,
                .capable = true
            }
        }
    };

    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_AP));
    ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_AP, &ap_config));
    ESP_ERROR_CHECK(esp_wifi_start());

    start_web_server();

    ESP_LOGI(TAG, "C5-Lab AP started");
    ESP_LOGI(TAG, "SSID: %s", LAB_AP_SSID);
    ESP_LOGI(TAG, "Password: %s", LAB_AP_PASSWORD);
    ESP_LOGI(TAG, "Open http://192.168.4.1/ from a connected device");
}
