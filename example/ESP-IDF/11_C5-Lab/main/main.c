#include <stdio.h>
#include <assert.h>
#include "nvs_flash.h"
#include "esp_event.h"
#include "esp_http_server.h"
#include "esp_log.h"
#include "esp_mac.h"
#include "esp_netif.h"
#include "esp_wifi.h"

#define LAB_AP_SSID "C5-Lab"
#define LAB_AP_PASSWORD "notforfun"
#define LAB_AP_CHANNEL 1
#define LAB_AP_MAX_CONN 4

static const char *TAG="C5-LAB";
static const char INDEX_HTML[]="<html><head><meta name='viewport' content='width=device-width,initial-scale=1'><title>C5-Lab</title></head><body><h1>C5-Lab</h1><p>AP OK — 192.168.4.1</p><p>Wi-Fi audit interface</p><button disabled>Wi-Fi Scan</button><br><button disabled>Passive Sniffer</button><br><button disabled>EAPOL Monitor</button><br><button disabled>Deauth Monitor</button><br><button disabled>BLE Scan</button><br><button onclick='info()'>Device Info</button><pre id='o'></pre><script>async function info(){o.textContent=await(await fetch('/api/info')).text()}</script></body></html>";

static esp_err_t index_get(httpd_req_t *req){httpd_resp_set_type(req,"text/html");return httpd_resp_send(req,INDEX_HTML,HTTPD_RESP_USE_STRLEN);}
static esp_err_t info_get(httpd_req_t *req){
 uint8_t mac[6]; ESP_ERROR_CHECK(esp_wifi_get_mac(WIFI_IF_AP,mac)); char b[256];
 snprintf(b,sizeof(b),"C5-Lab\nSSID: %s\nChannel: %d\nAP MAC: %02X:%02X:%02X:%02X:%02X:%02X\nIP: 192.168.4.1",LAB_AP_SSID,LAB_AP_CHANNEL,mac[0],mac[1],mac[2],mac[3],mac[4],mac[5]);
 httpd_resp_set_type(req,"text/plain"); return httpd_resp_send(req,b,HTTPD_RESP_USE_STRLEN);
}
static httpd_handle_t start_web_server(void){
 httpd_config_t c=HTTPD_DEFAULT_CONFIG(); httpd_handle_t s=NULL; if(httpd_start(&s,&c)!=ESP_OK)return NULL;
 const httpd_uri_t a={.uri="/",.method=HTTP_GET,.handler=index_get}; const httpd_uri_t b={.uri="/api/info",.method=HTTP_GET,.handler=info_get};
 ESP_ERROR_CHECK(httpd_register_uri_handler(s,&a)); ESP_ERROR_CHECK(httpd_register_uri_handler(s,&b)); return s;
}
static void wifi_event_handler(void *arg,esp_event_base_t base,int32_t id,void *data){
 if(id==WIFI_EVENT_AP_STACONNECTED){wifi_event_ap_staconnected_t *e=data;ESP_LOGI(TAG,"Station connected: "MACSTR,MAC2STR(e->mac));}
 else if(id==WIFI_EVENT_AP_STADISCONNECTED){wifi_event_ap_stadisconnected_t *e=data;ESP_LOGI(TAG,"Station disconnected: "MACSTR,MAC2STR(e->mac));}
}
void app_main(void){
 esp_err_t r=nvs_flash_init(); if(r==ESP_ERR_NVS_NO_FREE_PAGES||r==ESP_ERR_NVS_NEW_VERSION_FOUND){ESP_ERROR_CHECK(nvs_flash_erase());ESP_ERROR_CHECK(nvs_flash_init());}else ESP_ERROR_CHECK(r);
 ESP_ERROR_CHECK(esp_netif_init()); ESP_ERROR_CHECK(esp_event_loop_create_default());
 esp_netif_t *ap=esp_netif_create_default_wifi_ap(); assert(ap);
 wifi_init_config_t cfg=WIFI_INIT_CONFIG_DEFAULT(); ESP_ERROR_CHECK(esp_wifi_init(&cfg));
 ESP_ERROR_CHECK(esp_event_handler_register(WIFI_EVENT,ESP_EVENT_ANY_ID,&wifi_event_handler,NULL));
 wifi_config_t w={.ap={.ssid=LAB_AP_SSID,.password=LAB_AP_PASSWORD,.ssid_len=sizeof(LAB_AP_SSID)-1,.channel=LAB_AP_CHANNEL,.max_connection=LAB_AP_MAX_CONN,.authmode=WIFI_AUTH_WPA2_PSK,.pmf_cfg={.required=false,.capable=true}}};
 ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_AP)); ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_AP,&w)); ESP_ERROR_CHECK(esp_wifi_start());
 start_web_server(); ESP_LOGI(TAG,"C5-Lab started: http://192.168.4.1/");
}