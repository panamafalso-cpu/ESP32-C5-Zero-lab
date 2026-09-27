#include <stdio.h>
#include <assert.h>
#include <string.h>
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
#define MAX_SCAN 32

static const char *TAG="C5-LAB";
static const char INDEX_HTML[] =
"<html><head><meta name='viewport' content='width=device-width,initial-scale=1'><title>C5-Lab</title>"
"<style>body{font-family:system-ui;background:#101318;color:#eee;padding:16px}.card{background:#191e26;padding:14px;margin:10px 0;border-radius:12px}button{padding:10px;margin:4px;border:0;border-radius:8px;background:#2875e8;color:white}table{width:100%;border-collapse:collapse}td,th{padding:6px;border-bottom:1px solid #333;text-align:left}.muted{color:#aaa}</style></head>"
"<body><h1>C5-Lab</h1><div class='card'><b>Uso autorizado únicamente</b><p class='muted'>Utiliza esta herramienta solo en redes y dispositivos que tengas permiso para auditar. Bajo tu propia responsabilidad.</p></div>"
"<div class='card'><h2>Wi-Fi</h2><button onclick='scan()'>Escanear redes</button><span id='s'></span><div id='r'></div></div>"
"<div class='card'><h2>Equipo</h2><button onclick='info()'>Device Info</button><pre id='i'></pre></div>"
"<script>async function scan(){s.textContent=' escaneando...';let x=await(await fetch('/api/scan')).json();s.textContent=' '+x.count+' redes';let h='<table><tr><th>SSID</th><th>BSSID</th><th>CH</th><th>RSSI</th><th>Seguridad</th></tr>';for(let a of x.results)h+='<tr><td>'+a.ssid+'</td><td>'+a.bssid+'</td><td>'+a.channel+'</td><td>'+a.rssi+'</td><td>'+a.auth+'</td></tr>';r.innerHTML=h+'</table>'}async function info(){i.textContent=await(await fetch('/api/info')).text()}</script></body></html>";

static const char *auth_name(wifi_auth_mode_t a){
 switch(a){case WIFI_AUTH_OPEN:return "OPEN";case WIFI_AUTH_WEP:return "WEP";case WIFI_AUTH_WPA_PSK:return "WPA";case WIFI_AUTH_WPA2_PSK:return "WPA2";case WIFI_AUTH_WPA_WPA2_PSK:return "WPA/WPA2";case WIFI_AUTH_WPA2_ENTERPRISE:return "WPA2-EAP";case WIFI_AUTH_WPA3_PSK:return "WPA3";case WIFI_AUTH_WPA2_WPA3_PSK:return "WPA2/WPA3";default:return "OTHER";}
}
static void macstr(const uint8_t *m,char *o){sprintf(o,"%02X:%02X:%02X:%02X:%02X:%02X",m[0],m[1],m[2],m[3],m[4],m[5]);}

static esp_err_t index_get(httpd_req_t *req){httpd_resp_set_type(req,"text/html");return httpd_resp_send(req,INDEX_HTML,HTTPD_RESP_USE_STRLEN);}
static esp_err_t info_get(httpd_req_t *req){
 uint8_t mac[6];ESP_ERROR_CHECK(esp_wifi_get_mac(WIFI_IF_AP,mac));char m[18];macstr(mac,m);
 char b[384];snprintf(b,sizeof(b),"{\"ssid\":\"%s\",\"mac\":\"%s\",\"channel\":%d,\"ip\":\"192.168.4.1\"}",LAB_AP_SSID,m,LAB_AP_CHANNEL);
 httpd_resp_set_type(req,"application/json");return httpd_resp_send(req,b,HTTPD_RESP_USE_STRLEN);
}
static esp_err_t scan_get(httpd_req_t *req){
 esp_wifi_set_promiscuous(false);
 wifi_scan_config_t cfg={0};cfg.show_hidden=true;cfg.scan_type=WIFI_SCAN_TYPE_ACTIVE;
 esp_err_t e=esp_wifi_scan_start(&cfg,true);if(e!=ESP_OK){httpd_resp_set_status(req,"500 Internal Server Error");return httpd_resp_sendstr(req,"{\"error\":\"scan failed\"}");}
 uint16_t n=MAX_SCAN;wifi_ap_record_t a[MAX_SCAN];e=esp_wifi_scan_get_ap_records(&n,a);
 if(e!=ESP_OK){httpd_resp_set_status(req,"500 Internal Server Error");return httpd_resp_sendstr(req,"{\"error\":\"results failed\"}");}
 char *out=malloc(10000);if(!out)return ESP_ERR_NO_MEM;int p=snprintf(out,10000,"{\"count\":%u,\"results\":[",(unsigned)n);
 for(int i=0;i<n&&p<9700;i++){char m[18];macstr(a[i].bssid,m);p+=snprintf(out+p,10000-p,"%s{\"ssid\":\"%s\",\"bssid\":\"%s\",\"channel\":%u,\"rssi\":%d,\"auth\":\"%s\"}",i?",":"",a[i].ssid,m,a[i].primary,a[i].rssi,auth_name(a[i].authmode));}
 snprintf(out+p,10000-p,"]}");httpd_resp_set_type(req,"application/json");esp_err_t r=httpd_resp_send(req,out,HTTPD_RESP_USE_STRLEN);free(out);return r;
}
static httpd_handle_t start_web_server(void){
 httpd_config_t c=HTTPD_DEFAULT_CONFIG();c.max_uri_handlers=6;httpd_handle_t s=NULL;if(httpd_start(&s,&c)!=ESP_OK)return NULL;
 const httpd_uri_t u[]={{.uri="/",.method=HTTP_GET,.handler=index_get},{.uri="/api/info",.method=HTTP_GET,.handler=info_get},{.uri="/api/scan",.method=HTTP_GET,.handler=scan_get}};
 for(size_t i=0;i<3;i++){ ESP_ERROR_CHECK(httpd_register_uri_handler(s,&u[i])); }\n return s;
}
static void wifi_event_handler(void *arg,esp_event_base_t base,int32_t id,void *data){
 if(id==WIFI_EVENT_AP_STACONNECTED){wifi_event_ap_staconnected_t *e=data;ESP_LOGI(TAG,"Station connected: "MACSTR,MAC2STR(e->mac));}
 if(id==WIFI_EVENT_AP_STADISCONNECTED){wifi_event_ap_stadisconnected_t *e=data;ESP_LOGI(TAG,"Station disconnected: "MACSTR,MAC2STR(e->mac));}
}
void app_main(void){
 esp_err_t r=nvs_flash_init();if(r==ESP_ERR_NVS_NO_FREE_PAGES||r==ESP_ERR_NVS_NEW_VERSION_FOUND){ESP_ERROR_CHECK(nvs_flash_erase());ESP_ERROR_CHECK(nvs_flash_init());}else ESP_ERROR_CHECK(r);
 ESP_ERROR_CHECK(esp_netif_init());ESP_ERROR_CHECK(esp_event_loop_create_default());esp_netif_t *ap=esp_netif_create_default_wifi_ap();assert(ap);
 wifi_init_config_t cfg=WIFI_INIT_CONFIG_DEFAULT();ESP_ERROR_CHECK(esp_wifi_init(&cfg));ESP_ERROR_CHECK(esp_event_handler_register(WIFI_EVENT,ESP_EVENT_ANY_ID,&wifi_event_handler,NULL));
 wifi_config_t w={.ap={.ssid=LAB_AP_SSID,.password=LAB_AP_PASSWORD,.ssid_len=sizeof(LAB_AP_SSID)-1,.channel=LAB_AP_CHANNEL,.max_connection=LAB_AP_MAX_CONN,.authmode=WIFI_AUTH_WPA2_PSK,.pmf_cfg={.required=false,.capable=true}}};
 ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_APSTA));ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_AP,&w));ESP_ERROR_CHECK(esp_wifi_start());start_web_server();ESP_LOGI(TAG,"C5-Lab started: http://192.168.4.1/");
}