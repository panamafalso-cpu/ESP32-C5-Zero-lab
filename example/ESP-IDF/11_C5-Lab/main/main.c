#include <stdio.h>
#include <assert.h>
#include <string.h>
#include <stdbool.h>
#include <stdlib.h>
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
#define MAX_TARGET_STATIONS 16

static const char *TAG="C5-LAB";
static char target_ssid[33]="";
static uint8_t target_bssid[6]={0};
static uint8_t target_channel=0;
static bool target_set=false;
static uint8_t target_stations[MAX_TARGET_STATIONS][6];
static int target_station_count=0;
static volatile uint32_t target_deauth=0,target_disassoc=0,target_eapol=0;
static bool mac_equal(const uint8_t *a,const uint8_t *b){return memcmp(a,b,6)==0;}
static bool mac_zero(const uint8_t *m){for(int i=0;i<6;i++)if(m[i])return false;return true;}
static void add_target_station(const uint8_t *m){
 if(!target_set||mac_zero(m)||mac_equal(m,target_bssid))return;
 for(int i=0;i<target_station_count;i++)if(mac_equal(target_stations[i],m))return;
 if(target_station_count<MAX_TARGET_STATIONS){memcpy(target_stations[target_station_count++],m,6);}
}
static const char INDEX_HTML[] =
"<html><head><meta name='viewport' content='width=device-width,initial-scale=1'><title>C5-Lab</title>"
"<style>body{font-family:system-ui;background:#101318;color:#eee;padding:16px}.card{background:#191e26;padding:14px;margin:10px 0;border-radius:12px}button{padding:10px;margin:4px;border:0;border-radius:8px;background:#2875e8;color:white}table{width:100%;border-collapse:collapse}td,th{padding:6px;border-bottom:1px solid #333;text-align:left}.muted{color:#aaa}</style></head>"
"<body><h1>C5-Lab</h1><div class='card'><b>Uso autorizado únicamente</b><p class='muted'>Utiliza esta herramienta solo en redes y dispositivos que tengas permiso para auditar. Bajo tu propia responsabilidad.</p></div>"
"<div class='card'><h2>Wi-Fi</h2><button onclick='scan()'>Escanear redes</button><span id='s'></span><div id='r'></div></div>"
"<div class='card'><h2>Monitor / Sniffer</h2><button onclick='mon(1)'>Iniciar</button><button onclick='mon(0)'>Parar</button><button onclick='resetm()'>Reset</button><pre id='m'>Monitor detenido</pre></div>"
"<div class='card'><h2>Equipo</h2><button onclick='info()'>Device Info</button><pre id='i'></pre></div>"
"<script>async function scan(){s.textContent=' escaneando...';let x=await(await fetch('/api/scan')).json();s.textContent=' '+x.count+' redes';let h='<table><tr><th>SSID</th><th>BSSID</th><th>CH</th><th>RSSI</th><th>Seguridad</th></tr>';for(let a of x.results)h+='<tr><td>'+a.ssid+'</td><td>'+a.bssid+'</td><td>'+a.channel+'</td><td>'+a.rssi+'</td><td>'+a.auth+'</td></tr>';r.innerHTML=h+'</table>'}async function info(){i.textContent=await(await fetch('/api/info')).text()}async function mon(v){let x=await(await fetch(v?'/api/monitor/start':'/api/monitor/stop')).json();m.textContent=JSON.stringify(x,null,2)}async function resetm(){let x=await(await fetch('/api/monitor/reset')).json();m.textContent=JSON.stringify(x,null,2)}setInterval(async()=>{let x=await(await fetch('/api/monitor')).json();if(x.enabled)m.textContent=JSON.stringify(x,null,2)},1000)</script></body></html>";

static volatile bool monitor_enabled=false;
static volatile uint32_t rx_total=0,rx_mgmt=0,rx_ctrl=0,rx_data=0;
static volatile uint32_t rx_beacon=0,rx_probe_req=0,rx_probe_resp=0;
static volatile uint32_t rx_deauth=0,rx_disassoc=0,rx_eapol=0;

static void promisc_cb(void *buf,wifi_promiscuous_pkt_type_t type){
    if(!monitor_enabled || !buf) return;
    wifi_promiscuous_pkt_t *p=(wifi_promiscuous_pkt_t *)buf;
    const uint8_t *d=p->payload;
    uint16_t len=p->rx_ctrl.sig_len;
    rx_total++;
    if(type==WIFI_PKT_MGMT){
        rx_mgmt++;
        if(len>=2){
            uint8_t fc0=d[0];
            uint8_t st=(fc0>>4)&0x0f;
            const uint8_t *a1=d+4,*a2=d+10,*a3=d+16;
            bool target_frame=target_set&&(mac_equal(a1,target_bssid)||mac_equal(a2,target_bssid)||mac_equal(a3,target_bssid));
            if(st==8) rx_beacon++;
            else if(st==4) rx_probe_req++;
            else if(st==5) rx_probe_resp++;
            else if(st==12){rx_deauth++;if(target_frame)target_deauth++;}
            else if(st==10){rx_disassoc++;if(target_frame)target_disassoc++;}
            if(target_set&&(st==8||st==5)&&mac_equal(a3,target_bssid))add_target_station(a2);
        }
    } else if(type==WIFI_PKT_CTRL) {
        rx_ctrl++;
    } else if(type==WIFI_PKT_DATA) {
        rx_data++;
        if(len>=32){
            uint16_t fc=(uint16_t)d[0]|((uint16_t)d[1]<<8);
            uint8_t subtype=(fc>>4)&0x0f;
            uint16_t hlen=24;
            bool to_ds=(fc>>8)&1, from_ds=(fc>>9)&1;
            if(to_ds && from_ds) hlen=30;
            if(subtype & 0x08) hlen+=2;
            if(len>=hlen+8 &&
               d[hlen]==0xaa && d[hlen+1]==0xaa && d[hlen+2]==0x03 &&
               d[hlen+6]==0x88 && d[hlen+7]==0x8e){
                rx_eapol++;
                if(target_set&&(mac_equal(d+4,target_bssid)||mac_equal(d+10,target_bssid)||mac_equal(d+16,target_bssid)))target_eapol++;
            }
            if(target_set){
                if(mac_equal(d+4,target_bssid))add_target_station(d+10);
                else if(mac_equal(d+10,target_bssid))add_target_station(d+4);
            }
        }
    }
}

static esp_err_t monitor_set(bool on){
    monitor_enabled=on;
    if(on){
        esp_err_t e=esp_wifi_set_promiscuous_rx_cb(promisc_cb);
        if(e!=ESP_OK){monitor_enabled=false;return e;}
        return esp_wifi_set_promiscuous(true);
    }
    return esp_wifi_set_promiscuous(false);
}

static esp_err_t monitor_get(httpd_req_t *req){
    char b[512];
    snprintf(b,sizeof(b),
        "{\"enabled\":%s,\"total\":%lu,\"mgmt\":%lu,\"ctrl\":%lu,\"data\":%lu,"
        "\"beacons\":%lu,\"probe_req\":%lu,\"probe_resp\":%lu,\"deauth\":%lu,"
        "\"disassoc\":%lu,\"eapol\":%lu,\"channel\":%d,"
        "\"target_set\":%s,\"target_bssid\":\"%02X:%02X:%02X:%02X:%02X:%02X:%02X\","
        "\"target_channel\":%u,\"target_stations\":%d,\"target_deauth\":%lu,\"target_disassoc\":%lu,\"target_eapol\":%lu}",
        monitor_enabled?"true":"false",
        (unsigned long)rx_total,(unsigned long)rx_mgmt,(unsigned long)rx_ctrl,
        (unsigned long)rx_data,(unsigned long)rx_beacon,(unsigned long)rx_probe_req,
        (unsigned long)rx_probe_resp,(unsigned long)rx_deauth,(unsigned long)rx_disassoc,
        (unsigned long)rx_eapol,LAB_AP_CHANNEL,target_set?"true":"false",
        target_bssid[0],target_bssid[1],target_bssid[2],target_bssid[3],target_bssid[4],target_bssid[5],
        (unsigned)target_channel,target_station_count,(unsigned long)target_deauth,(unsigned long)target_disassoc,(unsigned long)target_eapol);
    httpd_resp_set_type(req,"application/json");
    return httpd_resp_send(req,b,HTTPD_RESP_USE_STRLEN);
}

static esp_err_t monitor_start_get(httpd_req_t *req){
    esp_err_t e=monitor_set(true);
    if(e!=ESP_OK){httpd_resp_set_status(req,"500 Internal Server Error");return httpd_resp_sendstr(req,"{\"error\":\"monitor start failed\"}");}
    return monitor_get(req);
}

static esp_err_t monitor_stop_get(httpd_req_t *req){
    esp_err_t e=monitor_set(false);
    if(e!=ESP_OK){httpd_resp_set_status(req,"500 Internal Server Error");return httpd_resp_sendstr(req,"{\"error\":\"monitor stop failed\"}");}
    return monitor_get(req);
}

static esp_err_t monitor_reset_get(httpd_req_t *req){
    rx_total=rx_mgmt=rx_ctrl=rx_data=0;
    rx_beacon=rx_probe_req=rx_probe_resp=rx_deauth=rx_disassoc=rx_eapol=0;
    target_deauth=target_disassoc=target_eapol=0; target_station_count=0;
    return monitor_get(req);
}

static esp_err_t lab_target_get(httpd_req_t *req){
 char q[256]={0},v[64]={0}; int n=httpd_req_get_url_query_len(req);
 if(n<=0||n>=sizeof(q)){httpd_resp_set_status(req,"400 Bad Request");return httpd_resp_sendstr(req,"{\"error\":\"use bssid,channel and optional ssid\"}");}
 if(httpd_req_get_url_query_str(req,q,sizeof(q))!=ESP_OK){httpd_resp_set_status(req,"400 Bad Request");return httpd_resp_sendstr(req,"{\"error\":\"bad query\"}");}
 if(httpd_query_key_value(q,"bssid",v,sizeof(v))!=ESP_OK){httpd_resp_set_status(req,"400 Bad Request");return httpd_resp_sendstr(req,"{\"error\":\"missing bssid\"}");}
 unsigned int m[6]; if(sscanf(v,"%2x:%2x:%2x:%2x:%2x:%2x",&m[0],&m[1],&m[2],&m[3],&m[4],&m[5])!=6){httpd_resp_set_status(req,"400 Bad Request");return httpd_resp_sendstr(req,"{\"error\":\"invalid bssid\"}");}
 if(httpd_query_key_value(q,"channel",v,sizeof(v))!=ESP_OK){httpd_resp_set_status(req,"400 Bad Request");return httpd_resp_sendstr(req,"{\"error\":\"missing channel\"}");}
 int ch=atoi(v); if(ch<1||ch>233){httpd_resp_set_status(req,"400 Bad Request");return httpd_resp_sendstr(req,"{\"error\":\"invalid channel\"}");}
 for(int i=0;i<6;i++)target_bssid[i]=(uint8_t)m[i]; target_channel=(uint8_t)ch; target_set=true; target_station_count=0; memset(target_stations,0,sizeof(target_stations));
 if(httpd_query_key_value(q,"ssid",target_ssid,sizeof(target_ssid))!=ESP_OK)target_ssid[0]=0;
 httpd_resp_set_type(req,"application/json"); return httpd_resp_sendstr(req,"{\"ok\":true,\"message\":\"target selected; verification only\"}");
}
static esp_err_t lab_target_clear_get(httpd_req_t *req){
 target_set=false;target_ssid[0]=0;target_channel=0;target_station_count=0;target_deauth=target_disassoc=target_eapol=0;memset(target_bssid,0,sizeof(target_bssid));memset(target_stations,0,sizeof(target_stations));
 httpd_resp_set_type(req,"application/json");return httpd_resp_sendstr(req,"{\"ok\":true,\"message\":\"target cleared\"}");
}
static esp_err_t lab_stations_get(httpd_req_t *req){
 char *out=malloc(2048);if(!out)return ESP_ERR_NO_MEM;
 int p=snprintf(out,2048,"{\"target_set\":%s,\"ssid\":\"%s\",\"bssid\":\"%02X:%02X:%02X:%02X:%02X:%02X\",\"channel\":%u,\"stations\":[",target_set?"true":"false",target_ssid,target_bssid[0],target_bssid[1],target_bssid[2],target_bssid[3],target_bssid[4],target_bssid[5],target_channel);
 for(int i=0;i<target_station_count&&p<1900;i++){char m[18];macstr(target_stations[i],m);p+=snprintf(out+p,2048-p,"%s\"%s\"",i?",":"",m);}
 snprintf(out+p,2048-p,"]}"); httpd_resp_set_type(req,"application/json"); esp_err_t r=httpd_resp_send(req,out,HTTPD_RESP_USE_STRLEN);free(out);return r;
}

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
 bool was_monitor=monitor_enabled;
 esp_wifi_set_promiscuous(false);
 wifi_scan_config_t cfg={0};cfg.show_hidden=true;cfg.scan_type=WIFI_SCAN_TYPE_ACTIVE;
 esp_err_t e=esp_wifi_scan_start(&cfg,true);if(e!=ESP_OK){httpd_resp_set_status(req,"500 Internal Server Error");return httpd_resp_sendstr(req,"{\"error\":\"scan failed\"}");}
 uint16_t n=MAX_SCAN;wifi_ap_record_t a[MAX_SCAN];e=esp_wifi_scan_get_ap_records(&n,a);
 if(e!=ESP_OK){httpd_resp_set_status(req,"500 Internal Server Error");return httpd_resp_sendstr(req,"{\"error\":\"results failed\"}");}
 char *out=malloc(10000);if(!out)return ESP_ERR_NO_MEM;int p=snprintf(out,10000,"{\"count\":%u,\"results\":[",(unsigned)n);
 for(int i=0;i<n&&p<9700;i++){char m[18];macstr(a[i].bssid,m);p+=snprintf(out+p,10000-p,"%s{\"ssid\":\"%s\",\"bssid\":\"%s\",\"channel\":%u,\"rssi\":%d,\"auth\":\"%s\"}",i?",":"",a[i].ssid,m,a[i].primary,a[i].rssi,auth_name(a[i].authmode));}
 snprintf(out+p,10000-p,"]}"); if(was_monitor) monitor_set(true); httpd_resp_set_type(req,"application/json");esp_err_t r=httpd_resp_send(req,out,HTTPD_RESP_USE_STRLEN);free(out);return r;
}
static httpd_handle_t start_web_server(void){
 httpd_config_t c=HTTPD_DEFAULT_CONFIG();c.max_uri_handlers=10;httpd_handle_t s=NULL;if(httpd_start(&s,&c)!=ESP_OK)return NULL;
 const httpd_uri_t u[]={{.uri="/",.method=HTTP_GET,.handler=index_get},{.uri="/api/info",.method=HTTP_GET,.handler=info_get},{.uri="/api/scan",.method=HTTP_GET,.handler=scan_get},{.uri="/api/monitor",.method=HTTP_GET,.handler=monitor_get},{.uri="/api/monitor/start",.method=HTTP_GET,.handler=monitor_start_get},{.uri="/api/monitor/stop",.method=HTTP_GET,.handler=monitor_stop_get},{.uri="/api/monitor/reset",.method=HTTP_GET,.handler=monitor_reset_get},{.uri="/api/lab/target",.method=HTTP_GET,.handler=lab_target_get},{.uri="/api/lab/target/clear",.method=HTTP_GET,.handler=lab_target_clear_get},{.uri="/api/lab/stations",.method=HTTP_GET,.handler=lab_stations_get}};
 for(size_t i=0;i<10;i++){ ESP_ERROR_CHECK(httpd_register_uri_handler(s,&u[i])); }
 return s;
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
