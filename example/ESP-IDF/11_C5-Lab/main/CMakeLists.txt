idf_component_register(
    SRCS "main.c"
    REQUIRES esp_wifi esp_event esp_netif nvs_flash esp_http_server
    INCLUDE_DIRS "."
)
