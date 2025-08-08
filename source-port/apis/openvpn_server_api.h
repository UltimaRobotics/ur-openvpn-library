
#ifndef OPENVPN_SERVER_API_H
#define OPENVPN_SERVER_API_H

#include "manage.h"
#include "multi.h"
#include "socket.h"
#include "mroute.h"
#include "otime.h"
#include "mstats.h"
#include "forward.h"
#include "event.h"
#include "ssl.h"
#include "buffer.h"
#include "common.h"
#include "options.h"
#include "init.h"
#include "pkcs11.h"
#include "cJSON.h"
#include <pthread.h>
#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

#define MAX_SERVER_CLIENTS 1000
#define MAX_CONFIG_LINE_SIZE 4096
#define MAX_CERT_SIZE 8192
#define MAX_KEY_SIZE 4096
#define MAX_CLIENT_NAME_SIZE 256
#define MAX_ROUTING_RULES 100

/* Server Configuration Structure */
typedef struct {
    char server_name[256];
    char listen_address[64];
    int listen_port;
    char protocol[16];                    /* UDP/TCP */
    char device_type[16];                 /* TUN/TAP */
    char server_subnet[32];               /* e.g., "10.8.0.0/24" */
    char server_ipv6_subnet[64];          /* IPv6 subnet if enabled */
    
    /* Certificate and Key Paths */
    char ca_cert_path[512];
    char server_cert_path[512];
    char server_key_path[512];
    char dh_params_path[512];
    char crl_path[512];
    
    /* Security Settings */
    char cipher[64];
    char auth_digest[32];
    bool compression_enabled;
    bool duplicate_cn_allowed;
    int max_clients;
    int keepalive_ping;
    int keepalive_timeout;
    
    /* Client Configuration */
    bool client_to_client;
    bool push_routes;
    char dns_servers[2][64];
    char domain_name[256];
    
    /* Logging */
    char log_file[512];
    int log_verbosity;
    bool log_append;
    
    /* Management Interface */
    char management_address[64];
    int management_port;
    char management_password[256];
    
    /* Advanced Options */
    int mtu_size;
    int fragment_size;
    bool mssfix_enabled;
    char custom_options[2048];            /* Additional OpenVPN options */
} ovpn_server_config_t;

/* Client Information Structure */
typedef struct {
    uint32_t client_id;
    char common_name[MAX_CLIENT_NAME_SIZE];
    char email[256];
    char description[512];
    
    /* Network Configuration */
    struct in_addr static_ip;             /* Static VPN IP if assigned */
    struct in6_addr static_ipv6;          /* Static IPv6 if assigned */
    bool has_static_ip;
    bool has_static_ipv6;
    
    /* Custom Routing */
    struct {
        char network[32];                 /* e.g., "192.168.1.0/24" */
        char gateway[32];
        bool push_to_client;
    } custom_routes[MAX_ROUTING_RULES];
    int route_count;
    
    /* Access Control */
    bool is_active;
    bool is_revoked;
    time_t created_time;
    time_t revoked_time;
    time_t last_connection;
    char revocation_reason[256];
    
    /* Certificate Information */
    char cert_serial[64];
    time_t cert_valid_from;
    time_t cert_valid_until;
    
    /* Connection Statistics */
    uint64_t bytes_sent;
    uint64_t bytes_received;
    uint32_t connection_count;
    time_t total_connection_time;
    
    /* Current Session Info (if connected) */
    bool currently_connected;
    struct in_addr real_address;
    int real_port;
    time_t session_start_time;
    char client_version[64];
} ovpn_client_info_t;

/* Server Statistics */
typedef struct {
    uint32_t total_clients;
    uint32_t active_clients;
    uint32_t connected_clients;
    uint32_t revoked_clients;
    uint64_t total_bytes_sent;
    uint64_t total_bytes_received;
    time_t server_start_time;
    time_t server_uptime;
    uint32_t total_connections;
    uint32_t authentication_failures;
    uint32_t connection_attempts;
} ovpn_server_stats_t;

/* Event Types */
typedef enum {
    SERVER_EVENT_STARTED,
    SERVER_EVENT_STOPPED,
    SERVER_EVENT_CLIENT_CONNECTED,
    SERVER_EVENT_CLIENT_DISCONNECTED,
    SERVER_EVENT_CLIENT_AUTHENTICATED,
    SERVER_EVENT_CLIENT_AUTH_FAILED,
    SERVER_EVENT_CLIENT_CREATED,
    SERVER_EVENT_CLIENT_REVOKED,
    SERVER_EVENT_CLIENT_UPDATED,
    SERVER_EVENT_CONFIG_RELOADED,
    SERVER_EVENT_ERROR,
    SERVER_EVENT_WARNING
} ovpn_server_event_type_t;

/* Event Structure */
typedef struct {
    ovpn_server_event_type_t event_type;
    time_t timestamp;
    uint32_t client_id;                   /* 0 if not client-specific */
    char message[512];
    char details[1024];
    void *event_data;
    size_t data_size;
} ovpn_server_event_t;

/* Event Callback Function */
typedef void (*ovpn_server_event_callback_t)(const ovpn_server_event_t *event, void *user_data);

/* Server Context */
typedef struct {
    ovpn_server_config_t config;
    struct context *openvpn_context;
    struct multi_context *multi_context;
    struct management *management;
    
    /* Client Management */
    ovpn_client_info_t clients[MAX_SERVER_CLIENTS];
    uint32_t client_count;
    uint32_t next_client_id;
    pthread_mutex_t clients_mutex;
    
    /* Server State */
    bool is_running;
    bool is_initialized;
    pthread_t server_thread;
    pthread_t monitoring_thread;
    
    /* Event Handling */
    ovpn_server_event_callback_t event_callback;
    void *event_callback_data;
    
    /* Statistics */
    ovpn_server_stats_t stats;
    pthread_mutex_t stats_mutex;
    
    /* Certificate Authority Management */
    char ca_key_path[512];
    char ca_cert_content[MAX_CERT_SIZE];
    char ca_key_content[MAX_KEY_SIZE];
} ovpn_server_context_t;

/* Client Configuration Generation Options */
typedef struct {
    bool include_ca_cert;
    bool include_client_cert;
    bool include_client_key;
    bool use_inline_certs;
    bool compress_config;
    char remote_host[256];
    int remote_port;
    char protocol[16];
    bool redirect_gateway;
    char custom_directives[1024];
} ovpn_client_config_options_t;

/* API Function Declarations */

/* Server Management */
ovpn_server_context_t *ovpn_server_init(void);
int ovpn_server_load_config_json(ovpn_server_context_t *ctx, const char *json_config);
int ovpn_server_start(ovpn_server_context_t *ctx);
int ovpn_server_stop(ovpn_server_context_t *ctx);
int ovpn_server_restart(ovpn_server_context_t *ctx);
void ovpn_server_cleanup(ovpn_server_context_t *ctx);
int ovpn_server_reload_config(ovpn_server_context_t *ctx);

/* Client Management */
uint32_t ovpn_server_create_client(ovpn_server_context_t *ctx, 
                                  const char *common_name,
                                  const char *email,
                                  const char *description);
int ovpn_server_revoke_client(ovpn_server_context_t *ctx, 
                             uint32_t client_id, 
                             const char *reason);
int ovpn_server_activate_client(ovpn_server_context_t *ctx, uint32_t client_id);
int ovpn_server_deactivate_client(ovpn_server_context_t *ctx, uint32_t client_id);
int ovpn_server_delete_client(ovpn_server_context_t *ctx, uint32_t client_id);

/* Client Configuration */
int ovpn_server_set_client_static_ip(ovpn_server_context_t *ctx, 
                                     uint32_t client_id, 
                                     const char *ip_address);
int ovpn_server_add_client_route(ovpn_server_context_t *ctx, 
                                uint32_t client_id,
                                const char *network, 
                                const char *gateway, 
                                bool push_to_client);
int ovpn_server_remove_client_route(ovpn_server_context_t *ctx, 
                                   uint32_t client_id, 
                                   const char *network);

/* Client Configuration File Generation */
char *ovpn_server_generate_client_config(ovpn_server_context_t *ctx, 
                                         uint32_t client_id,
                                         const ovpn_client_config_options_t *options);
int ovpn_server_save_client_config(ovpn_server_context_t *ctx, 
                                  uint32_t client_id,
                                  const char *file_path,
                                  const ovpn_client_config_options_t *options);

/* Certificate Management */
int ovpn_server_generate_client_certificate(ovpn_server_context_t *ctx, 
                                           uint32_t client_id,
                                           int validity_days);
int ovpn_server_renew_client_certificate(ovpn_server_context_t *ctx, 
                                        uint32_t client_id,
                                        int validity_days);
int ovpn_server_export_client_certificate(ovpn_server_context_t *ctx, 
                                         uint32_t client_id,
                                         char **cert_pem, 
                                         char **key_pem);

/* Client Information and Status */
int ovpn_server_get_client_info(ovpn_server_context_t *ctx, 
                               uint32_t client_id, 
                               ovpn_client_info_t *info);
int ovpn_server_list_clients(ovpn_server_context_t *ctx, 
                            ovpn_client_info_t **clients, 
                            uint32_t *count,
                            bool include_revoked);
int ovpn_server_get_connected_clients(ovpn_server_context_t *ctx, 
                                     ovpn_client_info_t **clients, 
                                     uint32_t *count);

/* Session Management */
int ovpn_server_disconnect_client(ovpn_server_context_t *ctx, uint32_t client_id);
int ovpn_server_kill_client_session(ovpn_server_context_t *ctx, 
                                   uint32_t client_id, 
                                   const char *reason);
int ovpn_server_send_message_to_client(ovpn_server_context_t *ctx, 
                                      uint32_t client_id, 
                                      const char *message);

/* Statistics and Monitoring */
int ovpn_server_get_statistics(ovpn_server_context_t *ctx, ovpn_server_stats_t *stats);
int ovpn_server_get_client_statistics(ovpn_server_context_t *ctx, 
                                     uint32_t client_id, 
                                     ovpn_client_info_t *stats);
int ovpn_server_reset_statistics(ovpn_server_context_t *ctx);

/* Event Management */
int ovpn_server_set_event_callback(ovpn_server_context_t *ctx, 
                                  ovpn_server_event_callback_t callback, 
                                  void *user_data);
int ovpn_server_get_recent_events(ovpn_server_context_t *ctx, 
                                 ovpn_server_event_t **events, 
                                 uint32_t *count, 
                                 time_t since_timestamp);

/* Configuration Management */
char *ovpn_server_export_config_json(ovpn_server_context_t *ctx);
int ovpn_server_update_config_json(ovpn_server_context_t *ctx, const char *json_config);
int ovpn_server_backup_config(ovpn_server_context_t *ctx, const char *backup_path);
int ovpn_server_restore_config(ovpn_server_context_t *ctx, const char *backup_path);

/* Utility Functions */
const char *ovpn_server_event_type_to_string(ovpn_server_event_type_t type);
bool ovpn_server_is_client_connected(ovpn_server_context_t *ctx, uint32_t client_id);
uint32_t ovpn_server_find_client_by_cn(ovpn_server_context_t *ctx, const char *common_name);
int ovpn_server_validate_config(const ovpn_server_config_t *config);

/* Memory Management */
void ovpn_server_free_client_list(ovpn_client_info_t *clients, uint32_t count);
void ovpn_server_free_events(ovpn_server_event_t *events, uint32_t count);
void ovpn_server_free_config_string(char *config_string);

#ifdef __cplusplus
}
#endif

#endif /* OPENVPN_SERVER_API_H */
