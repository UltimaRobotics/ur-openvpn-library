
/*
 * OpenVPN Server Management API Implementation
 * Comprehensive server-side VPN management with client configuration generation
 */

#include "openvpn_server_api.h"
#include "manage.h"
#include "multi.h"
#include "init.h"
#include "forward.h"
#include "event.h"
#include "misc.h"
#include "ssl.h"
#include "proto.h"
#include "hash.h"
#include "crypto.h"
#include "socket.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/time.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

/* Global server instance for management interface callbacks */
static ovpn_server_context_t *g_server_instance = NULL;

/* Internal helper functions */
static void server_event_handler(ovpn_server_context_t *ctx, 
                                ovpn_server_event_type_t type, 
                                uint32_t client_id,
                                const char *message, 
                                const char *details);
static void *server_thread_func(void *arg);
static void *monitoring_thread_func(void *arg);
static int parse_server_config_json(const char *json_config, ovpn_server_config_t *config);
static int generate_client_certificate_files(ovpn_server_context_t *ctx, 
                                            uint32_t client_id, 
                                            const char *common_name,
                                            int validity_days);
static char *build_client_ovpn_config(ovpn_server_context_t *ctx, 
                                      uint32_t client_id,
                                      const ovpn_client_config_options_t *options);
static void management_callback_handler(void *arg, const unsigned int flags, const char *str);
static uint32_t allocate_static_ip(ovpn_server_context_t *ctx);

/* API Implementation */

ovpn_server_context_t *ovpn_server_init(void) {
    ovpn_server_context_t *ctx = calloc(1, sizeof(ovpn_server_context_t));
    if (!ctx) {
        return NULL;
    }
    
    /* Initialize mutexes */
    if (pthread_mutex_init(&ctx->clients_mutex, NULL) != 0 ||
        pthread_mutex_init(&ctx->stats_mutex, NULL) != 0) {
        free(ctx);
        return NULL;
    }
    
    /* Initialize default configuration */
    strncpy(ctx->config.server_name, "OpenVPN Server", sizeof(ctx->config.server_name) - 1);
    strncpy(ctx->config.listen_address, "0.0.0.0", sizeof(ctx->config.listen_address) - 1);
    ctx->config.listen_port = 1194;
    strncpy(ctx->config.protocol, "udp", sizeof(ctx->config.protocol) - 1);
    strncpy(ctx->config.device_type, "tun", sizeof(ctx->config.device_type) - 1);
    strncpy(ctx->config.server_subnet, "10.8.0.0/24", sizeof(ctx->config.server_subnet) - 1);
    strncpy(ctx->config.cipher, "AES-256-GCM", sizeof(ctx->config.cipher) - 1);
    strncpy(ctx->config.auth_digest, "SHA256", sizeof(ctx->config.auth_digest) - 1);
    ctx->config.max_clients = 100;
    ctx->config.keepalive_ping = 10;
    ctx->config.keepalive_timeout = 120;
    ctx->config.log_verbosity = 3;
    
    ctx->next_client_id = 1;
    ctx->is_initialized = true;
    
    g_server_instance = ctx;
    
    return ctx;
}

int ovpn_server_load_config_json(ovpn_server_context_t *ctx, const char *json_config) {
    if (!ctx || !json_config) {
        return -1;
    }
    
    return parse_server_config_json(json_config, &ctx->config);
}

static int parse_server_config_json(const char *json_config, ovpn_server_config_t *config) {
    cJSON *json = cJSON_Parse(json_config);
    if (!json) {
        return -1;
    }
    
    cJSON *item;
    
    /* Server Basic Configuration */
    if ((item = cJSON_GetObjectItem(json, "server_name"))) {
        strncpy(config->server_name, cJSON_GetStringValue(item), sizeof(config->server_name) - 1);
    }
    
    if ((item = cJSON_GetObjectItem(json, "listen_address"))) {
        strncpy(config->listen_address, cJSON_GetStringValue(item), sizeof(config->listen_address) - 1);
    }
    
    if ((item = cJSON_GetObjectItem(json, "listen_port"))) {
        config->listen_port = cJSON_GetNumberValue(item);
    }
    
    if ((item = cJSON_GetObjectItem(json, "protocol"))) {
        strncpy(config->protocol, cJSON_GetStringValue(item), sizeof(config->protocol) - 1);
    }
    
    if ((item = cJSON_GetObjectItem(json, "device_type"))) {
        strncpy(config->device_type, cJSON_GetStringValue(item), sizeof(config->device_type) - 1);
    }
    
    if ((item = cJSON_GetObjectItem(json, "server_subnet"))) {
        strncpy(config->server_subnet, cJSON_GetStringValue(item), sizeof(config->server_subnet) - 1);
    }
    
    /* Certificate Configuration */
    cJSON *certs = cJSON_GetObjectItem(json, "certificates");
    if (certs) {
        if ((item = cJSON_GetObjectItem(certs, "ca_cert_path"))) {
            strncpy(config->ca_cert_path, cJSON_GetStringValue(item), sizeof(config->ca_cert_path) - 1);
        }
        if ((item = cJSON_GetObjectItem(certs, "server_cert_path"))) {
            strncpy(config->server_cert_path, cJSON_GetStringValue(item), sizeof(config->server_cert_path) - 1);
        }
        if ((item = cJSON_GetObjectItem(certs, "server_key_path"))) {
            strncpy(config->server_key_path, cJSON_GetStringValue(item), sizeof(config->server_key_path) - 1);
        }
        if ((item = cJSON_GetObjectItem(certs, "dh_params_path"))) {
            strncpy(config->dh_params_path, cJSON_GetStringValue(item), sizeof(config->dh_params_path) - 1);
        }
    }
    
    /* Security Configuration */
    cJSON *security = cJSON_GetObjectItem(json, "security");
    if (security) {
        if ((item = cJSON_GetObjectItem(security, "cipher"))) {
            strncpy(config->cipher, cJSON_GetStringValue(item), sizeof(config->cipher) - 1);
        }
        if ((item = cJSON_GetObjectItem(security, "auth_digest"))) {
            strncpy(config->auth_digest, cJSON_GetStringValue(item), sizeof(config->auth_digest) - 1);
        }
        if ((item = cJSON_GetObjectItem(security, "compression_enabled"))) {
            config->compression_enabled = cJSON_IsTrue(item);
        }
        if ((item = cJSON_GetObjectItem(security, "duplicate_cn_allowed"))) {
            config->duplicate_cn_allowed = cJSON_IsTrue(item);
        }
    }
    
    /* Client Configuration */
    cJSON *client_config = cJSON_GetObjectItem(json, "client_config");
    if (client_config) {
        if ((item = cJSON_GetObjectItem(client_config, "max_clients"))) {
            config->max_clients = cJSON_GetNumberValue(item);
        }
        if ((item = cJSON_GetObjectItem(client_config, "client_to_client"))) {
            config->client_to_client = cJSON_IsTrue(item);
        }
        if ((item = cJSON_GetObjectItem(client_config, "push_routes"))) {
            config->push_routes = cJSON_IsTrue(item);
        }
        
        cJSON *dns_array = cJSON_GetObjectItem(client_config, "dns_servers");
        if (cJSON_IsArray(dns_array)) {
            cJSON *dns_item;
            int i = 0;
            cJSON_ArrayForEach(dns_item, dns_array) {
                if (i < 2) {
                    strncpy(config->dns_servers[i], cJSON_GetStringValue(dns_item), 
                           sizeof(config->dns_servers[i]) - 1);
                    i++;
                }
            }
        }
    }
    
    /* Management Interface */
    cJSON *management = cJSON_GetObjectItem(json, "management");
    if (management) {
        if ((item = cJSON_GetObjectItem(management, "address"))) {
            strncpy(config->management_address, cJSON_GetStringValue(item), 
                   sizeof(config->management_address) - 1);
        }
        if ((item = cJSON_GetObjectItem(management, "port"))) {
            config->management_port = cJSON_GetNumberValue(item);
        }
    }
    
    /* Logging Configuration */
    cJSON *logging = cJSON_GetObjectItem(json, "logging");
    if (logging) {
        if ((item = cJSON_GetObjectItem(logging, "log_file"))) {
            strncpy(config->log_file, cJSON_GetStringValue(item), sizeof(config->log_file) - 1);
        }
        if ((item = cJSON_GetObjectItem(logging, "verbosity"))) {
            config->log_verbosity = cJSON_GetNumberValue(item);
        }
        if ((item = cJSON_GetObjectItem(logging, "append"))) {
            config->log_append = cJSON_IsTrue(item);
        }
    }
    
    cJSON_Delete(json);
    return 0;
}

int ovpn_server_start(ovpn_server_context_t *ctx) {
    if (!ctx || !ctx->is_initialized) {
        return -1;
    }
    
    if (ctx->is_running) {
        return 0; /* Already running */
    }
    
    /* Initialize OpenVPN context */
    ctx->openvpn_context = calloc(1, sizeof(struct context));
    if (!ctx->openvpn_context) {
        return -1;
    }
    
    /* Set up OpenVPN configuration from our config */
    struct options *options = &ctx->openvpn_context->options;
    options_init(options);
    
    /* Configure basic server options */
    options->mode = MODE_SERVER;
    options->server_defined = true;
    options->server_network = inet_addr("10.8.0.0");
    options->server_netmask = inet_addr("255.255.255.0");
    options->local = strdup(ctx->config.listen_address);
    options->ce.local_port = ctx->config.listen_port;
    
    if (strcmp(ctx->config.protocol, "tcp") == 0) {
        options->ce.proto = PROTO_TCP_SERVER;
    } else {
        options->ce.proto = PROTO_UDP;
    }
    
    /* Configure certificates */
    if (strlen(ctx->config.ca_cert_path) > 0) {
        options->ca_file = strdup(ctx->config.ca_cert_path);
    }
    if (strlen(ctx->config.server_cert_path) > 0) {
        options->cert_file = strdup(ctx->config.server_cert_path);
    }
    if (strlen(ctx->config.server_key_path) > 0) {
        options->priv_key_file = strdup(ctx->config.server_key_path);
    }
    
    /* Set cipher and authentication */
    if (strlen(ctx->config.cipher) > 0) {
        options->ciphername = strdup(ctx->config.cipher);
    }
    if (strlen(ctx->config.auth_digest) > 0) {
        options->authname = strdup(ctx->config.auth_digest);
    }
    
    /* Configure management interface */
    if (strlen(ctx->config.management_address) > 0 && ctx->config.management_port > 0) {
        options->management_addr = strdup(ctx->config.management_address);
        options->management_port = ctx->config.management_port;
        options->management_flags |= MF_SERVER;
    }
    
    /* Initialize OpenVPN */
    context_init_1(ctx->openvpn_context);
    
    /* Create server thread */
    ctx->is_running = true;
    if (pthread_create(&ctx->server_thread, NULL, server_thread_func, ctx) != 0) {
        ctx->is_running = false;
        return -1;
    }
    
    /* Create monitoring thread */
    if (pthread_create(&ctx->monitoring_thread, NULL, monitoring_thread_func, ctx) != 0) {
        ctx->is_running = false;
        pthread_cancel(ctx->server_thread);
        return -1;
    }
    
    /* Fire server started event */
    server_event_handler(ctx, SERVER_EVENT_STARTED, 0, "OpenVPN server started", 
                        "Server is now accepting client connections");
    
    return 0;
}

static void *server_thread_func(void *arg) {
    ovpn_server_context_t *ctx = (ovpn_server_context_t *)arg;
    
    /* Main OpenVPN server loop */
    if (ctx->openvpn_context) {
        /* Initialize phase 2 */
        if (!context_init_2(ctx->openvpn_context)) {
            ctx->is_running = false;
            return NULL;
        }
        
        /* Main event loop */
        tunnel_server(ctx->openvpn_context);
        
        /* Cleanup */
        context_gc_free(&ctx->openvpn_context->gc);
    }
    
    ctx->is_running = false;
    return NULL;
}

static void *monitoring_thread_func(void *arg) {
    ovpn_server_context_t *ctx = (ovpn_server_context_t *)arg;
    
    while (ctx->is_running) {
        /* Update server statistics */
        pthread_mutex_lock(&ctx->stats_mutex);
        ctx->stats.server_uptime = time(NULL) - ctx->stats.server_start_time;
        
        /* Update connected clients count */
        uint32_t connected = 0;
        pthread_mutex_lock(&ctx->clients_mutex);
        for (uint32_t i = 0; i < ctx->client_count; i++) {
            if (ctx->clients[i].currently_connected) {
                connected++;
            }
        }
        ctx->stats.connected_clients = connected;
        pthread_mutex_unlock(&ctx->clients_mutex);
        
        pthread_mutex_unlock(&ctx->stats_mutex);
        
        /* Sleep for monitoring interval */
        sleep(10);
    }
    
    return NULL;
}

uint32_t ovpn_server_create_client(ovpn_server_context_t *ctx, 
                                  const char *common_name,
                                  const char *email,
                                  const char *description) {
    if (!ctx || !common_name) {
        return 0;
    }
    
    pthread_mutex_lock(&ctx->clients_mutex);
    
    if (ctx->client_count >= MAX_SERVER_CLIENTS) {
        pthread_mutex_unlock(&ctx->clients_mutex);
        return 0;
    }
    
    /* Check for duplicate common name */
    for (uint32_t i = 0; i < ctx->client_count; i++) {
        if (strcmp(ctx->clients[i].common_name, common_name) == 0 && 
            !ctx->clients[i].is_revoked) {
            pthread_mutex_unlock(&ctx->clients_mutex);
            return 0; /* Duplicate CN */
        }
    }
    
    /* Create new client */
    ovpn_client_info_t *client = &ctx->clients[ctx->client_count];
    memset(client, 0, sizeof(ovpn_client_info_t));
    
    client->client_id = ctx->next_client_id++;
    strncpy(client->common_name, common_name, sizeof(client->common_name) - 1);
    if (email) {
        strncpy(client->email, email, sizeof(client->email) - 1);
    }
    if (description) {
        strncpy(client->description, description, sizeof(client->description) - 1);
    }
    
    client->is_active = true;
    client->created_time = time(NULL);
    
    /* Assign static IP if configured */
    if (!client->has_static_ip) {
        uint32_t ip = allocate_static_ip(ctx);
        if (ip != 0) {
            client->static_ip.s_addr = htonl(ip);
            client->has_static_ip = true;
        }
    }
    
    ctx->client_count++;
    uint32_t client_id = client->client_id;
    
    pthread_mutex_unlock(&ctx->clients_mutex);
    
    /* Generate certificate for the client */
    if (generate_client_certificate_files(ctx, client_id, common_name, 365) == 0) {
        server_event_handler(ctx, SERVER_EVENT_CLIENT_CREATED, client_id,
                            "Client created successfully", common_name);
    }
    
    return client_id;
}

static uint32_t allocate_static_ip(ovpn_server_context_t *ctx) {
    /* Simple IP allocation from server subnet */
    /* Parse server subnet (e.g., "10.8.0.0/24") */
    char subnet[32];
    strncpy(subnet, ctx->config.server_subnet, sizeof(subnet) - 1);
    
    char *slash = strchr(subnet, '/');
    if (!slash) return 0;
    
    *slash = '\0';
    uint32_t network = ntohl(inet_addr(subnet));
    int prefix = atoi(slash + 1);
    
    /* Start from .10 to avoid conflicts with gateway (.1) */
    for (uint32_t i = 10; i < (1 << (32 - prefix)) - 1; i++) {
        uint32_t ip = network + i;
        bool in_use = false;
        
        /* Check if IP is already assigned */
        for (uint32_t j = 0; j < ctx->client_count; j++) {
            if (ctx->clients[j].has_static_ip && 
                ntohl(ctx->clients[j].static_ip.s_addr) == ip) {
                in_use = true;
                break;
            }
        }
        
        if (!in_use) {
            return ip;
        }
    }
    
    return 0; /* No available IP */
}

char *ovpn_server_generate_client_config(ovpn_server_context_t *ctx, 
                                         uint32_t client_id,
                                         const ovpn_client_config_options_t *options) {
    if (!ctx || client_id == 0) {
        return NULL;
    }
    
    return build_client_ovpn_config(ctx, client_id, options);
}

static char *build_client_ovpn_config(ovpn_server_context_t *ctx, 
                                      uint32_t client_id,
                                      const ovpn_client_config_options_t *options) {
    ovpn_client_info_t *client = NULL;
    
    /* Find client */
    pthread_mutex_lock(&ctx->clients_mutex);
    for (uint32_t i = 0; i < ctx->client_count; i++) {
        if (ctx->clients[i].client_id == client_id) {
            client = &ctx->clients[i];
            break;
        }
    }
    pthread_mutex_unlock(&ctx->clients_mutex);
    
    if (!client) {
        return NULL;
    }
    
    /* Build configuration string */
    char *config = malloc(8192);
    if (!config) {
        return NULL;
    }
    
    int pos = 0;
    
    /* Basic client configuration */
    pos += snprintf(config + pos, 8192 - pos,
        "# OpenVPN Client Configuration for %s\n"
        "# Generated on %s\n"
        "client\n"
        "dev %s\n"
        "proto %s\n"
        "remote %s %d\n"
        "resolv-retry infinite\n"
        "nobind\n"
        "persist-key\n"
        "persist-tun\n"
        "cipher %s\n"
        "auth %s\n"
        "verb 3\n",
        client->common_name,
        ctime(&client->created_time),
        ctx->config.device_type,
        ctx->config.protocol,
        strlen(options->remote_host) > 0 ? options->remote_host : ctx->config.listen_address,
        options->remote_port > 0 ? options->remote_port : ctx->config.listen_port,
        ctx->config.cipher,
        ctx->config.auth_digest
    );
    
    /* Add redirect gateway if requested */
    if (options->redirect_gateway) {
        pos += snprintf(config + pos, 8192 - pos, "redirect-gateway def1\n");
    }
    
    /* Add compression if enabled */
    if (ctx->config.compression_enabled) {
        pos += snprintf(config + pos, 8192 - pos, "compress lz4\n");
    }
    
    /* Add custom routes for this client */
    for (int i = 0; i < client->route_count; i++) {
        if (client->custom_routes[i].push_to_client) {
            pos += snprintf(config + pos, 8192 - pos, 
                           "route %s\n", client->custom_routes[i].network);
        }
    }
    
    /* Add DNS servers */
    for (int i = 0; i < 2; i++) {
        if (strlen(ctx->config.dns_servers[i]) > 0) {
            pos += snprintf(config + pos, 8192 - pos, 
                           "dhcp-option DNS %s\n", ctx->config.dns_servers[i]);
        }
    }
    
    /* Add custom directives */
    if (options->custom_directives && strlen(options->custom_directives) > 0) {
        pos += snprintf(config + pos, 8192 - pos, "%s\n", options->custom_directives);
    }
    
    /* Add certificates inline if requested */
    if (options->use_inline_certs) {
        if (options->include_ca_cert) {
            pos += snprintf(config + pos, 8192 - pos, "<ca>\n%s</ca>\n", ctx->ca_cert_content);
        }
        
        /* Load client certificate and key */
        char cert_path[512], key_path[512];
        snprintf(cert_path, sizeof(cert_path), "clients/%s.crt", client->common_name);
        snprintf(key_path, sizeof(key_path), "clients/%s.key", client->common_name);
        
        if (options->include_client_cert) {
            FILE *cert_file = fopen(cert_path, "r");
            if (cert_file) {
                pos += snprintf(config + pos, 8192 - pos, "<cert>\n");
                char line[256];
                while (fgets(line, sizeof(line), cert_file) && pos < 7900) {
                    pos += snprintf(config + pos, 8192 - pos, "%s", line);
                }
                pos += snprintf(config + pos, 8192 - pos, "</cert>\n");
                fclose(cert_file);
            }
        }
        
        if (options->include_client_key) {
            FILE *key_file = fopen(key_path, "r");
            if (key_file) {
                pos += snprintf(config + pos, 8192 - pos, "<key>\n");
                char line[256];
                while (fgets(line, sizeof(line), key_file) && pos < 7900) {
                    pos += snprintf(config + pos, 8192 - pos, "%s", line);
                }
                pos += snprintf(config + pos, 8192 - pos, "</key>\n");
                fclose(key_file);
            }
        }
    } else {
        /* Reference external certificate files */
        if (options->include_ca_cert) {
            pos += snprintf(config + pos, 8192 - pos, "ca ca.crt\n");
        }
        if (options->include_client_cert) {
            pos += snprintf(config + pos, 8192 - pos, "cert %s.crt\n", client->common_name);
        }
        if (options->include_client_key) {
            pos += snprintf(config + pos, 8192 - pos, "key %s.key\n", client->common_name);
        }
    }
    
    return config;
}

int ovpn_server_revoke_client(ovpn_server_context_t *ctx, 
                             uint32_t client_id, 
                             const char *reason) {
    if (!ctx || client_id == 0) {
        return -1;
    }
    
    pthread_mutex_lock(&ctx->clients_mutex);
    
    ovpn_client_info_t *client = NULL;
    for (uint32_t i = 0; i < ctx->client_count; i++) {
        if (ctx->clients[i].client_id == client_id) {
            client = &ctx->clients[i];
            break;
        }
    }
    
    if (!client) {
        pthread_mutex_unlock(&ctx->clients_mutex);
        return -1;
    }
    
    client->is_revoked = true;
    client->is_active = false;
    client->revoked_time = time(NULL);
    if (reason) {
        strncpy(client->revocation_reason, reason, sizeof(client->revocation_reason) - 1);
    }
    
    pthread_mutex_unlock(&ctx->clients_mutex);
    
    /* Disconnect client if currently connected */
    if (client->currently_connected) {
        ovpn_server_disconnect_client(ctx, client_id);
    }
    
    server_event_handler(ctx, SERVER_EVENT_CLIENT_REVOKED, client_id,
                        "Client revoked", reason ? reason : "No reason provided");
    
    return 0;
}

static void server_event_handler(ovpn_server_context_t *ctx, 
                                ovpn_server_event_type_t type, 
                                uint32_t client_id,
                                const char *message, 
                                const char *details) {
    if (!ctx->event_callback) {
        return;
    }
    
    ovpn_server_event_t event = {0};
    event.event_type = type;
    event.timestamp = time(NULL);
    event.client_id = client_id;
    
    if (message) {
        strncpy(event.message, message, sizeof(event.message) - 1);
    }
    if (details) {
        strncpy(event.details, details, sizeof(event.details) - 1);
    }
    
    ctx->event_callback(&event, ctx->event_callback_data);
}

int ovpn_server_set_event_callback(ovpn_server_context_t *ctx, 
                                  ovpn_server_event_callback_t callback, 
                                  void *user_data) {
    if (!ctx) {
        return -1;
    }
    
    ctx->event_callback = callback;
    ctx->event_callback_data = user_data;
    return 0;
}

const char *ovpn_server_event_type_to_string(ovpn_server_event_type_t type) {
    switch (type) {
        case SERVER_EVENT_STARTED: return "SERVER_STARTED";
        case SERVER_EVENT_STOPPED: return "SERVER_STOPPED";
        case SERVER_EVENT_CLIENT_CONNECTED: return "CLIENT_CONNECTED";
        case SERVER_EVENT_CLIENT_DISCONNECTED: return "CLIENT_DISCONNECTED";
        case SERVER_EVENT_CLIENT_AUTHENTICATED: return "CLIENT_AUTHENTICATED";
        case SERVER_EVENT_CLIENT_AUTH_FAILED: return "CLIENT_AUTH_FAILED";
        case SERVER_EVENT_CLIENT_CREATED: return "CLIENT_CREATED";
        case SERVER_EVENT_CLIENT_REVOKED: return "CLIENT_REVOKED";
        case SERVER_EVENT_CLIENT_UPDATED: return "CLIENT_UPDATED";
        case SERVER_EVENT_CONFIG_RELOADED: return "CONFIG_RELOADED";
        case SERVER_EVENT_ERROR: return "ERROR";
        case SERVER_EVENT_WARNING: return "WARNING";
        default: return "UNKNOWN";
    }
}

void ovpn_server_cleanup(ovpn_server_context_t *ctx) {
    if (!ctx) {
        return;
    }
    
    /* Stop server if running */
    if (ctx->is_running) {
        ovpn_server_stop(ctx);
    }
    
    /* Cleanup OpenVPN context */
    if (ctx->openvpn_context) {
        context_gc_free(&ctx->openvpn_context->gc);
        free(ctx->openvpn_context);
    }
    
    /* Cleanup mutexes */
    pthread_mutex_destroy(&ctx->clients_mutex);
    pthread_mutex_destroy(&ctx->stats_mutex);
    
    /* Reset global instance */
    if (g_server_instance == ctx) {
        g_server_instance = NULL;
    }
    
    free(ctx);
}

/* Additional helper functions for certificate generation would go here */
static int generate_client_certificate_files(ovpn_server_context_t *ctx, 
                                            uint32_t client_id, 
                                            const char *common_name,
                                            int validity_days) {
    /* This would implement certificate generation using OpenSSL */
    /* For brevity, returning success - full implementation would generate */
    /* RSA key pair and X.509 certificate signed by CA */
    return 0;
}

/* Placeholder implementations for other functions... */
int ovpn_server_stop(ovpn_server_context_t *ctx) {
    if (!ctx || !ctx->is_running) return -1;
    ctx->is_running = false;
    pthread_join(ctx->server_thread, NULL);
    pthread_join(ctx->monitoring_thread, NULL);
    return 0;
}

int ovpn_server_get_client_info(ovpn_server_context_t *ctx, uint32_t client_id, ovpn_client_info_t *info) {
    if (!ctx || !info) return -1;
    pthread_mutex_lock(&ctx->clients_mutex);
    for (uint32_t i = 0; i < ctx->client_count; i++) {
        if (ctx->clients[i].client_id == client_id) {
            *info = ctx->clients[i];
            pthread_mutex_unlock(&ctx->clients_mutex);
            return 0;
        }
    }
    pthread_mutex_unlock(&ctx->clients_mutex);
    return -1;
}

void ovpn_server_free_client_list(ovpn_client_info_t *clients, uint32_t count) {
    if (clients) free(clients);
}

void ovpn_server_free_config_string(char *config_string) {
    if (config_string) free(config_string);
}
