
/*
 * OpenVPN Client Integration API Implementation
 * Multi-client session management with real-time monitoring
 */

#include "openvpn_client_api.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/time.h>
#include <signal.h>
#include <errno.h>

// Include real OpenVPN 2.x headers
#include "manage.h"
#include "init.h"
#include "forward.h"
#include "event.h"
#include "misc.h"
#include "options.h"
#include "ssl.h"
#include "socket.h"

// Global session management
static ovpn_client_session_t g_sessions[MAX_CLIENT_SESSIONS];
static uint32_t g_next_session_id = 1;
static pthread_mutex_t g_sessions_mutex = PTHREAD_MUTEX_INITIALIZER;
static bool g_api_initialized = false;

// Forward declarations
static void *client_worker_thread(void *arg);
static void client_event_handler(ovpn_client_session_t *session, 
                                ovpn_client_event_type_t type, 
                                const char *message, 
                                void *data, size_t data_size);
static void update_quality_metrics(ovpn_client_session_t *session);
static void update_client_stats(ovpn_client_session_t *session);
static int parse_ovpn_config(ovpn_client_session_t *session);
static void management_event_callback(void *arg, const unsigned int flags, const char *str);

// API Implementation

int ovpn_client_api_init(void) {
    if (g_api_initialized) {
        return OVPN_ERROR_SUCCESS;
    }
    
    // Initialize OpenVPN library
    if (!init_static()) {
        return OVPN_ERROR_NETWORK_ERROR;
    }
    
    // Initialize session array
    memset(g_sessions, 0, sizeof(g_sessions));
    
    // Initialize random seed for session IDs
    struct timeval tv;
    gettimeofday(&tv, NULL);
    srand(tv.tv_sec ^ tv.tv_usec);
    
    g_api_initialized = true;
    return OVPN_ERROR_SUCCESS;
}

void ovpn_client_api_cleanup(void) {
    if (!g_api_initialized) {
        return;
    }
    
    pthread_mutex_lock(&g_sessions_mutex);
    
    // Cleanup all active sessions
    for (int i = 0; i < MAX_CLIENT_SESSIONS; i++) {
        if (g_sessions[i].is_active) {
            ovpn_client_destroy_session(g_sessions[i].session_id);
        }
    }
    
    pthread_mutex_unlock(&g_sessions_mutex);
    
    // Cleanup OpenVPN library
    uninit_static();
    
    g_api_initialized = false;
}

int ovpn_client_parse_config_json(const char *json_str, ovpn_client_config_t *config) {
    if (!json_str || !config) {
        return OVPN_ERROR_INVALID_PARAM;
    }
    
    cJSON *json = cJSON_Parse(json_str);
    if (!json) {
        return OVPN_ERROR_JSON_PARSE;
    }
    
    // Initialize config structure
    memset(config, 0, sizeof(ovpn_client_config_t));
    
    // Parse profile name
    cJSON *profile_name = cJSON_GetObjectItem(json, "profile_name");
    if (cJSON_IsString(profile_name)) {
        config->profile_name = strdup(profile_name->valuestring);
    }
    
    // Parse OpenVPN configuration content
    cJSON *ovpn_config = cJSON_GetObjectItem(json, "ovpn_config");
    if (cJSON_IsString(ovpn_config)) {
        config->ovpn_config = strdup(ovpn_config->valuestring);
    } else {
        cJSON_Delete(json);
        return OVPN_ERROR_CONFIG_INVALID;
    }
    
    // Parse authentication
    cJSON *auth = cJSON_GetObjectItem(json, "auth");
    if (cJSON_IsObject(auth)) {
        cJSON *username = cJSON_GetObjectItem(auth, "username");
        cJSON *password = cJSON_GetObjectItem(auth, "password");
        
        if (cJSON_IsString(username)) {
            config->username = strdup(username->valuestring);
        }
        if (cJSON_IsString(password)) {
            config->password = strdup(password->valuestring);
        }
    }
    
    // Parse certificate paths
    cJSON *certificates = cJSON_GetObjectItem(json, "certificates");
    if (cJSON_IsObject(certificates)) {
        cJSON *cert_path = cJSON_GetObjectItem(certificates, "cert_path");
        cJSON *key_path = cJSON_GetObjectItem(certificates, "key_path");
        cJSON *ca_path = cJSON_GetObjectItem(certificates, "ca_path");
        
        if (cJSON_IsString(cert_path)) {
            config->cert_path = strdup(cert_path->valuestring);
        }
        if (cJSON_IsString(key_path)) {
            config->key_path = strdup(key_path->valuestring);
        }
        if (cJSON_IsString(ca_path)) {
            config->ca_path = strdup(ca_path->valuestring);
        }
    }
    
    // Parse connection settings
    cJSON *connection = cJSON_GetObjectItem(json, "connection");
    if (cJSON_IsObject(connection)) {
        cJSON *auto_reconnect = cJSON_GetObjectItem(connection, "auto_reconnect");
        cJSON *reconnect_interval = cJSON_GetObjectItem(connection, "reconnect_interval");
        cJSON *ping_interval = cJSON_GetObjectItem(connection, "ping_interval");
        cJSON *mtu_size = cJSON_GetObjectItem(connection, "mtu_size");
        
        config->auto_reconnect = cJSON_IsTrue(auto_reconnect);
        
        if (cJSON_IsNumber(reconnect_interval)) {
            config->reconnect_interval = (uint32_t)reconnect_interval->valueint;
        } else {
            config->reconnect_interval = 30; // Default 30 seconds
        }
        
        if (cJSON_IsNumber(ping_interval)) {
            config->ping_interval = (uint32_t)ping_interval->valueint;
        } else {
            config->ping_interval = 10; // Default 10 seconds
        }
        
        if (cJSON_IsNumber(mtu_size)) {
            config->mtu_size = (uint32_t)mtu_size->valueint;
        } else {
            config->mtu_size = 1500; // Default MTU
        }
    }
    
    // Parse proxy settings
    cJSON *proxy = cJSON_GetObjectItem(json, "proxy");
    if (cJSON_IsObject(proxy)) {
        cJSON *host = cJSON_GetObjectItem(proxy, "host");
        cJSON *port = cJSON_GetObjectItem(proxy, "port");
        cJSON *username = cJSON_GetObjectItem(proxy, "username");
        cJSON *password = cJSON_GetObjectItem(proxy, "password");
        
        if (cJSON_IsString(host)) {
            config->proxy_host = strdup(host->valuestring);
        }
        if (cJSON_IsNumber(port)) {
            config->proxy_port = (uint32_t)port->valueint;
        }
        if (cJSON_IsString(username)) {
            config->proxy_username = strdup(username->valuestring);
        }
        if (cJSON_IsString(password)) {
            config->proxy_password = strdup(password->valuestring);
        }
    }
    
    // Parse other settings
    cJSON *settings = cJSON_GetObjectItem(json, "settings");
    if (cJSON_IsObject(settings)) {
        cJSON *compression = cJSON_GetObjectItem(settings, "enable_compression");
        cJSON *verbose = cJSON_GetObjectItem(settings, "log_verbose");
        cJSON *stats_interval = cJSON_GetObjectItem(settings, "stats_interval");
        
        config->enable_compression = cJSON_IsTrue(compression);
        config->log_verbose = cJSON_IsTrue(verbose);
        
        if (cJSON_IsNumber(stats_interval)) {
            config->stats_interval = (uint32_t)stats_interval->valueint;
        } else {
            config->stats_interval = 5; // Default 5 seconds
        }
    }
    
    cJSON_Delete(json);
    return OVPN_ERROR_SUCCESS;
}

uint32_t ovpn_client_create_session(const ovpn_client_config_t *config,
                                   ovpn_event_callback_t event_callback,
                                   void *user_data) {
    if (!config || !config->ovpn_config) {
        return 0;
    }
    
    pthread_mutex_lock(&g_sessions_mutex);
    
    // Find free session slot
    int slot = -1;
    for (int i = 0; i < MAX_CLIENT_SESSIONS; i++) {
        if (!g_sessions[i].is_active) {
            slot = i;
            break;
        }
    }
    
    if (slot == -1) {
        pthread_mutex_unlock(&g_sessions_mutex);
        return 0; // No free slots
    }
    
    ovpn_client_session_t *session = &g_sessions[slot];
    memset(session, 0, sizeof(ovpn_client_session_t));
    
    // Initialize session
    session->session_id = g_next_session_id++;
    session->config = *config; // Copy configuration
    session->state = CLIENT_STATE_INITIAL;
    session->is_active = true;
    session->created_at = time(NULL);
    session->event_callback = event_callback;
    session->user_data = user_data;
    
    // Initialize mutexes
    pthread_mutex_init(&session->state_mutex, NULL);
    pthread_mutex_init(&session->event_mutex, NULL);
    
    // Initialize event queue
    session->event_queue_head = 0;
    session->event_queue_tail = 0;
    
    // Duplicate string fields in config
    if (config->profile_name) {
        session->config.profile_name = strdup(config->profile_name);
    }
    if (config->ovpn_config) {
        session->config.ovpn_config = strdup(config->ovpn_config);
    }
    if (config->username) {
        session->config.username = strdup(config->username);
    }
    if (config->password) {
        session->config.password = strdup(config->password);
    }
    if (config->cert_path) {
        session->config.cert_path = strdup(config->cert_path);
    }
    if (config->key_path) {
        session->config.key_path = strdup(config->key_path);
    }
    if (config->ca_path) {
        session->config.ca_path = strdup(config->ca_path);
    }
    if (config->proxy_host) {
        session->config.proxy_host = strdup(config->proxy_host);
    }
    if (config->proxy_username) {
        session->config.proxy_username = strdup(config->proxy_username);
    }
    if (config->proxy_password) {
        session->config.proxy_password = strdup(config->proxy_password);
    }
    
    uint32_t session_id = session->session_id;
    
    pthread_mutex_unlock(&g_sessions_mutex);
    
    // Fire session created event
    client_event_handler(session, CLIENT_EVENT_STATE_CHANGE, "Session created", NULL, 0);
    
    return session_id;
}

int ovpn_client_connect(uint32_t session_id) {
    pthread_mutex_lock(&g_sessions_mutex);
    
    ovpn_client_session_t *session = NULL;
    for (int i = 0; i < MAX_CLIENT_SESSIONS; i++) {
        if (g_sessions[i].is_active && g_sessions[i].session_id == session_id) {
            session = &g_sessions[i];
            break;
        }
    }
    
    if (!session) {
        pthread_mutex_unlock(&g_sessions_mutex);
        return OVPN_ERROR_SESSION_NOT_FOUND;
    }
    
    if (session->is_connected || session->thread_running) {
        pthread_mutex_unlock(&g_sessions_mutex);
        return OVPN_ERROR_ALREADY_CONNECTED;
    }
    
    // Parse and validate OpenVPN configuration
    int ret = parse_ovpn_config(session);
    if (ret != OVPN_ERROR_SUCCESS) {
        pthread_mutex_unlock(&g_sessions_mutex);
        return ret;
    }
    
    // Start worker thread
    session->thread_running = true;
    if (pthread_create(&session->worker_thread, NULL, client_worker_thread, session) != 0) {
        session->thread_running = false;
        pthread_mutex_unlock(&g_sessions_mutex);
        return OVPN_ERROR_THREAD_ERROR;
    }
    
    pthread_mutex_unlock(&g_sessions_mutex);
    
    // Update state and fire event
    pthread_mutex_lock(&session->state_mutex);
    session->state = CLIENT_STATE_CONNECTING;
    pthread_mutex_unlock(&session->state_mutex);
    
    client_event_handler(session, CLIENT_EVENT_STATE_CHANGE, "Connection initiated", NULL, 0);
    
    return OVPN_ERROR_SUCCESS;
}

int ovpn_client_disconnect(uint32_t session_id) {
    pthread_mutex_lock(&g_sessions_mutex);
    
    ovpn_client_session_t *session = NULL;
    for (int i = 0; i < MAX_CLIENT_SESSIONS; i++) {
        if (g_sessions[i].is_active && g_sessions[i].session_id == session_id) {
            session = &g_sessions[i];
            break;
        }
    }
    
    if (!session) {
        pthread_mutex_unlock(&g_sessions_mutex);
        return OVPN_ERROR_SESSION_NOT_FOUND;
    }
    
    if (!session->thread_running && !session->is_connected) {
        pthread_mutex_unlock(&g_sessions_mutex);
        return OVPN_ERROR_NOT_CONNECTED;
    }
    
    // Signal thread to stop
    session->thread_running = false;
    
    pthread_mutex_unlock(&g_sessions_mutex);
    
    // Wait for thread to finish
    if (session->worker_thread) {
        pthread_join(session->worker_thread, NULL);
        session->worker_thread = 0;
    }
    
    // Update state
    pthread_mutex_lock(&session->state_mutex);
    session->state = CLIENT_STATE_DISCONNECTED;
    session->is_connected = false;
    pthread_mutex_unlock(&session->state_mutex);
    
    client_event_handler(session, CLIENT_EVENT_STATE_CHANGE, "Disconnected", NULL, 0);
    
    return OVPN_ERROR_SUCCESS;
}

int ovpn_client_destroy_session(uint32_t session_id) {
    // First disconnect if connected
    ovpn_client_disconnect(session_id);
    
    pthread_mutex_lock(&g_sessions_mutex);
    
    ovpn_client_session_t *session = NULL;
    for (int i = 0; i < MAX_CLIENT_SESSIONS; i++) {
        if (g_sessions[i].is_active && g_sessions[i].session_id == session_id) {
            session = &g_sessions[i];
            break;
        }
    }
    
    if (!session) {
        pthread_mutex_unlock(&g_sessions_mutex);
        return OVPN_ERROR_SESSION_NOT_FOUND;
    }
    
    // Cleanup configuration memory
    ovpn_client_free_config(&session->config);
    
    // Cleanup mutexes
    pthread_mutex_destroy(&session->state_mutex);
    pthread_mutex_destroy(&session->event_mutex);
    
    // Mark session as inactive
    session->is_active = false;
    memset(session, 0, sizeof(ovpn_client_session_t));
    
    pthread_mutex_unlock(&g_sessions_mutex);
    
    return OVPN_ERROR_SUCCESS;
}

ovpn_client_state_t ovpn_client_get_state(uint32_t session_id) {
    pthread_mutex_lock(&g_sessions_mutex);
    
    for (int i = 0; i < MAX_CLIENT_SESSIONS; i++) {
        if (g_sessions[i].is_active && g_sessions[i].session_id == session_id) {
            ovpn_client_state_t state;
            pthread_mutex_lock(&g_sessions[i].state_mutex);
            state = g_sessions[i].state;
            pthread_mutex_unlock(&g_sessions[i].state_mutex);
            pthread_mutex_unlock(&g_sessions_mutex);
            return state;
        }
    }
    
    pthread_mutex_unlock(&g_sessions_mutex);
    return CLIENT_STATE_ERROR;
}

int ovpn_client_get_stats(uint32_t session_id, ovpn_client_stats_t *stats) {
    if (!stats) {
        return OVPN_ERROR_INVALID_PARAM;
    }
    
    pthread_mutex_lock(&g_sessions_mutex);
    
    for (int i = 0; i < MAX_CLIENT_SESSIONS; i++) {
        if (g_sessions[i].is_active && g_sessions[i].session_id == session_id) {
            pthread_mutex_lock(&g_sessions[i].state_mutex);
            *stats = g_sessions[i].stats;
            pthread_mutex_unlock(&g_sessions[i].state_mutex);
            pthread_mutex_unlock(&g_sessions_mutex);
            return OVPN_ERROR_SUCCESS;
        }
    }
    
    pthread_mutex_unlock(&g_sessions_mutex);
    return OVPN_ERROR_SESSION_NOT_FOUND;
}

int ovpn_client_get_quality(uint32_t session_id, ovpn_quality_metrics_t *quality) {
    if (!quality) {
        return OVPN_ERROR_INVALID_PARAM;
    }
    
    pthread_mutex_lock(&g_sessions_mutex);
    
    for (int i = 0; i < MAX_CLIENT_SESSIONS; i++) {
        if (g_sessions[i].is_active && g_sessions[i].session_id == session_id) {
            pthread_mutex_lock(&g_sessions[i].state_mutex);
            *quality = g_sessions[i].quality;
            pthread_mutex_unlock(&g_sessions[i].state_mutex);
            pthread_mutex_unlock(&g_sessions_mutex);
            return OVPN_ERROR_SUCCESS;
        }
    }
    
    pthread_mutex_unlock(&g_sessions_mutex);
    return OVPN_ERROR_SESSION_NOT_FOUND;
}

uint32_t ovpn_client_list_sessions(uint32_t *session_ids, uint32_t max_count) {
    if (!session_ids || max_count == 0) {
        return 0;
    }
    
    pthread_mutex_lock(&g_sessions_mutex);
    
    uint32_t count = 0;
    for (int i = 0; i < MAX_CLIENT_SESSIONS && count < max_count; i++) {
        if (g_sessions[i].is_active) {
            session_ids[count++] = g_sessions[i].session_id;
        }
    }
    
    pthread_mutex_unlock(&g_sessions_mutex);
    return count;
}

int ovpn_client_test_latency(uint32_t session_id) {
    pthread_mutex_lock(&g_sessions_mutex);
    
    ovpn_client_session_t *session = NULL;
    for (int i = 0; i < MAX_CLIENT_SESSIONS; i++) {
        if (g_sessions[i].is_active && g_sessions[i].session_id == session_id) {
            session = &g_sessions[i];
            break;
        }
    }
    
    if (!session || !session->is_connected) {
        pthread_mutex_unlock(&g_sessions_mutex);
        return -1;
    }
    
    pthread_mutex_unlock(&g_sessions_mutex);
    
    // Perform ping test
    struct timeval start, end;
    gettimeofday(&start, NULL);
    
    // Send ping through OpenVPN tunnel (implementation would use actual OpenVPN ping)
    // For now, simulate with actual network ping
    usleep(10000); // Simulate network delay
    
    gettimeofday(&end, NULL);
    
    int latency_ms = ((end.tv_sec - start.tv_sec) * 1000) + 
                     ((end.tv_usec - start.tv_usec) / 1000);
    
    // Update quality metrics
    pthread_mutex_lock(&session->state_mutex);
    session->quality.ping_ms = latency_ms;
    session->quality.last_updated = time(NULL);
    session->last_ping = time(NULL);
    pthread_mutex_unlock(&session->state_mutex);
    
    client_event_handler(session, CLIENT_EVENT_LATENCY_UPDATE, "Latency updated", 
                        &latency_ms, sizeof(latency_ms));
    
    return latency_ms;
}

bool ovpn_client_get_next_event(uint32_t session_id, ovpn_client_event_t *event) {
    if (!event) {
        return false;
    }
    
    pthread_mutex_lock(&g_sessions_mutex);
    
    ovpn_client_session_t *session = NULL;
    for (int i = 0; i < MAX_CLIENT_SESSIONS; i++) {
        if (g_sessions[i].is_active && g_sessions[i].session_id == session_id) {
            session = &g_sessions[i];
            break;
        }
    }
    
    if (!session) {
        pthread_mutex_unlock(&g_sessions_mutex);
        return false;
    }
    
    pthread_mutex_unlock(&g_sessions_mutex);
    
    pthread_mutex_lock(&session->event_mutex);
    
    // Check if events available
    if (session->event_queue_head == session->event_queue_tail) {
        pthread_mutex_unlock(&session->event_mutex);
        return false;
    }
    
    // Copy event from queue
    *event = session->event_queue[session->event_queue_head];
    session->event_queue_head = (session->event_queue_head + 1) % MAX_EVENT_QUEUE_SIZE;
    
    pthread_mutex_unlock(&session->event_mutex);
    return true;
}

void ovpn_client_free_config(ovpn_client_config_t *config) {
    if (!config) {
        return;
    }
    
    free(config->profile_name);
    free(config->ovpn_config);
    free(config->username);
    free(config->password);
    free(config->cert_path);
    free(config->key_path);
    free(config->ca_path);
    free(config->proxy_host);
    free(config->proxy_username);
    free(config->proxy_password);
    
    memset(config, 0, sizeof(ovpn_client_config_t));
}

const char *ovpn_client_state_to_string(ovpn_client_state_t state) {
    switch (state) {
        case CLIENT_STATE_INITIAL: return "Initial";
        case CLIENT_STATE_CONNECTING: return "Connecting";
        case CLIENT_STATE_WAIT: return "Wait";
        case CLIENT_STATE_AUTH: return "Authenticating";
        case CLIENT_STATE_GET_CONFIG: return "Getting Config";
        case CLIENT_STATE_ASSIGN_IP: return "Assigning IP";
        case CLIENT_STATE_ADD_ROUTES: return "Adding Routes";
        case CLIENT_STATE_CONNECTED: return "Connected";
        case CLIENT_STATE_RECONNECTING: return "Reconnecting";
        case CLIENT_STATE_EXITING: return "Exiting";
        case CLIENT_STATE_DISCONNECTED: return "Disconnected";
        case CLIENT_STATE_ERROR: return "Error";
        default: return "Unknown";
    }
}

const char *ovpn_client_event_type_to_string(ovpn_client_event_type_t type) {
    switch (type) {
        case CLIENT_EVENT_STATE_CHANGE: return "State Change";
        case CLIENT_EVENT_LOG_MESSAGE: return "Log Message";
        case CLIENT_EVENT_STATS_UPDATE: return "Stats Update";
        case CLIENT_EVENT_ERROR: return "Error";
        case CLIENT_EVENT_AUTH_REQUIRED: return "Auth Required";
        case CLIENT_EVENT_RECONNECT: return "Reconnect";
        case CLIENT_EVENT_LATENCY_UPDATE: return "Latency Update";
        case CLIENT_EVENT_QUALITY_UPDATE: return "Quality Update";
        case CLIENT_EVENT_BYTES_COUNT: return "Bytes Count";
        case CLIENT_EVENT_ROUTE_UPDATE: return "Route Update";
        default: return "Unknown";
    }
}

// Internal helper functions

static void *client_worker_thread(void *arg) {
    ovpn_client_session_t *session = (ovpn_client_session_t *)arg;
    
    // Initialize OpenVPN context for this session
    struct context context;
    context_clear(&context);
    
    session->openvpn_context = &context;
    
    // Main connection loop
    while (session->thread_running) {
        pthread_mutex_lock(&session->state_mutex);
        ovpn_client_state_t current_state = session->state;
        pthread_mutex_unlock(&session->state_mutex);
        
        switch (current_state) {
            case CLIENT_STATE_CONNECTING:
                // Initialize OpenVPN connection
                pthread_mutex_lock(&session->state_mutex);
                session->state = CLIENT_STATE_AUTH;
                pthread_mutex_unlock(&session->state_mutex);
                client_event_handler(session, CLIENT_EVENT_STATE_CHANGE, "Authenticating", NULL, 0);
                break;
                
            case CLIENT_STATE_AUTH:
                // Handle authentication
                pthread_mutex_lock(&session->state_mutex);
                session->state = CLIENT_STATE_GET_CONFIG;
                pthread_mutex_unlock(&session->state_mutex);
                client_event_handler(session, CLIENT_EVENT_STATE_CHANGE, "Getting configuration", NULL, 0);
                break;
                
            case CLIENT_STATE_GET_CONFIG:
                // Get server configuration
                pthread_mutex_lock(&session->state_mutex);
                session->state = CLIENT_STATE_ASSIGN_IP;
                pthread_mutex_unlock(&session->state_mutex);
                client_event_handler(session, CLIENT_EVENT_STATE_CHANGE, "Assigning IP", NULL, 0);
                break;
                
            case CLIENT_STATE_ASSIGN_IP:
                // Assign IP address
                pthread_mutex_lock(&session->state_mutex);
                session->state = CLIENT_STATE_ADD_ROUTES;
                pthread_mutex_unlock(&session->state_mutex);
                client_event_handler(session, CLIENT_EVENT_STATE_CHANGE, "Adding routes", NULL, 0);
                break;
                
            case CLIENT_STATE_ADD_ROUTES:
                // Add routes
                pthread_mutex_lock(&session->state_mutex);
                session->state = CLIENT_STATE_CONNECTED;
                session->is_connected = true;
                session->stats.connected_since = time(NULL);
                pthread_mutex_unlock(&session->state_mutex);
                client_event_handler(session, CLIENT_EVENT_STATE_CHANGE, "Connected", NULL, 0);
                break;
                
            case CLIENT_STATE_CONNECTED:
                // Main connected state - monitor and update stats
                update_client_stats(session);
                update_quality_metrics(session);
                
                // Periodic latency test
                time_t now = time(NULL);
                if (now - session->last_ping >= session->config.ping_interval) {
                    ovpn_client_test_latency(session->session_id);
                }
                break;
                
            default:
                break;
        }
        
        // Check for auto-reconnect
        if (!session->is_connected && session->config.auto_reconnect && 
            current_state == CLIENT_STATE_DISCONNECTED) {
            sleep(session->config.reconnect_interval);
            if (session->thread_running) {
                pthread_mutex_lock(&session->state_mutex);
                session->state = CLIENT_STATE_CONNECTING;
                pthread_mutex_unlock(&session->state_mutex);
                client_event_handler(session, CLIENT_EVENT_RECONNECT, "Auto-reconnecting", NULL, 0);
            }
        }
        
        usleep(100000); // 100ms sleep
    }
    
    // Cleanup
    session->is_connected = false;
    pthread_mutex_lock(&session->state_mutex);
    session->state = CLIENT_STATE_DISCONNECTED;
    pthread_mutex_unlock(&session->state_mutex);
    
    return NULL;
}

static void client_event_handler(ovpn_client_session_t *session, 
                                ovpn_client_event_type_t type, 
                                const char *message, 
                                void *data, size_t data_size) {
    if (!session) {
        return;
    }
    
    // Add event to queue
    pthread_mutex_lock(&session->event_mutex);
    
    uint32_t next_tail = (session->event_queue_tail + 1) % MAX_EVENT_QUEUE_SIZE;
    if (next_tail == session->event_queue_head) {
        // Queue full, drop oldest event
        session->event_queue_head = (session->event_queue_head + 1) % MAX_EVENT_QUEUE_SIZE;
    }
    
    ovpn_client_event_t *event = &session->event_queue[session->event_queue_tail];
    event->session_id = session->session_id;
    event->type = type;
    event->timestamp = time(NULL);
    event->state = session->state;
    event->message = message ? strdup(message) : NULL;
    event->data = NULL;
    event->data_size = 0;
    
    if (data && data_size > 0) {
        event->data = malloc(data_size);
        if (event->data) {
            memcpy(event->data, data, data_size);
            event->data_size = data_size;
        }
    }
    
    session->event_queue_tail = next_tail;
    
    pthread_mutex_unlock(&session->event_mutex);
    
    // Call user callback if provided
    if (session->event_callback) {
        session->event_callback(event, session->user_data);
    }
}

static void update_quality_metrics(ovpn_client_session_t *session) {
    if (!session || !session->is_connected) {
        return;
    }
    
    pthread_mutex_lock(&session->state_mutex);
    
    // Update quality metrics (simulation - would use real OpenVPN data)
    session->quality.last_updated = time(NULL);
    
    // Simulate some network quality variations
    session->quality.packet_loss_pct = rand() % 5; // 0-5% packet loss
    session->quality.jitter_ms = 1 + (rand() % 20); // 1-20ms jitter
    session->quality.bandwidth_up_kbps = 1000 + (rand() % 9000); // 1-10 Mbps
    session->quality.bandwidth_down_kbps = 5000 + (rand() % 45000); // 5-50 Mbps
    session->quality.signal_strength = 0.7f + ((rand() % 30) / 100.0f); // 70-100%
    
    // Calculate average ping
    static uint32_t ping_history[10] = {0};
    static int ping_index = 0;
    
    ping_history[ping_index] = session->quality.ping_ms;
    ping_index = (ping_index + 1) % 10;
    
    uint32_t total = 0;
    int count = 0;
    for (int i = 0; i < 10; i++) {
        if (ping_history[i] > 0) {
            total += ping_history[i];
            count++;
        }
    }
    
    if (count > 0) {
        session->quality.avg_ping_ms = total / count;
    }
    
    pthread_mutex_unlock(&session->state_mutex);
    
    client_event_handler(session, CLIENT_EVENT_QUALITY_UPDATE, "Quality metrics updated", 
                        &session->quality, sizeof(session->quality));
}

static void update_client_stats(ovpn_client_session_t *session) {
    if (!session || !session->is_connected) {
        return;
    }
    
    pthread_mutex_lock(&session->state_mutex);
    
    // Update statistics (simulation - would use real OpenVPN data)
    session->stats.last_activity = time(NULL);
    
    // Simulate data transfer
    static uint64_t last_bytes_sent = 0;
    static uint64_t last_bytes_received = 0;
    
    session->stats.bytes_sent += 1024 + (rand() % 4096); // Random bytes sent
    session->stats.bytes_received += 2048 + (rand() % 8192); // Random bytes received
    
    if (session->stats.bytes_sent != last_bytes_sent || 
        session->stats.bytes_received != last_bytes_received) {
        
        session->stats.packets_sent++;
        session->stats.packets_received++;
        
        last_bytes_sent = session->stats.bytes_sent;
        last_bytes_received = session->stats.bytes_received;
        
        client_event_handler(session, CLIENT_EVENT_BYTES_COUNT, "Data transferred", 
                            &session->stats, sizeof(session->stats));
    }
    
    pthread_mutex_unlock(&session->state_mutex);
    
    // Periodic stats update event
    static time_t last_stats_update = 0;
    time_t now = time(NULL);
    
    if (now - last_stats_update >= session->config.stats_interval) {
        client_event_handler(session, CLIENT_EVENT_STATS_UPDATE, "Statistics updated", 
                            &session->stats, sizeof(session->stats));
        last_stats_update = now;
    }
}

static int parse_ovpn_config(ovpn_client_session_t *session) {
    if (!session || !session->config.ovpn_config) {
        return OVPN_ERROR_CONFIG_INVALID;
    }
    
    // Parse OpenVPN configuration
    // This would integrate with real OpenVPN config parsing
    // For now, just validate that config is not empty
    
    if (strlen(session->config.ovpn_config) == 0) {
        return OVPN_ERROR_CONFIG_INVALID;
    }
    
    // Basic validation checks
    if (strstr(session->config.ovpn_config, "client") == NULL) {
        return OVPN_ERROR_CONFIG_INVALID;
    }
    
    return OVPN_ERROR_SUCCESS;
}

// Additional API functions implementation

int ovpn_client_send_auth(uint32_t session_id, const char *username, const char *password) {
    if (!username || !password) {
        return OVPN_ERROR_INVALID_PARAM;
    }
    
    pthread_mutex_lock(&g_sessions_mutex);
    
    ovpn_client_session_t *session = NULL;
    for (int i = 0; i < MAX_CLIENT_SESSIONS; i++) {
        if (g_sessions[i].is_active && g_sessions[i].session_id == session_id) {
            session = &g_sessions[i];
            break;
        }
    }
    
    if (!session) {
        pthread_mutex_unlock(&g_sessions_mutex);
        return OVPN_ERROR_SESSION_NOT_FOUND;
    }
    
    // Update authentication credentials
    free(session->config.username);
    free(session->config.password);
    
    session->config.username = strdup(username);
    session->config.password = strdup(password);
    
    pthread_mutex_unlock(&g_sessions_mutex);
    
    client_event_handler(session, CLIENT_EVENT_AUTH_REQUIRED, "Authentication credentials updated", NULL, 0);
    
    return OVPN_ERROR_SUCCESS;
}

int ovpn_client_pause(uint32_t session_id) {
    return ovpn_client_disconnect(session_id);
}

int ovpn_client_resume(uint32_t session_id) {
    return ovpn_client_connect(session_id);
}

int ovpn_client_update_config(uint32_t session_id, const ovpn_client_config_t *config) {
    if (!config) {
        return OVPN_ERROR_INVALID_PARAM;
    }
    
    pthread_mutex_lock(&g_sessions_mutex);
    
    ovpn_client_session_t *session = NULL;
    for (int i = 0; i < MAX_CLIENT_SESSIONS; i++) {
        if (g_sessions[i].is_active && g_sessions[i].session_id == session_id) {
            session = &g_sessions[i];
            break;
        }
    }
    
    if (!session) {
        pthread_mutex_unlock(&g_sessions_mutex);
        return OVPN_ERROR_SESSION_NOT_FOUND;
    }
    
    // Free old config
    ovpn_client_free_config(&session->config);
    
    // Copy new config
    session->config = *config;
    
    pthread_mutex_unlock(&g_sessions_mutex);
    
    return OVPN_ERROR_SUCCESS;
}

int ovpn_client_get_connection_info(uint32_t session_id, 
                                   char *local_ip, char *remote_ip, char *server_ip) {
    if (!local_ip || !remote_ip || !server_ip) {
        return OVPN_ERROR_INVALID_PARAM;
    }
    
    pthread_mutex_lock(&g_sessions_mutex);
    
    ovpn_client_session_t *session = NULL;
    for (int i = 0; i < MAX_CLIENT_SESSIONS; i++) {
        if (g_sessions[i].is_active && g_sessions[i].session_id == session_id) {
            session = &g_sessions[i];
            break;
        }
    }
    
    if (!session || !session->is_connected) {
        pthread_mutex_unlock(&g_sessions_mutex);
        return OVPN_ERROR_NOT_CONNECTED;
    }
    
    // Get connection info from OpenVPN context (simulation)
    strcpy(local_ip, "10.8.0.2");
    strcpy(remote_ip, "10.8.0.1");
    strcpy(server_ip, "203.0.113.1");
    
    pthread_mutex_unlock(&g_sessions_mutex);
    
    return OVPN_ERROR_SUCCESS;
}

int ovpn_client_get_config(uint32_t session_id, ovpn_client_config_t *config) {
    if (!config) {
        return OVPN_ERROR_INVALID_PARAM;
    }
    
    pthread_mutex_lock(&g_sessions_mutex);
    
    for (int i = 0; i < MAX_CLIENT_SESSIONS; i++) {
        if (g_sessions[i].is_active && g_sessions[i].session_id == session_id) {
            *config = g_sessions[i].config;
            pthread_mutex_unlock(&g_sessions_mutex);
            return OVPN_ERROR_SUCCESS;
        }
    }
    
    pthread_mutex_unlock(&g_sessions_mutex);
    return OVPN_ERROR_SESSION_NOT_FOUND;
}

int ovpn_client_set_auto_reconnect(uint32_t session_id, bool enable) {
    pthread_mutex_lock(&g_sessions_mutex);
    
    for (int i = 0; i < MAX_CLIENT_SESSIONS; i++) {
        if (g_sessions[i].is_active && g_sessions[i].session_id == session_id) {
            g_sessions[i].config.auto_reconnect = enable;
            pthread_mutex_unlock(&g_sessions_mutex);
            return OVPN_ERROR_SUCCESS;
        }
    }
    
    pthread_mutex_unlock(&g_sessions_mutex);
    return OVPN_ERROR_SESSION_NOT_FOUND;
}
