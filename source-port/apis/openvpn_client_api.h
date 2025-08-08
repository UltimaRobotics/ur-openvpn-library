
/*
 * OpenVPN Client Integration API
 * Multi-client session management with real-time monitoring
 */

#ifndef OPENVPN_CLIENT_API_H
#define OPENVPN_CLIENT_API_H

#include <stdint.h>
#include <stdbool.h>
#include <time.h>
#include <pthread.h>
#include "cjson/cJSON.h"

#ifdef __cplusplus
extern "C" {
#endif

// Maximum number of concurrent client sessions
#define MAX_CLIENT_SESSIONS 64
#define MAX_CONFIG_SIZE 65536
#define MAX_LOG_ENTRIES 1000
#define MAX_EVENT_QUEUE_SIZE 256

// Client connection states
typedef enum {
    CLIENT_STATE_INITIAL = 0,
    CLIENT_STATE_CONNECTING = 1,
    CLIENT_STATE_WAIT = 2,
    CLIENT_STATE_AUTH = 3,
    CLIENT_STATE_GET_CONFIG = 4,
    CLIENT_STATE_ASSIGN_IP = 5,
    CLIENT_STATE_ADD_ROUTES = 6,
    CLIENT_STATE_CONNECTED = 7,
    CLIENT_STATE_RECONNECTING = 8,
    CLIENT_STATE_EXITING = 9,
    CLIENT_STATE_DISCONNECTED = 10,
    CLIENT_STATE_ERROR = 11
} ovpn_client_state_t;

// Client event types
typedef enum {
    CLIENT_EVENT_STATE_CHANGE = 0,
    CLIENT_EVENT_LOG_MESSAGE = 1,
    CLIENT_EVENT_STATS_UPDATE = 2,
    CLIENT_EVENT_ERROR = 3,
    CLIENT_EVENT_AUTH_REQUIRED = 4,
    CLIENT_EVENT_RECONNECT = 5,
    CLIENT_EVENT_LATENCY_UPDATE = 6,
    CLIENT_EVENT_QUALITY_UPDATE = 7,
    CLIENT_EVENT_BYTES_COUNT = 8,
    CLIENT_EVENT_ROUTE_UPDATE = 9
} ovpn_client_event_type_t;

// Network quality metrics
typedef struct {
    uint32_t ping_ms;           // Current ping in milliseconds
    uint32_t avg_ping_ms;       // Average ping over time window
    uint32_t packet_loss_pct;   // Packet loss percentage (0-100)
    uint32_t jitter_ms;         // Network jitter in milliseconds
    uint32_t bandwidth_up_kbps; // Upload bandwidth in Kbps
    uint32_t bandwidth_down_kbps; // Download bandwidth in Kbps
    float signal_strength;      // Signal strength (0.0-1.0)
    time_t last_updated;        // When these metrics were last updated
} ovpn_quality_metrics_t;

// Connection statistics
typedef struct {
    uint64_t bytes_sent;        // Total bytes sent
    uint64_t bytes_received;    // Total bytes received
    uint64_t packets_sent;      // Total packets sent
    uint64_t packets_received;  // Total packets received
    uint32_t connection_count;  // Number of connections made
    uint32_t reconnection_count; // Number of reconnections
    time_t connected_since;     // Time when connection was established
    time_t last_activity;       // Last time data was transferred
    uint32_t compression_ratio; // Compression ratio percentage
    uint32_t auth_failures;     // Number of authentication failures
} ovpn_client_stats_t;

// Client configuration from JSON
typedef struct {
    char *profile_name;         // Profile identifier
    char *ovpn_config;          // OpenVPN configuration content
    char *username;             // Authentication username
    char *password;             // Authentication password
    char *cert_path;            // Client certificate path
    char *key_path;             // Private key path
    char *ca_path;              // CA certificate path
    bool auto_reconnect;        // Enable automatic reconnection
    uint32_t reconnect_interval; // Reconnection interval in seconds
    uint32_t ping_interval;     // Ping interval for quality monitoring
    bool enable_compression;    // Enable data compression
    uint32_t mtu_size;          // MTU size
    char *proxy_host;           // Proxy hostname
    uint32_t proxy_port;        // Proxy port
    char *proxy_username;       // Proxy username
    char *proxy_password;       // Proxy password
    bool log_verbose;           // Enable verbose logging
    uint32_t stats_interval;    // Statistics update interval
} ovpn_client_config_t;

// Client event structure
typedef struct {
    uint32_t session_id;        // Client session identifier
    ovpn_client_event_type_t type; // Event type
    time_t timestamp;           // Event timestamp
    ovpn_client_state_t state;  // Current client state
    char *message;              // Event message
    void *data;                 // Additional event data
    size_t data_size;           // Size of additional data
} ovpn_client_event_t;

// Client session context
typedef struct {
    uint32_t session_id;        // Unique session identifier
    ovpn_client_config_t config; // Session configuration
    ovpn_client_state_t state;  // Current connection state
    ovpn_client_stats_t stats;  // Connection statistics
    ovpn_quality_metrics_t quality; // Network quality metrics
    
    // OpenVPN context pointers
    void *openvpn_context;      // OpenVPN context structure
    void *management_context;   // Management interface context
    
    // Threading and synchronization
    pthread_t worker_thread;    // Worker thread for this session
    pthread_mutex_t state_mutex; // State synchronization
    bool thread_running;        // Thread status flag
    
    // Event handling
    ovpn_client_event_t event_queue[MAX_EVENT_QUEUE_SIZE];
    uint32_t event_queue_head;
    uint32_t event_queue_tail;
    pthread_mutex_t event_mutex;
    
    // Status flags
    bool is_active;             // Session is active
    bool is_connected;          // Currently connected
    time_t created_at;          // Session creation time
    time_t last_ping;           // Last ping measurement time
    
    // Callback functions
    void (*event_callback)(const ovpn_client_event_t *event, void *user_data);
    void *user_data;            // User-provided callback data
} ovpn_client_session_t;

// Event callback function type
typedef void (*ovpn_event_callback_t)(const ovpn_client_event_t *event, void *user_data);

// API Functions

/**
 * Initialize the OpenVPN client API
 * @return 0 on success, negative error code on failure
 */
int ovpn_client_api_init(void);

/**
 * Cleanup the OpenVPN client API
 */
void ovpn_client_api_cleanup(void);

/**
 * Parse configuration from JSON
 * @param json_str JSON configuration string
 * @param config Output configuration structure
 * @return 0 on success, negative error code on failure
 */
int ovpn_client_parse_config_json(const char *json_str, ovpn_client_config_t *config);

/**
 * Create a new client session
 * @param config Client configuration
 * @param event_callback Event callback function
 * @param user_data User data for callback
 * @return Session ID on success, 0 on failure
 */
uint32_t ovpn_client_create_session(const ovpn_client_config_t *config,
                                   ovpn_event_callback_t event_callback,
                                   void *user_data);

/**
 * Start a client connection
 * @param session_id Session identifier
 * @return 0 on success, negative error code on failure
 */
int ovpn_client_connect(uint32_t session_id);

/**
 * Disconnect a client session
 * @param session_id Session identifier
 * @return 0 on success, negative error code on failure
 */
int ovpn_client_disconnect(uint32_t session_id);

/**
 * Destroy a client session
 * @param session_id Session identifier
 * @return 0 on success, negative error code on failure
 */
int ovpn_client_destroy_session(uint32_t session_id);

/**
 * Get client session state
 * @param session_id Session identifier
 * @return Current client state
 */
ovpn_client_state_t ovpn_client_get_state(uint32_t session_id);

/**
 * Get client session statistics
 * @param session_id Session identifier
 * @param stats Output statistics structure
 * @return 0 on success, negative error code on failure
 */
int ovpn_client_get_stats(uint32_t session_id, ovpn_client_stats_t *stats);

/**
 * Get client network quality metrics
 * @param session_id Session identifier
 * @param quality Output quality metrics structure
 * @return 0 on success, negative error code on failure
 */
int ovpn_client_get_quality(uint32_t session_id, ovpn_quality_metrics_t *quality);

/**
 * Get list of active sessions
 * @param session_ids Output array of session IDs
 * @param max_count Maximum number of sessions to return
 * @return Number of active sessions
 */
uint32_t ovpn_client_list_sessions(uint32_t *session_ids, uint32_t max_count);

/**
 * Send authentication credentials
 * @param session_id Session identifier
 * @param username Username
 * @param password Password
 * @return 0 on success, negative error code on failure
 */
int ovpn_client_send_auth(uint32_t session_id, const char *username, const char *password);

/**
 * Pause a client session
 * @param session_id Session identifier
 * @return 0 on success, negative error code on failure
 */
int ovpn_client_pause(uint32_t session_id);

/**
 * Resume a paused client session
 * @param session_id Session identifier
 * @return 0 on success, negative error code on failure
 */
int ovpn_client_resume(uint32_t session_id);

/**
 * Update client configuration
 * @param session_id Session identifier
 * @param config New configuration
 * @return 0 on success, negative error code on failure
 */
int ovpn_client_update_config(uint32_t session_id, const ovpn_client_config_t *config);

/**
 * Get client connection info
 * @param session_id Session identifier
 * @param local_ip Output local IP address
 * @param remote_ip Output remote IP address
 * @param server_ip Output server IP address
 * @return 0 on success, negative error code on failure
 */
int ovpn_client_get_connection_info(uint32_t session_id, 
                                   char *local_ip, char *remote_ip, char *server_ip);

/**
 * Perform network latency test
 * @param session_id Session identifier
 * @return Latency in milliseconds, -1 on error
 */
int ovpn_client_test_latency(uint32_t session_id);

/**
 * Get session configuration
 * @param session_id Session identifier
 * @param config Output configuration structure
 * @return 0 on success, negative error code on failure
 */
int ovpn_client_get_config(uint32_t session_id, ovpn_client_config_t *config);

/**
 * Enable/disable automatic reconnection
 * @param session_id Session identifier
 * @param enable Enable flag
 * @return 0 on success, negative error code on failure
 */
int ovpn_client_set_auto_reconnect(uint32_t session_id, bool enable);

/**
 * Get next event from event queue
 * @param session_id Session identifier
 * @param event Output event structure
 * @return true if event available, false if queue empty
 */
bool ovpn_client_get_next_event(uint32_t session_id, ovpn_client_event_t *event);

/**
 * Free configuration structure memory
 * @param config Configuration to free
 */
void ovpn_client_free_config(ovpn_client_config_t *config);

/**
 * Convert state enum to string
 * @param state Client state
 * @return String representation of state
 */
const char *ovpn_client_state_to_string(ovpn_client_state_t state);

/**
 * Convert event type to string
 * @param type Event type
 * @return String representation of event type
 */
const char *ovpn_client_event_type_to_string(ovpn_client_event_type_t type);

// Error codes
#define OVPN_ERROR_SUCCESS          0
#define OVPN_ERROR_INVALID_PARAM    -1
#define OVPN_ERROR_NO_MEMORY        -2
#define OVPN_ERROR_SESSION_LIMIT    -3
#define OVPN_ERROR_SESSION_NOT_FOUND -4
#define OVPN_ERROR_ALREADY_CONNECTED -5
#define OVPN_ERROR_NOT_CONNECTED    -6
#define OVPN_ERROR_CONFIG_INVALID   -7
#define OVPN_ERROR_AUTH_FAILED      -8
#define OVPN_ERROR_NETWORK_ERROR    -9
#define OVPN_ERROR_TIMEOUT          -10
#define OVPN_ERROR_THREAD_ERROR     -11
#define OVPN_ERROR_JSON_PARSE       -12

#ifdef __cplusplus
}
#endif

#endif // OPENVPN_CLIENT_API_H
