
/*
 * Example usage of OpenVPN Client Integration API
 * Demonstrates multi-client session management with JSON configuration
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include "openvpn_client_api.h"

static bool running = true;
static uint32_t active_sessions[5];
static int session_count = 0;

// Signal handler for graceful shutdown
void signal_handler(int signum) {
    printf("Received signal %d, shutting down...\n", signum);
    running = false;
}

// Event callback function
void client_event_callback(const ovpn_client_event_t *event, void *user_data) {
    const char *session_name = (const char *)user_data;
    
    printf("[%s] Event: %s - %s (State: %s)\n",
           session_name,
           ovpn_client_event_type_to_string(event->type),
           event->message ? event->message : "No message",
           ovpn_client_state_to_string(event->state));
    
    // Handle specific events
    switch (event->type) {
        case CLIENT_EVENT_STATS_UPDATE:
            if (event->data) {
                ovpn_client_stats_t *stats = (ovpn_client_stats_t *)event->data;
                printf("  Stats: Sent: %lu bytes, Received: %lu bytes\n",
                       stats->bytes_sent, stats->bytes_received);
            }
            break;
            
        case CLIENT_EVENT_QUALITY_UPDATE:
            if (event->data) {
                ovpn_quality_metrics_t *quality = (ovpn_quality_metrics_t *)event->data;
                printf("  Quality: Ping: %u ms, Loss: %u%%, Jitter: %u ms\n",
                       quality->ping_ms, quality->packet_loss_pct, quality->jitter_ms);
            }
            break;
            
        case CLIENT_EVENT_LATENCY_UPDATE:
            if (event->data) {
                int *latency = (int *)event->data;
                printf("  Latency: %d ms\n", *latency);
            }
            break;
            
        default:
            break;
    }
}

// Example JSON configurations
const char *config_json_1 = 
"{"
"  \"profile_name\": \"Office VPN\","
"  \"ovpn_config\": \"client\\nremote vpn.company.com 1194\\nproto udp\\ndev tun\\nca ca.crt\\ncert client.crt\\nkey client.key\\nverb 3\","
"  \"auth\": {"
"    \"username\": \"john.doe\","
"    \"password\": \"secretpass123\""
"  },"
"  \"certificates\": {"
"    \"ca_path\": \"/etc/openvpn/ca.crt\","
"    \"cert_path\": \"/etc/openvpn/client.crt\","
"    \"key_path\": \"/etc/openvpn/client.key\""
"  },"
"  \"connection\": {"
"    \"auto_reconnect\": true,"
"    \"reconnect_interval\": 30,"
"    \"ping_interval\": 10,"
"    \"mtu_size\": 1500"
"  },"
"  \"settings\": {"
"    \"enable_compression\": true,"
"    \"log_verbose\": true,"
"    \"stats_interval\": 5"
"  }"
"}";

const char *config_json_2 = 
"{"
"  \"profile_name\": \"Home VPN\","
"  \"ovpn_config\": \"client\\nremote home.vpn.com 443\\nproto tcp\\ndev tun\\nauth-user-pass\\nverb 3\","
"  \"auth\": {"
"    \"username\": \"homeuser\","
"    \"password\": \"homepass456\""
"  },"
"  \"connection\": {"
"    \"auto_reconnect\": true,"
"    \"reconnect_interval\": 15,"
"    \"ping_interval\": 5"
"  },"
"  \"proxy\": {"
"    \"host\": \"proxy.company.com\","
"    \"port\": 8080,"
"    \"username\": \"proxyuser\","
"    \"password\": \"proxypass\""
"  },"
"  \"settings\": {"
"    \"enable_compression\": false,"
"    \"log_verbose\": false,"
"    \"stats_interval\": 10"
"  }"
"}";

void print_session_status(uint32_t session_id) {
    ovpn_client_state_t state = ovpn_client_get_state(session_id);
    ovpn_client_stats_t stats;
    ovpn_quality_metrics_t quality;
    
    printf("\n=== Session %u Status ===\n", session_id);
    printf("State: %s\n", ovpn_client_state_to_string(state));
    
    if (ovpn_client_get_stats(session_id, &stats) == OVPN_ERROR_SUCCESS) {
        printf("Statistics:\n");
        printf("  Bytes sent: %lu\n", stats.bytes_sent);
        printf("  Bytes received: %lu\n", stats.bytes_received);
        printf("  Packets sent: %lu\n", stats.packets_sent);
        printf("  Packets received: %lu\n", stats.packets_received);
        printf("  Connections: %u\n", stats.connection_count);
        printf("  Reconnections: %u\n", stats.reconnection_count);
        
        if (stats.connected_since > 0) {
            printf("  Connected since: %s", ctime(&stats.connected_since));
        }
    }
    
    if (ovpn_client_get_quality(session_id, &quality) == OVPN_ERROR_SUCCESS) {
        printf("Quality Metrics:\n");
        printf("  Ping: %u ms (avg: %u ms)\n", quality.ping_ms, quality.avg_ping_ms);
        printf("  Packet loss: %u%%\n", quality.packet_loss_pct);
        printf("  Jitter: %u ms\n", quality.jitter_ms);
        printf("  Upload bandwidth: %u kbps\n", quality.bandwidth_up_kbps);
        printf("  Download bandwidth: %u kbps\n", quality.bandwidth_down_kbps);
        printf("  Signal strength: %.2f\n", quality.signal_strength);
    }
    
    char local_ip[16], remote_ip[16], server_ip[16];
    if (ovpn_client_get_connection_info(session_id, local_ip, remote_ip, server_ip) == OVPN_ERROR_SUCCESS) {
        printf("Connection Info:\n");
        printf("  Local IP: %s\n", local_ip);
        printf("  Remote IP: %s\n", remote_ip);
        printf("  Server IP: %s\n", server_ip);
    }
}

void monitor_events() {
    printf("\n=== Event Monitoring ===\n");
    
    for (int i = 0; i < session_count; i++) {
        ovpn_client_event_t event;
        while (ovpn_client_get_next_event(active_sessions[i], &event)) {
            printf("Session %u Event: %s - %s\n",
                   event.session_id,
                   ovpn_client_event_type_to_string(event.type),
                   event.message ? event.message : "No message");
            
            // Free event message if allocated
            if (event.message) {
                free((void*)event.message);
            }
            if (event.data) {
                free(event.data);
            }
        }
    }
}

int main() {
    printf("OpenVPN Client API Example\n");
    printf("==========================\n");
    
    // Set up signal handlers
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    
    // Initialize the API
    int result = ovpn_client_api_init();
    if (result != OVPN_ERROR_SUCCESS) {
        printf("Failed to initialize OpenVPN client API: %d\n", result);
        return 1;
    }
    
    printf("OpenVPN Client API initialized successfully\n");
    
    // Parse configurations
    ovpn_client_config_t config1, config2;
    
    result = ovpn_client_parse_config_json(config_json_1, &config1);
    if (result != OVPN_ERROR_SUCCESS) {
        printf("Failed to parse config 1: %d\n", result);
        goto cleanup;
    }
    
    result = ovpn_client_parse_config_json(config_json_2, &config2);
    if (result != OVPN_ERROR_SUCCESS) {
        printf("Failed to parse config 2: %d\n", result);
        ovpn_client_free_config(&config1);
        goto cleanup;
    }
    
    printf("Configurations parsed successfully\n");
    
    // Create sessions
    uint32_t session1 = ovpn_client_create_session(&config1, client_event_callback, (void*)"Office");
    uint32_t session2 = ovpn_client_create_session(&config2, client_event_callback, (void*)"Home");
    
    if (session1 == 0 || session2 == 0) {
        printf("Failed to create sessions\n");
        goto cleanup;
    }
    
    active_sessions[0] = session1;
    active_sessions[1] = session2;
    session_count = 2;
    
    printf("Created sessions: %u, %u\n", session1, session2);
    
    // Connect sessions
    printf("\nConnecting sessions...\n");
    
    result = ovpn_client_connect(session1);
    if (result != OVPN_ERROR_SUCCESS) {
        printf("Failed to connect session 1: %d\n", result);
    }
    
    result = ovpn_client_connect(session2);
    if (result != OVPN_ERROR_SUCCESS) {
        printf("Failed to connect session 2: %d\n", result);
    }
    
    // Main monitoring loop
    printf("\nStarting monitoring loop (press Ctrl+C to exit)...\n");
    
    time_t last_status_print = time(NULL);
    time_t last_latency_test = time(NULL);
    
    while (running) {
        // Monitor events
        monitor_events();
        
        // Print status every 30 seconds
        time_t now = time(NULL);
        if (now - last_status_print >= 30) {
            for (int i = 0; i < session_count; i++) {
                print_session_status(active_sessions[i]);
            }
            last_status_print = now;
        }
        
        // Test latency every 60 seconds
        if (now - last_latency_test >= 60) {
            for (int i = 0; i < session_count; i++) {
                int latency = ovpn_client_test_latency(active_sessions[i]);
                if (latency >= 0) {
                    printf("Session %u latency: %d ms\n", active_sessions[i], latency);
                }
            }
            last_latency_test = now;
        }
        
        // Check session states
        for (int i = 0; i < session_count; i++) {
            ovpn_client_state_t state = ovpn_client_get_state(active_sessions[i]);
            if (state == CLIENT_STATE_ERROR) {
                printf("Session %u is in error state, attempting reconnect...\n", active_sessions[i]);
                ovpn_client_disconnect(active_sessions[i]);
                sleep(5);
                ovpn_client_connect(active_sessions[i]);
            }
        }
        
        sleep(1);
    }
    
    printf("\nShutting down...\n");
    
    // Disconnect and destroy sessions
    for (int i = 0; i < session_count; i++) {
        printf("Disconnecting session %u...\n", active_sessions[i]);
        ovpn_client_disconnect(active_sessions[i]);
        
        printf("Destroying session %u...\n", active_sessions[i]);
        ovpn_client_destroy_session(active_sessions[i]);
    }
    
    // List remaining sessions
    uint32_t remaining_sessions[MAX_CLIENT_SESSIONS];
    uint32_t count = ovpn_client_list_sessions(remaining_sessions, MAX_CLIENT_SESSIONS);
    printf("Remaining active sessions: %u\n", count);
    
cleanup:
    // Free configurations
    ovpn_client_free_config(&config1);
    ovpn_client_free_config(&config2);
    
    // Cleanup API
    ovpn_client_api_cleanup();
    
    printf("OpenVPN Client API example completed\n");
    return 0;
}
