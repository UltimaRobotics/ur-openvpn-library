
/*
 * Example usage of OpenVPN Server Management API
 * Demonstrates comprehensive server-side VPN management
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include "openvpn_server_api.h"

static bool running = true;
static ovpn_server_context_t *server_ctx = NULL;

// Signal handler for graceful shutdown
void signal_handler(int signum) {
    printf("Received signal %d, shutting down server...\n", signum);
    running = false;
}

// Event callback function
void server_event_callback(const ovpn_server_event_t *event, void *user_data) {
    const char *context = (const char *)user_data;
    
    printf("[%s] Event: %s\n", context, ovpn_server_event_type_to_string(event->event_type));
    printf("  Time: %s", ctime(&event->timestamp));
    printf("  Client ID: %u\n", event->client_id);
    printf("  Message: %s\n", event->message);
    if (strlen(event->details) > 0) {
        printf("  Details: %s\n", event->details);
    }
    printf("\n");
}

// Example JSON configuration for OpenVPN server
const char *server_config_json = 
"{"
"  \"server_name\": \"Corporate VPN Server\","
"  \"listen_address\": \"0.0.0.0\","
"  \"listen_port\": 1194,"
"  \"protocol\": \"udp\","
"  \"device_type\": \"tun\","
"  \"server_subnet\": \"10.8.0.0/24\","
"  \"server_ipv6_subnet\": \"fd00:8::/64\","
"  \"certificates\": {"
"    \"ca_cert_path\": \"/etc/openvpn/ca.crt\","
"    \"server_cert_path\": \"/etc/openvpn/server.crt\","
"    \"server_key_path\": \"/etc/openvpn/server.key\","
"    \"dh_params_path\": \"/etc/openvpn/dh2048.pem\","
"    \"crl_path\": \"/etc/openvpn/crl.pem\""
"  },"
"  \"security\": {"
"    \"cipher\": \"AES-256-GCM\","
"    \"auth_digest\": \"SHA256\","
"    \"compression_enabled\": true,"
"    \"duplicate_cn_allowed\": false"
"  },"
"  \"client_config\": {"
"    \"max_clients\": 100,"
"    \"client_to_client\": false,"
"    \"push_routes\": true,"
"    \"dns_servers\": [\"8.8.8.8\", \"8.8.4.4\"],"
"    \"domain_name\": \"company.local\""
"  },"
"  \"management\": {"
"    \"address\": \"127.0.0.1\","
"    \"port\": 7505,"
"    \"password\": \"management_secret\""
"  },"
"  \"logging\": {"
"    \"log_file\": \"/var/log/openvpn/server.log\","
"    \"verbosity\": 3,"
"    \"append\": true"
"  },"
"  \"network\": {"
"    \"keepalive_ping\": 10,"
"    \"keepalive_timeout\": 120,"
"    \"mtu_size\": 1500,"
"    \"mssfix_enabled\": true"
"  }"
"}";

void print_server_status(ovpn_server_context_t *ctx) {
    ovpn_server_stats_t stats;
    if (ovpn_server_get_statistics(ctx, &stats) == 0) {
        printf("\n=== Server Status ===\n");
        printf("Total Clients: %u\n", stats.total_clients);
        printf("Active Clients: %u\n", stats.active_clients);
        printf("Connected Clients: %u\n", stats.connected_clients);
        printf("Revoked Clients: %u\n", stats.revoked_clients);
        printf("Total Bytes Sent: %llu\n", (unsigned long long)stats.total_bytes_sent);
        printf("Total Bytes Received: %llu\n", (unsigned long long)stats.total_bytes_received);
        printf("Server Uptime: %lu seconds\n", (unsigned long)stats.server_uptime);
        printf("Total Connections: %u\n", stats.total_connections);
        printf("Auth Failures: %u\n", stats.authentication_failures);
        printf("======================\n\n");
    }
}

void list_clients(ovpn_server_context_t *ctx) {
    ovpn_client_info_t *clients;
    uint32_t count;
    
    if (ovpn_server_list_clients(ctx, &clients, &count, true) == 0) {
        printf("\n=== Client List ===\n");
        for (uint32_t i = 0; i < count; i++) {
            printf("Client ID: %u\n", clients[i].client_id);
            printf("  Name: %s\n", clients[i].common_name);
            printf("  Email: %s\n", clients[i].email);
            printf("  Status: %s\n", clients[i].is_revoked ? "REVOKED" : 
                                   (clients[i].is_active ? "ACTIVE" : "INACTIVE"));
            printf("  Connected: %s\n", clients[i].currently_connected ? "YES" : "NO");
            
            if (clients[i].has_static_ip) {
                char ip_str[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, &clients[i].static_ip, ip_str, INET_ADDRSTRLEN);
                printf("  Static IP: %s\n", ip_str);
            }
            
            printf("  Created: %s", ctime(&clients[i].created_time));
            if (clients[i].is_revoked) {
                printf("  Revoked: %s", ctime(&clients[i].revoked_time));
                printf("  Reason: %s\n", clients[i].revocation_reason);
            }
            printf("  Routes: %d custom routes\n", clients[i].route_count);
            printf("\n");
        }
        printf("==================\n\n");
        
        ovpn_server_free_client_list(clients, count);
    }
}

void demonstrate_client_management(ovpn_server_context_t *ctx) {
    printf("Creating test clients...\n");
    
    // Create several test clients
    uint32_t client1 = ovpn_server_create_client(ctx, "john.doe", "john@company.com", 
                                                 "Engineering Department - John Doe");
    uint32_t client2 = ovpn_server_create_client(ctx, "jane.smith", "jane@company.com", 
                                                 "Marketing Department - Jane Smith");
    uint32_t client3 = ovpn_server_create_client(ctx, "bob.wilson", "bob@company.com", 
                                                 "IT Department - Bob Wilson");
    
    if (client1 && client2 && client3) {
        printf("Created clients: %u, %u, %u\n", client1, client2, client3);
        
        // Set static IP for client1
        ovpn_server_set_client_static_ip(ctx, client1, "10.8.0.100");
        
        // Add custom route for client2
        ovpn_server_add_client_route(ctx, client2, "192.168.1.0/24", "10.8.0.1", true);
        
        // Generate client configuration files
        ovpn_client_config_options_t options = {0};
        options.include_ca_cert = true;
        options.include_client_cert = true;
        options.include_client_key = true;
        options.use_inline_certs = true;
        options.redirect_gateway = true;
        strncpy(options.remote_host, "vpn.company.com", sizeof(options.remote_host) - 1);
        options.remote_port = 1194;
        strncpy(options.protocol, "udp", sizeof(options.protocol) - 1);
        
        printf("\nGenerating client configurations...\n");
        
        char *config1 = ovpn_server_generate_client_config(ctx, client1, &options);
        if (config1) {
            printf("Generated config for client %u (length: %zu bytes)\n", 
                   client1, strlen(config1));
            
            // Save to file
            char filename[256];
            snprintf(filename, sizeof(filename), "john.doe.ovpn");
            FILE *f = fopen(filename, "w");
            if (f) {
                fprintf(f, "%s", config1);
                fclose(f);
                printf("Saved configuration to %s\n", filename);
            }
            
            ovpn_server_free_config_string(config1);
        }
        
        // Demonstrate client revocation
        printf("\nRevoking client %u for testing...\n", client3);
        ovpn_server_revoke_client(ctx, client3, "Test revocation - user left company");
        
    } else {
        printf("Failed to create some clients\n");
    }
}

int main() {
    printf("OpenVPN Server Management API Example\n");
    printf("=====================================\n");
    
    // Set up signal handlers
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    
    // Initialize the server
    server_ctx = ovpn_server_init();
    if (!server_ctx) {
        printf("Failed to initialize OpenVPN server context\n");
        return 1;
    }
    
    printf("OpenVPN server context initialized\n");
    
    // Set up event callback
    ovpn_server_set_event_callback(server_ctx, server_event_callback, "ServerManager");
    
    // Load configuration from JSON
    int result = ovpn_server_load_config_json(server_ctx, server_config_json);
    if (result != 0) {
        printf("Failed to load server configuration: %d\n", result);
        ovpn_server_cleanup(server_ctx);
        return 1;
    }
    
    printf("Server configuration loaded successfully\n");
    
    // Start the server
    printf("Starting OpenVPN server...\n");
    result = ovpn_server_start(server_ctx);
    if (result != 0) {
        printf("Failed to start OpenVPN server: %d\n", result);
        ovpn_server_cleanup(server_ctx);
        return 1;
    }
    
    printf("OpenVPN server started successfully\n");
    
    // Wait a moment for server to fully initialize
    sleep(2);
    
    // Demonstrate client management
    demonstrate_client_management(server_ctx);
    
    // Main monitoring loop
    printf("\nServer is running. Monitoring status...\n");
    printf("Press Ctrl+C to stop the server.\n\n");
    
    int status_counter = 0;
    while (running) {
        sleep(5);
        status_counter++;
        
        // Print status every 30 seconds (6 * 5 seconds)
        if (status_counter % 6 == 0) {
            print_server_status(server_ctx);
        }
        
        // List clients every 60 seconds
        if (status_counter % 12 == 0) {
            list_clients(server_ctx);
        }
    }
    
    printf("\nShutting down server...\n");
    
    // Stop and cleanup
    ovpn_server_stop(server_ctx);
    ovpn_server_cleanup(server_ctx);
    
    printf("OpenVPN Server Management API example completed\n");
    return 0;
}
