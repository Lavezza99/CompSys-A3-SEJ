#include <stdlib.h>
#include <stdio.h>
#include <math.h>
#include <netdb.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <pthread.h>

#ifdef __APPLE__
#include "./endian.h"
#else
#include <endian.h>
#endif

#include "./peer.h"

// Global variables to be used by both the server and client side of the peer.
NetworkAddress_t *my_address;

NetworkAddress_t** network = NULL;
uint32_t peer_count = 0;

// Protects network and peer_count
pthread_mutex_t network_mutex = PTHREAD_MUTEX_INITIALIZER;

// Forward declaration of the per-connection handler thread
void* connection_handler(void *arg);

// We might later need a list of files currently being retrieved,
// but we can add that when we implement RETRIEVE.

// --- Helper: compute signature = SHA256(password || salt) ---
static void assemble_signature(const char *password, const char *salt, hashdata_t out) {
    // password: up to PASSWORD_LEN chars (may contain '\0' after scanf)
    // salt:     exactly SALT_LEN chars (not necessarily '\0'-terminated)

    char buffer[PASSWORD_LEN + SALT_LEN];

    // How many chars of password do we actually use?
    size_t pass_len = strnlen(password, PASSWORD_LEN);
    size_t salt_len = SALT_LEN;  // always use all salt bytes

    memcpy(buffer, password, pass_len);
    memcpy(buffer + pass_len, salt, salt_len);

    // Total length of data to hash
    uint32_t total_len = (uint32_t)(pass_len + salt_len);

    // Use helper from common.c
    get_data_sha(buffer, out, total_len, SHA256_HASH_SIZE);
}

// STATIC HELPER FUNCTIONS FOR REQUEST HANDLING
//
static void send_reply(int connfd, uint32_t status, uint32_t block_number,
                       uint32_t block_count, const void* data, uint32_t data_len,
                       const hashdata_t block_hash, const hashdata_t total_hash) {
    ReplyHeader_t header;
    memset(&header, 0, sizeof(header));

    header.length = htonl(data_len);
    header.status = htonl(status);
    header.this_block = htonl(block_number);
    header.block_count = htonl(block_count);

    if (block_hash) {
        memcpy(header.block_hash, block_hash, SHA256_HASH_SIZE);
    } else {
        get_data_sha("", header.block_hash, 0, SHA256_HASH_SIZE);
    }

    if (total_hash) {
        memcpy(header.total_hash, total_hash, SHA256_HASH_SIZE);
    } else {
        get_data_sha("", header.total_hash, 0, SHA256_HASH_SIZE);
    }

    // Send header
    ssize_t written = compsys_helper_writen(connfd, &header, REPLY_HEADER_LEN);
    if (written != REPLY_HEADER_LEN) {
        perror("Failed to write reply header");
        return;
    }

    // Send data if present
    if (data && data_len > 0) {
        written = compsys_helper_writen(connfd, (void*)data, data_len);
        if (written != (ssize_t)data_len) {
            perror("Failed to write reply data");
        }
    }

    // Debug
    printf("Sent reply: status=%u, block=%u/%u, data_len=%u\n",
           status, block_number, block_count, data_len);
}

//
static void send_error_reply(int connfd, uint32_t status, const char* message) {
    printf("Sending error reply: status=%u, message=%s\n", status, message);

    // Convert message to bytes
    size_t msg_len = strlen(message);
    char* msg_bytes = (char*)malloc(msg_len);
    if (msg_bytes) {
        memcpy(msg_bytes, message, msg_len);
        // For errors treat as single-block
        hashdata_t h;
        get_data_sha(msg_bytes, h, (uint32_t)msg_len, SHA256_HASH_SIZE);
        send_reply(connfd, status, 0, 1, msg_bytes, (uint32_t)msg_len, h, h);
        free(msg_bytes);
    } else {
        // Fallback: send empty reply with error status
        hashdata_t h;
        get_data_sha("", h, 0, SHA256_HASH_SIZE);
        send_reply(connfd, status, 0, 1, NULL, 0, h, h);
    }
}

//
static int find_peer_index(const char* ip, uint32_t port) {
    for (uint32_t i = 0; i < peer_count; i++) {
        if (network[i]->port == (int)port &&
            strncmp(network[i]->ip, ip, IP_LEN) == 0) {
            return (int)i;
        }
    }
    return -1;
}

//
static void send_inform_to_peer(const NetworkAddress_t *dest, const NetworkAddress_t *new_peer_info) {
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        perror("socket (INFORM)");
        return;
    }

    struct sockaddr_in servaddr;
    memset(&servaddr, 0, sizeof(servaddr));
    servaddr.sin_family = AF_INET;
    servaddr.sin_port = htons((uint16_t)dest->port);

    if (inet_pton(AF_INET, dest->ip, &servaddr.sin_addr) <= 0) {
        fprintf(stderr, "Invalid peer IP address (INFORM): %s\n", dest->ip);
        close(sockfd);
        return;
    }

    if (connect(sockfd, (struct sockaddr*)&servaddr, sizeof(servaddr)) < 0) {
        // Non-fatal: remote peer may be down
        // Don't perror repeatedly
        // perror("connect (INFORM)");
        close(sockfd);
        return;
    }

    // Build request header
    char header[REQUEST_HEADER_LEN];
    memset(header, 0, sizeof(header));

    // IP (16 bytes)
    size_t ip_len = strnlen(my_address->ip, IP_LEN);
    memcpy(header, my_address->ip, ip_len);

    // Port
    uint32_t port_net = htonl((uint32_t)my_address->port);
    memcpy(header + IP_LEN, &port_net, sizeof(port_net));

    // Signature
    memcpy(header + IP_LEN + PORT_LEN, my_address->signature, SHA256_HASH_SIZE);

    // Command = INFORM
    uint32_t cmd_net = htonl((uint32_t)COMMAND_INFORM);
    memcpy(header + IP_LEN + PORT_LEN + SHA256_HASH_SIZE, &cmd_net, sizeof(cmd_net));

    // Body length = PEER_ADDR_LEN
    uint32_t bodylen_net = htonl((uint32_t)PEER_ADDR_LEN);
    memcpy(header + IP_LEN + PORT_LEN + SHA256_HASH_SIZE + LEN_COMMAND_LENGTH, &bodylen_net, sizeof(bodylen_net));

    // Send header
    ssize_t written = compsys_helper_writen(sockfd, header, REQUEST_HEADER_LEN);
    if (written != REQUEST_HEADER_LEN) {
        // perror("compsys_helper_writen (INFORM header)");
        close(sockfd);
        return;
    }

    // Build body: 16 bytes IP, 4 bytes port (network order), 32 bytes signature, 16 bytes salt
    char body[PEER_ADDR_LEN];
    memset(body, 0, sizeof(body));
    memcpy(body, new_peer_info->ip, IP_LEN);
    uint32_t newport_net = htonl((uint32_t)new_peer_info->port);
    memcpy(body + IP_LEN, &newport_net, sizeof(newport_net));
    memcpy(body + IP_LEN + PORT_LEN, new_peer_info->signature, SHA256_HASH_SIZE);
    memcpy(body + IP_LEN + PORT_LEN + SHA256_HASH_SIZE, new_peer_info->salt, SALT_LEN);

    // Send body
    written = compsys_helper_writen(sockfd, body, PEER_ADDR_LEN);
    // We don't expect a reply to INFORM
    close(sockfd);
}

//
static void handle_register_request(int connfd, const char* sender_ip, uint32_t sender_port,
                                   const hashdata_t sender_signature, const char* body, uint32_t body_len) {
    (void)body;
    (void)body_len;

    printf("REGISTER from %s:%u\n", sender_ip, sender_port);

    // Lock network while checking/adding
    pthread_mutex_lock(&network_mutex);

    // Check if peer already exists (by ip+port)
    int existing_idx = find_peer_index(sender_ip, sender_port);

    if (existing_idx >= 0) {
        // Peer exists: verify password (signature) matches
        // saved_signature == SHA256( client_signature || saved_salt )
        hashdata_t rehashed;
        char combined[SHA256_HASH_SIZE + SALT_LEN];
        memcpy(combined, sender_signature, SHA256_HASH_SIZE);
        memcpy(combined + SHA256_HASH_SIZE, network[existing_idx]->salt, SALT_LEN);
        get_data_sha(combined, rehashed, SHA256_HASH_SIZE + SALT_LEN, SHA256_HASH_SIZE);

        if (memcmp(rehashed, network[existing_idx]->signature, SHA256_HASH_SIZE) != 0) {
            pthread_mutex_unlock(&network_mutex);
            send_error_reply(connfd, STATUS_BAD_PASSWORD, "Password mismatch");
            return;
        } else {
            // Peer registering again but same credentials -> send PEER_EXISTS (status 2)
            pthread_mutex_unlock(&network_mutex);
            send_error_reply(connfd, STATUS_PEER_EXISTS, "Peer already registered");
            return;
        }
    }

    // Generate salt for the new peer
    char salt[SALT_LEN];
    generate_random_salt(salt);

    // Calculate saveable signature (SHA256(sender_signature || salt))
    hashdata_t saveable_sig;
    char combined[SHA256_HASH_SIZE + SALT_LEN];

    memcpy(combined, sender_signature, SHA256_HASH_SIZE);
    memcpy(combined + SHA256_HASH_SIZE, salt, SALT_LEN);

    get_data_sha(combined, saveable_sig,
                SHA256_HASH_SIZE + SALT_LEN, SHA256_HASH_SIZE);

    // Add peer to network
    NetworkAddress_t* new_peer = (NetworkAddress_t*)malloc(sizeof(NetworkAddress_t));
    if (!new_peer) {
        pthread_mutex_unlock(&network_mutex);
        send_error_reply(connfd, STATUS_OTHER, "Memory allocation failed");
        return;
    }
    memset(new_peer, 0, sizeof(NetworkAddress_t));
    strncpy(new_peer->ip, sender_ip, IP_LEN);
    new_peer->ip[IP_LEN-1] = '\0';
    new_peer->port = sender_port;
    memcpy(new_peer->signature, saveable_sig, SHA256_HASH_SIZE);
    memcpy(new_peer->salt, salt, SALT_LEN);

    NetworkAddress_t** new_network = (NetworkAddress_t**)realloc(network,
                                        (peer_count + 1) * sizeof(NetworkAddress_t*));
    if (!new_network) {
        free(new_peer);
        pthread_mutex_unlock(&network_mutex);
        send_error_reply(connfd, STATUS_OTHER, "Memory allocation failed");
        return;
    }

    network = new_network;
    network[peer_count] = new_peer;
    peer_count++;

    printf("Registered new peer: %s:%u. Total peers in network: %u\n", sender_ip, sender_port, peer_count);

    // Prepare response body: list of peers excluding the newly added peer
    uint32_t peers_to_send = 0;
    for (uint32_t i = 0; i < peer_count; i++) {
        if (network[i]->port == new_peer->port &&
            strncmp(network[i]->ip, new_peer->ip, IP_LEN) == 0) {
            continue;
        }
        peers_to_send++;
    }

    uint32_t response_size = peers_to_send * PEER_ADDR_LEN;
    char* response_data = NULL;
    if (response_size > 0) {
        response_data = (char*)malloc(response_size);
        if (!response_data) {
            pthread_mutex_unlock(&network_mutex);
            send_error_reply(connfd, STATUS_OTHER, "Memory allocation failed");
            return;
        }

        char* current_pos = response_data;
        for (uint32_t i = 0; i < peer_count; i++) {
            if (network[i]->port == new_peer->port &&
                strncmp(network[i]->ip, new_peer->ip, IP_LEN) == 0) {
                continue;
            }
            // IP
            strncpy(current_pos, network[i]->ip, IP_LEN);
            current_pos += IP_LEN;
            // Port
            uint32_t port_net = htonl(network[i]->port);
            memcpy(current_pos, &port_net, sizeof(port_net));
            current_pos += sizeof(port_net);
            // Signature
            memcpy(current_pos, network[i]->signature, SHA256_HASH_SIZE);
            current_pos += SHA256_HASH_SIZE;
            // Salt
            memcpy(current_pos, network[i]->salt, SALT_LEN);
            current_pos += SALT_LEN;
        }
    }

    // Unlock before sending replies and broadcasting
    pthread_mutex_unlock(&network_mutex);

    // Send OK reply with peer list (as a single block)
    hashdata_t body_hash;
    if (response_size > 0)
        get_data_sha(response_data, body_hash, response_size, SHA256_HASH_SIZE);
    else
        get_data_sha("", body_hash, 0, SHA256_HASH_SIZE);

    send_reply(connfd, STATUS_OK, 0, 1, response_data, response_size, body_hash, body_hash);
    if (response_data) free(response_data);

    // INFORM-broadcast the new peer to all other peers (best-effort)
    pthread_mutex_lock(&network_mutex);
    for (uint32_t i = 0; i < peer_count; i++) {
        // Skip the new peer itself and ourselves
        if (network[i]->port == new_peer->port &&
            strncmp(network[i]->ip, new_peer->ip, IP_LEN) == 0) {
            continue;
        }
        if (network[i]->port == my_address->port &&
            strncmp(network[i]->ip, my_address->ip, IP_LEN) == 0) {
            continue;
        }
        // Fire-and-forget (could be threaded; kept simple)
        send_inform_to_peer(network[i], new_peer);
    }
    pthread_mutex_unlock(&network_mutex);

    printf("Registration successful for %s:%u\n", sender_ip, sender_port);
}

//
static void handle_retrieve_request(int connfd, const char* sender_ip, uint32_t sender_port,
                                   const hashdata_t sender_signature, const char* body, uint32_t body_len) {
    printf("RETRIEVE from %s:%u\n", sender_ip, sender_port);

    if (body_len == 0 || body == NULL) {
        send_error_reply(connfd, STATUS_MALFORMED, "Empty RETRIEVE request");
        return;
    }

    // Verify peer is registered
    pthread_mutex_lock(&network_mutex);
    int idx = find_peer_index(sender_ip, sender_port);
    if (idx < 0) {
        pthread_mutex_unlock(&network_mutex);
        send_error_reply(connfd, STATUS_PEER_MISSING, "Peer not registered");
        return;
    }

    // Verify signature: saved_signature == SHA256(sender_signature || saved_salt)
    hashdata_t rehashed;
    char comb[SHA256_HASH_SIZE + SALT_LEN];
    memcpy(comb, sender_signature, SHA256_HASH_SIZE);
    memcpy(comb + SHA256_HASH_SIZE, network[idx]->salt, SALT_LEN);
    get_data_sha(comb, rehashed, SHA256_HASH_SIZE + SALT_LEN, SHA256_HASH_SIZE);

    if (memcmp(rehashed, network[idx]->signature, SHA256_HASH_SIZE) != 0) {
        pthread_mutex_unlock(&network_mutex);
        send_error_reply(connfd, STATUS_BAD_PASSWORD, "Password mismatch");
        return;
    }
    pthread_mutex_unlock(&network_mutex);

    // Filnavnet kommer som rå bytes i body (uden '\0')
    // Vi laver en kopi med '\0' til fopen.
    char filename[512];
    if (body_len >= sizeof(filename)) {
        send_error_reply(connfd, STATUS_MALFORMED, "Filename too long");
        return;
    }

    memcpy(filename, body, body_len);
    filename[body_len] = '\0';

    printf("RETRIEVE requested filename: '%s'\n", filename);

    // Forsøg at åbne filen (fra nuværende directory)
    FILE *f = fopen(filename, "rb");
    if (!f) {
        perror("fopen (RETRIEVE)");
        send_error_reply(connfd, STATUS_BAD_REQUEST, "File not found");
        return;
    }

    // Find filstørrelse
    if (fseek(f, 0, SEEK_END) != 0) {
        perror("fseek");
        fclose(f);
        send_error_reply(connfd, STATUS_OTHER, "Failed to read file");
        return;
    }

    long fsize = ftell(f);
    if (fsize < 0) {
        perror("ftell");
        fclose(f);
        send_error_reply(connfd, STATUS_OTHER, "Failed to read file size");
        return;
    }
    rewind(f);

    if (fsize == 0) {
        // Tom fil – send bare en OK med tom body (single block)
        fclose(f);
        hashdata_t empty_hash;
        get_data_sha("", empty_hash, 0, SHA256_HASH_SIZE);
        send_reply(connfd, STATUS_OK, 0, 1, NULL, 0, empty_hash, empty_hash);
        return;
    }

    // Læs hele filen i memory (for at lave total-hash). Hvis fil er for stor, vi kan stadig streame.
    // Her antager vi at memory er tilgængelig (typisk ok). Alternativt kan man beregne total-hash ved streaming.
    char *filebuf = (char*)malloc((size_t)fsize);
    if (!filebuf) {
        fclose(f);
        send_error_reply(connfd, STATUS_OTHER, "Memory allocation failed");
        return;
    }

    size_t read_bytes = fread(filebuf, 1, (size_t)fsize, f);
    fclose(f);

    if (read_bytes != (size_t)fsize) {
        free(filebuf);
        send_error_reply(connfd, STATUS_OTHER, "Failed to read entire file");
        return;
    }

    // Compute total hash
    hashdata_t total_hash;
    get_data_sha(filebuf, total_hash, (uint32_t)fsize, SHA256_HASH_SIZE);

    // Determine chunk size: messages limited to MAX_MSG_LEN including header
    uint32_t max_body_per_msg = MAX_MSG_LEN - REPLY_HEADER_LEN;
    if (max_body_per_msg == 0) {
        free(filebuf);
        send_error_reply(connfd, STATUS_OTHER, "Max message size configuration error");
        return;
    }

    uint32_t block_count = (uint32_t)((fsize + max_body_per_msg - 1) / max_body_per_msg);

    // Send each block
    for (uint32_t block = 0; block < block_count; block++) {
        uint32_t offset = block * max_body_per_msg;
        uint32_t to_send = (uint32_t)fsize - offset;
        if (to_send > max_body_per_msg) to_send = max_body_per_msg;

        hashdata_t block_hash;
        get_data_sha(filebuf + offset, block_hash, to_send, SHA256_HASH_SIZE);

        send_reply(connfd, STATUS_OK, block, block_count, filebuf + offset, to_send, block_hash, total_hash);
    }

    free(filebuf);
    printf("RETRIEVE: sent file '%s' in %u blocks\n", filename, block_count);
}

//
static void handle_inform_request(int connfd, const char* sender_ip, uint32_t sender_port,
                                 const hashdata_t sender_signature, const char* body, uint32_t body_len) {
    (void)connfd;
    (void)sender_signature;

    printf("INFORM from %s:%u - Basic implementation\n", sender_ip, sender_port);

    // INFORM doesn't expect a reply according to protocol
    // Just parse the body and add the peer to our network

    if (body_len != PEER_ADDR_LEN) {
        fprintf(stderr, "INFORM message has wrong size: %u (expected %d)\n", body_len, PEER_ADDR_LEN);
        return;
    }

    // Parse the inform message (68 bytes: IP + port + signature + salt)
    char new_ip[IP_LEN];
    uint32_t new_port_net, new_port;
    hashdata_t new_signature;
    char new_salt[SALT_LEN];

    memcpy(new_ip, body, IP_LEN);
    new_ip[IP_LEN - 1] = '\0';

    memcpy(&new_port_net, body + IP_LEN, sizeof(new_port_net));
    new_port = ntohl(new_port_net);

    memcpy(new_signature, body + IP_LEN + PORT_LEN, SHA256_HASH_SIZE);
    memcpy(new_salt, body + IP_LEN + PORT_LEN + SHA256_HASH_SIZE, SALT_LEN);

    char new_address[50];
    snprintf(new_address, sizeof(new_address), "%s:%u", new_ip, new_port);

    pthread_mutex_lock(&network_mutex);

    // Check if peer already exists
    int peer_exists = 0;
    for (uint32_t i = 0; i < peer_count; i++) {
        char existing_address[50];
        snprintf(existing_address, sizeof(existing_address), "%s:%d",
                 network[i]->ip, network[i]->port);
        if (strcmp(new_address, existing_address) == 0) {
            peer_exists = 1;
            break;
        }
    }

    if (!peer_exists) {
        // Add new peer to network
        NetworkAddress_t* new_peer = (NetworkAddress_t*)malloc(sizeof(NetworkAddress_t));
        if (!new_peer) {
            fprintf(stderr, "Failed to allocate new peer in INFORM\n");
            pthread_mutex_unlock(&network_mutex);
            return;
        }
        memset(new_peer, 0, sizeof(NetworkAddress_t));
        strncpy(new_peer->ip, new_ip, IP_LEN);
        new_peer->ip[IP_LEN-1] = '\0';
        new_peer->port = new_port;
        memcpy(new_peer->signature, new_signature, SHA256_HASH_SIZE);
        memcpy(new_peer->salt, new_salt, SALT_LEN);

        NetworkAddress_t** new_network = (NetworkAddress_t**)realloc(network,
                                            (peer_count + 1) * sizeof(NetworkAddress_t*));
        if (new_network) {
            network = new_network;
            network[peer_count] = new_peer;
            peer_count++;
            printf("Added peer from INFORM: %s:%u\n", new_ip, new_port);
        } else {
            free(new_peer);
            fprintf(stderr, "Failed to allocate memory for new peer\n");
        }
    }

    pthread_mutex_unlock(&network_mutex);
}

// Forward declarations of new helpers
static int perform_register(const NetworkAddress_t *peer_address);
static void update_network_from_register_response(const char *body, uint32_t body_len);

// New helpers for RETRIEVE
static int pick_random_peer(NetworkAddress_t *out_peer);
static int perform_retrieve(const NetworkAddress_t *peer_address, const char *filepath);

// Pick a random peer from the global network (excluding ourselves).
// Returns 0 on success and writes result into out_peer.
// Returns -1 if no suitable peer exists.
static int pick_random_peer(NetworkAddress_t *out_peer) {
    pthread_mutex_lock(&network_mutex);

    if (peer_count == 0) {
        pthread_mutex_unlock(&network_mutex);
        return -1;
    }

    // Collect candidates that are not ourselves
    uint32_t candidates = 0;
    uint32_t indices[peer_count ? peer_count : 1];

    for (uint32_t i = 0; i < peer_count; i++) {
        if (network[i]->port == my_address->port &&
            strncmp(network[i]->ip, my_address->ip, IP_LEN) == 0) {
            continue; // skip ourselves
        }
        indices[candidates++] = i;
    }

    if (candidates == 0) {
        pthread_mutex_unlock(&network_mutex);
        return -1;
    }

    uint32_t chosen = indices[rand() % candidates];
    memcpy(out_peer, network[chosen], sizeof(NetworkAddress_t));

    pthread_mutex_unlock(&network_mutex);
    return 0;
}

//
void* client_thread() {
    char peer_ip[IP_LEN];
    fprintf(stdout, "Enter peer IP to connect to: ");
    scanf("%16s", peer_ip);

    // Clean up IP string
    for (int i = (int)strlen(peer_ip); i < IP_LEN; i++) {
        peer_ip[i] = '\0';
    }

    char peer_port[PORT_STR_LEN];
    fprintf(stdout, "Enter peer port to connect to: ");
    scanf("%16s", peer_port);

    // Clean up port string
    for (int i = (int)strlen(peer_port); i < PORT_STR_LEN; i++) {
        peer_port[i] = '\0';
    }

    NetworkAddress_t peer_address;
    memset(&peer_address, 0, sizeof(NetworkAddress_t));
    memcpy(peer_address.ip, peer_ip, IP_LEN);
    peer_address.port = atoi(peer_port);

    // --- REGISTER med den angivne peer ---
    if (perform_register(&peer_address) == 0) {
        fprintf(stdout,
                "REGISTER succeeded with %s:%d. Known peers now: %u\n",
                peer_address.ip, peer_address.port, peer_count);
    } else {
        fprintf(stderr,
                "REGISTER failed with %s:%d\n",
                peer_address.ip, peer_address.port);
        printf("Client thread done\n");
        return NULL;
    }

    // --- Enkel RETRIEVE-loop (kan ændres senere) ---
    while (1) {
        char filepath[256];

        fprintf(stdout, "Enter file path to RETRIEVE (or 'quit' to exit): ");
        if (scanf("%255s", filepath) != 1) {
            break;
        }

        if (strcmp(filepath, "quit") == 0) {
            break;
        }

        NetworkAddress_t target;
        if (pick_random_peer(&target) != 0) {
            fprintf(stderr, "No other peers available to retrieve from.\n");
            continue;
        }

        if (perform_retrieve(&target, filepath) == 0) {
            fprintf(stdout,
                    "RETRIEVE from %s:%d succeeded for '%s'\n",
                    target.ip, target.port, filepath);
        } else {
            fprintf(stderr,
                    "RETRIEVE from %s:%d failed for '%s'\n",
                    target.ip, target.port, filepath);
        }
    }

    printf("Client thread done\n");
    return NULL;
}

//
void* server_thread() {
    char port_str[PORT_STR_LEN];

    // Convert our numeric port to a string for compsys_helper_open_listenfd
    snprintf(port_str, PORT_STR_LEN, "%u", my_address->port);

    int listenfd = compsys_helper_open_listenfd(port_str);
    if (listenfd < 0) {
        perror("compsys_helper_open_listenfd");
        // If we can't listen, the server can't run – exit the thread.
        return NULL;
    }

    fprintf(stdout, "Listening on %s:%u\n", my_address->ip, my_address->port);

    while (1) {
        struct sockaddr_storage clientaddr;
        socklen_t clientlen = sizeof(clientaddr);

        int connfd = accept(listenfd, (struct sockaddr*)&clientaddr, &clientlen);
        if (connfd < 0) {
            perror("accept");
            continue; // try again
        }

        // Allocate space for the fd to pass to the handler thread
        int *connfdp = (int*)malloc(sizeof(int));
        if (connfdp == NULL) {
            perror("malloc");
            close(connfd);
            continue;
        }
        *connfdp = connfd;

        pthread_t tid;
        int rc = pthread_create(&tid, NULL, connection_handler, connfdp);
        if (rc != 0) {
            fprintf(stderr, "pthread_create failed: %s\n", strerror(rc));
            close(connfd);
            free(connfdp);
            continue;
        }

        // We don't need to join these handler threads; let them clean up themselves.
        pthread_detach(tid);
    }

    close(listenfd);
    return NULL;
}

//
void* connection_handler(void* arg) {
    int connfd = *(int*)arg;
    free(arg);

    char header_buffer[REQUEST_HEADER_LEN];
    ssize_t n = compsys_helper_readn(connfd, header_buffer, REQUEST_HEADER_LEN);

    if (n != REQUEST_HEADER_LEN) {
        fprintf(stderr, "Failed to read complete header (got %zd bytes, expected %d)\n", n, REQUEST_HEADER_LEN);
        close(connfd);
        return NULL;
    }

    // Parse request header
    char sender_ip[IP_LEN];
    uint32_t sender_port_net, sender_port;
    hashdata_t sender_signature;
    uint32_t command_net, command;
    uint32_t body_len_net, body_len;

    // Extract fields from header buffer
    memcpy(sender_ip, header_buffer, IP_LEN);
    sender_ip[IP_LEN - 1] = '\0'; // Ensure null-termination

    memcpy(&sender_port_net, header_buffer + IP_LEN, sizeof(sender_port_net));
    sender_port = ntohl(sender_port_net);

    memcpy(sender_signature, header_buffer + IP_LEN + PORT_LEN, SHA256_HASH_SIZE);

    memcpy(&command_net, header_buffer + IP_LEN + PORT_LEN + SHA256_HASH_SIZE, sizeof(command_net));
    command = ntohl(command_net);

    memcpy(&body_len_net, header_buffer + IP_LEN + PORT_LEN + SHA256_HASH_SIZE + LEN_COMMAND_LENGTH, sizeof(body_len_net));
    body_len = ntohl(body_len_net);

    // Debug output
    printf("Incoming request: IP=%s, port=%u, command=%u, body_len=%u\n",
           sender_ip, sender_port, command, body_len);

    // Read request body if present
    char* body = NULL;
    if (body_len > 0) {
        if (body_len > MAX_MSG_LEN - REQUEST_HEADER_LEN) {
            fprintf(stderr, "Body too large: %u bytes\n", body_len);
            send_error_reply(connfd, STATUS_MALFORMED, "Request body too large");
            close(connfd);
            return NULL;
        }

        body = (char*)malloc(body_len);
        if (!body) {
            perror("malloc for body failed");
            send_error_reply(connfd, STATUS_OTHER, "Memory allocation failed");
            close(connfd);
            return NULL;
        }

        n = compsys_helper_readn(connfd, body, body_len);
        if (n != (ssize_t)body_len) {
            fprintf(stderr, "Failed to read complete body (got %zd bytes, expected %u)\n", n, body_len);
            free(body);
            send_error_reply(connfd, STATUS_MALFORMED, "Incomplete body received");
            close(connfd);
            return NULL;
        }
    }

    // Dispatch based on command
    int handled = 0;
    switch (command) {
        case COMMAND_REGISTER:
            printf("Handling REGISTER request from %s:%u\n", sender_ip, sender_port);
            handle_register_request(connfd, sender_ip, sender_port, sender_signature, body, body_len);
            handled = 1;
            break;

        case COMMAND_RETREIVE:
            printf("Handling RETRIEVE request from %s:%u\n", sender_ip, sender_port);
            handle_retrieve_request(connfd, sender_ip, sender_port, sender_signature, body, body_len);
            handled = 1;
            break;

        case COMMAND_INFORM:
            printf("Handling INFORM request from %s:%u\n", sender_ip, sender_port);
            handle_inform_request(connfd, sender_ip, sender_port, sender_signature, body, body_len);
            handled = 1;
            break;

        default:
            fprintf(stderr, "Unknown command: %u\n", command);
            send_error_reply(connfd, STATUS_MALFORMED, "Unknown command");
            handled = 1;
            break;
    }

    if (!handled) {
        send_error_reply(connfd, STATUS_OTHER, "Request not handled");
    }

    if (body) {
        free(body);
    }

    close(connfd);
    return NULL;
}


// ---------------------------------------------------------------------------
//  Client-side REGISTER implementation (Task 2.1 core)
// ---------------------------------------------------------------------------

static int perform_register(const NetworkAddress_t *peer_address) {
    // 1) Open a TCP connection to peer_address
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        perror("socket");
        return -1;
    }

    struct sockaddr_in servaddr;
    memset(&servaddr, 0, sizeof(servaddr));
    servaddr.sin_family = AF_INET;
    servaddr.sin_port = htons((uint16_t)peer_address->port);

    if (inet_pton(AF_INET, peer_address->ip, &servaddr.sin_addr) <= 0) {
        fprintf(stderr, "Invalid peer IP address: %s\n", peer_address->ip);
        close(sockfd);
        return -1;
    }

    if (connect(sockfd, (struct sockaddr*)&servaddr, sizeof(servaddr)) < 0) {
        perror("connect");
        close(sockfd);
        return -1;
    }

    // 2) Build REGISTER request header (command code 1, no body)
    char header[REQUEST_HEADER_LEN];
    memset(header, 0, sizeof(header));

    // IP (16 bytes, UTF-8, zero-padded)
    size_t ip_len = strnlen(my_address->ip, IP_LEN);
    memcpy(header, my_address->ip, ip_len);

    // Port (4 bytes, network byte-order)
    uint32_t port_net = htonl((uint32_t)my_address->port);
    memcpy(header + IP_LEN, &port_net, sizeof(port_net));

    // Signature (32 bytes)
    memcpy(header + IP_LEN + PORT_LEN, my_address->signature, SHA256_HASH_SIZE);

    // Command = COMMAND_REGISTER
    uint32_t cmd_net = htonl((uint32_t)COMMAND_REGISTER);
    memcpy(header + IP_LEN + PORT_LEN + SHA256_HASH_SIZE, &cmd_net, sizeof(cmd_net));

    // Body length = 0
    uint32_t bodylen_net = htonl(0u);
    memcpy(header + IP_LEN + PORT_LEN + SHA256_HASH_SIZE + LEN_COMMAND_LENGTH, &bodylen_net, sizeof(bodylen_net));

    // Send header (no body)
    ssize_t written = compsys_helper_writen(sockfd, header, REQUEST_HEADER_LEN);
    if (written != REQUEST_HEADER_LEN) {
        perror("compsys_helper_writen (REGISTER header)");
        close(sockfd);
        return -1;
    }

    // 3) Read response header
    unsigned char resp_hdr[REPLY_HEADER_LEN];
    ssize_t read_bytes = compsys_helper_readn(sockfd, resp_hdr, REPLY_HEADER_LEN);
    if (read_bytes != REPLY_HEADER_LEN) {
        perror("compsys_helper_readn (response header)");
        close(sockfd);
        return -1;
    }

    uint32_t resp_body_len_net;
    uint32_t status_net;
    uint32_t block_num_net;
    uint32_t block_count_net;

    memcpy(&resp_body_len_net, resp_hdr + 0, 4);
    memcpy(&status_net,        resp_hdr + 4, 4);
    memcpy(&block_num_net,     resp_hdr + 8, 4);
    memcpy(&block_count_net,   resp_hdr + 12, 4);

    uint32_t resp_body_len = ntohl(resp_body_len_net);
    uint32_t status         = ntohl(status_net);
    uint32_t block_num      = ntohl(block_num_net);
    uint32_t block_count    = ntohl(block_count_net);

    // NOTE: We ignore the two SHA256 hashes for now (indices 16..79).
    if (status != STATUS_OK) {
        fprintf(stderr, "REGISTER failed, status code = %u\n", status);
        if (resp_body_len > 0) {
            char *dummy = (char*)malloc(resp_body_len);
            if (dummy) {
                compsys_helper_readn(sockfd, dummy, resp_body_len);
                free(dummy);
            }
        }
        close(sockfd);
        return -1;
    }

    // For now, we only properly handle single-block responses.
    if (block_count != 1 || block_num != 0) {
        fprintf(stderr,
                "Multi-block REGISTER response not yet supported "
                "(block_num=%u, block_count=%u)\n",
                block_num, block_count);
        if (resp_body_len > 0) {
            char *dummy = (char*)malloc(resp_body_len);
            if (dummy) {
                compsys_helper_readn(sockfd, dummy, resp_body_len);
                free(dummy);
            }
        }
        close(sockfd);
        return -1;
    }

    // 4) Read response body (list of peers), if any
    if (resp_body_len == 0) {
        close(sockfd);
        return 0;
    }

    char *body = (char*)malloc(resp_body_len);
    if (body == NULL) {
        fprintf(stderr, "malloc failed for REGISTER body\n");
        close(sockfd);
        return -1;
    }

    read_bytes = compsys_helper_readn(sockfd, body, resp_body_len);
    if (read_bytes != (ssize_t)resp_body_len) {
        perror("compsys_helper_readn (REGISTER body)");
        free(body);
        close(sockfd);
        return -1;
    }

    // 5) Parse body into `network[]`
    update_network_from_register_response(body, resp_body_len);

    free(body);
    close(sockfd);
    return 0;
}


// ---------------------------------------------------------------------------
//  Client-side RETRIEVE (now with multi-block receive and file save)
// ---------------------------------------------------------------------------
static int perform_retrieve(const NetworkAddress_t *peer_address, const char *filepath) {
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        perror("socket (RETRIEVE)");
        return -1;
    }

    struct sockaddr_in servaddr;
    memset(&servaddr, 0, sizeof(servaddr));
    servaddr.sin_family = AF_INET;
    servaddr.sin_port = htons((uint16_t)peer_address->port);

    if (inet_pton(AF_INET, peer_address->ip, &servaddr.sin_addr) <= 0) {
        fprintf(stderr, "Invalid peer IP address (RETRIEVE): %s\n", peer_address->ip);
        close(sockfd);
        return -1;
    }

    if (connect(sockfd, (struct sockaddr*)&servaddr, sizeof(servaddr)) < 0) {
        perror("connect (RETRIEVE)");
        close(sockfd);
        return -1;
    }

    // Byg RETRIEVE request header
    char header[REQUEST_HEADER_LEN];
    memset(header, 0, sizeof(header));

    // IP (16 bytes)
    size_t ip_len = strnlen(my_address->ip, IP_LEN);
    memcpy(header, my_address->ip, ip_len);

    // Port (4 bytes, netværks-byte-order)
    uint32_t port_net = htonl((uint32_t)my_address->port);
    memcpy(header + IP_LEN, &port_net, sizeof(port_net));

    // Signature (32 bytes)
    memcpy(header + IP_LEN + PORT_LEN, my_address->signature, SHA256_HASH_SIZE);

    // Command = COMMAND_RETREIVE
    uint32_t cmd_net = htonl((uint32_t)COMMAND_RETREIVE);
    memcpy(header + IP_LEN + PORT_LEN + SHA256_HASH_SIZE, &cmd_net, sizeof(cmd_net));

    // Body = filepath som bytes (uden '\0')
    size_t name_len = strnlen(filepath, 255);
    uint32_t body_len = (uint32_t)name_len;
    uint32_t bodylen_net = htonl(body_len);
    memcpy(header + IP_LEN + PORT_LEN + SHA256_HASH_SIZE + LEN_COMMAND_LENGTH, &bodylen_net, sizeof(bodylen_net));

    // Send header
    ssize_t written = compsys_helper_writen(sockfd, header, REQUEST_HEADER_LEN);
    if (written != REQUEST_HEADER_LEN) {
        perror("compsys_helper_writen (RETRIEVE header)");
        close(sockfd);
        return -1;
    }

    // Send body (filnavn)
    if (body_len > 0) {
        written = compsys_helper_writen(sockfd, (void*)filepath, body_len);
        if (written != (ssize_t)body_len) {
            perror("compsys_helper_writen (RETRIEVE body)");
            close(sockfd);
            return -1;
        }
    }

    // We'll receive one or more responses (blocks). We must loop until we have all blocks.
    // First read the first block header to get block_count.
    // Since replies are independent messages, read header per block in loop.

    // We'll store blocks in arrays to reassemble once we got them all.
    uint32_t expected_block_count = 0;
    char **block_buffers = NULL;
    uint32_t *block_lengths = NULL;
    uint32_t received_blocks = 0;
    hashdata_t expected_total_hash;
    int have_total_hash = 0;

    while (1) {
        unsigned char resp_hdr[REPLY_HEADER_LEN];
        ssize_t read_bytes = compsys_helper_readn(sockfd, resp_hdr, REPLY_HEADER_LEN);
        if (read_bytes != REPLY_HEADER_LEN) {
            perror("compsys_helper_readn (RETRIEVE response header)");
            // cleanup
            if (block_buffers) {
                for (uint32_t i = 0; i < expected_block_count; i++) {
                    if (block_buffers[i]) free(block_buffers[i]);
                }
                free(block_buffers);
                free(block_lengths);
            }
            close(sockfd);
            return -1;
        }

        uint32_t resp_body_len_net;
        uint32_t status_net;
        uint32_t block_num_net;
        uint32_t block_count_net;

        memcpy(&resp_body_len_net, resp_hdr + 0, 4);
        memcpy(&status_net,        resp_hdr + 4, 4);
        memcpy(&block_num_net,     resp_hdr + 8, 4);
        memcpy(&block_count_net,   resp_hdr + 12, 4);

        uint32_t resp_body_len = ntohl(resp_body_len_net);
        uint32_t status         = ntohl(status_net);
        uint32_t block_num      = ntohl(block_num_net);
        uint32_t block_count    = ntohl(block_count_net);

        // Copy hashes
        hashdata_t block_hash, total_hash;
        memcpy(block_hash, resp_hdr + 16, SHA256_HASH_SIZE);
        memcpy(total_hash, resp_hdr + 16 + SHA256_HASH_SIZE, SHA256_HASH_SIZE);

        if (status != STATUS_OK) {
            fprintf(stderr, "RETRIEVE failed, status = %u\n", status);
            // read and discard body if present, cleanup
            if (resp_body_len > 0) {
                char *dummy = (char*)malloc(resp_body_len);
                if (dummy) {
                    compsys_helper_readn(sockfd, dummy, resp_body_len);
                    free(dummy);
                }
            }
            if (block_buffers) {
                for (uint32_t i = 0; i < expected_block_count; i++) {
                    if (block_buffers[i]) free(block_buffers[i]);
                }
                free(block_buffers);
                free(block_lengths);
            }
            close(sockfd);
            return -1;
        }

        if (!have_total_hash) {
            memcpy(expected_total_hash, total_hash, SHA256_HASH_SIZE);
            have_total_hash = 1;
            expected_block_count = block_count;
            // allocate structures
            block_buffers = (char**)calloc(expected_block_count, sizeof(char*));
            block_lengths = (uint32_t*)calloc(expected_block_count, sizeof(uint32_t));
            if (!block_buffers || !block_lengths) {
                fprintf(stderr, "Memory allocation failed for blocks\n");
                if (block_buffers) free(block_buffers);
                if (block_lengths) free(block_lengths);
                close(sockfd);
                return -1;
            }
        } else {
            // ensure block_count matches
            if (block_count != expected_block_count) {
                fprintf(stderr, "Inconsistent block_count\n");
                // cleanup
                for (uint32_t i = 0; i < expected_block_count; i++) if (block_buffers[i]) free(block_buffers[i]);
                free(block_buffers); free(block_lengths);
                close(sockfd);
                return -1;
            }
        }

        // Read body
        char *b = NULL;
        if (resp_body_len > 0) {
            b = (char*)malloc(resp_body_len);
            if (!b) {
                fprintf(stderr, "malloc failed for RETRIEVE block\n");
                for (uint32_t i = 0; i < expected_block_count; i++) if (block_buffers[i]) free(block_buffers[i]);
                free(block_buffers); free(block_lengths);
                close(sockfd);
                return -1;
            }
            read_bytes = compsys_helper_readn(sockfd, b, resp_body_len);
            if (read_bytes != (ssize_t)resp_body_len) {
                perror("compsys_helper_readn (RETRIEVE body)");
                free(b);
                for (uint32_t i = 0; i < expected_block_count; i++) if (block_buffers[i]) free(block_buffers[i]);
                free(block_buffers); free(block_lengths);
                close(sockfd);
                return -1;
            }
        }

        // Validate block hash
        hashdata_t computed_block_hash;
        if (resp_body_len > 0)
            get_data_sha(b, computed_block_hash, resp_body_len, SHA256_HASH_SIZE);
        else
            get_data_sha("", computed_block_hash, 0, SHA256_HASH_SIZE);

        if (memcmp(computed_block_hash, block_hash, SHA256_HASH_SIZE) != 0) {
            fprintf(stderr, "Block hash mismatch for block %u\n", block_num);
            if (b) free(b);
            for (uint32_t i = 0; i < expected_block_count; i++) if (block_buffers[i]) free(block_buffers[i]);
            free(block_buffers); free(block_lengths);
            close(sockfd);
            return -1;
        }

        // Store block (if not already stored)
        if (block_num < expected_block_count && block_buffers[block_num] == NULL) {
            block_buffers[block_num] = b;
            block_lengths[block_num] = resp_body_len;
            received_blocks++;
        } else {
            // duplicate block or out-of-range
            if (b) free(b);
        }

        // If we've received all blocks -> assemble and verify total hash
        if (received_blocks == expected_block_count) {
            // compute total size
            uint32_t total_size = 0;
            for (uint32_t i = 0; i < expected_block_count; i++) total_size += block_lengths[i];

            char *assembled = (char*)malloc(total_size);
            if (!assembled) {
                fprintf(stderr, "malloc failed assembling file\n");
                for (uint32_t i = 0; i < expected_block_count; i++) if (block_buffers[i]) free(block_buffers[i]);
                free(block_buffers); free(block_lengths);
                close(sockfd);
                return -1;
            }
            uint32_t pos = 0;
            for (uint32_t i = 0; i < expected_block_count; i++) {
                if (block_lengths[i] > 0) {
                    memcpy(assembled + pos, block_buffers[i], block_lengths[i]);
                    pos += block_lengths[i];
                }
            }

            // verify total hash
            hashdata_t computed_total_hash;
            get_data_sha(assembled, computed_total_hash, total_size, SHA256_HASH_SIZE);
            if (memcmp(computed_total_hash, expected_total_hash, SHA256_HASH_SIZE) != 0) {
                fprintf(stderr, "Total hash mismatch\n");
                free(assembled);
                for (uint32_t i = 0; i < expected_block_count; i++) if (block_buffers[i]) free(block_buffers[i]);
                free(block_buffers); free(block_lengths);
                close(sockfd);
                return -1;
            }

            // Write assembled file to disk under src/ (or current directory)
            // Create file path same as requested filename
            FILE *out = fopen(filepath, "wb");
            if (!out) {
                perror("fopen (write retrieved file)");
                free(assembled);
                for (uint32_t i = 0; i < expected_block_count; i++) if (block_buffers[i]) free(block_buffers[i]);
                free(block_buffers); free(block_lengths);
                close(sockfd);
                return -1;
            }
            size_t wrote = fwrite(assembled, 1, total_size, out);
            fclose(out);
            if (wrote != total_size) {
                fprintf(stderr, "Failed to write entire file to disk\n");
                free(assembled);
                for (uint32_t i = 0; i < expected_block_count; i++) if (block_buffers[i]) free(block_buffers[i]);
                free(block_buffers); free(block_lengths);
                close(sockfd);
                return -1;
            }

            printf("RETRIEVE: saved file '%s' (%u bytes)\n", filepath, total_size);

            free(assembled);
            for (uint32_t i = 0; i < expected_block_count; i++) if (block_buffers[i]) free(block_buffers[i]);
            free(block_buffers); free(block_lengths);

            close(sockfd);
            return 0;
        }

        // otherwise continue loop to read next reply (block)
    }

    // unreachable
    close(sockfd);
    return -1;
}

// Parse the REGISTER response body into the global `network[]` list.
// Body is a list of entries, each 68 bytes:
//   16 bytes - IP
//   4 bytes  - port (network order)
//   32 bytes - signature
//   16 bytes - salt
static void update_network_from_register_response(const char *body, uint32_t body_len) {
    if (body_len % PEER_ADDR_LEN != 0) {
        fprintf(stderr,
                "REGISTER response body length %u is not a multiple of %d bytes\n",
                body_len, PEER_ADDR_LEN);
        return;
    }

    uint32_t count = body_len / PEER_ADDR_LEN;
    printf("DEBUG: Adding %u peers from register response\n", count);

    for (uint32_t i = 0; i < count; i++) {
        const char *entry = body + i * PEER_ADDR_LEN;

        NetworkAddress_t *peer = (NetworkAddress_t*)malloc(sizeof(NetworkAddress_t));
        if (peer == NULL) {
            fprintf(stderr, "malloc failed while adding peer to network\n");
            return;
        }
        memset(peer, 0, sizeof(NetworkAddress_t));

        // IP (16 bytes, ensure null-termination)
        memcpy(peer->ip, entry, IP_LEN);
        peer->ip[IP_LEN - 1] = '\0';

        // Port (4 bytes, network order)
        uint32_t port_net;
        memcpy(&port_net, entry + IP_LEN, 4);
        peer->port = (int)ntohl(port_net);

        // Signature (32 bytes)
        memcpy(peer->signature, entry + IP_LEN + 4, SHA256_HASH_SIZE);

        // Salt (16 bytes)
        memcpy(peer->salt, entry + IP_LEN + 4 + SHA256_HASH_SIZE, SALT_LEN);

        printf("DEBUG: Processing peer: %s:%d\n", peer->ip, peer->port);

        // Skip if this entry is ourselves
        if (peer->port == my_address->port &&
            strncmp(peer->ip, my_address->ip, IP_LEN) == 0) {
            printf("DEBUG: Skipping self\n");
            free(peer);
            continue;
        }

        // Insert into global network list if not already present.
        pthread_mutex_lock(&network_mutex);

        int exists = 0;
        for (uint32_t j = 0; j < peer_count; j++) {
            if (network[j]->port == peer->port &&
                strncmp(network[j]->ip, peer->ip, IP_LEN) == 0) {
                exists = 1;
                break;
            }
        }

        if (!exists) {
            NetworkAddress_t **tmp =
                (NetworkAddress_t**)realloc(network,
                                            (peer_count + 1) * sizeof(NetworkAddress_t*));
            if (tmp == NULL) {
                fprintf(stderr, "realloc failed while growing network\n");
                pthread_mutex_unlock(&network_mutex);
                free(peer);
                return;
            }
            network = tmp;
            network[peer_count] = peer;
            peer_count++;
            printf("DEBUG: Added peer to network. Total peers: %u\n", peer_count);
        } else {
            // Already know this peer
            printf("DEBUG: Peer already exists in network\n");
            free(peer);
        }

        pthread_mutex_unlock(&network_mutex);
    }
}


// ---------------------------------------------------------------------------
//  main()
// ---------------------------------------------------------------------------

int main(int argc, char **argv) {
    // Users should call this script with a single argument describing what
    // config to use
    if (argc != 3) {
        fprintf(stderr, "Usage: %s <IP> <PORT>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    my_address = (NetworkAddress_t*)malloc(sizeof(NetworkAddress_t));
    memset(my_address, 0, sizeof(NetworkAddress_t));
    memset(my_address->ip, '\0', IP_LEN);
    memcpy(my_address->ip, argv[1], strlen(argv[1]));
    my_address->port = atoi(argv[2]);

    if (!is_valid_ip(my_address->ip)) {
        fprintf(stderr, ">> Invalid peer IP: %s\n", my_address->ip);
        exit(EXIT_FAILURE);
    }

    if (!is_valid_port(my_address->port)) {
        fprintf(stderr, ">> Invalid peer port: %d\n",
            my_address->port);
        exit(EXIT_FAILURE);
    }

    // Seed random once (for pick_random_peer)
    srand((unsigned int)time(NULL));


    char password[PASSWORD_LEN];
    fprintf(stdout, "Create a password to proceed: ");
    scanf("%16s", password);

    // Clean up password string as otherwise some extra chars can sneak in.
    for (int i = (int)strlen(password); i < PASSWORD_LEN; i++) {
        password[i] = '\0';
    }

    // For debugging, we use a fixed salt of exactly SALT_LEN bytes (no '\0').
    // We use a string literal as source but only copy the first SALT_LEN bytes.
    char fixed_salt_str[] = "0123456789ABCDEF"; // 16 visible chars + '\0' in memory
    memcpy(my_address->salt, fixed_salt_str, SALT_LEN);
    // (Alternativt i den endelige løsning: generate_random_salt(my_address->salt);)

    // Compute this peer's signature = SHA256(password || salt)
    hashdata_t my_signature;
    assemble_signature(password, my_address->salt, my_signature);
    memcpy(my_address->signature, my_signature, SHA256_HASH_SIZE);

    // Add ourselves to the network
    pthread_mutex_lock(&network_mutex);
    NetworkAddress_t* self_peer = (NetworkAddress_t*)malloc(sizeof(NetworkAddress_t));
    if (self_peer) {
        memset(self_peer, 0, sizeof(NetworkAddress_t));
        strncpy(self_peer->ip, my_address->ip, IP_LEN);
        self_peer->ip[IP_LEN-1] = '\0';
        self_peer->port = my_address->port;
        memcpy(self_peer->signature, my_address->signature, SHA256_HASH_SIZE);
        memcpy(self_peer->salt, my_address->salt, SALT_LEN);

        NetworkAddress_t** new_network = (NetworkAddress_t**)realloc(network,
                                        (peer_count + 1) * sizeof(NetworkAddress_t*));
        if (new_network) {
            network = new_network;
            network[peer_count] = self_peer;
            peer_count++;
            printf("Added self to network: %s:%d\n", my_address->ip, my_address->port);
        } else {
            free(self_peer);
        }
    }
    pthread_mutex_unlock(&network_mutex);

    // Setup the client and server threads
    pthread_t client_thread_id;
    pthread_t server_thread_id;
    pthread_create(&client_thread_id, NULL, client_thread, NULL);
    pthread_create(&server_thread_id, NULL, server_thread, NULL);

    // Wait for them to complete.
    pthread_join(client_thread_id, NULL);
    pthread_join(server_thread_id, NULL);

    exit(EXIT_SUCCESS);
}
