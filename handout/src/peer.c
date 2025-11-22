#include <stdlib.h>
#include <stdio.h>
#include <math.h>
#include <netdb.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#ifdef __APPLE__
#include "./endian.h"
#else
#include <endian.h>
#endif

#include "./peer.h"


// Global variables to be used by both the server and client side of the peer.
// Note the addition of mutexs to prevent race conditions.
NetworkAddress_t *my_address;

NetworkAddress_t** network = NULL;
uint32_t peer_count = 0;

// Protects network and peer_count
pthread_mutex_t network_mutex = PTHREAD_MUTEX_INITIALIZER;

// Forward declaration of the per-connection handler thread
void* connection_handler(void *arg);

// We might later need a list of files currently being retrieved,
// but we can add that when we implement RETREIVE.

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
/*
 * Send a reply to the client (basic single-block version)
 */
static void send_reply(int connfd, uint32_t status, const void* data, uint32_t data_len) {
    ReplyHeader_t header;
    memset(&header, 0, sizeof(header));
    
    header.length = htonl(data_len);
    header.status = htonl(status);
    header.this_block = htonl(0);  // Single block
    header.block_count = htonl(1); // Total blocks
    
    // Calculate hashes
    if (data && data_len > 0) {
        get_data_sha(data, header.block_hash, data_len, SHA256_HASH_SIZE);
        get_data_sha(data, header.total_hash, data_len, SHA256_HASH_SIZE);
    } else {
        // For empty data, use hash of empty string
        get_data_sha("", header.block_hash, 0, SHA256_HASH_SIZE);
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
    
    printf("Sent reply: status=%u, data_len=%u\n", status, data_len);
}

/*
 * Send an error reply to the client
 */
static void send_error_reply(int connfd, uint32_t status, const char* message) {
    printf("Sending error reply: status=%u, message=%s\n", status, message);
    
    // Convert message to bytes
    size_t msg_len = strlen(message);
    char* msg_bytes = (char*)malloc(msg_len);
    if (msg_bytes) {
        memcpy(msg_bytes, message, msg_len);
        send_reply(connfd, status, msg_bytes, msg_len);
        free(msg_bytes);
    } else {
        // Fallback: send empty reply with error status
        send_reply(connfd, status, NULL, 0);
    }
}

/*
 * Handler for REGISTER requests
 */
static void handle_register_request(int connfd, const char* sender_ip, uint32_t sender_port, 
                                   const hashdata_t sender_signature, const char* body, uint32_t body_len) {
    (void)body;
    (void)body_len;
    
    printf("REGISTER from %s:%u\n", sender_ip, sender_port);
    
    // Check if peer already exists
    char sender_address[50];
    snprintf(sender_address, sizeof(sender_address), "%s:%u", sender_ip, sender_port);
    
    pthread_mutex_lock(&network_mutex);
    
    // Check if peer already exists
    int peer_exists = 0;
    for (uint32_t i = 0; i < peer_count; i++) {
        char existing_address[50];
        snprintf(existing_address, sizeof(existing_address), "%s:%d", 
                 network[i]->ip, network[i]->port);
        if (strcmp(sender_address, existing_address) == 0) {
            peer_exists = 1;
            break;
        }
    }
    
    if (peer_exists) {
        pthread_mutex_unlock(&network_mutex);
        send_error_reply(connfd, STATUS_PEER_EXISTS, "Peer already registered");
        return;
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
    memset(new_peer, 0, sizeof(NetworkAddress_t));
    strncpy(new_peer->ip, sender_ip, IP_LEN);
    new_peer->port = sender_port;
    memcpy(new_peer->signature, saveable_sig, SHA256_HASH_SIZE);
    memcpy(new_peer->salt, salt, SALT_LEN);
    
    // Reallocate network array
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
    
    printf("Registered new peer: %s. Total peers in network: %u\n", sender_address, peer_count);
    
    // Debug: print all peers in network
    printf("DEBUG: Current network peers:\n");
    for (uint32_t i = 0; i < peer_count; i++) {
        printf("  Peer %u: %s:%d\n", i, network[i]->ip, network[i]->port);
    }
    
    // Count how many peers we will send (excluding the new peer)
    uint32_t peers_to_send = 0;
    for (uint32_t i = 0; i < peer_count; i++) {
        if (network[i]->port == sender_port && 
            strncmp(network[i]->ip, sender_ip, IP_LEN) == 0) {
            continue; // Skip the new peer
        }
        peers_to_send++;
    }
    
    uint32_t response_size = peers_to_send * PEER_ADDR_LEN;
    printf("DEBUG: Will send %u peers in response (%u bytes)\n", peers_to_send, response_size);
    
    char* response_data = (char*)malloc(response_size);
    if (!response_data) {
        pthread_mutex_unlock(&network_mutex);
        send_error_reply(connfd, STATUS_OTHER, "Memory allocation failed");
        return;
    }
    
    char* current_pos = response_data;
    
    // Add all peers except the new one
    for (uint32_t i = 0; i < peer_count; i++) {
        // Skip the new peer we just added
        if (network[i]->port == sender_port && 
            strncmp(network[i]->ip, sender_ip, IP_LEN) == 0) {
            continue;
        }
        
        printf("DEBUG: Adding peer to response: %s:%d\n", network[i]->ip, network[i]->port);
        
        // IP (16 bytes)
        strncpy(current_pos, network[i]->ip, IP_LEN);
        current_pos += IP_LEN;
        
        // Port (4 bytes, network order)
        uint32_t port_net = htonl(network[i]->port);
        memcpy(current_pos, &port_net, sizeof(port_net));
        current_pos += sizeof(port_net);
        
        // Signature (32 bytes)
        memcpy(current_pos, network[i]->signature, SHA256_HASH_SIZE);
        current_pos += SHA256_HASH_SIZE;
        
        // Salt (16 bytes)
        memcpy(current_pos, network[i]->salt, SALT_LEN);
        current_pos += SALT_LEN;
    }
    
    pthread_mutex_unlock(&network_mutex);
    
    // Send successful response with peer list (excluding the new peer)
    send_reply(connfd, STATUS_OK, response_data, response_size);
    free(response_data);
    
    printf("Registration successful for %s, sent %u peers in response\n", 
           sender_address, peers_to_send);
}

/*
 * Handler for RETRIEVE requests  
 */
static void handle_retrieve_request(int connfd, const char* sender_ip, uint32_t sender_port,
                                   const hashdata_t sender_signature, const char* body, uint32_t body_len) {
    (void)sender_signature;

    printf("RETRIEVE from %s:%u\n", sender_ip, sender_port);

    if (body_len == 0 || body == NULL) {
        send_error_reply(connfd, STATUS_MALFORMED, "Empty RETRIEVE request");
        return;
    }

    // Filnavnet kommer som rå bytes i body (uden '\0')
    // Vi laver en kopi med '\0' til fopen.
    char filename[256];
    if (body_len >= sizeof(filename)) {
        send_error_reply(connfd, STATUS_MALFORMED, "Filename too long");
        return;
    }

    memcpy(filename, body, body_len);
    filename[body_len] = '\0';

    printf("RETRIEVE requested filename: '%s'\n", filename);

    // Forsøg at åbne filen (fra nuværende directory / src)
    FILE *f = fopen(filename, "rb");
    if (!f) {
        perror("fopen (RETRIEVE)");
        send_error_reply(connfd, STATUS_OTHER, "File not found");
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
        // Tom fil – send bare en OK med tom body
        fclose(f);
        send_reply(connfd, STATUS_OK, NULL, 0);
        return;
    }

    // Læs hele filen i memory (enkelt-block løsning)
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

    // Send filens indhold som ét svar-block
    send_reply(connfd, STATUS_OK, filebuf, (uint32_t)fsize);
    free(filebuf);

    printf("RETRIEVE: sent file '%s' (%ld bytes)\n", filename, fsize);
}


/*
 * Handler for INFORM requests
 */
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
        memset(new_peer, 0, sizeof(NetworkAddress_t));
        strncpy(new_peer->ip, new_ip, IP_LEN);
        new_peer->port = new_port;
        memcpy(new_peer->signature, new_signature, SHA256_HASH_SIZE);
        memcpy(new_peer->salt, new_salt, SALT_LEN);
        
        NetworkAddress_t** new_network = (NetworkAddress_t**)realloc(network, 
                                            (peer_count + 1) * sizeof(NetworkAddress_t*));
        if (new_network) {
            network = new_network;
            network[peer_count] = new_peer;
            peer_count++;
            printf("Added peer from INFORM: %s\n", new_address);
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

    // Saml kandidater som ikke er os selv
    uint32_t indices[peer_count];
    uint32_t candidate_count = 0;

    for (uint32_t i = 0; i < peer_count; i++) {
        if (network[i]->port == my_address->port &&
            strncmp(network[i]->ip, my_address->ip, IP_LEN) == 0) {
            continue; // spring os selv over
        }
        indices[candidate_count++] = i;
    }

    if (candidate_count == 0) {
        pthread_mutex_unlock(&network_mutex);
        return -1; // ingen andre peers
    }

    // Vælg en tilfældig index blandt kandidaterne
    uint32_t chosen = indices[rand() % candidate_count];
    memcpy(out_peer, network[chosen], sizeof(NetworkAddress_t));

    pthread_mutex_unlock(&network_mutex);
    return 0;
}



/*
 * Function to act as thread for all required client interactions. This thread 
 * will be run concurrently with the server_thread. It will start by requesting
 * the IP and port for another peer to connect to. Once both have been provided
 * the thread will register with that peer and expect a response outlining the
 * complete network. The user will then be prompted to provide a file path to
 * retrieve. This file request will be sent to a random peer on the network.
 * This request/retrieve interaction is then repeated forever.
 */ 
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


/*
 * Function to act as basis for running the server thread. This thread will be
 * run concurrently with the client thread, but is infinite in nature.
 */
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

/*
 * This is the per-connection handler for *incoming* requests.
 * Right now it only reads the request header and closes the connection.
 *
 * === TODO FOR TEAM ===
 *  1) Parse the request header in `buffer` into:
 *       - sender_ip[IP_LEN]
 *       - sender_port
 *       - sender_signature[SHA256_HASH_SIZE]
 *       - command (1=REGISTER, 2=RETRIEVE, 3=INFORM)
 *       - body_len
 *  2) Read `body_len` bytes of payload into a separate buffer.
 *  3) Switch on `command`:
 *       - if 1: call a future `handle_register_request(...)`
 *       - if 2: call a future `handle_retrieve_request(...)`
 *       - if 3: call a future `handle_inform_request(...)`
 *  4) Those handler functions must:
 *       - Check passwords/signatures (Section 3.2)
 *       - Update `network` safely using `network_mutex`
 *       - Send appropriate responses using the response format in Section 3.4.
 */
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
    // Request format (Section 3.3):
    //   16 bytes - our IP
    //   4 bytes  - our port (network order)
    //   32 bytes - our signature (SHA256 of salted password)
    //   4 bytes  - command code (1 = REGISTER)
    //   4 bytes  - body length (0 for REGISTER)
    char header[REQUEST_HEADER_LEN];
    memset(header, 0, sizeof(header));

    // IP (16 bytes, UTF-8, zero-padded)
    size_t ip_len = strnlen(my_address->ip, IP_LEN);
    memcpy(header, my_address->ip, ip_len);

    // Port (4 bytes, network byte-order)
    uint32_t port_net = htonl((uint32_t)my_address->port);
    memcpy(header + IP_LEN, &port_net, sizeof(port_net));

    // Signature (32 bytes)
    memcpy(header + IP_LEN + 4, my_address->signature, SHA256_HASH_SIZE);

    // Command = 1 (REGISTER)
    uint32_t cmd_net = htonl(1u);
    memcpy(header + IP_LEN + 4 + SHA256_HASH_SIZE, &cmd_net, sizeof(cmd_net));

    // Body length = 0
    uint32_t bodylen_net = htonl(0u);
    memcpy(header + IP_LEN + 4 + SHA256_HASH_SIZE + 4, &bodylen_net, sizeof(bodylen_net));

    // Send header (no body)
    ssize_t written = compsys_helper_writen(sockfd, header, REQUEST_HEADER_LEN);
    if (written != REQUEST_HEADER_LEN) {
        perror("compsys_helper_writen (REGISTER header)");
        close(sockfd);
        return -1;
    }

    // 3) Read response header
    // Response format (Section 3.4):
    //   4 bytes - body length
    //   4 bytes - status
    //   4 bytes - block number
    //   4 bytes - block count
    //   32 bytes - block hash
    //   32 bytes - total hash
    // Total = 80 bytes.
    unsigned char resp_hdr[80];
    ssize_t read_bytes = compsys_helper_readn(sockfd, resp_hdr, 80);
    if (read_bytes != 80) {
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
    // TODO TEAM: verify `block hash` and `total hash` as part of security.

    if (status != 1) {
        // Status codes in Section 3.4, 1 = OK.
        fprintf(stderr, "REGISTER failed, status code = %u\n", status);
        // We still need to read and discard the body if present.
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
        // Discard body
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
        // We're probably the first peer on the network.
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
//  Client-side RETRIEVE (basic stub)
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
    memcpy(header + IP_LEN + 4, my_address->signature, SHA256_HASH_SIZE);

    // Command = COMMAND_RETREIVE (typisk 2 ifølge spec)
    uint32_t cmd_net = htonl((uint32_t)COMMAND_RETREIVE);
    memcpy(header + IP_LEN + 4 + SHA256_HASH_SIZE, &cmd_net, sizeof(cmd_net));

    // Body = filepath som bytes (uden '\0')
    size_t name_len = strnlen(filepath, 255);
    uint32_t body_len = (uint32_t)name_len;
    uint32_t bodylen_net = htonl(body_len);
    memcpy(header + IP_LEN + 4 + SHA256_HASH_SIZE + 4, &bodylen_net, sizeof(bodylen_net));

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


    // Læs svar-header (samme format som REGISTER)
    unsigned char resp_hdr[REPLY_HEADER_LEN];
    ssize_t read_bytes = compsys_helper_readn(sockfd, resp_hdr, REPLY_HEADER_LEN);
    if (read_bytes != REPLY_HEADER_LEN) {
        perror("compsys_helper_readn (RETRIEVE response header)");
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

    if (status != STATUS_OK) {
        fprintf(stderr, "RETRIEVE failed, status = %u\n", status);
        // læs og kassér body hvis der er en fejlbesked
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

    // For nu håndterer vi kun single-block svar (ligesom REGISTER)
    if (block_count != 1 || block_num != 0) {
        fprintf(stderr,
                "Multi-block RETRIEVE response not yet supported "
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

    if (resp_body_len > 0) {
        char *body = (char*)malloc(resp_body_len + 1);
        if (!body) {
            fprintf(stderr, "malloc failed for RETRIEVE body\n");
            close(sockfd);
            return -1;
        }

        read_bytes = compsys_helper_readn(sockfd, body, resp_body_len);
        if (read_bytes != (ssize_t)resp_body_len) {
            perror("compsys_helper_readn (RETRIEVE body)");
            free(body);
            close(sockfd);
            return -1;
        }

        // midlertidigt: print kun længden, ikke gem filen rigtigt
        body[resp_body_len] = '\0';
        printf("RETRIEVE: received %u bytes of data\n", resp_body_len);
        // TODO (for gruppen): skriv body til fil i src/-mappen

        free(body);
    } else {
        printf("RETRIEVE: response body is empty\n");
    }

    close(sockfd);
    return 0;
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

