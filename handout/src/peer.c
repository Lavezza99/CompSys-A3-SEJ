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

// Forward declarations of new helpers
static int perform_register(const NetworkAddress_t *peer_address);
static void update_network_from_register_response(const char *body, uint32_t body_len);


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

    // --- Our main implemented behaviour: REGISTER with the chosen peer ---
    if (perform_register(&peer_address) == 0) {
        fprintf(stdout,
                "REGISTER succeeded with %s:%d. Known peers now: %u\n",
                peer_address.ip, peer_address.port, peer_count);
    } else {
        fprintf(stderr,
                "REGISTER failed with %s:%d\n",
                peer_address.ip, peer_address.port);
    }

    // In a full implementation, after registration we would:
    //  - repeatedly ask for filenames
    //  - send RETRIEVE requests to random peers from `network`
    //  - write received files to the src/ directory
    //
    // For now we just terminate the client thread.
    // (You should not see this in the final solution, but it is useful while developing.)
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

    char buffer[MAX_MSG_LEN];
    ssize_t n = compsys_helper_readn(connfd, buffer, REQUEST_HEADER_LEN);

    if (n <= 0) {
        close(connfd);
        return NULL;
    }

    // TODO TEAM: Parse request header (IP, port, signature, command, body_len)
    // TODO TEAM: Read request body, then dispatch based on command.
    //            (REGISTER, RETRIEVE, INFORM)

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

// Parse the REGISTER response body into the global `network[]` list.
// Body is a list of entries, each 68 bytes:
//   16 bytes - IP
//   4 bytes  - port (network order)
//   32 bytes - signature
//   16 bytes - salt
static void update_network_from_register_response(const char *body, uint32_t body_len) {
    if (body_len % 68 != 0) {
        fprintf(stderr,
                "REGISTER response body length %u is not a multiple of 68 bytes\n",
                body_len);
        return;
    }

    uint32_t count = body_len / 68;

    for (uint32_t i = 0; i < count; i++) {
        const char *entry = body + i * 68;

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

        // Skip if this entry is ourselves
        if (peer->port == my_address->port &&
            strncmp(peer->ip, my_address->ip, IP_LEN) == 0) {
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
        } else {
            // Already know this peer
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

    char password[PASSWORD_LEN];
    fprintf(stdout, "Create a password to proceed: ");
    scanf("%16s", password);

    // Clean up password string as otherwise some extra chars can sneak in.
    for (int i = (int)strlen(password); i < PASSWORD_LEN; i++) {
        password[i] = '\0';
    }

    // For debugging, we use a fixed salt. (Spec suggests random salt in practice.)
    char salt[SALT_LEN] = "0123456789ABCDEF";
    // generate_random_salt(salt);  // optional improvement
    memcpy(my_address->salt, salt, SALT_LEN);
    
    // Compute this peer's signature = SHA256(password || salt)
    hashdata_t my_signature;
    assemble_signature(password, my_address->salt, my_signature);
    memcpy(my_address->signature, my_signature, SHA256_HASH_SIZE);

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
