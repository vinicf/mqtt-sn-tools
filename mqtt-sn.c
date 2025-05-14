/*
  Common functions used by the MQTT-SN Tools
  Copyright (C) Nicholas Humfrey

  Permission is hereby granted, free of charge, to any person obtaining
  a copy of this software and associated documentation files (the
  "Software"), to deal in the Software without restriction, including
  without limitation the rights to use, copy, modify, merge, publish,
  distribute, sublicense, and/or sell copies of the Software, and to
  permit persons to whom the Software is furnished to do so, subject to
  the following conditions:

  The above copyright notice and this permission notice shall be
  included in all copies or substantial portions of the Software.

  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
  EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
  MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
  NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
  LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
  OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
  WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <time.h>
#include <errno.h>
#include <stdarg.h>

#include "mqtt-sn.h" // Includes DTLS headers now

#ifndef AI_DEFAULT
#define AI_DEFAULT (AI_ADDRCONFIG|AI_V4MAPPED)
#endif

// ---- DTLS Globals ----
static SSL_CTX *dtls_ctx = NULL;
static SSL *ssl_session = NULL;
static int dtls_enabled = FALSE; // Flag to check if DTLS is active
static int underlying_sock_fd = -1; // Store the raw UDP socket FD
// ---- End DTLS Globals ----


static uint8_t debug = 0;
static uint8_t verbose = 0;
static uint8_t timeout = MQTT_SN_DEFAULT_TIMEOUT;
static uint16_t next_message_id = 1;
static time_t last_transmit = 0;
static time_t last_receive = 0;
static time_t keep_alive = 0;
static uint8_t forwarder_encapsulation = FALSE;
const uint8_t *wireless_node_id = NULL;
uint8_t wireless_node_id_len  = 0;

topic_map_t *topic_map = NULL;


void mqtt_sn_set_debug(uint8_t value)
{
    debug = value;
    mqtt_sn_log_debug("Debug level is: %d.", debug);
}

void mqtt_sn_set_verbose(uint8_t value)
{
    verbose = value;
    mqtt_sn_log_debug("Verbose level is: %d.", verbose);
}

void mqtt_sn_set_timeout(uint8_t value)
{
    if (value < 1) {
        timeout = MQTT_SN_DEFAULT_TIMEOUT;
    } else {
        timeout = value;
    }
    mqtt_sn_log_debug("Network timeout is: %d seconds.", timeout);
}

// ---- DTLS Implementation ----
int mqtt_sn_dtls_init(const char* ca_file, const char* cert_file, const char* key_file)
{
    mqtt_sn_log_debug("Initialising DTLS context...");

    // Initialize OpenSSL library (needed for older versions)
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();

    // Create DTLS context (client method)
    dtls_ctx = SSL_CTX_new(DTLS_client_method());
    if (!dtls_ctx) {
        mqtt_sn_log_err("Failed to create DTLS context.");
        ERR_print_errors_fp(stderr);
        return -1;
    }

    // Configure context options (e.g., disable older protocols)
    // SSL_CTX_set_options(dtls_ctx, SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_NO_TLSv1 | SSL_OP_NO_TLSv1_1);

    // Set cipher list if needed (example: secure defaults)
    // if (SSL_CTX_set_cipher_list(dtls_ctx, "HIGH:!aNULL:!eNULL:!EXPORT:!DES:!RC4:!MD5:!PSK:!SRP:!CAMELLIA") != 1) {
    //     mqtt_sn_log_err("Failed to set cipher list.");
    //     ERR_print_errors_fp(stderr);
    //     SSL_CTX_free(dtls_ctx);
    //     dtls_ctx = NULL;
    //     return -1;
    // }

    // Load CA certificate for server verification (RECOMMENDED)
    if (ca_file) {
        if (!SSL_CTX_load_verify_locations(dtls_ctx, ca_file, NULL)) {
            mqtt_sn_log_err("Failed to load CA certificate file: %s", ca_file);
            ERR_print_errors_fp(stderr);
            SSL_CTX_free(dtls_ctx);
            dtls_ctx = NULL;
            return -1;
        }
        SSL_CTX_set_verify(dtls_ctx, SSL_VERIFY_PEER, NULL); // Enable peer verification
        mqtt_sn_log_debug("Loaded CA certificate: %s", ca_file);
    } else {
        mqtt_sn_log_warn("No CA certificate provided, server identity will not be verified.");
        SSL_CTX_set_verify(dtls_ctx, SSL_VERIFY_NONE, NULL); // Disable verification if no CA given
    }

    // Load client certificate (if provided for client authentication)
    if (cert_file) {
        if (SSL_CTX_use_certificate_file(dtls_ctx, cert_file, SSL_FILETYPE_PEM) <= 0) {
            mqtt_sn_log_err("Failed to load client certificate file: %s", cert_file);
            ERR_print_errors_fp(stderr);
            SSL_CTX_free(dtls_ctx);
            dtls_ctx = NULL;
            return -1;
        }
        mqtt_sn_log_debug("Loaded client certificate: %s", cert_file);
    }

    // Load client private key (if provided for client authentication)
    if (key_file) {
        if (SSL_CTX_use_PrivateKey_file(dtls_ctx, key_file, SSL_FILETYPE_PEM) <= 0) {
            mqtt_sn_log_err("Failed to load client private key file: %s", key_file);
            ERR_print_errors_fp(stderr);
            SSL_CTX_free(dtls_ctx);
            dtls_ctx = NULL;
            return -1;
        }
         mqtt_sn_log_debug("Loaded client private key: %s", key_file);

        // Check if private key matches certificate
        if (!SSL_CTX_check_private_key(dtls_ctx)) {
            mqtt_sn_log_err("Client private key does not match the client certificate.");
            ERR_print_errors_fp(stderr);
            SSL_CTX_free(dtls_ctx);
            dtls_ctx = NULL;
            return -1;
        }
    }

    // Check if both cert and key are provided if one is
    if ((cert_file && !key_file) || (!cert_file && key_file)) {
         mqtt_sn_log_warn("Client certificate and private key must both be provided for client authentication.");
         // Continue without client auth if only one is provided, but log warning
    }

    dtls_enabled = TRUE;
    mqtt_sn_log_debug("DTLS context initialised successfully.");
    return 0;
}

void mqtt_sn_dtls_cleanup()
{
     mqtt_sn_log_debug("Cleaning up DTLS resources...");
    if (ssl_session) {
        // SSL_shutdown might need non-blocking handling in a real app
        // For simple clients, just freeing might be okay, but shutdown is cleaner
        SSL_shutdown(ssl_session);
        SSL_free(ssl_session);
        ssl_session = NULL;
    }
    if (dtls_ctx) {
        SSL_CTX_free(dtls_ctx);
        dtls_ctx = NULL;
    }
    // Cleanup OpenSSL resources (less critical in modern versions)
    ERR_free_strings();
    EVP_cleanup();
    CRYPTO_cleanup_all_ex_data(); // More comprehensive cleanup

    dtls_enabled = FALSE;
    mqtt_sn_log_debug("DTLS resources cleaned up.");
}
// ---- End DTLS Implementation ----


int mqtt_sn_create_socket(const char* host, const char* port, uint16_t source_port)
{
    struct addrinfo hints;
    struct addrinfo *result, *rp;
    struct timeval tv;
    int fd = -1, ret; // Initialize fd to -1

    // --- Existing UDP Socket creation logic ---
    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_flags = AI_DEFAULT; // Use AI_DEFAULT
    hints.ai_protocol = IPPROTO_UDP; // Specify UDP

    ret = getaddrinfo(host, port, &hints, &result);
    if (ret != 0) {
        mqtt_sn_log_err("getaddrinfo failed for %s:%s : %s", host, port, gai_strerror(ret));
        exit(EXIT_FAILURE); // Exit if lookup fails
    }

    for (rp = result; rp != NULL; rp = rp->ai_next) {
        char hoststr[NI_MAXHOST] = "";
        getnameinfo(rp->ai_addr, rp->ai_addrlen, hoststr, sizeof(hoststr), NULL, 0, NI_NUMERICHOST | NI_NUMERICSERV);
        mqtt_sn_log_debug("Attempting to create UDP socket for %s...", hoststr);

        fd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (fd == -1) {
            mqtt_sn_log_warn("Failed to create socket (%s): %s", hoststr, strerror(errno));
            continue; // Try next address
        }

        if (source_port != 0) {
            struct sockaddr_storage local_addr; // Use sockaddr_storage for IPv6 compatibility
            memset(&local_addr, 0, sizeof(local_addr));
            if (rp->ai_family == AF_INET) {
                 struct sockaddr_in *addr4 = (struct sockaddr_in *)&local_addr;
                 addr4->sin_family = AF_INET;
                 addr4->sin_addr.s_addr = htonl(INADDR_ANY);
                 addr4->sin_port = htons(source_port);
            } else if (rp->ai_family == AF_INET6) {
                 struct sockaddr_in6 *addr6 = (struct sockaddr_in6 *)&local_addr;
                 addr6->sin6_family = AF_INET6;
                 addr6->sin6_addr = in6addr_any;
                 addr6->sin6_port = htons(source_port);
            } else {
                 close(fd);
                 fd = -1;
                 continue; // Should not happen with AF_UNSPEC
            }

            if (bind(fd, (struct sockaddr *)&local_addr, rp->ai_addrlen) < 0) { // Size should match family
                mqtt_sn_log_warn("Failed to bind socket to source port %d (%s): %s", source_port, hoststr, strerror(errno));
                close(fd);
                fd = -1; // Mark as failed
                continue; // Try next address
            }
             mqtt_sn_log_debug("Successfully bound socket to source port %d", source_port);
        }

        // Connect UDP socket - crucial for DTLS client
        mqtt_sn_log_debug("Connecting UDP socket to %s...", hoststr);
        if (connect(fd, rp->ai_addr, rp->ai_addrlen) == 0) {
             mqtt_sn_log_debug("UDP socket connected successfully.");
            break; // Success
        } else {
            mqtt_sn_log_warn("UDP connect failed for %s: %s", hoststr, strerror(errno));
            close(fd);
            fd = -1; // Mark as failed
        }
    } // End address loop

    freeaddrinfo(result); // Free the address list

    if (fd == -1) { // Check if loop completed without success
        mqtt_sn_log_err("Could not create and connect UDP socket to %s:%s.", host, port);
        exit(EXIT_FAILURE);
    }

    underlying_sock_fd = fd; // Store the successfully created UDP socket FD

    // --- DTLS Setup (if enabled) ---
    if (dtls_enabled) {
        mqtt_sn_log_debug("DTLS is enabled, setting up DTLS session...");
        if (!dtls_ctx) {
            mqtt_sn_log_err("DTLS enabled but context is not initialized. Call mqtt_sn_dtls_init first.");
            close(underlying_sock_fd);
            underlying_sock_fd = -1;
            exit(EXIT_FAILURE);
        }

        ssl_session = SSL_new(dtls_ctx);
        if (!ssl_session) {
            mqtt_sn_log_err("Failed to create SSL session.");
            ERR_print_errors_fp(stderr);
            close(underlying_sock_fd);
            underlying_sock_fd = -1;
            exit(EXIT_FAILURE);
        }

        if (!SSL_set_fd(ssl_session, underlying_sock_fd)) {
            mqtt_sn_log_err("Failed to set file descriptor for SSL session.");
             ERR_print_errors_fp(stderr);
             SSL_free(ssl_session); ssl_session = NULL;
             close(underlying_sock_fd); underlying_sock_fd = -1;
             exit(EXIT_FAILURE);
        }

        // --- Perform DTLS Handshake ---
        mqtt_sn_log_debug("Performing DTLS handshake...");
        int ssl_ret;
        // Loop for non-blocking handshake (less relevant here due to blocking socket with timeout)
        // For simplicity, we attempt a blocking connect here.
        // A robust implementation would handle WANT_READ/WANT_WRITE with select/poll.
        ssl_ret = SSL_connect(ssl_session);
        if (ssl_ret <= 0) {
            int ssl_err = SSL_get_error(ssl_session, ssl_ret);
            mqtt_sn_log_err("DTLS handshake failed (SSL_connect returned %d, error %d).", ssl_ret, ssl_err);
            ERR_print_errors_fp(stderr); // Print OpenSSL error stack
             // Specific error checking
            if (ssl_err == SSL_ERROR_ZERO_RETURN) {
                 mqtt_sn_log_err("  Reason: TLS/DTLS connection was closed cleanly by peer during handshake.");
            } else if (ssl_err == SSL_ERROR_SSL) {
                 mqtt_sn_log_err("  Reason: Fatal SSL error occurred.");
            } else if (ssl_err == SSL_ERROR_SYSCALL) {
                 mqtt_sn_log_err("  Reason: System call error (errno=%d: %s). Check network connectivity/firewall.", errno, strerror(errno));
            }
            SSL_free(ssl_session); ssl_session = NULL;
            close(underlying_sock_fd); underlying_sock_fd = -1;
            exit(EXIT_FAILURE); // Exit on handshake failure
        }
         mqtt_sn_log_debug("DTLS handshake successful. Cipher: %s", SSL_get_cipher_name(ssl_session));

         // Verify server certificate if verification is enabled
        if (SSL_CTX_get_verify_mode(dtls_ctx) & SSL_VERIFY_PEER) {
             long verify_result = SSL_get_verify_result(ssl_session);
             if (verify_result != X509_V_OK) {
                  mqtt_sn_log_err("DTLS server certificate verification failed: %s (Code: %ld)",
                                  X509_verify_cert_error_string(verify_result), verify_result);
                  // Decide whether to exit based on policy, for now we exit
                  SSL_free(ssl_session); ssl_session = NULL;
                  close(underlying_sock_fd); underlying_sock_fd = -1;
                  exit(EXIT_FAILURE);
             } else {
                  mqtt_sn_log_debug("DTLS server certificate verified successfully.");
             }
        }

    } else {
         mqtt_sn_log_debug("DTLS is disabled, using plain UDP.");
    }

    // Setup timeout on the raw socket (important for both DTLS and plain UDP)
    tv.tv_sec = timeout; // Use global timeout setting
    tv.tv_usec = 0;
    if (setsockopt(underlying_sock_fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0) {
        // Log error but don't necessarily exit, socket might still work
        mqtt_sn_log_warn("Failed to set receive timeout on socket: %s", strerror(errno));
    } else {
         mqtt_sn_log_debug("Set socket receive timeout to %d seconds.", timeout);
    }

    return underlying_sock_fd; // Return the underlying FD, DTLS is managed internally
}


// Modified send function
void mqtt_sn_send_packet(int sock /* ignored */, const void* data)
{
    ssize_t sent = 0;
    size_t len = 0; // Initialize len

     // Check if data is valid before accessing length
    if (data == NULL) {
         mqtt_sn_log_err("Attempted to send NULL data packet.");
         return;
    }
    len = ((uint8_t*)data)[0]; // Get length from packet header


    // If forwarder encapsulation enabled, wrap packet FIRST
    // Note: This means DTLS encrypts the *encapsulated* packet
    if (forwarder_encapsulation) {
        // Check if wireless_node_id is set if encapsulation is enabled
        if (wireless_node_id == NULL && wireless_node_id_len == 0) {
             mqtt_sn_log_warn("Forwarder encapsulation enabled but wireless node ID not set. Using default.");
        }
        // We modify the 'data' pointer and 'len' variable to point to the encapsulated packet
        frwdencap_packet_t *encap_packet = mqtt_sn_create_frwdencap_packet(data, &len, wireless_node_id, wireless_node_id_len);
        if (!encap_packet) {
             mqtt_sn_log_err("Failed to create forwarder encapsulation packet.");
             return; // Don't proceed if encapsulation failed
        }
        // Now 'data' points to the dynamic memory of encap_packet, and 'len' is updated
        // We need to free this memory after sending
        data = encap_packet;
    } else {
        // Log non-encapsulated send only if not encapsulated above
        if (debug > 1) {
             mqtt_sn_log_debug("Sending  %2lu bytes. Type=%s (Plain UDP/DTLS)", (long unsigned int)len,
                               mqtt_sn_type_string(((uint8_t*)data)[1]));
        }
    }


    if (dtls_enabled) {
        if (!ssl_session) {
            mqtt_sn_log_err("DTLS send error: SSL session not initialized.");
            // Free encapsulated packet if created
             if (forwarder_encapsulation && data) free((void*)data);
            return;
        }
         mqtt_sn_log_debug("DTLS: Sending %lu bytes...", (long unsigned int)len);
        int ssl_ret;
        // Attempt blocking write. Handle WANT_READ/WANT_WRITE in a robust app.
        ssl_ret = SSL_write(ssl_session, data, len);
        if (ssl_ret <= 0) {
            int ssl_err = SSL_get_error(ssl_session, ssl_ret);
            mqtt_sn_log_err("DTLS SSL_write failed (returned %d, error %d)", ssl_ret, ssl_err);
            ERR_print_errors_fp(stderr);
            // Handle specific errors if needed (e.g., connection closed)
        } else {
            sent = ssl_ret; // SSL_write returns bytes written on success
             mqtt_sn_log_debug("DTLS: Sent %ld bytes.", (long int)sent);
        }
    } else {
         // Plain UDP send using the underlying socket FD
         if (underlying_sock_fd < 0) {
              mqtt_sn_log_err("UDP send error: Socket not initialized.");
               // Free encapsulated packet if created
              if (forwarder_encapsulation && data) free((void*)data);
              return;
         }
         sent = send(underlying_sock_fd, data, len, 0);
         if (sent < 0) {
              mqtt_sn_log_err("UDP send failed: %s", strerror(errno));
         } else {
               mqtt_sn_log_debug("UDP: Sent %ld bytes.", (long int)sent);
         }
    }

     // Free encapsulated packet memory if it was allocated
    if (forwarder_encapsulation && data) {
        free((void*)data); // Cast needed as data was reassigned
    }

    if (sent != len && sent >= 0) { // Check if sent is non-negative before comparing
        mqtt_sn_log_warn("Warning: Only sent %ld of %lu bytes", (long int)sent, (long unsigned int)len);
    }

    // Store the last time that we sent a packet
    last_transmit = time(NULL);
}


// Forwarder send function - now just calls mqtt_sn_send_packet which handles encapsulation if enabled
void mqtt_sn_send_frwdencap_packet(int sock, const void* data, const uint8_t *wlnid, uint8_t wlnid_len)
{
    // We assume forwarder_encapsulation flag is set elsewhere if this is intended
    // The actual encapsulation happens within mqtt_sn_send_packet if the flag is TRUE
     if (!forwarder_encapsulation) {
          mqtt_sn_log_warn("mqtt_sn_send_frwdencap_packet called but forwarder encapsulation is not enabled. Sending plain packet.");
     }
     // Set parameters just in case they weren't set via command line (though they should be)
     mqtt_sn_set_frwdencap_parameters(wlnid, wlnid_len);
     mqtt_sn_send_packet(sock, data); // Let the main send function handle it
}

// Validation function remains mostly the same, but operates on *decrypted* data
uint8_t mqtt_sn_validate_packet(const void *packet, size_t length)
{
    const uint8_t* buf = packet;

    if (length < 2) { // Basic check: need at least length and type
        mqtt_sn_log_warn("Packet too short (length %zu) to be valid.", length);
        return FALSE;
    }

    if (buf[0] == 0x00) {
        mqtt_sn_log_warn("Packet length header (0x00) is not valid");
        return FALSE;
    }

    // Length check: MQTT-SN v1.2: length is the number of octets the PDU consists of.
    // So, the received 'length' should exactly match buf[0].
    if (buf[0] != length) {
        mqtt_sn_log_warn("Packet validation failed: Received length (%zu) does not match header length (%u).", length, buf[0]);
        return FALSE;
    }

    // FRWDENCAP check needs to happen *before* decryption, so it's moved to receive logic.
    // This function now assumes it receives a decrypted, standard MQTT-SN packet.

    return TRUE;
}

// Core receive function - modified for DTLS
void* mqtt_sn_receive_frwdencap_packet(int sock /* ignored */, uint8_t **received_wireless_node_id, uint8_t *received_wireless_node_id_len)
{
    // Increased buffer size slightly for potential DTLS overhead/padding, though SSL_read handles decryption size.
    // The buffer needs to hold the largest *decrypted* MQTT-SN packet + potential FRWDENCAP header *after* decryption.
    static uint8_t dtls_recv_buffer[MQTT_SN_MAX_PACKET_LENGTH + MQTT_SN_MAX_WIRELESS_NODE_ID_LENGTH + 3 + 1 + 512]; // Added extra space
    uint8_t *packet_start = dtls_recv_buffer; // Pointer to the start of the actual MQTT-SN packet data
    ssize_t bytes_read = 0;

    // Initialize output parameters
    if (received_wireless_node_id) *received_wireless_node_id = NULL;
    if (received_wireless_node_id_len) *received_wireless_node_id_len = 0;


    mqtt_sn_log_debug("Waiting for UDP/DTLS packet...");

    if (dtls_enabled) {
        if (!ssl_session) {
            mqtt_sn_log_err("DTLS receive error: SSL session not initialized.");
            return NULL;
        }
         mqtt_sn_log_debug("DTLS: Reading...");
        int ssl_ret;
        // Attempt blocking read. Handle WANT_READ/WANT_WRITE in robust app.
        // SSL_read returns bytes read or <= 0 on error/close
        ssl_ret = SSL_read(ssl_session, dtls_recv_buffer, sizeof(dtls_recv_buffer) - 1); // Leave space for null terminator

        if (ssl_ret <= 0) {
            int ssl_err = SSL_get_error(ssl_session, ssl_ret);
            if (ssl_err == SSL_ERROR_ZERO_RETURN) {
                mqtt_sn_log_debug("DTLS connection closed by peer.");
            } else if (ssl_err == SSL_ERROR_SYSCALL) {
                // Check errno for underlying socket error
                if (errno == EAGAIN || errno == EWOULDBLOCK) {
                    mqtt_sn_log_debug("DTLS receive timed out (underlying socket).");
                } else if (errno == 0 && ssl_ret == -1) {
                     // SSL_ERROR_SYSCALL with errno=0 and ret=-1 often means unexpected EOF
                     mqtt_sn_log_warn("DTLS receive failed: Unexpected EOF (connection likely closed).");
                }
                 else {
                    mqtt_sn_log_warn("DTLS receive failed: Syscall error (errno=%d: %s)", errno, strerror(errno));
                }
            } else if (ssl_err == SSL_ERROR_SSL) {
                 mqtt_sn_log_warn("DTLS receive failed: SSL protocol error.");
                 ERR_print_errors_fp(stderr);
            } else {
                mqtt_sn_log_warn("DTLS SSL_read failed (returned %d, error %d)", ssl_ret, ssl_err);
                ERR_print_errors_fp(stderr);
            }
            return NULL; // Return NULL on any error or timeout
        }
        bytes_read = ssl_ret; // Bytes of decrypted data read
         mqtt_sn_log_debug("DTLS: Received %ld decrypted bytes.", (long int)bytes_read);

    } else {
         // Plain UDP receive
         struct sockaddr_storage addr; // To store sender address (optional)
         socklen_t slen = sizeof(addr);

         if (underlying_sock_fd < 0) {
             mqtt_sn_log_err("UDP receive error: Socket not initialized.");
             return NULL;
         }

         // Use recv() since the socket is connected
         bytes_read = recv(underlying_sock_fd, dtls_recv_buffer, sizeof(dtls_recv_buffer) - 1, 0);

        if (bytes_read < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                mqtt_sn_log_debug("UDP receive timed out.");
            } else {
                mqtt_sn_log_warn("UDP recv failed: %s", strerror(errno));
            }
            return NULL; // Return NULL on error or timeout
        }
         mqtt_sn_log_debug("UDP: Received %ld bytes.", (long int)bytes_read);

         // Optional: Log sender address if needed
         // getpeername(underlying_sock_fd, (struct sockaddr *)&addr, &slen);
         // ... log address info ...
    }


    // --- Process Received Data (Common for DTLS/UDP) ---

    // Packet start currently points to the beginning of the received data
    packet_start = dtls_recv_buffer;

    // Handle Forwarder Encapsulation *after* potential decryption
    if (bytes_read >= 2 && packet_start[1] == MQTT_SN_TYPE_FRWDENCAP) {
         mqtt_sn_log_debug("Received packet is FRWDENCAP type.");
         // Basic validation of FRWDENCAP header length itself
         if (bytes_read < 3 || bytes_read < packet_start[0]) {
              mqtt_sn_log_warn("FRWDENCAP packet too short for header (read %ld, header len %u).", (long int)bytes_read, packet_start[0]);
              return NULL;
         }

         uint8_t header_len = packet_start[0]; // Length of FRWDENCAP header (incl. len+type)
         uint8_t ctrl_byte = packet_start[2]; // Control byte
         uint8_t encap_wlnid_len = header_len - 3; // Length of Wireless Node ID field

         if (encap_wlnid_len > MQTT_SN_MAX_WIRELESS_NODE_ID_LENGTH) {
              mqtt_sn_log_warn("FRWDENCAP Wireless Node ID field too long (%u).", encap_wlnid_len);
              return NULL;
         }

         // Check if the total bytes read accommodate the inner packet
         // Note: Inner packet length is NOT explicitly in FRWDENCAP header
         // We rely on the inner packet's own length field later.

         if (received_wireless_node_id && received_wireless_node_id_len) {
             *received_wireless_node_id = &packet_start[3]; // Point to start of WLNID
             *received_wireless_node_id_len = encap_wlnid_len;
               // Optional: Log the received wireless node ID
                if (debug) {
                     char wlnd_hex[MQTT_SN_MAX_WIRELESS_NODE_ID_LENGTH * 2 + 1] = {0};
                     for(int i=0; i < encap_wlnid_len && i*2 < sizeof(wlnd_hex)-2; ++i) {
                          sprintf(wlnd_hex + i*2, "%02X", (*received_wireless_node_id)[i]);
                     }
                      mqtt_sn_log_debug("  FRWDENCAP Wireless Node ID (len %u): %s", encap_wlnid_len, wlnd_hex);
                }

         }

         // Adjust packet_start to point to the *encapsulated* MQTT-SN packet
         packet_start += header_len;
         // Adjust bytes_read to reflect the length of the *encapsulated* packet
         bytes_read -= header_len;

         if (bytes_read <= 0) {
              mqtt_sn_log_warn("FRWDENCAP packet contains no encapsulated data (header len %u).", header_len);
              return NULL;
         }
          mqtt_sn_log_debug("  Encapsulated packet starts after %u bytes, remaining length %ld.", header_len, (long int)bytes_read);
    } else if (forwarder_encapsulation) {
         // If encapsulation is expected but not received (and not FRWDENCAP type)
          mqtt_sn_log_warn("Forwarder encapsulation enabled, but received non-FRWDENCAP packet (type 0x%02X).", packet_start[1]);
          // Depending on policy, might discard (return NULL) or process anyway.
          // For now, let it proceed to validation.
          // return NULL;
    }


    // Validate the (potentially encapsulated) MQTT-SN packet using its own length header
    if (!mqtt_sn_validate_packet(packet_start, bytes_read)) {
        mqtt_sn_log_warn("Failed validation for received (potentially encapsulated) packet.");
        // No need to print packet details here, validate_packet does it
        return NULL;
    }

    // NULL-terminate the validated packet data area for safety
    // Note: packet_start points to the actual MQTT-SN packet now
    packet_start[bytes_read] = '\0';


    if (debug) {
        // Log the actual MQTT-SN packet type received
        mqtt_sn_log_debug("Successfully processed packet. Type=%s, Length=%ld",
                          mqtt_sn_type_string(packet_start[1]), (long int)bytes_read);
    }

    // Store the last time that we received a packet
    last_receive = time(NULL);

    // Return the pointer to the start of the actual MQTT-SN packet data
    return packet_start;
}

// Wrapper receive function - calls the core receiver
void* mqtt_sn_receive_packet(int sock)
{
    // These outputs are ignored by the caller, but the core function needs them
    uint8_t *wireless_node_id  = NULL;
    uint8_t wireless_node_id_len = 0;

    return mqtt_sn_receive_frwdencap_packet(sock, &wireless_node_id, &wireless_node_id_len);
}


// ---- Other functions largely remain the same, using the modified send/receive ----
// ---- They operate on the assumption that the DTLS layer is handled beneath them ----

void mqtt_sn_send_connect(int sock, const char* client_id, uint16_t keepalive, uint8_t clean_session)
{
    connect_packet_t packet;
    memset(&packet, 0, sizeof(packet));

    if (client_id && strlen(client_id) > MQTT_SN_MAX_CLIENT_ID_LENGTH) {
        mqtt_sn_log_err("Client id '%s' is too long (max %d chars)", client_id, MQTT_SN_MAX_CLIENT_ID_LENGTH);
        exit(EXIT_FAILURE);
    }

    packet.type = MQTT_SN_TYPE_CONNECT;
    packet.flags = clean_session ? MQTT_SN_FLAG_CLEAN : 0;
    packet.protocol_id = MQTT_SN_PROTOCOL_ID;
    packet.duration = htons(keepalive);

    if (client_id == NULL || client_id[0] == '\0') {
        snprintf(packet.client_id, sizeof(packet.client_id), "mqtt-sn-tools-%d", getpid());
         mqtt_sn_log_debug("Using generated Client ID: %s", packet.client_id);
    } else {
        strncpy(packet.client_id, client_id, sizeof(packet.client_id) -1);
         packet.client_id[sizeof(packet.client_id)-1] = '\0'; // Ensure null termination
         mqtt_sn_log_debug("Using provided Client ID: %s", packet.client_id);
    }

    packet.length = 6 + strlen(packet.client_id);

    mqtt_sn_log_debug("Sending CONNECT packet (CleanSession: %d, KeepAlive: %d)...", clean_session, keepalive);

    if (keepalive) {
        keep_alive = keepalive;
         mqtt_sn_log_debug("Keep alive period set to %ld seconds.", (long)keep_alive);
    }

    mqtt_sn_send_packet(sock, &packet);
}

void mqtt_sn_send_register(int sock, const char* topic_name)
{
    if (!topic_name) {
         mqtt_sn_log_err("REGISTER: Topic name cannot be NULL.");
         return;
    }
    size_t topic_name_len = strlen(topic_name);
    register_packet_t packet;
    memset(&packet, 0, sizeof(packet));

    if (topic_name_len == 0) {
        mqtt_sn_log_err("REGISTER: Topic name cannot be empty.");
        return; // Or exit? For now, just return.
    }
    if (topic_name_len > sizeof(packet.topic_name)) {
        mqtt_sn_log_err("REGISTER: Topic name '%s' is too long (max %zu)", topic_name, sizeof(packet.topic_name));
        exit(EXIT_FAILURE);
    }

    packet.type = MQTT_SN_TYPE_REGISTER;
    packet.topic_id = 0; // Must be 0 for REGISTER
    packet.message_id = htons(next_message_id++);
    memcpy(packet.topic_name, topic_name, topic_name_len); // Use memcpy, already know length
    packet.length = 6 + topic_name_len;

    mqtt_sn_log_debug("Sending REGISTER packet (MsgId: %d, Topic: %s)...", ntohs(packet.message_id), topic_name);

    mqtt_sn_send_packet(sock, &packet);
}

void mqtt_sn_send_regack(int sock, int topic_id, int message_id) // Changed arg type for clarity
{
    regack_packet_t packet;
    memset(&packet, 0, sizeof(packet));

    packet.type = MQTT_SN_TYPE_REGACK;
    packet.topic_id = htons(topic_id);
    packet.message_id = htons(message_id);
    packet.return_code = MQTT_SN_ACCEPTED; // Assuming success here
    packet.length = 7;

    mqtt_sn_log_debug("Sending REGACK packet (MsgId: %d, TopicId: 0x%04X, RC: %d)...",
                      message_id, topic_id, packet.return_code);

    mqtt_sn_send_packet(sock, &packet);
}

static uint8_t mqtt_sn_get_qos_flag(int8_t qos)
{
    switch (qos) {
        case -1: return MQTT_SN_FLAG_QOS_N1;
        case 0:  return MQTT_SN_FLAG_QOS_0;
        case 1:  return MQTT_SN_FLAG_QOS_1;
        case 2:  return MQTT_SN_FLAG_QOS_2; // Note: QoS 2 is not fully handled in this client
        default:
             mqtt_sn_log_warn("Invalid QoS level %d requested, defaulting to QoS 0 flag.", qos);
             return MQTT_SN_FLAG_QOS_0;
    }
}

void mqtt_sn_send_publish(int sock, uint16_t topic_id, uint8_t topic_type, const void* data, uint16_t data_len, int8_t qos, uint8_t retain)
{
    publish_packet_t packet; // Use stack allocation if possible
    memset(&packet, 0, sizeof(packet));

    // Check payload size against the struct field size
    if (data_len > sizeof(packet.data)) {
        mqtt_sn_log_err("PUBLISH payload size (%u) exceeds maximum allowed (%zu).", data_len, sizeof(packet.data));
        exit(EXIT_FAILURE); // Consider returning error instead of exit
    }
    // Check payload size against MQTT-SN overall limit derived from length field (1 byte)
    if (7 + data_len > 255) {
         mqtt_sn_log_err("PUBLISH total packet size (%d) would exceed 255 bytes.", 7 + data_len);
         exit(EXIT_FAILURE); // Consider returning error
    }
    if (!data && data_len > 0) {
         mqtt_sn_log_err("PUBLISH data is NULL but data_len (%u) > 0.", data_len);
         exit(EXIT_FAILURE); // Or return error
    }


    packet.type = MQTT_SN_TYPE_PUBLISH;
    packet.flags = 0x00;
    packet.flags |= (retain ? MQTT_SN_FLAG_RETAIN : 0);
    packet.flags |= mqtt_sn_get_qos_flag(qos);
    packet.flags |= (topic_type & 0x03); // Mask to ensure only valid topic type bits

    packet.topic_id = htons(topic_id);
    // Assign Message ID only if QoS > 0
    if (qos > 0) {
        packet.message_id = htons(next_message_id++);
    } else {
        packet.message_id = 0x0000;
    }

    // Copy payload if it exists
    if (data && data_len > 0) {
        memcpy(packet.data, data, data_len);
    }
    packet.length = 7 + data_len;

    mqtt_sn_log_debug("Sending PUBLISH packet (MsgId: %d, TopicId: 0x%04X, QoS: %d, Retain: %d, Len: %u)...",
                      ntohs(packet.message_id), topic_id, qos, retain, data_len);

    mqtt_sn_send_packet(sock, &packet);

    // Handle QoS 1 PUBACK expectation
    if (qos == 1) {
        mqtt_sn_log_debug("Waiting for PUBACK for MsgId: %d...", ntohs(packet.message_id));
        // Use mqtt_sn_wait_for which handles timeouts and other packets
        puback_packet_t *puback_resp = mqtt_sn_wait_for(MQTT_SN_TYPE_PUBACK, sock);
        if (puback_resp) {
             // Check if the PUBACK matches the PUBLISH
             if (puback_resp->topic_id == packet.topic_id && puback_resp->message_id == packet.message_id) {
                  if (puback_resp->return_code == MQTT_SN_ACCEPTED) {
                        mqtt_sn_log_debug("Received matching PUBACK (RC: Accepted).");
                  } else {
                        mqtt_sn_log_warn("Received matching PUBACK but with error code: %s (%d)",
                                         mqtt_sn_return_code_string(puback_resp->return_code), puback_resp->return_code);
                  }
             } else {
                   mqtt_sn_log_warn("Received PUBACK, but it does not match the sent PUBLISH (Expected MsgId: %d, TopicId: 0x%04X; Got MsgId: %d, TopicId: 0x%04X)",
                                   ntohs(packet.message_id), ntohs(packet.topic_id),
                                   ntohs(puback_resp->message_id), ntohs(puback_resp->topic_id));
                   // This might indicate an out-of-order packet or issue at the gateway
             }
        } else {
            // mqtt_sn_wait_for already logged timeout/error
            mqtt_sn_log_warn("Did not receive PUBACK for MsgId: %d.", ntohs(packet.message_id));
             // Consider retransmission logic here in a more robust client
        }
    }
     // Note: QoS 2 flow (PUBREC, PUBREL, PUBCOMP) is not implemented here.
}

void mqtt_sn_send_puback(int sock, publish_packet_t* publish, uint8_t return_code)
{
    if (!publish) {
        mqtt_sn_log_err("PUBACK: publish packet cannot be NULL.");
        return;
    }
    puback_packet_t puback;
    memset(&puback, 0, sizeof(puback));

    puback.type = MQTT_SN_TYPE_PUBACK;
    puback.topic_id = publish->topic_id; // Already in network byte order from received publish
    puback.message_id = publish->message_id; // Already in network byte order
    puback.return_code = return_code;
    puback.length = 7;

    mqtt_sn_log_debug("Sending PUBACK packet (MsgId: %d, TopicId: 0x%04X, RC: %d)...",
                      ntohs(puback.message_id), ntohs(puback.topic_id), return_code);

    mqtt_sn_send_packet(sock, &puback);
}

void mqtt_sn_send_subscribe_topic_name(int sock, const char* topic_name, uint8_t qos) // QoS type changed for consistency
{
     if (!topic_name) {
         mqtt_sn_log_err("SUBSCRIBE: Topic name cannot be NULL.");
         return;
    }
    size_t topic_name_len = strlen(topic_name);
    subscribe_packet_t packet;
    memset(&packet, 0, sizeof(packet));

     if (topic_name_len == 0) {
        mqtt_sn_log_err("SUBSCRIBE: Topic name cannot be empty.");
        return; // Or exit?
    }
    // Check length against struct field size AND overall packet limit
    if (topic_name_len > sizeof(packet.topic_name)) {
        mqtt_sn_log_err("SUBSCRIBE Topic name '%s' is too long (max %zu)", topic_name, sizeof(packet.topic_name));
        exit(EXIT_FAILURE);
    }
     if (5 + topic_name_len > 255) {
         mqtt_sn_log_err("SUBSCRIBE total packet size (%zu) would exceed 255 bytes.", 5 + topic_name_len);
         exit(EXIT_FAILURE);
     }

    packet.type = MQTT_SN_TYPE_SUBSCRIBE;
    packet.flags = 0x00;
    packet.flags |= mqtt_sn_get_qos_flag(qos);
    // Determine topic type based on name length
    if (topic_name_len == 2) {
        packet.flags |= MQTT_SN_TOPIC_TYPE_SHORT;
    } else {
        packet.flags |= MQTT_SN_TOPIC_TYPE_NORMAL;
    }
    packet.message_id = htons(next_message_id++);
    memcpy(packet.topic_name, topic_name, topic_name_len); // Use memcpy

    packet.length = 5 + topic_name_len;

    mqtt_sn_log_debug("Sending SUBSCRIBE packet (MsgId: %d, Topic: %s, QoS: %d)...",
                      ntohs(packet.message_id), topic_name, qos);

    mqtt_sn_send_packet(sock, &packet);
}

void mqtt_sn_send_subscribe_topic_id(int sock, uint16_t topic_id, uint8_t qos) // QoS type changed
{
    subscribe_packet_t packet;
    memset(&packet, 0, sizeof(packet));

    packet.type = MQTT_SN_TYPE_SUBSCRIBE;
    packet.flags = 0x00;
    packet.flags |= mqtt_sn_get_qos_flag(qos);
    packet.flags |= MQTT_SN_TOPIC_TYPE_PREDEFINED; // Topic type is predefined
    packet.message_id = htons(next_message_id++);
    packet.topic_id = htons(topic_id); // Put topic_id in the union field
    packet.length = 7; // Length is fixed for predefined topic id subscription

    mqtt_sn_log_debug("Sending SUBSCRIBE packet (MsgId: %d, Predefined TopicId: 0x%04X, QoS: %d)...",
                      ntohs(packet.message_id), topic_id, qos);

    mqtt_sn_send_packet(sock, &packet);
}

void mqtt_sn_send_pingreq(int sock)
{
    // Use a static buffer for simple, fixed packets
    static const uint8_t packet[2] = {2, MQTT_SN_TYPE_PINGREQ};

    mqtt_sn_log_debug("Sending PINGREQ packet...");

    mqtt_sn_send_packet(sock, packet); // Pass the static buffer
}

void mqtt_sn_send_disconnect(int sock, uint16_t duration)
{
    disconnect_packet_t packet;
    memset(&packet, 0, sizeof(packet));

    packet.type = MQTT_SN_TYPE_DISCONNECT;
    if (duration == 0) {
        packet.length = 2; // Only length and type for standard disconnect
        mqtt_sn_log_debug("Sending DISCONNECT packet...");
    } else {
        packet.length = 4; // Length, type, duration
        packet.duration = htons(duration);
        mqtt_sn_log_debug("Sending DISCONNECT packet with Sleep Duration %d...", duration);
    }

    mqtt_sn_send_packet(sock, &packet);
}

// Receive disconnect needs to handle the case where the other side sends one
void mqtt_sn_receive_disconnect(int sock)
{
    mqtt_sn_log_debug("Waiting for DISCONNECT confirmation or response...");
    disconnect_packet_t *packet = mqtt_sn_wait_for(MQTT_SN_TYPE_DISCONNECT, sock);

    if (packet == NULL) {
        // This can happen if the wait times out, which might be expected after sending DISCONNECT
        mqtt_sn_log_debug("Did not receive DISCONNECT response from gateway (timeout or other issue).");
        // Don't exit failure here, as the goal was to disconnect anyway.
    } else {
        // Check Disconnect return duration if present (optional feature)
        if (packet->length == 4) {
            mqtt_sn_log_debug("Received DISCONNECT response with duration %d.", ntohs(packet->duration));
        } else {
             mqtt_sn_log_debug("Received DISCONNECT response (no duration).");
        }
    }
}


void mqtt_sn_receive_connack(int sock)
{
    mqtt_sn_log_debug("Waiting for CONNACK...");
    // Use wait_for which handles other packet types and timeouts
    connack_packet_t *packet = mqtt_sn_wait_for(MQTT_SN_TYPE_CONNACK, sock);

    if (packet == NULL) {
        mqtt_sn_log_err("Failed to receive CONNACK from MQTT-SN gateway (timeout or other error).");
        // Maybe cleanup DTLS if initialized?
        if(dtls_enabled) mqtt_sn_dtls_cleanup();
        exit(EXIT_FAILURE);
    }

    // Check Connack return code
    mqtt_sn_log_debug("CONNACK received. Return Code: 0x%02X (%s)",
                      packet->return_code, mqtt_sn_return_code_string(packet->return_code));

    if (packet->return_code != MQTT_SN_ACCEPTED) {
        mqtt_sn_log_err("Connection rejected by gateway: %s", mqtt_sn_return_code_string(packet->return_code));
         if(dtls_enabled) mqtt_sn_dtls_cleanup();
        exit(packet->return_code); // Exit with the specific error code
    }
     mqtt_sn_log_debug("Connection Accepted by gateway.");
}

// Processes incoming REGISTER requests (if this client were acting as a gateway/bridge)
// For a simple client, receiving REGISTER is unexpected.
static int mqtt_sn_process_register(int sock, const register_packet_t *packet)
{
    if (!packet) return -1;

     mqtt_sn_log_warn("Received unexpected REGISTER packet from gateway (Topic: %s, MsgId: %d). This client does not process registrations.",
                     packet->topic_name, ntohs(packet->message_id));

    // A simple client shouldn't normally receive REGISTER packets.
    // If it did, it might indicate a configuration error or unexpected gateway behavior.
    // We could optionally send a REGACK with an error code?
    // For now, just log the warning.

    // int message_id = ntohs(packet->message_id);
    // int topic_id = ntohs(packet->topic_id); // This would be 0 in a received REGISTER
    // const char* topic_name = packet->topic_name;

    // // Respond with REGACK (potentially with error code?)
    // mqtt_sn_send_regack(sock, 0, message_id); // Send back with topic_id=0 and error?

    return 0; // Indicate processed (by logging)
}

// Topic registration remains the same conceptually
void mqtt_sn_register_topic(int topic_id, const char* topic_name)
{
    topic_map_t **ptr = &topic_map;

    if (topic_id == 0x0000 || topic_id == 0xFFFF) {
        mqtt_sn_log_warn("Attempted to register invalid topic id: 0x%04X", topic_id);
        return;
    }
    if (topic_name == NULL || strlen(topic_name) == 0) {
        mqtt_sn_log_warn("Attempted to register invalid topic name (NULL or empty).");
        return;
    }
    if (strlen(topic_name) >= MQTT_SN_MAX_TOPIC_LENGTH) {
         mqtt_sn_log_warn("Attempted to register topic name longer than max length (%d): %s", MQTT_SN_MAX_TOPIC_LENGTH, topic_name);
         // Truncate? For now, just proceed but be aware.
    }


    mqtt_sn_log_debug("Registering Topic Map: ID=0x%04X, Name='%s'", topic_id, topic_name);

    while (*ptr) {
        if ((*ptr)->topic_id == topic_id) {
             mqtt_sn_log_debug("  Updating existing entry for Topic ID 0x%04X.", topic_id);
            break; // Found existing entry for this ID
        } else if (strncmp((*ptr)->topic_name, topic_name, MQTT_SN_MAX_TOPIC_LENGTH) == 0) {
             mqtt_sn_log_debug("  Updating existing entry for Topic Name '%s' (ID was 0x%04X, changing to 0x%04X).", topic_name, (*ptr)->topic_id, topic_id);
             break; // Found existing entry for this Name
        }
        ptr = &((*ptr)->next);
    }

    if (*ptr == NULL) {
         mqtt_sn_log_debug("  Creating new entry.");
        *ptr = malloc(sizeof(topic_map_t));
        if (!*ptr) {
            mqtt_sn_log_err("Failed to allocate memory for topic map entry!");
            // Consider cleanup before exit
             if(dtls_enabled) mqtt_sn_dtls_cleanup();
            exit(EXIT_FAILURE);
        }
        (*ptr)->next = NULL;
    }

    // Copy data into the entry (*ptr points to the correct entry now)
    (*ptr)->topic_id = topic_id;
    strncpy((*ptr)->topic_name, topic_name, sizeof((*ptr)->topic_name) - 1);
    (*ptr)->topic_name[sizeof((*ptr)->topic_name) - 1] = '\0'; // Ensure null termination
}

const char* mqtt_sn_lookup_topic(int topic_id)
{
    topic_map_t *current = topic_map; // Use a temporary pointer to iterate

    while (current) {
        if (current->topic_id == topic_id) {
            return current->topic_name;
        }
        current = current->next;
    }

    mqtt_sn_log_debug("Failed to lookup topic name for topic id: 0x%04X", topic_id);
    return NULL; // Not found
}


uint16_t mqtt_sn_receive_regack(int sock)
{
     mqtt_sn_log_debug("Waiting for REGACK...");
    regack_packet_t *packet = mqtt_sn_wait_for(MQTT_SN_TYPE_REGACK, sock);
    uint16_t received_message_id, received_topic_id;

    if (packet == NULL) {
        mqtt_sn_log_err("Failed to receive REGACK from MQTT-SN gateway.");
         if(dtls_enabled) mqtt_sn_dtls_cleanup();
        exit(EXIT_FAILURE);
    }

    received_message_id = ntohs(packet->message_id);
    received_topic_id = ntohs(packet->topic_id);

    mqtt_sn_log_debug("REGACK received. MsgId: %d, TopicId: 0x%04X, RC: 0x%02X (%s)",
                      received_message_id, received_topic_id,
                      packet->return_code, mqtt_sn_return_code_string(packet->return_code));

    // Check if the Message ID matches the last one sent (next_message_id - 1)
    // This assumes REGISTER was the very last message requiring an ack.
    if (received_message_id != next_message_id - 1) {
        mqtt_sn_log_warn("Received REGACK MsgId (%d) does not match the last sent message ID (%d).",
                         received_message_id, next_message_id - 1);
        // Don't exit, but log warning. Could be due to timing or other messages sent.
    }

    // Check Regack return code
    if (packet->return_code != MQTT_SN_ACCEPTED) {
        mqtt_sn_log_err("Topic registration failed by gateway: %s", mqtt_sn_return_code_string(packet->return_code));
         if(dtls_enabled) mqtt_sn_dtls_cleanup();
        exit(packet->return_code);
    }

    // Return the topic ID assigned by the gateway
    return received_topic_id;
}

// Dump packet remains the same - operates on decrypted data
void mqtt_sn_dump_packet(char* packet) { /* ... original code ... */ }

// Print publish packet remains the same - operates on decrypted data
void mqtt_sn_print_publish_packet(publish_packet_t* packet) { /* ... original code ... */ }


uint16_t mqtt_sn_receive_suback(int sock)
{
     mqtt_sn_log_debug("Waiting for SUBACK...");
    suback_packet_t *packet = mqtt_sn_wait_for(MQTT_SN_TYPE_SUBACK, sock);
    uint16_t received_message_id, received_topic_id;
     uint8_t received_qos; // To store granted QoS

    if (packet == NULL) {
        mqtt_sn_log_err("Failed to receive SUBACK from MQTT-SN gateway.");
         if(dtls_enabled) mqtt_sn_dtls_cleanup();
        exit(EXIT_FAILURE);
    }

     received_message_id = ntohs(packet->message_id);
     received_topic_id = ntohs(packet->topic_id);
     received_qos = (packet->flags & MQTT_SN_FLAG_QOS_MASK); // Extract QoS level granted

    mqtt_sn_log_debug("SUBACK received. MsgId: %d, TopicId: 0x%04X, Granted QoS Flag: 0x%02X, RC: 0x%02X (%s)",
                      received_message_id, received_topic_id, received_qos,
                      packet->return_code, mqtt_sn_return_code_string(packet->return_code));


    // Check if the Message ID matches the last one sent
    if (received_message_id != next_message_id - 1) {
        mqtt_sn_log_warn("Received SUBACK MsgId (%d) does not match the last sent message ID (%d).",
                         received_message_id, next_message_id - 1);
    }

    // Check Suback return code
    if (packet->return_code != MQTT_SN_ACCEPTED) {
        mqtt_sn_log_err("Subscription failed by gateway: %s", mqtt_sn_return_code_string(packet->return_code));
         if(dtls_enabled) mqtt_sn_dtls_cleanup();
        exit(packet->return_code);
    }

    // Optional: Check if granted QoS matches requested QoS (not stored currently)

    // Return the topic ID confirmed/assigned by the gateway (useful if subscribing by name)
    return received_topic_id;
}

// Select needs to operate on the underlying socket FD
int mqtt_sn_select(int sock /* ignored, uses underlying_sock_fd */)
{
    struct timeval tv;
    fd_set rfd;
    int ret;

     // Check if the underlying socket is valid
     if (underlying_sock_fd < 0) {
          mqtt_sn_log_err("Select error: Underlying socket not initialized.");
          return -1; // Indicate error
     }

    FD_ZERO(&rfd);
    FD_SET(underlying_sock_fd, &rfd); // Use the raw UDP socket FD

    // Use a potentially shorter timeout for select itself,
    // as the main timeout logic is handled in mqtt_sn_wait_for
    // and the socket SO_RCVTIMEO handles blocking receive timeout.
    // Let's use 1 second for select polling interval.
    tv.tv_sec = 1;
    tv.tv_usec = 0;

    ret = select(underlying_sock_fd + 1, &rfd, NULL, NULL, &tv);
    if (ret < 0) {
         if (errno == EINTR) {
              mqtt_sn_log_debug("Select interrupted, continuing...");
              return 0; // Treat as no data ready yet
         } else {
             mqtt_sn_log_err("Select error: %s", strerror(errno));
             // Consider exiting or returning error
             return -1; // Indicate error
         }
    }

    // ret == 0 means timeout (no data ready within tv interval)
    // ret > 0 means data is available on underlying_sock_fd
    return ret;
}


// Wait_for loop needs to handle other incoming packets correctly
void* mqtt_sn_wait_for(uint8_t type, int sock /* ignored */)
{
    time_t started_waiting = time(NULL);
     time_t now = time(NULL); // Initialize now

     mqtt_sn_log_debug("Waiting for packet type 0x%02X (%s)... (Timeout: %ds, KeepAlive: %lds)",
                      type, mqtt_sn_type_string(type), timeout, (long)keep_alive);

    while(TRUE) {
        now = time(NULL); // Update current time

        // --- Keep Alive Check ---
        // Send PINGREQ if connected and keep_alive is enabled and interval passed
        // Assumes 'connected' state implicitly - add proper state check if needed
        if (keep_alive > 0 && (now - last_transmit) >= keep_alive) {
            mqtt_sn_send_pingreq(sock); // sock arg is ignored, uses internal state
            // last_transmit is updated within send_pingreq -> send_packet
        }

        // --- Check for Incoming Data using Select ---
        int select_ret = mqtt_sn_select(sock); // sock arg is ignored

        if (select_ret < 0) {
             mqtt_sn_log_err("Error during select in wait_for. Aborting wait.");
             return NULL; // Error in select
        } else if (select_ret > 0) {
             // Data might be available, attempt to receive and process
              mqtt_sn_log_debug("Select indicated data ready, attempting receive...");
             // Call the core receive function
             uint8_t *r_wlnid = NULL; uint8_t r_wlnid_len = 0; // Dummy vars for receive call
             char* packet = mqtt_sn_receive_frwdencap_packet(sock, &r_wlnid, &r_wlnid_len); // sock arg ignored

             if (packet) {
                 // --- Process Received Packet ---
                 uint8_t received_type = packet[1];
                  mqtt_sn_log_debug("Processing received packet type 0x%02X (%s).", received_type, mqtt_sn_type_string(received_type));

                 // Did we find the packet type we were waiting for?
                 if (received_type == type) {
                      mqtt_sn_log_debug("Found expected packet type: %s.", mqtt_sn_type_string(type));
                     return packet; // Success! Return the packet buffer
                 }

                 // --- Handle Other Common Packet Types ---
                 switch(received_type) {
                    case MQTT_SN_TYPE_PUBLISH:
                        // Process publish if not the target type (e.g., if waiting for SUBACK)
                         mqtt_sn_log_debug("Received PUBLISH while waiting for %s.", mqtt_sn_type_string(type));
                        mqtt_sn_print_publish_packet((publish_packet_t *)packet);
                        // Handle QoS 1 PUBACK if needed
                        if ((packet[2] & MQTT_SN_FLAG_QOS_MASK) == MQTT_SN_FLAG_QOS_1) {
                             mqtt_sn_send_puback(sock, (publish_packet_t*)packet, MQTT_SN_ACCEPTED);
                        }
                        break;

                    case MQTT_SN_TYPE_REGISTER:
                        // Client usually doesn't receive REGISTER, but handle it defensively
                         mqtt_sn_log_debug("Received REGISTER while waiting for %s.", mqtt_sn_type_string(type));
                        mqtt_sn_process_register(sock, (register_packet_t*)packet);
                        break;

                    case MQTT_SN_TYPE_PINGRESP:
                         mqtt_sn_log_debug("Received PINGRESP.");
                        // No action needed, just resets keep-alive timer implicitly via last_receive update
                        break;

                     case MQTT_SN_TYPE_PINGREQ:
                          mqtt_sn_log_warn("Received unexpected PINGREQ from gateway.");
                          // Respond with PINGRESP? Standard client shouldn't need to.
                          break;

                    case MQTT_SN_TYPE_DISCONNECT:
                         mqtt_sn_log_warn("Received DISCONNECT from gateway while waiting for %s.", mqtt_sn_type_string(type));
                         // If we were waiting for DISCONNECT, return it
                         if (type == MQTT_SN_TYPE_DISCONNECT) return packet;
                         // Otherwise, treat as an error/unexpected termination
                          mqtt_sn_log_err("Gateway initiated disconnect unexpectedly.");
                          if(dtls_enabled) mqtt_sn_dtls_cleanup();
                          exit(EXIT_FAILURE); // Or handle more gracefully
                         break;

                    // Add cases for other packets that might be received unexpectedly
                    // but shouldn't abort the wait (e.g., PUBACK for a previous QoS1 message)
                     case MQTT_SN_TYPE_PUBACK:
                          mqtt_sn_log_debug("Received PUBACK while waiting for %s (MsgId: %d).",
                                           mqtt_sn_type_string(type), ntohs(((puback_packet_t*)packet)->message_id) );
                          // Ignore if not waiting for PUBACK
                          break;
                     case MQTT_SN_TYPE_REGACK:
                     case MQTT_SN_TYPE_SUBACK:
                          mqtt_sn_log_debug("Received %s while waiting for %s.",
                                            mqtt_sn_type_string(received_type), mqtt_sn_type_string(type));
                           // Ignore if not the expected ACK type
                           break;


                    default:
                         mqtt_sn_log_warn("Received unhandled packet type 0x%02X (%s) while waiting for %s.",
                                          received_type, mqtt_sn_type_string(received_type), mqtt_sn_type_string(type));
                         // Continue waiting
                        break;
                 } // End switch on received packet type

             } else {
                  // mqtt_sn_receive_packet returned NULL.
                  // This usually means timeout happened during the SSL_read/recv call
                  // OR a genuine error occurred. The receive function already logged details.
                   mqtt_sn_log_debug("Receive function returned NULL (likely timeout or error).");
             }
        } else {
             // select_ret == 0 means select timed out (1 second interval)
              mqtt_sn_log_debug("Select timed out (no data available).");
             // Continue loop to check overall timeout and keep-alive
        }


        // --- Check for Overall Timeouts ---
        now = time(NULL); // Update time again after potentially long receive/process

        // Check for Gateway Keep Alive Timeout (based on last receive)
        // Use 1.5 * keep_alive as grace period
        if (keep_alive > 0 && (now - last_receive) >= (time_t)(keep_alive * 1.5) && last_receive > 0 ) {
             mqtt_sn_log_err("Keep alive TIMEOUT: No packet received from gateway for ~%.1f seconds (KeepAlive=%lds).",
                            (double)(now - last_receive), (long)keep_alive);
             // Consider cleanup and exit
              if(dtls_enabled) mqtt_sn_dtls_cleanup();
             exit(EXIT_FAILURE);
        }

        // Check for Function Call Timeout (based on when wait_for started)
        if ((now - started_waiting) >= timeout) {
            mqtt_sn_log_warn("Overall TIMEOUT waiting for %s packet (waited %ld seconds).",
                            mqtt_sn_type_string(type), (long)(now - started_waiting));
            return NULL; // Return NULL to indicate timeout for the specific packet type
        }

         // Small sleep to prevent busy-waiting if select times out quickly
         // Only sleep if select returned 0 (timeout)
         if (select_ret == 0) {
              usleep(10000); // Sleep for 10ms
         }


    } // End while(TRUE)

    // Should not be reached normally
    return NULL;
}


// Type string function remains the same
const char* mqtt_sn_type_string(uint8_t type) { /* ... original code ... */ }

// Return code string function remains the same
const char* mqtt_sn_return_code_string(uint8_t return_code) { /* ... original code ... */ }

// Cleanup function - add DTLS cleanup
void mqtt_sn_cleanup()
{
     mqtt_sn_log_debug("Performing general MQTT-SN cleanup...");
    topic_map_t *ptr = topic_map;
    topic_map_t *ptr2 = NULL;

    // Walk through the topic map, deleting each entry
    while (ptr) {
        ptr2 = ptr;
        ptr = ptr->next;
         mqtt_sn_log_debug("  Freeing topic map entry (ID: 0x%04X, Name: %s)", ptr2->topic_id, ptr2->topic_name);
        free(ptr2);
    }
    topic_map = NULL;
     mqtt_sn_log_debug("Topic map cleaned.");

     // Clean up DTLS resources if they were initialized
     if (dtls_enabled || dtls_ctx || ssl_session) { // Check if any DTLS resource might exist
          mqtt_sn_dtls_cleanup();
     }

     // Close the underlying socket if it's still open
     if (underlying_sock_fd >= 0) {
          mqtt_sn_log_debug("Closing underlying socket FD: %d", underlying_sock_fd);
          close(underlying_sock_fd);
          underlying_sock_fd = -1;
     }
      mqtt_sn_log_debug("MQTT-SN cleanup complete.");
}

// Forwarder encapsulation enable/disable/set parameters remain the same
uint8_t mqtt_sn_enable_frwdencap() { /* ... original code ... */ }
uint8_t mqtt_sn_disable_frwdencap() { /* ... original code ... */ }
void mqtt_sn_set_frwdencap_parameters(const uint8_t *wlnid, uint8_t wlnid_len) { /* ... original code ... */ }
// Create forwarder packet remains the same conceptually, operates on plaintext before encryption
frwdencap_packet_t* mqtt_sn_create_frwdencap_packet(const void *data, size_t *len, const uint8_t *wireless_node_id, uint8_t wireless_node_id_len) {
     /* ... original code ... */
     // Ensure malloc result is checked
     frwdencap_packet_t* packet = malloc(sizeof(frwdencap_packet_t));
      if (!packet) {
           mqtt_sn_log_err("Failed to allocate memory for frwdencap packet!");
           // Don't exit here, return NULL so caller can handle
           return NULL;
      }
       memset(packet, 0, sizeof(frwdencap_packet_t)); // Initialize memory
      // ... rest of original code ...
      return packet;
}


// Logging functions remain the same
static void mqtt_sn_log_msg(const char* level, const char* format, va_list arglist) { /* ... original code ... */ }
void mqtt_sn_log_debug(const char * format, ...) { /* ... original code ... */ }
void mqtt_sn_log_warn(const char * format, ...) { /* ... original code ... */ }
void mqtt_sn_log_err(const char * format, ...) { /* ... original code ... */ }