#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <signal.h>
#include <pthread.h>
#include <sys/stat.h>
#include <time.h>
#include <limits.h>

#define MAX_BUFFER 8192
#define DEFAULT_PORT 80
#define CACHE_DIR "./cache"
#define BLOCKLIST "./blocklist"

volatile sig_atomic_t keep_running = 1;
int timeout = 0;

typedef struct {
    char method[8];
    char url[MAX_BUFFER];
    char host[MAX_BUFFER];
    char path[MAX_BUFFER];
    int port;
} http_request;

void handle_sigint(int sig);
void *handle_client(void *client_sock);
int parse_request(char *request, http_request *req);
int check_blocklist(const char *host);
char *get_cache_filename(const char *url);
int is_cached_valid(const char *cache_file);
void cache_response(const char *cache_file, const char *response);

unsigned long hash_string(const char *str) {
    unsigned long hash = 5381;
    int c;
    while ((c = *str++))
        hash = ((hash << 5) + hash) + c;
    return hash;
}

int parse_request(char *request, http_request *req) {
    memset(req, 0, sizeof(http_request));
    req->port = DEFAULT_PORT;

    char *token = strtok(request, " ");
    if (!token || strcmp(token, "GET") != 0) {
        return 400; 
    }
    strncpy(req->method, token, sizeof(req->method) - 1);

    token = strtok(NULL, " ");
    if (!token || strlen(token) >= MAX_BUFFER) {
        return 400;
    }
    strncpy(req->url, token, sizeof(req->url) - 1);

    if (strncmp(req->url, "http://", 7) == 0) {
        char *host_start = req->url + 7;
        char *path_start = strchr(host_start, '/');
        
        if (!path_start) {
            strncpy(req->path, "/", sizeof(req->path) - 1);
        } else {
            strncpy(req->path, path_start, sizeof(req->path) - 1);
            *path_start = '\0';
        }

        // Check for port number in host
        char *port_start = strchr(host_start, ':');
        if (port_start) {
            *port_start = '\0';
            req->port = atoi(port_start + 1);
        }
        
        strncpy(req->host, host_start, sizeof(req->host) - 1);
    } else {
        return 400;
    }

    return 200;
}

int check_blocklist(const char *host) {
    FILE *fp = fopen(BLOCKLIST, "r");
    if (!fp) return 0;

    char line[MAX_BUFFER];
    while (fgets(line, sizeof(line), fp)) {
        line[strcspn(line, "\n")] = 0;
        if (strcmp(line, host) == 0) {
            fclose(fp);
            return 1;
        }
    }
    fclose(fp);
    return 0;
}

char *get_cache_filename(const char *url) {
    char *filename = malloc(4096);
    snprintf(filename, 4096, "%s/%lu", CACHE_DIR, hash_string(url));
    return filename;
}

int is_cached_valid(const char *cache_file) {
    struct stat st;
    if (stat(cache_file, &st) != 0) {
        return 0;
    }

    time_t now = time(NULL);
    return (now - st.st_mtime) < timeout;
}

void *handle_client(void *arg) {
    int client_sock = *(int *)arg;
    free(arg);
    
    char buffer[MAX_BUFFER];
    char response[MAX_BUFFER];
    ssize_t bytes_read;

    bytes_read = recv(client_sock, buffer, sizeof(buffer) - 1, 0);
    if (bytes_read <= 0) {
        close(client_sock);
        return NULL;
    }
    buffer[bytes_read] = '\0';

    http_request req;
    int status = parse_request(buffer, &req);
    if (status != 200) {
        snprintf(response, sizeof(response),
                "HTTP/1.1 %d %s\r\n\r\n",
                status,
                status == 400 ? "Bad Request" : "Internal Server Error");
        send(client_sock, response, strlen(response), 0);
        close(client_sock);
        return NULL;
    }

    if (check_blocklist(req.host)) {
        snprintf(response, sizeof(response),
                "HTTP/1.1 403 Forbidden\r\n\r\n");
        send(client_sock, response, strlen(response), 0);
        close(client_sock);
        return NULL;
    }

    char *cache_file = get_cache_filename(req.url);
    if (timeout > 0 && is_cached_valid(cache_file)) {
        FILE *fp = fopen(cache_file, "r");
        while ((bytes_read = fread(buffer, 1, sizeof(buffer), fp)) > 0) {
            send(client_sock, buffer, bytes_read, 0);
        }
        fclose(fp);
        free(cache_file);
        close(client_sock);
        return NULL;
    }

    struct hostent *server = gethostbyname(req.host);
    if (!server) {
        snprintf(response, sizeof(response),
                "HTTP/1.1 404 Not Found\r\n\r\n");
        send(client_sock, response, strlen(response), 0);
        free(cache_file);
        close(client_sock);
        return NULL;
    }

    int server_sock = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in server_addr = {
        .sin_family = AF_INET,
        .sin_port = htons(req.port),
    };
    memcpy(&server_addr.sin_addr.s_addr, server->h_addr, server->h_length);

    if (connect(server_sock, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        snprintf(response, sizeof(response),
                "HTTP/1.1 502 Bad Gateway\r\n\r\n");
        send(client_sock, response, strlen(response), 0);
        free(cache_file);
        close(client_sock);
        close(server_sock);
        return NULL;
    }

    snprintf(buffer, sizeof(buffer),
            "GET %s HTTP/1.1\r\n"
            "Host: %s\r\n"
            "Connection: close\r\n\r\n",
            req.path, req.host);
    send(server_sock, buffer, strlen(buffer), 0);

    FILE *cache_fp = NULL;
    if (timeout > 0 && !strstr(req.url, "?")) { 
        cache_fp = fopen(cache_file, "w");
    }

    while ((bytes_read = recv(server_sock, buffer, sizeof(buffer), 0)) > 0) {
        send(client_sock, buffer, bytes_read, 0);
        if (cache_fp) {
            fwrite(buffer, 1, bytes_read, cache_fp);
        }
    }

    if (cache_fp) {
        fclose(cache_fp);
    }

    free(cache_file);
    close(server_sock);
    close(client_sock);
    return NULL;
}

void handle_sigint(int sig) {
    keep_running = 0;
    printf("\nShutting down proxy server...\n");
}

int main(int argc, char *argv[]) {
    if (argc < 2 || argc > 3) {
        fprintf(stderr, "Usage: %s <port> [timeout]\n", argv[0]);
        exit(1);
    }

    int port = atoi(argv[1]);
    if (argc == 3) {
        timeout = atoi(argv[2]);
    }

    mkdir(CACHE_DIR, 0755);

    signal(SIGINT, handle_sigint);

    int server_sock = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in server_addr = {
        .sin_family = AF_INET,
        .sin_port = htons(port),
        .sin_addr.s_addr = INADDR_ANY
    };

    bind(server_sock, (struct sockaddr*)&server_addr, sizeof(server_addr));
    listen(server_sock, 10);

    printf("Proxy server listening on port %d\n", port);

    while (keep_running) {
        struct sockaddr_in client_addr;
        socklen_t client_len = sizeof(client_addr);
        int *client_sock = malloc(sizeof(int));
        *client_sock = accept(server_sock, (struct sockaddr*)&client_addr, &client_len);

        pthread_t thread;
        pthread_create(&thread, NULL, handle_client, client_sock);
        pthread_detach(thread);
    }

    close(server_sock);
    return 0;
} 