#!/bin/bash

# This bash will install the proxy service completed
# If you have any question,please send mail to siberlysily@outlook.com or siberlysily@gmail.com
# You can git the source code from github society:https://wwww.github.com/Siberly
README_ZH="[Warning]免责声明：本代码仅供技术学习和研究使用。使用者在使用本代码时必须遵守相关法律法规，严禁用于任何违法违规用途。因使用本代码造成的任何损失或后果，均由使用者自行承担。"
README_EN="[Warning]Disclaimer:This code is intended for technical learning and research purposes only. Users must comply with all applicable laws and regulations when using this code. Any illegal or unauthorized use is strictly prohibited. The user assumes all risks and responsibilities for any losses or consequences arising from the use of this code."
version="Siberly Proxy Server v25.0.1"
service_port="8080"
proxy_server_name="siberlyproxy"
proxy_server_path="/usr/bin/${proxy_server_name}"
source_file="/root/linux_proxy_server.c"
auth_user="siberly"
auth_pass="123456"
echo "[+]Loading source code..."
sleep 5
if cat > /root/linux_proxy_server.c << EOF
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <errno.h>
#include <ctype.h>
#include <time.h>
#include <signal.h>

#define BUFFER_SIZE 8192
#define PORT 8080
#define AUTH_USER "siberly"
#define AUTH_PASS "123456"

// 在文件开头添加函数声明
void record_failed_attempt(const char* client_ip);
int is_ip_blocked(const char* client_ip);
char* base64_encode(const char* input);
void send_auth_required(int client_socket);

// 添加 Base64 编码函数
static const char base64_chars[] = 
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

char* base64_encode(const char* input) {
    size_t input_len = strlen(input);
    size_t output_len = 4 * ((input_len + 2) / 3);
    char* encoded = (char*)malloc(output_len + 1);
    
    if (!encoded) return NULL;
    
    size_t i = 0, j = 0;
    uint32_t octet_a, octet_b, octet_c, triple;
    
    while (i < input_len) {
        octet_a = i < input_len ? (unsigned char)input[i++] : 0;
        octet_b = i < input_len ? (unsigned char)input[i++] : 0;
        octet_c = i < input_len ? (unsigned char)input[i++] : 0;
        
        triple = (octet_a << 16) + (octet_b << 8) + octet_c;
        
        encoded[j++] = base64_chars[(triple >> 18) & 0x3F];
        encoded[j++] = base64_chars[(triple >> 12) & 0x3F];
        encoded[j++] = base64_chars[(triple >> 6) & 0x3F];
        encoded[j++] = base64_chars[triple & 0x3F];
    }
    
    // 添加填充
    if (input_len % 3 == 1) {
        encoded[output_len - 1] = '=';
        encoded[output_len - 2] = '=';
    } else if (input_len % 3 == 2) {
        encoded[output_len - 1] = '=';
    }
    
    encoded[output_len] = '\0';
    return encoded;
}

// 修改验证函数
int verify_proxy_auth(const char* auth_header, const char* client_ip) {
    if (!auth_header || !client_ip) {
        printf("[Auth] 无效的参数\n");
        return 0;
    }

    // 检查 IP 是否被封禁
    if (is_ip_blocked(client_ip)) {
        return 0;
    }

    // 跳过 "Proxy-Authorization: Basic " 并去除空格
    auth_header = strstr(auth_header, "Basic ");
    if (!auth_header) {
        printf("[Auth] 未找到 Basic 认证头\n");
        record_failed_attempt(client_ip);
        return 0;
    }
    
    auth_header += 6;
    while (*auth_header && isspace(*auth_header)) auth_header++;
    
    // 使用配置文件中的用户名密码
    char auth_str[256];
    snprintf(auth_str, sizeof(auth_str), "%s:%s", AUTH_USER, AUTH_PASS);
    
    char* encoded = base64_encode(auth_str);
    if (!encoded) {
        printf("[Auth] Base64 编码失败\n");
        return 0;
    }
    
    // 去除认证字符串中的空格和换行
    char auth_copy[256] = {0};
    strncpy(auth_copy, auth_header, sizeof(auth_copy) - 1);
    char* end = strchr(auth_copy, '\r');
    if (end) *end = '\0';
    end = strchr(auth_copy, '\n');
    if (end) *end = '\0';
    
    printf("[Auth] 收到的认证: [%s]\n", auth_copy);
    printf("[Auth] 期望的认证: [%s]\n", encoded);
    
    int result = (strcmp(auth_copy, encoded) == 0);
    free(encoded);
    
    if (!result) {
        printf("[Auth] 认证失败\n");
        record_failed_attempt(client_ip);
    } else {
        printf("[Auth] 认证成功\n");
    }
    
    return result;
}

// 发送认证请求
void send_auth_required(int client_socket) {
    const char* response = "HTTP/1.1 407 Proxy Authentication Required\r\n"
                          "Proxy-Authenticate: Basic realm=\"Proxy\"\r\n"
                          "Connection: keep-alive\r\n"
                          "Proxy-Connection: keep-alive\r\n"
                          "Content-Type: text/html\r\n"
                          "Content-Length: 29\r\n"
                          "\r\n"
                          "Proxy Authentication Required.\r\n";
    send(client_socket, response, strlen(response), 0);
}

// 函数声明
void parse_http_request(const char* request, char* host, int* port);
void handle_connect_request(int client_socket, const char* host, int port);
void signal_handler(int signo);
void init_sessions(void);
void cleanup_sessions(void);
int is_ip_authenticated(const char* client_ip);
void add_auth_session(const char* client_ip);

// 解析HTTP请求中的主机名和端口
void parse_http_request(const char* request, char* host, int* port) {
    const char* host_start = strstr(request, "Host: ");
    if (host_start) {
        host_start += 6; // 跳过 "Host: "
        const char* host_end = strstr(host_start, "\r\n");
        if (host_end) {
            int host_len = host_end - host_start;
            strncpy(host, host_start, host_len);
            host[host_len] = '\0';
            
            // 检查是否包含端口号
            char* colon = strchr(host, ':');
            if (colon) {
                *colon = '\0';
                *port = atoi(colon + 1);
            } else {
                *port = 80; // 默认HTTP端口
            }
        }
    }
}

// 线程函数的参数结构
typedef struct {
    int client_socket;
    struct sockaddr_in client_addr;
} ThreadArgs;

// 添加认证会话结构
#define MAX_SESSIONS 1000
#define SESSION_TIMEOUT 3600  // 1小时超时
#define MAX_FAILED_ATTEMPTS 3
#define BLOCK_TIME 3600  // 1小时封禁时间

typedef struct {
    char ip[INET_ADDRSTRLEN];
    time_t last_access;
    int authenticated;
    int failed_attempts;
    time_t block_until;
} AuthSession;

// 全局会话数组
static AuthSession* sessions = NULL;
static pthread_mutex_t sessions_mutex = PTHREAD_MUTEX_INITIALIZER;

// 初始化会话管理
void init_sessions() {
    sessions = (AuthSession*)calloc(MAX_SESSIONS, sizeof(AuthSession));
    if (!sessions) {
        perror("Failed to allocate session memory");
        exit(1);
    }
    
    // 初始化所有会话
    for (int i = 0; i < MAX_SESSIONS; i++) {
        sessions[i].authenticated = 0;
        sessions[i].failed_attempts = 0;
        sessions[i].block_until = 0;
        sessions[i].last_access = 0;
        sessions[i].ip[0] = '\0';
    }
}

// 清理过期会话
void cleanup_sessions() {
    if (!sessions) return;
    
    time_t current_time = time(NULL);
    pthread_mutex_lock(&sessions_mutex);
    for (int i = 0; i < MAX_SESSIONS; i++) {
        if (sessions[i].authenticated && 
            (current_time - sessions[i].last_access) > SESSION_TIMEOUT) {
            memset(&sessions[i], 0, sizeof(AuthSession));
        }
    }
    pthread_mutex_unlock(&sessions_mutex);
}

// 检查IP是否已认证
int is_ip_authenticated(const char* client_ip) {
    if (!sessions || !client_ip) return 0;
    
    time_t current_time = time(NULL);
    pthread_mutex_lock(&sessions_mutex);
    
    int result = 0;
    for (int i = 0; i < MAX_SESSIONS; i++) {
        if (sessions[i].authenticated && 
            strcmp(sessions[i].ip, client_ip) == 0) {
            if ((current_time - sessions[i].last_access) <= SESSION_TIMEOUT) {
                sessions[i].last_access = current_time;
                result = 1;
                break;
            } else {
                memset(&sessions[i], 0, sizeof(AuthSession));
            }
        }
    }
    
    pthread_mutex_unlock(&sessions_mutex);
    return result;
}

// 添加认证会话
void add_auth_session(const char* client_ip) {
    if (!sessions || !client_ip) return;
    
    pthread_mutex_lock(&sessions_mutex);
    
    // 先查找是否已存在
    for (int i = 0; i < MAX_SESSIONS; i++) {
        if (sessions[i].authenticated && 
            strcmp(sessions[i].ip, client_ip) == 0) {
            sessions[i].last_access = time(NULL);
            pthread_mutex_unlock(&sessions_mutex);
            return;
        }
    }
    
    // 查找空位
    for (int i = 0; i < MAX_SESSIONS; i++) {
        if (!sessions[i].authenticated) {
            strncpy(sessions[i].ip, client_ip, INET_ADDRSTRLEN-1);
            sessions[i].ip[INET_ADDRSTRLEN-1] = '\0';
            sessions[i].last_access = time(NULL);
            sessions[i].authenticated = 1;
            break;
        }
    }
    
    pthread_mutex_unlock(&sessions_mutex);
}

// 检查 IP 是否被封禁
int is_ip_blocked(const char* client_ip) {
    if (!sessions || !client_ip) return 0;
    
    pthread_mutex_lock(&sessions_mutex);
    time_t current_time = time(NULL);
    
    int blocked = 0;
    for (int i = 0; i < MAX_SESSIONS; i++) {
        if (sessions[i].ip[0] != '\0' && 
            strcmp(sessions[i].ip, client_ip) == 0) {
            if (sessions[i].block_until > current_time) {
                blocked = 1;
                printf("[Security] IP %s 被封禁至 %ld (当前时间 %ld)\n", 
                       client_ip, sessions[i].block_until, current_time);
            } else {
                // 如果封禁时间已过，重置失败次数
                sessions[i].failed_attempts = 0;
                sessions[i].block_until = 0;
            }
            break;
        }
    }
    
    pthread_mutex_unlock(&sessions_mutex);
    return blocked;
}

// 记录失败尝试
void record_failed_attempt(const char* client_ip) {
    if (!sessions || !client_ip) return;
    
    pthread_mutex_lock(&sessions_mutex);
    time_t current_time = time(NULL);
    int slot = -1;
    
    // 查找现有记录或空槽位
    for (int i = 0; i < MAX_SESSIONS; i++) {
        if (sessions[i].ip[0] == '\0') {
            if (slot == -1) slot = i;  // 记住第一个空槽位
        } else if (strcmp(sessions[i].ip, client_ip) == 0) {
            slot = i;
            break;
        }
    }
    
    if (slot != -1) {
        if (sessions[slot].ip[0] == '\0') {
            strncpy(sessions[slot].ip, client_ip, INET_ADDRSTRLEN - 1);
            sessions[slot].ip[INET_ADDRSTRLEN - 1] = '\0';
            sessions[slot].failed_attempts = 1;
        } else {
            sessions[slot].failed_attempts++;
        }
        
        sessions[slot].last_access = current_time;
        
        if (sessions[slot].failed_attempts >= MAX_FAILED_ATTEMPTS) {
            sessions[slot].block_until = current_time + BLOCK_TIME;
            printf("[Security] IP %s 已被封禁，失败次数: %d\n", 
                   client_ip, sessions[slot].failed_attempts);
        } else {
            printf("[Security] IP %s 失败次数: %d/%d\n", 
                   client_ip, sessions[slot].failed_attempts, MAX_FAILED_ATTEMPTS);
        }
    }
    
    pthread_mutex_unlock(&sessions_mutex);
}

// 处理 CONNECT 请求的函数
void handle_connect_request(int client_socket, const char* host, int port) {
    // 连接到目标服务器
    struct sockaddr_in target_addr;
    int target_socket = socket(AF_INET, SOCK_STREAM, 0);
    
    struct hostent *target_host = gethostbyname(host);
    if (!target_host) {
        printf("无法解析主机名: %s\n", host);
        return;
    }

    target_addr.sin_family = AF_INET;
    target_addr.sin_port = htons(port);
    target_addr.sin_addr.s_addr = *(unsigned long*)target_host->h_addr;

    if (connect(target_socket, (struct sockaddr*)&target_addr, sizeof(target_addr)) < 0) {
        printf("无法连接到目标服务器: %s:%d\n", host, port);
        close(target_socket);
        return;
    }

    // 发送连接成功响应
    const char* response = "HTTP/1.1 200 Connection Established\r\n\r\n";
    send(client_socket, response, strlen(response), 0);

    // 在客户端和目标服务器之间转发数据
    char buffer[BUFFER_SIZE];
    fd_set readfds;
    struct timeval timeout;
    
    while (1) {
        FD_ZERO(&readfds);
        FD_SET(client_socket, &readfds);
        FD_SET(target_socket, &readfds);
        
        timeout.tv_sec = 30;
        timeout.tv_usec = 0;
        
        int maxfd = (client_socket > target_socket ? client_socket : target_socket) + 1;
        int activity = select(maxfd, &readfds, NULL, NULL, &timeout);
        if (activity <= 0) break;
        
        if (FD_ISSET(client_socket, &readfds)) {
            int bytes_received = recv(client_socket, buffer, BUFFER_SIZE, 0);
            if (bytes_received <= 0) break;
            send(target_socket, buffer, bytes_received, 0);
        }
        
        if (FD_ISSET(target_socket, &readfds)) {
            int bytes_received = recv(target_socket, buffer, BUFFER_SIZE, 0);
            if (bytes_received <= 0) break;
            send(client_socket, buffer, bytes_received, 0);
        }
    }

    close(target_socket);
}

// 处理客户端连接的线程函数
void* handle_client(void* arg) {
    ThreadArgs* args = (ThreadArgs*)arg;
    char client_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(args->client_addr.sin_addr), client_ip, INET_ADDRSTRLEN);

    // 检查 IP 是否被封禁
    if (is_ip_blocked(client_ip)) {
        printf("[Security] 拒绝来自被封禁 IP %s 的连接\n", client_ip);
        close(args->client_socket);
        free(args);
        return NULL;
    }
    
    int client_socket = args->client_socket;
    char buffer[BUFFER_SIZE];
    char host[256];
    int port;
    ssize_t bytes_received;

    // 检查是否已认证
    int needs_auth = !is_ip_authenticated(client_ip);
    printf("[Auth] 客户端 %s %s认证\n", client_ip, needs_auth ? "需要" : "已");

    while (needs_auth) {
        printf("[Auth] 等待认证请求...\n");
        bytes_received = recv(client_socket, buffer, BUFFER_SIZE - 1, 0);
        
        if (bytes_received <= 0) {
            printf("[Auth] 连接已关闭或出错\n");
            goto cleanup;
        }

        buffer[bytes_received] = '\0';

        // 检查代理认证
        char* auth_header = strstr(buffer, "Proxy-Authorization:");
        if (!auth_header) {
            printf("[Auth] 未提供认证信息，发送认证请求\n");
            send_auth_required(client_socket);
            continue;
        }

        if (verify_proxy_auth(auth_header, client_ip)) {
            printf("[Auth] 认证成功，添加会话\n");
            add_auth_session(client_ip);
            needs_auth = 0;
            break;
        }

        printf("[Auth] 认证失败，发送认证请求\n");
        send_auth_required(client_socket);
    }

    // 处理实际的代理请求
    do {
        if (!needs_auth) {  // 如果是已认证的客户端，需要先接收请求
            bytes_received = recv(client_socket, buffer, BUFFER_SIZE - 1, 0);
            if (bytes_received <= 0) {
                goto cleanup;
            }
            buffer[bytes_received] = '\0';
        }

        if (strncmp(buffer, "CONNECT ", 8) == 0) {
            // 处理 HTTPS 请求
            sscanf(buffer + 8, "%[^:]:%d", host, &port);
            printf("CONNECT 请求: %s:%d\n", host, port);
            handle_connect_request(client_socket, host, port);
        } else {
            // 处理 HTTP 请求
            parse_http_request(buffer, host, &port);
            printf("目标主机: %s:%d\n", host, port);

            // 连接到目标服务器
            struct sockaddr_in target_addr;
            int target_socket = socket(AF_INET, SOCK_STREAM, 0);
            
            struct hostent *target_host = gethostbyname(host);
            if (!target_host) {
                printf("无法解析主机名: %s\n", host);
                goto cleanup;
            }

            target_addr.sin_family = AF_INET;
            target_addr.sin_port = htons(port);
            target_addr.sin_addr.s_addr = *(unsigned long*)target_host->h_addr;

            if (connect(target_socket, (struct sockaddr*)&target_addr, sizeof(target_addr)) < 0) {
                printf("无法连接到目标服务器: %s:%d\n", host, port);
                close(target_socket);
                goto cleanup;
            }

            // 转发原始请求到目标服务器
            send(target_socket, buffer, bytes_received, 0);

            // 在客户端和目标服务器之间转发数据
            fd_set readfds;
            struct timeval timeout;
            
            while (1) {
                FD_ZERO(&readfds);
                FD_SET(client_socket, &readfds);
                FD_SET(target_socket, &readfds);
                
                timeout.tv_sec = 30;
                timeout.tv_usec = 0;
                
                int maxfd = (client_socket > target_socket ? client_socket : target_socket) + 1;
                int activity = select(maxfd, &readfds, NULL, NULL, &timeout);
                if (activity <= 0) break;
                
                if (FD_ISSET(client_socket, &readfds)) {
                    bytes_received = recv(client_socket, buffer, BUFFER_SIZE, 0);
                    if (bytes_received <= 0) break;
                    send(target_socket, buffer, bytes_received, 0);
                }
                
                if (FD_ISSET(target_socket, &readfds)) {
                    bytes_received = recv(target_socket, buffer, BUFFER_SIZE, 0);
                    if (bytes_received <= 0) break;
                    send(client_socket, buffer, bytes_received, 0);
                }
            }
            
            close(target_socket);
        }
    } while (0);  // 处理完一个请求就结束

cleanup:
    free(args);
    close(client_socket);
    return NULL;
}

// 添加信号处理函数
void signal_handler(int signo) {
    if (signo == SIGSEGV || signo == SIGTERM || signo == SIGINT) {
        fprintf(stderr, "Caught signal %d, cleaning up...\n", signo);
        if (sessions) {
            free(sessions);
            sessions = NULL;
        }
        exit(signo == SIGSEGV ? 1 : 0);
    }
}

int main() {
    int server_socket, client_socket;
    struct sockaddr_in server_addr, client_addr;
    socklen_t client_len = sizeof(client_addr);

    // 创建服务器socket
    server_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (server_socket < 0) {
        perror("Socket创建失败");
        exit(1);
    }

    // 设置地址重用
    int opt = 1;
    if (setsockopt(server_socket, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        perror("设置socket选项失败");
        exit(1);
    }

    // 设置服务器地址
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(PORT);

    // 绑定地址
    if (bind(server_socket, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        perror("绑定失败");
        exit(1);
    }

    // 监听连接
    if (listen(server_socket, 10) < 0) {
        perror("监听失败");
        exit(1);
    }

    printf("代理服务器正在监听端口 %d...\n", PORT);
    printf("请确保浏览器代理设置为 [服务器IP]:%d\n", PORT);

    // 初始化会话管理
    init_sessions();
    
    // 添加信号处理
    signal(SIGSEGV, signal_handler);
    signal(SIGTERM, signal_handler);
    signal(SIGINT, signal_handler);
    
    while (1) {
        printf("等待新的连接...\n");
        client_socket = accept(server_socket, (struct sockaddr*)&client_addr, &client_len);
        if (client_socket < 0) {
            perror("接受连接失败");
            continue;
        }

        printf("新客户端连接: %s\n", inet_ntoa(client_addr.sin_addr));

        // 定期清理过期会话
        cleanup_sessions();

        // 为新连接创建线程
        ThreadArgs* args = (ThreadArgs*)malloc(sizeof(ThreadArgs));
        args->client_socket = client_socket;
        args->client_addr = client_addr;  // 保存客户端地址

        pthread_t thread_id;
        if (pthread_create(&thread_id, NULL, handle_client, args) != 0) {
            printf("创建线程失败: %s\n", strerror(errno));
            free(args);
            close(client_socket);
        } else {
            pthread_detach(thread_id);
        }
    }

    // 清理资源
    if (sessions) {
        free(sessions);
        sessions = NULL;
    }
    close(server_socket);
    return 0;
}
EOF
then
    echo "[+]Load source code Successfully!"
else
    echo "[Error]Failed to load source code"
    exit 1
fi
sleep 5
echo "${version}"
echo "${README_ZH}"
echo "${README_EN}"
echo "[Warning]Service Installing...If break Ctrl+C"
echo "[+]The installation environment is being checked"
sleep 5
if [ "$EUID" -ne 0 ]; then 
    echo "[Error]Please use root"
    exit 1
fi
if [ ! -f "${source_file}" ]; then
    echo "[Error]Not found source file: ${source_file}"
    exit 1
fi
if ! command -v gcc >/dev/null 2>&1; then
    echo "[+]Install gcc tools..."
    if command -v yum >/dev/null 2>&1; then
        yum install -y gcc
    elif command -v apt-get >/dev/null 2>&1; then
        apt-get update && apt-get install -y gcc
    else
        echo "[Error]Couldn't install gcc,please install for other ways"
        exit 1
    fi
fi
sleep 2
echo "[+]gcc your proxy service..."
sed -i "s/#define AUTH_USER.*/#define AUTH_USER \"${auth_user}\"/" "${source_file}"
sed -i "s/#define AUTH_PASS.*/#define AUTH_PASS \"${auth_pass}\"/" "${source_file}"
if gcc "${source_file}" -o "${proxy_server_path}" -pthread -g -Wall -O0; then
    echo "[+]Gcc successfully!"
else
    echo "[Error]Gcc failed"
    exit 1
fi
if chmod +x "${proxy_server_path}"; then
    echo "[+]chmod +x ${proxy_server_path} successfully"
else
    echo "[Error]Failed to chmod +x ${proxy_server_path}"
    exit 1
fi
if [ ! -x "${proxy_server_path}" ]; then
    echo "[Error]You are not a root or ..."
    ls -l "${proxy_server_path}"
    exit 1
fi
if netstat -tuln | grep ":${service_port}" > /dev/null; then
    echo "[Error]${service_port} is using"
    echo "[Error]Please realse port"
    exit 1
fi
if command -v firewall-cmd >/dev/null 2>&1; then
    if ! firewall-cmd --list-ports | grep "${service_port}" > /dev/null; then
        echo "[+]Opening ${service_port}..."
        firewall-cmd --permanent --add-port=${service_port}/tcp
        firewall-cmd --reload
    fi
elif command -v ufw >/dev/null 2>&1; then
    if ! ufw status | grep "${service_port}" > /dev/null; then
        echo "[+]opening ${service_port}..."
        ufw allow ${service_port}/tcp
    fi
fi
sleep 5
echo "[+]Install shell auto to run proxy service,please wait..."
if cat > /etc/systemd/system/siberly-proxy-server.service << EOF
[Unit]
Description=HTTP Proxy Server
After=network.target

[Service]
Type=simple
ExecStart=${proxy_server_path}
Restart=on-failure
RestartSec=3
User=root

[Install]
WantedBy=multi-user.target
EOF
then
    echo "[+]Created proxy service Successfully!"
else
    echo "[Error]Failed to create proxy.service"
    exit 1
fi
if sudo systemctl daemon-reload; then
    echo "[+]Reload daemon Successfully!"
else
    echo "[Error]Failed to reload daemon."
    exit 1
fi
if sudo systemctl enable siberly-proxy-server; then
    echo "[+]Setting enable to[${proxy_server_name}] Successfully!"
else
    echo "[Error]Failed to enable [${proxy_server_name}]."
    exit 1
fi
if sudo systemctl start siberly-proxy-server; then
    echo "[+]Start [${proxy_server_name}]Successfully!"
else
    echo "[Error]Failed to start [${proxy_server_name}]."
    echo "[Error]more info："
    systemctl status ${proxy_server_name}
    journalctl -u ${proxy_server_name} --no-pager -n 50
    exit 1
fi
echo "Install completed!"
echo "============================================================================================="
echo "[+]${version}"
echo "[+]Check'[netstat -lntp|grep ${service_port}]' or '[systemctl status siberly-proxy-server]'"
echo "[+]Proxy authentication: ${auth_user}/${auth_pass}"
echo "[+]Thank you for using our service! ^_^"
echo "=============================================================================================="
