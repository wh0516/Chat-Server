#ifndef SERVER_HPP
#define SERVER_HPP

#include <signal.h>
#include <poll.h>
#include <iostream>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <string>
#include <vector>
#include <string.h>
#include <arpa/inet.h>
#include <nlohmann/json.hpp>
#include <mysql.h>
#include <unordered_map>

using namespace std;
using json = nlohmann::json;

struct UserInfo
{
    int clientfd;    // 账号
    string password; // 密码
    char status;     // 'y' 或 'n'
    string message;  // 存储消息
};

class Server
{
public:
    // 默认构造函数
    Server() = default;

    // 带端口构造函数
    Server(string port);

    // 析构函数
    ~Server();

    // 运行服务器
    void run();

private:
    enum
    {
        MAX_CLIENTS = 1000, // 最大连接数
        BUFFER_SIZE = 1024  // 最大缓存区
    };

    sockaddr_in server_addr, client_addr;        // 服务端地址配置
    socklen_t client_len = sizeof(client_addr);  // 地址长度
    string port;                                 // 端口
    int listenfd;                                // 监听文件描述符
    int clientfd;                                // 客服端fd
    pollfd fds[MAX_CLIENTS + 1];                 // pollfd结构
    int nfds;                                    // 活跃描述符数量
    string buffer;                               // 缓冲区
    MYSQL *con;                                  // mysql连接
    unordered_map<string, UserInfo> users_cache; // account与数据库数据映射
    unordered_map<int, int> fdIdx;               // clientfd and Idx
    unordered_map<int, string> fdAccount;        // clientfd and account

    // 初始化服务器
    bool initial();

    // 连接mysql
    bool connect_with_MySQL();

    // 接受连接
    bool accept();

    // 客服端任务处理
    void process_client();

    // 关闭单个链接
    inline bool close_single(int &);

    // 处理关闭获取退出
    inline void handle_logout_or_close();

    // 查询数据库
    inline bool select_sql(const char *, const string &);

    // 检查账号是否存在
    bool account_exists(const std::string &account);

    // 更新数据库
    bool update_sql(const char *);

    // 强制退出其他客户端的登录
    bool force_logout_other_client(const string &account);

    // 0处理登陆
    void login(const json &);

    // 1处理注册
    void sign_in(const json &);

    // 2处理私发
    void private_send(const json &);

    // 3处理群法
    void group_send(const json &);

    // 4退出登录
    bool quitlog(string &);

    // 关闭服务器
    bool close();
};

#endif