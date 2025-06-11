#include "server.hpp"

// 带端口号的构造函数
Server::Server(string port) : port(port)
{
    nfds = 0;

    // 连接MySQL
    if (connect_with_MySQL())
    {
        printf("mysql success\n");
    }

    buffer.resize(BUFFER_SIZE);

    if (initial())
    {
        printf("initial server success\n");
    }
}

// 连接mysql
bool Server::connect_with_MySQL()
{
    // 初始化mysql对象
    con = mysql_init(nullptr);
    if (con == nullptr)
    {
        perror("mysql init");
        return false;
    }
    if (mysql_real_connect(con, "localhost", "root", "wh051116", "chat", 3306, nullptr, 0) == nullptr)
    {
        perror("mysql connect");
        mysql_close(con);
        return false;
    }
    return true;
}

// 析构函数
Server::~Server()
{
    // 关闭mysql
    mysql_close(con);
    close();
}

// 初始化服务器
bool Server::initial()
{
    // 创建监听描述符
    listenfd = socket(AF_INET, SOCK_STREAM, 0);
    if (listenfd < 0)
    {
        perror("socket");
        return false;
    }

    // 加入到pollfd
    fds[0].fd = listenfd;
    fds[0].events = POLLIN;
    fds[0].revents = 0;
    nfds++;

    // 设置同一个地址可重用
    int opt = 1;
    if (setsockopt(listenfd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)))
    {
        perror("setsockopt");
        return false;
    }

    // 配置服务器地址
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(stoi(port));

    // 绑定到监听fd
    if (bind(listenfd, (sockaddr *)&server_addr, sizeof(server_addr)) < 0)
    {
        perror("bind");
        return false;
    }

    // 开始监听
    if (listen(listenfd, 128) < 0)
    {
        perror("listen");
        return false;
    }

    // 初始化fds数组
    for (int i = 1; i <= MAX_CLIENTS; i++)
    {
        fds[i].fd = -1;
        fds[i].events = POLLIN;
        fds[i].revents = 0;
    }
    return true;
}

// 处理连接
bool Server::accept()
{
    int clientfd = ::accept(listenfd, (sockaddr *)&client_addr, &client_len);
    if (clientfd < 0)
    {
        perror("accept");
        return false;
    }

    // 添加到pollfd
    bool added = false;
    for (int i = 1; i < MAX_CLIENTS; i++)
    {
        if (fds[i].fd == -1)
        {
            fds[i].fd = clientfd;
            fds[i].events = POLLIN;
            fds[i].revents = 0;
            fdIdx[clientfd] = i;
            if (i >= nfds)
                nfds = i + 1;
            added = true;
            break;
        }
    }

    // 判断连接是否达到上限
    if (!added)
    {
        ::close(clientfd);
        return false;
    }
    return true;
}

// 关闭单个客服端
inline bool Server::close_single(int &clientfd)
{
    int res = ::close(clientfd);
    if (res < 0)
        return false;
    fds[fdIdx[clientfd]].fd = -1;
    fds[fdIdx[clientfd]].events = 0;
    fds[fdIdx[clientfd]].revents = 0;
    fdIdx.erase(clientfd);
    return true;
}

inline void Server::handle_logout_or_close()
{
    auto it = users_cache.find(fdAccount[clientfd]);
    if (it != users_cache.end())
    {
        quitlog(fdAccount[clientfd]);
    }
    else
    {
        close_single(clientfd);
    }
}

// 查询数据库
bool Server::select_sql(const char *query_sql, const string &account)
{
    if (mysql_query(con, query_sql))
    {
        perror("select user info");
        return false;
    }

    MYSQL_RES *res = mysql_store_result(con);
    if (!res)
    {
        perror("get res");
        return false;
    }

    MYSQL_FIELD *fields = mysql_fetch_fields(res);
    MYSQL_ROW row = mysql_fetch_row(res);
    if (row)
    {
        int num_fields = mysql_num_fields(res);
        UserInfo user_info;
        for (int i = 0; i < num_fields; i++)
        {
            std::string field_name = fields[i].name;
            std::string field_value = row[i] ? row[i] : "";

            if (field_name == "password")
            {
                user_info.password = field_value;
            }
            else if (field_name == "status")
            {
                user_info.status = field_value.empty() ? 'n' : field_value[0];
            }
            else if (field_name == "clientfd")
            {
                user_info.clientfd = field_value.empty() ? -1 : atoi(field_value.c_str());
            }
            else if (field_name == "message")
            {
                user_info.message = field_value;
            }
        }

        users_cache[account] = user_info;
    }
    mysql_free_result(res);
    return row != nullptr;
}

// 更新数据库
inline bool Server::update_sql(const char *update_sql)
{
    if (mysql_query(con, update_sql))
    {
        perror("update sql");
        return false;
    }

    return true;
}

// 处理登录请求
void Server::login(const json &data)
{
    string account = data["account"];
    fdAccount[clientfd] = account;
    string pwd = data["password"];

    // 从mysql中查询，如果没有注册，如果有判断帐号密码是否对应
    char query[256];
    snprintf(query, sizeof(query),
             "SELECT password, status, clientfd, message FROM users WHERE account = '%s'",
             account.c_str());

    // 返回空值代表没有账号在数据库
    if (!select_sql(query, account))
    {
        buffer = "no account\n";
        printf("no account\n");
        if (send(clientfd, buffer.c_str(), sizeof(buffer), 0) < 0)
        {
            perror("log send");
            return;
        }
        return;
    }

    UserInfo user_info = users_cache[account];
    if (user_info.password == pwd)
    {
        buffer = " log success\n";
        printf("log success\n");
        if (send(clientfd, buffer.c_str(), sizeof(buffer), 0) < 0)
        {
            perror("log send");
            return;
        }
    }
    else if (user_info.password != pwd)
    {
        buffer = "password error\n";
        printf("password error\n");
        if (send(clientfd, buffer.c_str(), sizeof(buffer), 0) < 0)
        {
            perror("log send");
            return;
        }
        return;
    }

    // 处于登录状态则推出当前登录重新登录，没有登录直接登录
    if (user_info.status = 'y')
    {
        if (!quitlog(account))
            return;
    }
    snprintf(query, sizeof(query),
             "UPDATE users SET clientfd = %d, status = 'y' WHERE account = '%s'",
             clientfd, account.c_str());
    update_sql(query);
    user_info.clientfd = clientfd;
    user_info.status = 'y';
    users_cache[account] = user_info;

    // 检查是否有离线消息，如果有则发送给客户端
    if (!user_info.message.empty())
    {
        // 解析多条离线消息（使用|||作为分隔符）
        string messages = user_info.message;
        size_t pos = 0;
        string delimiter = "|||";

        while ((pos = messages.find(delimiter)) != string::npos || !messages.empty())
        {
            string single_message;
            if (pos != string::npos)
            {
                single_message = messages.substr(0, pos);
                messages.erase(0, pos + delimiter.length());
            }
            else
            {
                single_message = messages;
                messages.clear();
            }

            if (!single_message.empty())
            {
                // 发送单条离线消息
                string msg_with_newline = single_message + "\n";
                if (send(clientfd, msg_with_newline.c_str(), msg_with_newline.length(), 0) < 0)
                {
                    perror("send offline message");
                    break;
                }
            }

            if (messages.empty())
                break;
        }

        // 清空数据库中的离线消息
        snprintf(query, sizeof(query),
                 "UPDATE users SET message = '' WHERE account = '%s'",
                 account.c_str());
        update_sql(query);

        // 更新缓存中的消息字段
        user_info.message = "";
        users_cache[account] = user_info;
    }
}

bool Server::account_exists(const std::string &account)
{
    char query[256];
    snprintf(query, sizeof(query),
             "SELECT 1 FROM users WHERE account = '%s' LIMIT 1",
             account.c_str());

    if (mysql_query(con, query))
    {
        perror("check account exists");
        return false;
    }

    MYSQL_RES *res = mysql_store_result(con);
    if (!res)
    {
        perror("get res");
        return false;
    }

    bool exists = (mysql_fetch_row(res) != nullptr);
    mysql_free_result(res);

    return exists;
}

// 处理注册请求
void Server::sign_in(const json &data)
{
    string account = data["account"];
    string pwd = data["password"];

    if (!account_exists(account))
    {
        char query[256];
        snprintf(query, sizeof(query),
                 "INSERT INTO users (account, password) VALUES ('%s', '%s')",
                 account.c_str(), pwd.c_str());
        update_sql(query);
        printf("sign in success\n");
        buffer = "sign in success\n";
        if (send(clientfd, buffer.c_str(), sizeof(buffer), 0) < 0)
        {
            perror("sign in success");
            return;
        }
        login(data);
    }
    else
    {
        buffer = "account exist\n";
        printf("sign in false\n");
        if (send(clientfd, buffer.c_str(), sizeof(buffer), 0) < 0)
        {
            perror("sign in false");
            return;
        }
    }
}

// 处理私发请求
void Server::private_send(const json &data)
{
    string source_account = data["source_account"];
    string destination_account = data["destination_account"];
    string message = data["message"];

    // 检查目标账户是否存在于缓存中（即是否在线）
    auto target_it = users_cache.find(destination_account);

    if (target_it != users_cache.end())
    {
        // 目标用户在线，直接发送消息
        int target_clientfd = target_it->second.clientfd;

        // 构造要发送的消息格式
        json response_msg;
        response_msg["type"] = "private_message";
        response_msg["from"] = source_account;
        response_msg["message"] = message;

        string msg_str = response_msg.dump() + "\n";

        // 发送消息给目标用户
        if (send(target_clientfd, msg_str.c_str(), msg_str.length(), 0) < 0)
        {
            perror("send private message to online user");
            return;
        }
    }
    else
    {
        // 目标用户不在线，先检查账户是否存在
        if (!account_exists(destination_account))
        {
            // 目标账户不存在
            buffer = "destination account does not exist\n";
            if (send(clientfd, buffer.c_str(), buffer.length(), 0) < 0)
            {
                perror("send account not exist response");
            }
            return;
        }

        // 目标账户存在但不在线，存储消息到数据库
        json offline_msg;
        offline_msg["type"] = "private_message";
        offline_msg["from"] = source_account;
        offline_msg["message"] = message;
        offline_msg["timestamp"] = time(nullptr); // 添加时间戳

        string stored_message = offline_msg.dump();

        // 获取当前存储的消息
        char query[256];
        snprintf(query, sizeof(query),
                 "SELECT message FROM users WHERE account = '%s'",
                 destination_account.c_str());

        string existing_messages = "";
        if (select_sql(query, destination_account))
        {
            auto temp_it = users_cache.find(destination_account);
            if (temp_it != users_cache.end())
            {
                existing_messages = temp_it->second.message;
            }
        }

        // 将新消息追加到现有消息后面（用分隔符分隔）
        string updated_messages = existing_messages;
        if (!existing_messages.empty())
        {
            updated_messages += "|||"; // 使用|||作为消息分隔符
        }
        updated_messages += stored_message;

        // 更新数据库中的message字段
        char update_query[1024];
        snprintf(update_query, sizeof(update_query),
                 "UPDATE users SET message = '%s' WHERE account = '%s'",
                 updated_messages.c_str(), destination_account.c_str());

        if (update_sql(update_query))
        {
            // 存储成功，给源用户发送确认
            buffer = "message stored for offline user\n";
            if (send(clientfd, buffer.c_str(), buffer.length(), 0) < 0)
            {
                perror("send stored response");
            }

            printf("Private message from %s stored for offline user %s\n",
                   source_account.c_str(), destination_account.c_str());
        }
        else
        {
            // 存储失败
            buffer = "failed to store message\n";
            if (send(clientfd, buffer.c_str(), buffer.length(), 0) < 0)
            {
                perror("send store failed response");
            }
        }

        // 清理临时缓存数据
        if (users_cache.find(destination_account) != users_cache.end() &&
            target_it == users_cache.end())
        {
            users_cache.erase(destination_account);
        }
    }
}

// 处理群发请求
void Server::group_send(const json &data)
{
}

// 处理退出登录
bool Server::quitlog(string &account)
{
    char query[256];
    snprintf(query, sizeof(query),
             "UPDATE users SET clientfd = -1, status = 'n' WHERE account = '%s'",
             account.c_str());
    update_sql(query);
    printf("quit log success\n");
    auto it = users_cache.find(account);
    buffer = "quit log success\n";
    if (send(clientfd, buffer.c_str(), sizeof(buffer), 0) < 0)
    {
        perror("quit log");
        return false;
    }
    fdAccount.erase(it->second.clientfd);
    close_single(it->second.clientfd);
    users_cache.erase(account);
    return true;
}

// 处理客服端请求
void Server::process_client()
{
    string data;
    while (true)
    {
        ssize_t bytes_read = recv(clientfd, buffer.data(), BUFFER_SIZE - 1, 0);
        if (bytes_read > 0)
        {
            data.append(buffer.data(), bytes_read);
            if (data.find("\n") != string::npos)
            {
                break;
            }
        }
        else if (bytes_read == 0) // 客服端关闭
        {
            printf("client close\n");
            handle_logout_or_close();
            return;
        }
        else
        {
            handle_logout_or_close();
            return;
        }
    }

    if (data.size() > 0)
    {
        if (data.back() == '\n')
        {
            data.pop_back();
        }

        try
        {
            json data_json = json::parse(data);

            // 查看请求任务类型
            string flag = data_json["type"];

            // 处理登陆
            if (flag == "login")
                login(data_json);

            // 处理注册
            else if (flag == "sign in")
            {
                sign_in(data_json);
            }

            // 处理私发
            else if (flag == "private send")
                private_send(data_json);

            // 处理群发
            else if (flag == "group send")
                group_send(data_json);

            // 处理退出
            else if (flag == "quit")
            {
                quitlog(fdAccount[clientfd]);
            }
        }
        catch (const json::parse_error &e)
        {
            std::cerr << "JSON解析错误: " << e.what() << std::endl;
        }
    }
}

// 运行服务端
void Server::run()
{
    while (true)
    {
        // 调用poll -1代表无限等待，返回小于0代表失败，等于0超时
        int poll_res = poll(fds, nfds, -1);
        sleep(1);
        if (poll_res <= 0)
        {
            perror("poll");
        }

        // 处理客服端连接
        if (fds[0].revents & POLLIN)
        {
            if (!accept())
            {
                perror("accept");
            }
        }

        // 处理客服端请求
        for (int i = 1; i < nfds; i++)
        {
            if (fds[i].fd != -1)
            {
                if (fds[i].revents & POLLIN)
                {
                    clientfd = fds[i].fd;
                    process_client();
                }
                if (fds[i].revents & (POLLERR | POLLHUP))
                {
                    handle_logout_or_close();
                }
            }
        }

        // 将返回事件置0
        for (int i = 0; i < nfds; i++)
        {
            fds[i].revents = 0;
        }
    }
}

// 关闭服务端
bool Server::close()
{
    for (int i = 0; i < nfds; i++)
    {
        if (fds[i].fd != -1)
        {
            handle_logout_or_close();
        }
    }
    return true;
}