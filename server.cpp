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
    client_buffers.erase(clientfd);
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
            string field_name = fields[i].name;
            string field_value = row[i] ? row[i] : "";

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

// 强制退出指定账户的其他登录
bool Server::force_logout_other_client(const string &account)
{
    auto it = users_cache.find(account);
    if (it != users_cache.end() && it->second.status == 'y')
    {
        int old_clientfd = it->second.clientfd;

        // 更新数据库状态
        char query[256];
        snprintf(query, sizeof(query),
                 "UPDATE users SET clientfd = -1, status = 'n' WHERE account = '%s'",
                 account.c_str());
        update_sql(query);

        // 发送强制下线通知给被踢下线的客户端
        string logout_msg = "force_logout:You have been logged out because this account logged in elsewhere\r\n";
        send(old_clientfd, logout_msg.c_str(), logout_msg.length(), 0);

        // 清理映射关系
        fdAccount.erase(old_clientfd);

        // 关闭旧的客户端连接
        close_single(old_clientfd);

        printf("Forced logout for account %s from clientfd %d\n", account.c_str(), old_clientfd);
        return true;
    }
    return false;
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
        buffer = "no account\r\n";
        printf("no account\n");
        if (send(clientfd, buffer.c_str(), buffer.length(), 0) < 0)
        {
            perror("log send");
            return;
        }
        fdAccount.erase(clientfd);
        return;
    }

    UserInfo user_info = users_cache[account];

    // 验证密码
    if (user_info.password != pwd)
    {
        buffer = "password error\r\n";
        printf("password error\n");
        if (send(clientfd, buffer.c_str(), buffer.length(), 0) < 0)
        {
            perror("log send");
            return;
        }
        fdAccount.erase(clientfd);
        return;
    }

    // 如果该账户已经在其他地方登录，强制退出其他客户端
    if (user_info.status == 'y' && user_info.clientfd != clientfd)
    {
        printf("Account %s is already logged in from clientfd %d, forcing logout\n",
               account.c_str(), user_info.clientfd);
        force_logout_other_client(account);
    }

    // 更新数据库和缓存，设置当前客户端为已登录
    snprintf(query, sizeof(query),
             "UPDATE users SET clientfd = %d, status = 'y' WHERE account = '%s'",
             clientfd, account.c_str());
    update_sql(query);

    user_info.clientfd = clientfd;
    user_info.status = 'y';
    users_cache[account] = user_info;

    // 发送登录成功消息
    buffer = "log success\r\n";
    printf("log success for account %s on clientfd %d\n", account.c_str(), clientfd);
    if (send(clientfd, buffer.c_str(), buffer.length(), 0) < 0)
    {
        perror("log send");
        return;
    }

    // 检查是否有离线消息，如果有则发送给客户端
    if (!user_info.message.empty())
    {
        printf("Sending offline messages to %s\n", account.c_str());

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
                string msg_with_newline = single_message + "\r\n";
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
                 "UPDATE users SET message = null WHERE account = '%s'",
                 account.c_str());
        update_sql(query);

        // 更新缓存中的消息字段
        user_info.message = "";
        users_cache[account] = user_info;

        printf("All offline messages sent to %s\n", account.c_str());
    }
}

// 判断账号是否存在
bool Server::account_exists(const string &account)
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
        buffer = "sign in success\r\n";
        if (send(clientfd, buffer.c_str(), buffer.length(), 0) < 0)
        {
            perror("sign in success");
            return;
        }
    }
    else
    {
        buffer = "account exist\r\n";
        printf("sign in false\n");
        if (send(clientfd, buffer.c_str(), buffer.length(), 0) < 0)
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

        string msg_str = response_msg.dump() + "\r\n";

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
            buffer = "destination account does not exist\r\n";
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
            buffer = "message stored for offline user\r\n";
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
            buffer = "failed to store message\r\n";
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

// 处理文件接收
void Server::file_recv(const json &data)
{
    string filename = data["filename"];
    long file_size = data["file_size"];

    // 验证文件大小
    if (file_size <= 0 || file_size > 1024 * 1024 * 1024) // 限制最大1GB
    {
        const char *error_msg = "INVALID_FILE_SIZE\r\n";
        send(clientfd, error_msg, strlen(error_msg), 0);
        return;
    }

    string username = fdAccount[clientfd];
    if (username.empty())
    {
        const char *error_msg = "USER_NOT_LOGGED_IN\r\n";
        send(clientfd, error_msg, strlen(error_msg), 0);
        return;
    }

    string dir_path = "../Storage/" + username;
    string full_path = dir_path + "/" + filename;

    try
    {
        // 创建目录
        if (!filesystem::exists(dir_path))
        {
            filesystem::create_directories(dir_path);
        }

        // 检查是否已在接收其他文件
        if (file_states.count(clientfd) && file_states[clientfd].is_receiving_file)
        {
            const char *error_msg = "ALREADY_RECEIVING_FILE\r\n";
            send(clientfd, error_msg, strlen(error_msg), 0);
            return;
        }

        // 准备文件接收状态
        FileReceiveState &state = file_states[clientfd];
        state.filename = filename;
        state.expected_size = file_size;
        state.received_size = 0;
        state.file_stream.open(full_path, ios::binary);

        if (!state.file_stream.is_open())
        {
            const char *error_msg = "FILE_CREATE_FAILED\r\n";
            send(clientfd, error_msg, strlen(error_msg), 0);
            file_states.erase(clientfd);
            return;
        }

        // 设置为文件接收模式
        state.is_receiving_file = true;

        // 发送准备就绪确认
        const char *ready_msg = "FILE_READY\r\n";
        send(clientfd, ready_msg, strlen(ready_msg), 0);
    }
    catch (const exception &e)
    {
        cerr << "error: " << e.what() << endl;
        const char *error_msg = "DIRECTORY_CREATE_FAILED";
        send(clientfd, error_msg, strlen(error_msg), 0);
        return;
    }
}

// 处理退出登录
bool Server::quitlog(string &account)
{
    auto it = users_cache.find(account);
    if (it == users_cache.end())
    {
        printf("Account %s not found in cache\n", account.c_str());
        return false;
    }

    int user_clientfd = it->second.clientfd;

    // 更新数据库状态
    char query[256];
    snprintf(query, sizeof(query),
             "UPDATE users SET clientfd = -1, status = 'n' WHERE account = '%s'",
             account.c_str());
    update_sql(query);

    printf("quit log success for account %s\n", account.c_str());

    // 发送退出成功消息
    buffer = "quit log success\r\n";
    if (send(user_clientfd, buffer.c_str(), buffer.length(), 0) < 0)
    {
        perror("quit log");
    }

    // 清理映射关系
    fdAccount.erase(user_clientfd);

    // 关闭客户端连接
    close_single(user_clientfd);

    // 从缓存中移除用户信息
    users_cache.erase(account);

    return true;
}

// 清理文件接收资源
void Server::cleanup_client(int client_fd, bool disconnect = false)
{
    // 清理文件接收状态
    auto file_it = file_states.find(client_fd);
    if (file_it != file_states.end())
    {
        if (file_it->second.file_stream.is_open())
        {
            file_it->second.file_stream.close();
            printf("Closed incomplete file: %s\n", file_it->second.filename.c_str());
        }

        // 只有在不断开连接时才发送错误消息
        if (!disconnect)
        {
            const char *error_msg = "FILE_TRANSFER_FAILED\r\n";
            send(client_fd, error_msg, strlen(error_msg), 0);
        }

        file_states.erase(file_it);
    }

    // 如果需要断开连接，清理所有资源
    if (disconnect)
    {
        client_buffers.erase(client_fd);
        handle_logout_or_close();
    }
}

// 处理接收文件数据
void Server::receive_file_data()
{
    FileReceiveState &state = file_states[clientfd];
    string &client_buffer = client_buffers[clientfd];

    // 处理缓冲区中已有的数据
    while (!client_buffer.empty() && state.received_size < state.expected_size)
    {
        long remaining = state.expected_size - state.received_size;
        size_t bytes_to_process = min((size_t)remaining, client_buffer.size());

        // 写入文件
        state.file_stream.write(client_buffer.c_str(), bytes_to_process);
        if (state.file_stream.fail())
        {
            printf("Error writing to file: %s\n", state.filename.c_str());
            cleanup_client(clientfd, false);
            return;
        }

        state.received_size += bytes_to_process;

        // 从缓冲区中移除已处理的数据
        client_buffer.erase(0, bytes_to_process);

        // 显示进度
        if (state.received_size - state.last_progress_size >= 1024 * 1024 ||
            state.received_size >= state.expected_size)
        {
            printf("File progress: %ld/%ld bytes (%.1f%%)\n",
                   state.received_size, state.expected_size,
                   (double)state.received_size / state.expected_size * 100);
            state.last_progress_size = state.received_size;
        }

        // 检查是否接收完成
        if (state.received_size >= state.expected_size)
        {
            state.file_stream.close();
            printf("File received successfully: %s\n", state.filename.c_str());

            const char *complete_msg = "FILE_COMPLETE\r\n";
            send(clientfd, complete_msg, strlen(complete_msg), 0);

            // 重置状态
            state.is_receiving_file = false;
            state.filename = "";
            state.expected_size = 0;
            state.received_size = 0;
            state.last_progress_size = 0;

            printf("File transfer completed, switching back to message mode\n");
            return;
        }
    }
}

// 处理客户端请求
void Server::process_client()
{
    char temp_buffer[BUFFER_SIZE];

    while (true)
    {
        ssize_t bytes_read = recv(clientfd, temp_buffer, BUFFER_SIZE - 1, MSG_DONTWAIT);

        if (bytes_read > 0)
        {
            // 处理接收到的数据
            client_buffers[clientfd].append(temp_buffer, bytes_read);
        }
        else if (bytes_read == 0)
        {
            printf("Client %d disconnected\n", clientfd);
            client_buffers.erase(clientfd);
            handle_logout_or_close();
            return;
        }
        else
        {
            if (errno == EAGAIN || errno == EWOULDBLOCK)
            {
                break; // 没有更多数据可读
            }
            else
            {
                printf("Recv error for client %d: %s\n", clientfd, strerror(errno));
                client_buffers.erase(clientfd);
                handle_logout_or_close();
                return;
            }
        }
    }

    // 检查是否正在接收文件
    if (file_states.count(clientfd) && file_states[clientfd].is_receiving_file)
    {
        // 文件接收模式
        receive_file_data();
        return;
    }

    // 处理缓冲区中的完整消息
    string &client_buffer = client_buffers[clientfd];
    size_t pos;
    while ((pos = client_buffer.find("\r\n")) != string::npos)
    {
        string message = client_buffer.substr(0, pos);
        client_buffer.erase(0, pos + 2);

        // 处理json接收
        if (!message.empty())
        {
            handle_single_message(message);
            if (file_states.count(clientfd) && file_states[clientfd].is_receiving_file)
            {
                if (!client_buffer.empty())
                {
                    receive_file_data();
                }
                break; // 退出消息处理循环
            }
        }
    }
}

// 处理单条消息
void Server::handle_single_message(const string &message)
{
    try
    {
        json data_json = json::parse(message);
        string flag = data_json["type"];

        if (flag == "log in")
            login(data_json);
        else if (flag == "sign in")
            sign_in(data_json);
        else if (flag == "private send")
            private_send(data_json);
        else if (flag == "group send")
            group_send(data_json);
        else if (flag == "file send")
            file_recv(data_json);
        else if (flag == "quit")
            quitlog(fdAccount[clientfd]);
    }
    catch (const json::parse_error &e)
    {
        cerr << "JSON解析错误: " << e.what() << endl;
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