cmake_minimum_required(VERSION 3.14)
project(ChatServer)

# 查找MySQL
find_package(PkgConfig REQUIRED)
pkg_check_modules(MYSQL REQUIRED mysqlclient)

# 创建可执行文件
add_executable(serverApp main.cpp server.cpp)

# 添加include目录
target_include_directories(serverApp PRIVATE 
    ${CMAKE_SOURCE_DIR}/include
    ${MYSQL_INCLUDE_DIRS}
)

# 链接MySQL库
target_link_libraries(serverApp PRIVATE ${MYSQL_LIBRARIES})
target_compile_options(serverApp PRIVATE ${MYSQL_CFLAGS_OTHER})