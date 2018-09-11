add_executable (server Server.c)
target_link_libraries (server coala)

add_executable (client Client.c)
target_link_libraries (client coala)
