#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>

#include <iostream>
#include <stdint.h>
#include <stddef.h>
#include <httpserver.hpp>

#define	PORT	8080
#define HOST	"localhost"

using namespace httpserver;
webserver ws = create_webserver(PORT).start_method(http::http_utils::INTERNAL_SELECT).max_threads(5);

class fuzz_resource : public http_resource {
	public:
		const std::shared_ptr<http_response> render(const http_request&);
}hwr;

const std::shared_ptr<http_response> fuzz_resource::render(const http_request& req)
{
	return std::shared_ptr<http_response>(new string_response("Hello World!!!", 200));
}

void error(const char *msg) {
	perror(msg);
	exit(0);
}

int connect_server(void) {
	struct hostent *server;
	struct sockaddr_in serv_addr;
	int sockfd;

	sockfd = socket(AF_INET, SOCK_STREAM, 0);
	if (sockfd < 0)
		error("ERROR opening socket");

	server = gethostbyname(HOST);
	if (server == NULL)
		error("ERROR, no such host");

	memset(&serv_addr,0,sizeof(serv_addr));
	serv_addr.sin_family = AF_INET;
	serv_addr.sin_port = htons(PORT);
	memcpy(&serv_addr.sin_addr.s_addr,server->h_addr,server->h_length);

	if (connect(sockfd,(struct sockaddr *)&serv_addr,sizeof(serv_addr)) < 0)
		error("ERROR connecting");
	return sockfd;
}

void write_request(int sockfd, const uint8_t *data, size_t size) {
	std::string method = "PUT ";
	std::string suffix = " HTTP/1.1\r\n\r\n";
	std::string str(reinterpret_cast<const char *>(data), size);
	std::string fstr = method+ str + suffix;
	const char *msg;
	int bytes, sent = 0;

	size = fstr.length();
	msg = fstr.c_str();
	do {
		bytes = write(sockfd, msg + sent, size - sent);
		if (bytes < 0)
			error("ERROR writing message to socket");
		if (bytes == 0)
			break;
		sent += bytes;
	} while (sent < size);
}

void read_response(int sockfd) {
	char response[1024];
	int bytes;

	bytes = read(sockfd,response ,200);
	if (bytes < 0)
		error("ERROR reading response from socket");

	//printf("%s\n", response);
}

extern "C" int LLVMFuzzerInitialize(int* argc, char*** argv)
{
	ws.register_resource("/hello", &hwr, true);
	hwr.allow_all();
	return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
	int sockfd;

	/* Start the server */
	ws.start(false);

	/* Client -> connect to server */
	sockfd = connect_server();

	/* HTTP request and response */
	write_request(sockfd, data, size);
	read_response(sockfd);

	/* Client -> close connection */
	close(sockfd);

	/* Stop the server */
	ws.stop();
	return 0;
}
