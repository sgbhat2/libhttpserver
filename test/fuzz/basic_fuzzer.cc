/*
 * Build steps:
 * export CC=clang
 * export CXX=clang++
 * export CFLAGS="-O1 -fno-omit-frame-pointer -gline-tables-only -fsanitize=address \
 *  -fsanitize-address-use-after-scope -fsanitize=fuzzer-no-link"
 * export CXXFLAGS="-O1 -fno-omit-frame-pointer -gline-tables-only -fsanitize=address \
 * -fsanitize-address-use-after-scope -fsanitize=fuzzer-no-link"
 *
 * cd libmicrohttpd-0.9.71/
 * make clean
 * ./configure
 * make && sudo make install
 *
 * cd ../libhttpserver
 * rm -rf build/*
 * cd build
 * ../configure
 * make && sudo make install
 *
 * cd libhttpserver/test/fuzz
 * clang++ -O1 -fno-omit-frame-pointer -gline-tables-only -fsanitize=address -fsanitize-address-use-after-scope -fsanitize=fuzzer-no-link  basic_fuzzer.cc -o basic_fuzzer -fsanitize=fuzzer,undefined  -L/usr/local/lib/ -lhttpserver -lmicrohttpd -I../../src/httpserver -I../../src/
 *
 * To run:
 * ./basic_fuzzer
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>

#include <iostream>
#include <sstream>
#include <stdint.h>
#include <stddef.h>
#include <httpserver.hpp>

#define	PORT	8080

using namespace httpserver;
webserver ws = create_webserver(PORT).start_method(http::http_utils::INTERNAL_SELECT);

class fuzz_resource : public http_resource {
public:
	const std::shared_ptr<http_response> render(const http_request& req) {
		std::stringstream ss;
		for (unsigned int i = 0; i < req.get_path_pieces().size(); i++)
			ss << req.get_path_piece(i) << ",";
		return std::shared_ptr<http_response>(new string_response(ss.str(), 200));
	}
}hwr;

class args_resource: public http_resource {
public:
	const std::shared_ptr<http_response> render(const http_request& req) {
		return std::shared_ptr<http_response>(new string_response("ARGS: " + req.get_arg("arg1") + "and" + req.get_arg("arg2")));
	}
}agr;

void error(const char *msg) {
	perror(msg);
	exit(0);
}

int connect_server(void) {
	struct sockaddr_in serv_addr;
	int sockfd, ret;

	sockfd = socket(AF_INET, SOCK_STREAM, 0);
	if (sockfd < 0) {
		if (sockfd == -EINTR)
			sockfd = socket(AF_INET, SOCK_STREAM, 0);
		if (sockfd < 0)
			error("ERROR opening socket");
	}

	memset(&serv_addr,0,sizeof(serv_addr));
	serv_addr.sin_family = AF_INET;
	serv_addr.sin_port = htons(PORT);
	serv_addr.sin_addr.s_addr = inet_addr("127.0.0.1");

	ret = connect(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr));
	if (ret < 0) {
		if (ret == -EINTR)
			ret = connect(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr));
		if (ret < 0)
			error("ERROR connecting");
	}
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
	char response[512];
	int bytes;

	bytes = read(sockfd,response , 200);
	if (bytes < 0) {
		// If interrupted try again
		if (bytes == -EINTR)
			bytes = read(sockfd,response , 200);
	}
#if PRINT_RESPONSE
	printf("%s\n", response);
#endif
}

extern "C" int LLVMFuzzerInitialize(int* argc, char*** argv)
{
	ws.register_resource("{arg1|[A-Z]+}/{arg2|(.*)}", &agr);
	ws.register_resource(R"(.*)", &hwr);
	hwr.allow_all();
	agr.allow_all();
	return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
	int sockfd;

	if (memchr(data, '\n', size))
		return 0;

	if (memchr(data, '\r', size))
		return 0;
	//if (size)
		//ws.register_resource(reinterpret_cast<const char *>(data), &agr);
	/* Start the server */
	ws.start(false);

	/* Client -> connect to server */
	sockfd = connect_server();

	/* HTTP request*/
	write_request(sockfd, data, size);
	read_response(sockfd);

	/* Client -> close connection */
	close(sockfd);

	/* Stop the server */
	ws.stop();
	return 0;
}
