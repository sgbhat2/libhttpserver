#include <iostream>
#include <stdint.h>
#include <stddef.h>
#include <thread>
#include <httpserver.hpp>

using namespace httpserver;
webserver ws = create_webserver(8080).start_method(http::http_utils::INTERNAL_SELECT).max_threads(5);
std::thread ts;

class fuzz_resource : public http_resource {
	public:
		const std::shared_ptr<http_response> render(const http_request&);
};

const std::shared_ptr<http_response> fuzz_resource::render(const http_request& req)
{
	return std::shared_ptr<http_response>(new string_response("Hello World!!!", 200));
}

extern "C" int LLVMFuzzerInitialize(int* argc, char*** argv)
{
	fuzz_resource hwr;
	ws.register_resource("/hello", &hwr, true);

	return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
	std::string cstr("curl -v http://localhost:8080/");
	std::string str(reinterpret_cast<const char *>(data), size);
	std::string fstr = cstr + str + std::string(" 2> /dev/null");

	ts = std::thread([&]() {ws.start(true);});

	std::this_thread::sleep_for(std::chrono::seconds(1));
	system(fstr.c_str());
	std::this_thread::sleep_for(std::chrono::seconds(1));

	ws.stop();
	ts.join();
	return 0;
}
