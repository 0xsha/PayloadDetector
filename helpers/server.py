from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse
import pickle
from sys import argv

from aiohttp import web

payload = {"version": [], "path_qs": [], "cookies": [], "content_length": [],
           "path": [], "raw_path": [], "query_string": [], "headers": [], "content_type": [], "body": []}


async def custom_logger(payload):
    log_file = open("logs.txt", "a+")

    # content = await log_file.read()
    for key, value in payload.items():
        print(key, value)
    #     log_file.write("=======" + key + "=====\n")
    #     log_file.write(value+"\n")
    #     log_file.write("=======================\n")
    # log_file.close()


async def all_handler(request):
    payload["version"].append(request.version)
    payload["path_qs"].append(request.path_qs)
    payload["cookies"].append(request.cookies)
    payload["path"].append(request.path)
    payload["raw_path"].append(request.raw_path)
    payload["query_string"].append(request.query_string)
    payload["content_length"].append(request.content_length)
    payload["headers"].append(request.headers.values())
    payload["content_type"].append(request.content_type)
    # payload["charset"].append(request.charset)

    if request.can_read_body:
        body = request.content.read()
        payload["body"].append(request.content_type)

    await custom_logger(payload)
    return web.Response(text="Gotcha")


app = web.Application()

app.add_routes(
    [web.route('*', '/', all_handler)]
)

web.run_app(app, host="192.168.1.100", port=9876, access_log=None)

attack_logger = {"payload": [], "category": []}
f = open("../models/tfidf_SVC_best_params_3.model", "rb")
loaded_pipe_model = pickle.load(f)
f.close()


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        #UnderAttackHandler()
        DoThePrediction(self)
        self.send_response(200, "ok")
        self.send_header('Content-type', 'text/html')
        self.end_headers()
        #print(self.headers)
        #print(self.path)

    def do_POST(self):
        #UnderAttackHandler()
        DoThePrediction(self)
        self.send_response(200, "ok")
        self.send_header('Content-type', 'text/html')
        self.end_headers()
        #content_length = int(self.headers['Content-Length'])
        #post_data = self.rfile.read(content_length)
        #print(post_data)


def RunServer(server_class=HTTPServer, host='', port="9876", handler_class=Handler):
    # logging.basicConfig(level=logging.INFO)
    server_address = (host, int(port))
    httpd = server_class(server_address, handler_class)
    # logging.info('Starting httpd...\n')
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    httpd.server_close()


def DoThePrediction(self):
    predict_header_values = loaded_pipe_model.predict(self.headers.values())
    actual_values = self.headers.values()
    PredictionHandler(predict_header_values, actual_values)
    # predict_query_values = loaded_pipe_model.predict(urlparse(self.path).query)
    # actual_query_values = urlparse(self.path).query
    #
    # PredictionHandler(predict_query_values, actual_query_values)


def PredictionHandler(predicted_values, actual_values):
    i = 0
    for predict in predicted_values:
        if predict != "clean":
            print("Possible attack detected : " + predict + " " + actual_values[i])
            print("predected" ,actual_values[i])
            attack_logger["category"].append(predict)
            attack_logger["payload"].append(actual_values[i])
    i += 1


# def UnderAttackHandler():
#     if len(attack_logger["payload"]) > 1:
#         print("Hmm we are detecting something")
#     if len(attack_logger["payload"]) > 3:
#         print("Did you hear me?")
#     if len(attack_logger["payload"]) > 10:
#         print("Shutting things down (kidding)")


if __name__ == '__main__':

    #  xss = ["192.168.1.10:9887", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9", "<script>alert(document.domain)</script>", "helllloooooo" , "1"]
    # #        "<svg/onload=prompt(1)>"]
    #  predicted = loaded_pipe_model.predict(xss)
    #  print(predicted)

    if len(argv) < 2:
        RunServer()
    elif len(argv) == 2:
        RunServer(host=argv[1])
    elif len(argv) == 3:
        RunServer(host=argv[1], port=argv[2])
    else:
        print("Invalid arguments usage : server.py host port ")

    RunServer()
