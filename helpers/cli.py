
import pickle
# driver code for base models 
# models are not optimized (tuned) on this repo
# models are built on top of unbalanced dataset

f = open("../models/RF_1024_Features_Base.model", "rb")
loaded_pipe_model = pickle.load(f)
f.close()
test_payloads = ["system(ls -la)", "xss", "crlf", "xxe", "sqli", "injection", "lfi", "passwd", "etc", "onmouseover",
                                      "onload", "192.168.1.100:9887", "127.0.0.1", "10.255.255.255", "host", "localhost"
                                                                                                             "10.0.0.0",
                                      "172.31.255.255", "192.168.255.255", "192.168.0.0", "172.16.0.0", "wait", "count",
                                      "select", "google", "google.com", "www.google.com", "alert", "alert(1)"
                                                                                                   "bin", "bash",
                                      "curl", "where", "char", "exec", "cgi", "extractvalue", "1", "2", "3"
                                                                                                        "tftp",
                                      "192.168", "192.", "127.", "'", "<>",
                                      "<a>example.com</a>", "cmd", "<>@!@#$%^&*()_+", "<b>example.com<<>>@",
                                      "Mozilla/5.0 (X11; OpenBSD i386) AppleWebKit/537.36 (KHTML, like Gecko) "
                                      "Chrome/36.0.1985.125 Safari/537.36" , "../../etc/passwd" , "and 1=1--" , "<svg/onload=alert(0)"]

results = loaded_pipe_model.predict(test_payloads)
print(results)