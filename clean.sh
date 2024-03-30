ps -aux|grep run.py | awk '{print $2}' | xargs sudo kill -9
ps -aux|grep p4run | awk '{print $2}' | xargs sudo kill -9
ps -aux|grep simple_switch | awk '{print $2}' | xargs sudo kill -9
