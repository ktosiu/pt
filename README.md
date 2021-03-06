准备工作
=======
准备sctp内核包加载
-----------------

```bash
#如果SCTP内核模块没有加载则执行如下指令加载
lsmod |grep sctp 
#建议修改sctp随机启动
modprobe sctp     
```

依赖包准备
----------

libxml2-devel-2.6.23-15.20.x86\_64.rpm

lksctp-tools-1.0.10-5.el6.x86\_64.rpm

lksctp-tools-devel-1.0.10-5.el6.x86\_64.rpm


编译
====

```bash
make clean && make
```

配置文件
========

执行程序                 | 配置事例     |备注
-------------------------|--------------|-------------------
build/bin/libpt\_ots.so  | pt\_ots.cfg  |中移ots测试平台使用
build/bin/pt             | pt.cfg       |


pt.out使用
========

help
--------
```bash
pt --help
Usage: pt [<options>]

Possible options:

        -c <path>               Set config file path, default: pt.cfg.
        -u <path>               Set usecase file path, default: pt.cfg.
        -r <path>               Set running file path, default: pt.cfg.
        -l <log_level>          Set log level, 0-DEBUG 1-INFO 2-ERROR default: 2.
        -b <cpuid>              Bind CPU.
        -i                      Run in interactive mode.
```

后台运行方式
--------
```bash
#open
build/bin/pt -c ./src/pt.cfg -u ./src/pt.cfg -r ./src/pt.cfg

#check
(_pid=$(ps -ef|awk '/\.\/[b]in\/pt/{print $2}') && kill -SIGUSR1 $_pid)

#start
(_pid=$(ps -ef|awk '/\.\/[b]in\/pt/{print $2}') && kill -SIGUSR2 $_pid)

#stop
(_pid=$(ps -ef|awk '/\.\/[b]in\/pt/{print $2}') && kill -9 $_pid)
```

shell运行方式
--------

```bash
#open
build/bin/pt -c ./src/pt.cfg -u ./src/pt.cfg -r ./src/pt.cfg -i

#shell
>>> ? 
show    Show information of diamlink m3ualink and uc
run     Run usecase
?       Help
```
