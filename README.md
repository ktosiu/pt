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

libxml2-devel-2.6.23-15.20.x86_64.rpm

lksctp-tools-1.0.10-5.el6.x86_64.rpm

lksctp-tools-devel-1.0.10-5.el6.x86_64.rpm


编译
====

```bash
cd src
make clean && make
```

配置文件
========

执行程序    | 配置事例     |备注
------------|--------------|-------------------
pt\_ots.so  | pt\_ots.cfg  |中移ots测试平台使用
pt.out      | pt.cfg       |


pt.out使用
=========

```bash
#help
pt.out --help
Usage: ./obj/pt.out [<options>]

Possible options:

        -c <path>               Set config file path, default: pt.cfg.
        -u <path>               Set usecase file path, default: pt.cfg.
        -r <path>               Set running file path, default: pt.cfg.
        -l <log_level>          Set log level, 0-DEBUG 1-INFO 2-ERROR default: 2.
        -b <cpuid>              Bind CPU.
        -i                      Run in interactive mode.

#open
./obj/pt.out -c pt.cfg -u pt.cfg -r pt.cfg -i

#check
(_pid=$(ps -ef|awk '/\.\/[o]bj\/pt/{print $2}') && kill -SIGUSR1 $_pid)

#start
 (_pid=$(ps -ef|awk '/\.\/[o]bj\/pt/{print $2}') && kill -SIGUSR2 $_pid)

#stop
 (_pid=$(ps -ef|awk '/\.\/[o]bj\/pt/{print $2}') && kill -9 $_pid)
```


