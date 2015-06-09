准备sctp内核包加载
=================

```bash
#如果SCTP内核模块没有加载则执行如下指令加载
lsmod |grep sctp 
#建议修改sctp随机启动
modprobe sctp     
```

cgsl64环境依赖包准备
===================

- libxml2-devel-2.6.23-15.20.x86_64.rpm
- lksctp-tools-1.0.10-5.el6.x86_64.rpm
- lksctp-tools-devel-1.0.10-5.el6.x86_64.rpm

sid生成规则 
==========

用例中的SID;pidxxxx:xxxxxxxx


配置规则
========

执行程序    | 配置事例
------------|-------------------
pt\_ots.so  | pt\_ots.cfg
pt.out      | pt.cfg


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

#check
 (_pid=$(ps -ef|awk '/\.\/[o]bj\/pt/{print $2}') && kill -SIGUSR1 $_pid)

#start
 (_pid=$(ps -ef|awk '/\.\/[o]bj\/pt/{print $2}') && kill -SIGUSR2 $_pid)

#stop
 (_pid=$(ps -ef|awk '/\.\/[o]bj\/pt/{print $2}') && kill -9 $_pid)
```


