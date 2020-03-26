# kp-abe

1. 虽然没有libclt13.so库文件，但貌似可以直接下载clt源文件的方式去调用，有时间可以试试。

2. 不清楚我的wsl环境带不带gmp，如果不带的话需要尝试手动安装。。。
   sudo apt install libgmp3-dev
   g++ test_gmp.cpp -o test_gmp -lgmp
   
   automake方法：https://blog.csdn.net/u011857683/article/details/82026809

3. 接下来都准备好后，就是要调通程序，能跑起来就行？
