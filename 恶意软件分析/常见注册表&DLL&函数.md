# 常见注册表&DLL&函数

## 一、常见注册表

- `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`：开机自启
- `HKLM\SYSTEM\CurrentControlSet\Services`：服务

## 二、常见DLL

| DLL                     | 介绍                                                         |
| ----------------------- | ------------------------------------------------------------ |
| Kernel32.dll            | 包含核心功能，例如访问和控制内存、文件、硬件                 |
| Advapi32.dll            | 提供访问高级核心Windows组件的功能，例如Service Manager以及注册表 |
| User32.dll              | UI组件，例如按钮、滚动条以及控制和响应用户操作的功能         |
| Gdi32.dll               | 显示及控制图形的功能                                         |
| Ntdll.dll               | 内核接口，一般只由kernel32.dll间接导入。恶意软件直接导入该文件实现功能隐藏或进程控制等功能 |
| WSock32.dll, Ws2_32.dll | 网络功能                                                     |
| Wininet.dll             | 更高级别的网络功能，实现更多的协议，例如FTP, HTTP, NTP       |

## 二、网络相关函数

1. socket

```c
SOCKET WSAAPI socket(
  int af,		// 2 AF_INET
  int type,		// 1 SOCK_STREAM
  int protocol	// 6 IPPROTO_TCP; 17 IPPROTO_UDP
);
```

2. `CreateProcess`+`Sleep`+`exec`: 可能是后门

## 三、文件相关函数

1. `FindFirstFile`、`FindNextFile`说明程序在文件系统中进行遍历搜索
2. `LoadResource`, `FindResource`, `SizeOfResource`：需要查看程序的`rsrc`段，可能隐藏了其他信息
3. `CreateFile`, `WriteFile`, `WinExec`：创建了文件并执行
4. 

## 四、系统相关函数

1. `CreateToolhelp32Snapshot`：生成进程列表
2. `OpenService`, `DeleteService`, `OpenSCManager`, `CreateService`：服务相关功能