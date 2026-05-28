# 溯源数据模型

## 节点类型 (Nodes)

| 类型 | 含义 | 示例 |
|------|------|------|
| `process` | 进程 (PID/TID) | nginx worker #1234 |
| `file` | 文件/目录 (inode) | /etc/passwd |
| `net` | 网络端点 (IP:Port) | 10.0.0.1:443 |
| `ipc` | 进程间通信 (pipe/shmem) | pipe:[12345] |
| `credential` | 凭证变更 | setuid/apparmor |

## 边类型 (Edges)

| 类型 | 含义 | 典型场景 |
|------|------|----------|
| `fork` | 进程派生 | shell 执行命令 |
| `execute` | 进程执行 | execve 加载二进制 |
| `read` | 进程读文件 | 读取配置文件 |
| `write` | 进程写文件 | 写入日志/恶意文件 |
| `connect` | 向外连接 | C2 外联 |
| `accept` | 监听接受连接 | 反弹 shell |
| `send/recv` | 网络数据收发 | 数据传输 |

## APT 检测关系

攻击过程中的溯源路径示例:
```
attacker.sh (exec)
  → bash (fork)
    → curl (exec)
      → connect(c2.attacker.com:443)  [C2 通信]
    → chmod (exec)
      → write(/tmp/malware)           [文件落地]
    → /tmp/malware (exec)
      → connect(c2.attacker.com:8443) [第二阶段]
      → read(/etc/shadow)             [提权/凭据窃取]
```
