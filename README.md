# doaswhat

快速 doas 权限枚举器 -- 检测哪些命令可免密或需密码通过 `doas` 执行。

---

## 实现

| 文件 | 语言 | 类型 |
|------|------|------|
| `doaswhat` | Bash | 脚本，直接运行 |
| `doaswhat.c` | C99 | 编译（并行 fork） |
| `doaswhat.go` | Go | 编译（goroutine） |

---

## 用法

```bash
doaswhat [-u user] [-h]
```

| 选项 | 说明 |
|------|------|
| `-u user` | 目标用户（默认：当前用户） |
| `-h` | 帮助 |

### 示例

```bash
doaswhat          # 测试当前用户
doaswhat -u silas # 测试指定用户
```

---

## 原理

1. 定位 `doas` 并显示文件信息
2. 解析 `/etc/doas.conf`、`/etc/doas.d/*.conf`
3. 枚举 `$PATH` 中所有可执行文件
4. 并发执行 `doas <cmd> --help`（全路径 + basename）
5. 分类：
   - **免密** -- 立即退出（exit 0），对应 `permit nopass`
   - **需密** -- 进程挂起（等待密码），超时后杀死
   - **拒绝** -- 执行失败
6. 排序输出结果

---

## 编译

### C

```bash
x86_64-linux-gnu-gcc -O2 -s -static -o doaswhat-c doaswhat.c
```

### Go

```bash
GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o doaswhat-go doaswhat.go
```

Bash 无需编译。

---

## 输出示例

```
doaswhat v2.0  Sublarge  https://github.com/yanxinwu946/doaswhat

[*] binary
-rwsr-xr-x 1 root root 34824 Oct 11 2024 /usr/bin/doas

[*] configs
[+] /etc/doas.conf
permit silas as root cmd /usr/bin/id
permit nopass silas as root cmd /usr/bin/vi

[*] probing 559 commands...
[559/559] testing...

[*] analyzing results...

[+] you can run these without a password:

    doas /usr/bin/vi

[!] these require a password:

    doas /usr/bin/id
```

---

## 故障排除

终端回显异常时运行：

```bash
stty echo
```
