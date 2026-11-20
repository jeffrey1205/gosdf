# SoftSDF 产物说明

本目录存放 **SoftSDF**(GmSSL 之上的 SDF 软件模拟器)的构建产物,供 gosdf 集成测试
(`integration/softsdf_test.go`)加载真实 SDF 设备做端到端验证:

| 文件 | 说明 |
|---|---|
| `libsoftsdf.so` | SDF 设备动态库,gosdf 通过 `gosdf.Open()` 加载 |
| `softsdfinit` | 密钥文件生成工具(KEK、SM2 签名/加密、RSA 密钥对) |

源码仓库:<https://github.com/jeffrey1205/SoftSDF>(依赖 GmSSL:<https://github.com/guanzhi/GmSSL>)

## 构建

两个产物均为 Linux x86_64 动态库/可执行文件,构建分两步:

**1. GmSSL 静态库(必须 static + PIC)**

先克隆并 checkout 钉定修订(3.3.0-dev.1183,含 `sm2_key_exchange`,SoftSDF CI 同一 SHA):

```sh
git clone https://github.com/guanzhi/GmSSL
git -C GmSSL checkout 24ae482701a7b124826c382fffc55c19f76d475d
```

SoftSDF 将 GmSSL 静态库整体链入 `libsoftsdf.so`,而 GmSSL 构建默认不开
位置无关代码,以下开关不可省;`ENABLE_SM4_*`/`ENABLE_SDF` 需与 SoftSDF 侧一致:

```sh
cmake -S GmSSL -B GmSSL/build-softsdf \
  -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_INSTALL_PREFIX="$PWD/GmSSL/build-softsdf/install" \
  -DBUILD_SHARED_LIBS=OFF -DCMAKE_POSITION_INDEPENDENT_CODE=ON \
  -DENABLE_SDF=ON -DENABLE_SM4_ECB=ON -DENABLE_SM4_CFB=ON \
  -DENABLE_SM4_OFB=ON -DENABLE_SM4_CBC_MAC=ON
cmake --build GmSSL/build-softsdf -j"$(nproc)"
cmake --install GmSSL/build-softsdf
```

**2. SoftSDF**

```sh
git clone https://github.com/jeffrey1205/SoftSDF
cmake -S SoftSDF -B SoftSDF/build -DCMAKE_BUILD_TYPE=Release \
  -DGmSSL_ROOT_DIR="$PWD/GmSSL/build-softsdf/install"
cmake --build SoftSDF/build -j"$(nproc)"
```

产物位于 `SoftSDF/build/libsoftsdf.so` 与 `SoftSDF/build/softsdfinit`,复制到本目录即可
(注意 `*.so` 与 `softsdfinit` 在上级 `.gitignore` 中,入库需 `git add -f`)。

SoftSDF 自带测试(ctest 会在临时夹具目录生成两组密钥后运行 softsdftest 与 GmSSL 工具链测试):

```sh
ctest --test-dir SoftSDF/build --output-on-failure
```

## 使用

**1. 生成密钥文件(必须在设备进程的工作目录中运行)**

SoftSDF 按**进程 CWD 相对路径**读取密钥文件,先在目标工作目录执行:

```sh
cd /path/to/workdir
/path/to/softsdfinit -kek 1 -key 1 -pass P@ssw0rd
```

生成 `kek-1.key`、`sm2sign-1.pem`/`sm2signpub-1.pem`、`sm2enc-1.pem`/`sm2encpub-1.pem`、
`rsasign-1.key`、`rsaenc-1.key`(RSA 为 2048 位)。`-kek N -key N` 可指定 1~4096 的索引,
多组索引需分别执行。

**2. 加载设备**

```go
dev, err := gosdf.Open("/abs/path/to/libsoftsdf.so") // 建议绝对路径
defer dev.Close()
```

**3. 约束**

- SoftSDF 为**全局单设备**:同一进程内二次 `OpenDevice` 返回 `SDR_OPENDEVICE`,
  gosdf 侧应全程共用一个 `*gosdf.Device`(关闭后可重新 Open)。
- 内部私钥运算(SM2 签名、ISK 解封、协商等)需先
  `AcquireKeyRight(keyIndex, []byte("P@ssw0rd"))`。
- 仅供测试:无侧信道防护,错误路径会向 stderr 打印 `error_print()` 诊断。
