# gosdf — GM/T 0018 密码设备 SDF 接口的 Go 封装

`gitee.com/zhujingfeng/gosdf`

通过 cgo + dlopen 加载设备动态库(厂商硬件 `.so` 或 SoftSDF 软件模拟器),接口形态贴近
Go 原生 crypto API。按 GM/T 0018-2023 实现并兼容 2012 版函数集。

```sh
go get gitee.com/zhujingfeng/gosdf
```

```go
dev, err := gosdf.Open("/path/to/libsdf.so") // 软件模拟器见 testdata/softsdf/
if err != nil {
	log.Fatal(err)
}
defer dev.Close()

s, err := dev.NewSession()
if err != nil {
	log.Fatal(err)
}
defer s.Close()

_, key, err := s.GenerateKeyWithKEK(1, 128, gosdf.SM4_ECB)
if err != nil {
	log.Fatal(err)
}
ct, err := key.Encrypt(gosdf.SM4_CBC, make([]byte, 16), []byte("0123456789abcdef"))
```

## 功能

- **设备/会话**:`Open`/`Close`、`NewSession`/`Close`、`GetDeviceInfo`、
  `GenerateRandom`、`Random()`(io.Reader)、`Supports` 查询绑定符号、
  `AcquireKeyRight`/`ReleaseKeyRight`
- **杂凑**:`Session.NewHash`(仅接受 SGD_SM3/SGD_SHA256)/`NewSM2ZAHash`/`SM2Digest`;
  `Device.NewSM3Hash` 提供 `hash.Hash`,`SM3Sum` 为一次性杂凑(不实现 `hash.Hash`)
- **HMAC**:`Key.HMAC`/`Key.NewHMAC` 一步式与多步式入口(C 线 `SDF_HMACInit/Update/Final`,
  GM/T 0018-2023 6.6.2~6.6.4,GB/T 15852.2 带密钥杂凑);
  alg 参数为 HMAC 类标识 `SGD_SM3_HMAC`/`SGD_SHA256_HMAC`,内部映射为杂凑标识下发设备
- **SM2**:`SignerKey` 实现 `crypto.Signer`(`SM2SignerOptions` 带 UID)、
  `VerifySM2`/`VerifySM2Digest`/`VerifySM2Internal` 验签、外部公钥加密(GB/T 35275 DER)、
  `GenerateKeyPairECC`(2023 表16 验证调试类)、密钥包装 `GenerateKeyWithIPK/EPK`、
  `ImportKeyWithISK`、密钥协商三接口、`ExchangeEnvelopeECC` 数字信封转换(2012 版)
- **RSA 密钥管理**:`ExportSign/EncPublicKeyRSA`、`GenerateKeyPairRSA`(2023 表16 验证调试类)、
  `GenerateKeyWithIPKRSA/EPKRSA`、`ImportKeyWithISKRSA`、`ExchangeEnvelopeRSA` 数字信封转换(2012 版);
  不含 RSA 加解密运算接口
- **密钥管理类**按 GM/T 0018 两版全集实现,另含 `ImportKey`(明文会话密钥,2012 版)与 `DestroyKey`
- **对称**:SM1/SM4/SM7/AES 单包与多包加解密(`NewEncrypter`/`NewDecrypter`/`Crypter.Update/Final`)、
  PKCS7 填充、CBC-MAC/ISO9797-M3(`MAC`/`MACM3`/`NewMAC`)、`Block()` 返回 `cipher.Block`(ECB 单分组)
- **可鉴别加解密(AEAD)**:`Key.AuthEncrypt`/`AuthDecrypt`(一步式)与
  `NewAuthEncer`/`NewAuthDecrypter`(`AuthCrypter.Update/Final`),GCM/CCM,标签 16 字节;
  startVar 长度 GCM 1~64、CCM 7~13,多步总长上限 1MiB。多步 `Update` 返回设备本段输出
  (缓冲型设备为空切片),`Final` 加密侧返回 (尾部密文, 标签)、解密侧返回 (尾部明文, nil);
  调用方按 Update 输出 + Final 输出顺序拼接;篡改返回 `SDR_VERIFYERR`;
  多步 AEAD 的 AAD 上限 256 字节,超出返回 `SDR_NOBUFFER`
- **文件**:`CreateFile`/`ReadFile`/`WriteFile`/`DeleteFile`(文件名最长 128 字节)

## 错误约定

所有操作返回 `error`;设备错误值为 `RV`(实现 `error` 接口),错误串含 SDF 函数名,如
`gosdf: SDF_Encrypt: SGD error 0x01000009`,可用 `errors.Is(err, SDR_XXX)` 判定。

## 兼容性

除 `OpenDevice`/`CloseDevice`/`OpenSession`/`CloseSession` 四个必需符号外,其余 `SDF_*`
符号均为可选:运行时按名 dlsym,缺失返回 `SDR_NOTSUPPORT`,不影响其余功能
(兼容 2012 时代 `.so`;其缺 `SDF_HMAC*` 与多包符号时对应功能不可用)。
不支持厂商自实现接口(如 `SDF_InternalDecrypt_ECC`、五参 `SDF_HMAC_Init` ABI)。
SM2 私钥解密不在标准中,不提供;标准模型为会话密钥加解密 + 非对称封装(IPK/EPK/ISK)。

## 使用注意

- `Device`/`Session`/`Key`/`Crypter`/`AuthCrypter`/`Hasher`/`SignerKey` 均不保证并发安全,
  禁止多线程共用。
- 内部私钥运算(`SignerKey.Sign`、`ImportKeyWithISK` 等 ISK 类操作)需调用方先
  `AcquireKeyRight(keyIndex, pin)`,用完 `ReleaseKeyRight`;设备缺权限时返回 `SDR_PARDENY`。
- `cipher.Block` 与 SM3 `hash.Hash` 的 `Sum` 路径无法返回 error,设备失败时
  panic(错误文本以 `gosdf:` 开头)。

## 设备能力探测

在自己的测试里对任意 SDF `.so` 一键探测"支持哪些 SDF 接口 + 每项功能是否正确",无需克隆/修改 gosdf 源码:

```go
func TestDeviceProbe(t *testing.T) {
	res, err := gosdf.TestDevice("/path/to/libxxx.so", gosdf.WithPIN([]byte("12345678")))
	if err != nil {
		t.Fatal(err) // 任一 FAIL 时非 nil,文本含 "N pass, N fail, N skip"
	}
	_ = res // res.Symbols 符号矩阵 / res.Checks 检查结论 / res.Summary() 统计
}
```

报告写到 stdout:63 个绑定符号的支持矩阵(`ok`/`miss`)+ 28 项功能检查的
PASS/FAIL/SKIP 结论(缺符号、缺 PIN、密钥索引不存在一律 SKIP,不算 FAIL)。
选项:`WithKeyIndex`/`WithKEKIndex` 指定内部密钥与 KEK 索引(默认 1)、
`WithPIN` 提供私钥权限 PIN(不提供则需私钥的检查全部 SKIP)、`WithOutput`
重定向报告(传 `io.Discard` 即静默)。探测非破坏:会话密钥用完销毁、
探测文件用完删除、权限用完释放;SoftSDF 等按进程 CWD 相对路径读密钥文件的
设备要求调用方在正确目录运行,`TestDevice` 不改变 CWD。

## 测试

```sh
go test .              # 根包:纯 Go 单测 + 桩契约测试
go test ./integration/ -v  # SoftSDF 端到端(需先按 testdata/softsdf/README.md 构建产物)
```

- **桩测试**:无硬件时自动用 `testdata/sdf_stub.c` 编译桩设备,覆盖参数传递、
  步骤机、缺符号降级等契约;`cc` 不可用时跳过。
- **集成测试**:`integration/` 包在 SoftSDF 软件模拟器上执行 A~H 全矩阵
  (设备管理/杂凑 HMAC/SM2/RSA/对称 AEAD/文件/错误契约),依赖
  `testdata/softsdf/` 下的 `libsoftsdf.so` 与 `softsdfinit`,缺失即失败;
  重建方法见 [testdata/softsdf/README.md](testdata/softsdf/README.md)。
- **真机能力验证**:对任意厂商 `.so` 用 `gosdf.TestDevice` 探测(见[设备能力探测](#设备能力探测))。
