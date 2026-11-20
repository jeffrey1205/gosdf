package gosdf

/*
#cgo CFLAGS: -I.
#cgo LDFLAGS: -ldl
#include <stdlib.h>
#include "sdf.h"
*/
import "C"

import (
	"bytes"
	"io"
	"unsafe"
)

// zeroByte 空切片取址用的包级零字节;C 调用同步完成,不会保留该指针。
var zeroByte [1]byte

// bytePtr 返回切片首字节指针;空切片返回指向包级零字节的指针(避免 &x[0] panic)。
func bytePtr(p []byte) *C.uchar {
	if len(p) == 0 {
		return (*C.uchar)(unsafe.Pointer(&zeroByte[0]))
	}
	return (*C.uchar)(unsafe.Pointer(&p[0]))
}

// cstr 将 C 字节串(去尾部 NUL)转为 Go 字符串。
func cstr(b []byte) string {
	if i := bytes.IndexByte(b, 0); i >= 0 {
		b = b[:i]
	}
	return string(b)
}

// newCipherBuf 分配含 ECCCipher 柔性数组 C 的 ABI 缓冲,
// capExtra 为内容字节上限(密钥包装/解析取 136;SM2 加密取
// max(消息长度, 136),因为 SDF_ExternalEncrypt_ECC 没有容量参数)。
func newCipherBuf(capExtra int) []byte {
	return make([]byte, int(unsafe.Sizeof(C.ECCCipher{}))+capExtra+16)
}

// Device 已加载的 SDF 设备(动态库 + 设备句柄)。
// Device/Session/Key/Crypter/AuthCrypter/Hasher/SignerKey 均不保证并发安全,禁止多线程共用。
type Device struct {
	ctx    *C.sdf_ctx
	closed bool
}

// Open 加载厂商 SDF 动态库并打开设备。
// 除 OpenDevice/CloseDevice/OpenSession/CloseSession 外的 SDF_* 符号均为可选,
// 缺失时相关方法返回 SDR_NOTSUPPORT,不影响其余功能。
func Open(libPath string) (*Device, error) {
	if libPath == "" {
		return nil, argErr("SDF_OpenDevice")
	}
	cpath := C.CString(libPath)
	defer C.free(unsafe.Pointer(cpath))

	var rv C.RV
	ctx := C.sdf_open(cpath, &rv)
	if ctx == nil {
		return nil, rvErr("SDF_OpenDevice", RV(rv))
	}
	return &Device{ctx: ctx}, nil
}

// Close 关闭设备并卸载动态库,幂等。
func (d *Device) Close() error {
	if d == nil || d.closed {
		return nil
	}
	d.closed = true
	C.sdf_close(d.ctx)
	d.ctx = nil
	return nil
}

// Supports 探测底层 .so 是否导出指定 SDF 符号(全名,如 "SDF_HMACInit")。
// 除四个生命周期符号外均为可选绑定,缺失时对应方法返回 SDR_NOTSUPPORT;
// 调用方可在启动时用本方法 fail-fast(如 2012 时代 .so 无 HMAC/多包符号)。
// 设备为 nil/已关闭或符号名不存在时返回 false。
func (d *Device) Supports(sdfSymbol string) bool {
	if d == nil || d.closed || d.ctx == nil {
		return false
	}
	cname := C.CString(sdfSymbol)
	defer C.free(unsafe.Pointer(cname))
	return C.sdf_has(d.ctx, cname) != 0
}

// Session 会话句柄。关闭后所有操作返回 SDR_NOTSUPPORT。
type Session struct {
	d *Device
	h HANDLE
}

// NewSession 在设备上打开一个新会话。
func (d *Device) NewSession() (*Session, error) {
	if d == nil {
		return nil, argErr("SDF_OpenSession")
	}
	var h HANDLE
	if rv := C.open_session(d.ctx, (**C.long)(unsafe.Pointer(&h))); rv != 0 {
		return nil, rvErr("SDF_OpenSession", RV(rv))
	}
	return &Session{d: d, h: h}, nil
}

// Close 关闭会话,幂等;设备已关闭时会话视为已关闭。
func (s *Session) Close() error {
	if s == nil || s.h == nil {
		return nil
	}
	ctx, h, err := s.handles("SDF_CloseSession")
	if err != nil {
		s.h = nil
		return nil
	}
	rv := C.close_session(ctx, h)
	if rv != 0 {
		return rvErr("SDF_CloseSession", RV(rv))
	}
	s.h = nil
	return nil
}

// handles 校验会话与设备状态,返回 C 上下文与会话句柄;
// 会话或设备已关闭时返回 SDR_NOTSUPPORT。
func (s *Session) handles(op string) (*C.sdf_ctx, *C.long, error) {
	if s == nil || s.d == nil || s.d.ctx == nil || s.h == nil {
		return nil, nil, rvErr(op, SDR_NOTSUPPORT)
	}
	return s.d.ctx, (*C.long)(unsafe.Pointer(s.h)), nil
}

// GetDeviceInfo 读取设备信息。
func (s *Session) GetDeviceInfo() (*DeviceInfo, error) {
	ctx, h, err := s.handles("SDF_GetDeviceInfo")
	if err != nil {
		return nil, err
	}
	var info C.DEVICEINFO
	if rv := C.get_device_info(ctx, h, &info); rv != 0 {
		return nil, rvErr("SDF_GetDeviceInfo", RV(rv))
	}
	return deviceInfoFromC(&info), nil
}

func deviceInfoFromC(info *C.DEVICEINFO) *DeviceInfo {
	return &DeviceInfo{
		IssuerName:      cstr((*[40]byte)(unsafe.Pointer(&info.IssuerName[0]))[:]),
		DeviceName:      cstr((*[16]byte)(unsafe.Pointer(&info.DeviceName[0]))[:]),
		DeviceSerial:    cstr((*[16]byte)(unsafe.Pointer(&info.DeviceSerial[0]))[:]),
		DeviceVersion:   uint32(info.DeviceVersion),
		StandardVersion: uint32(info.StandardVersion),
		AsymAlgAbility:  [2]uint32{uint32(info.AsymAlgAbility[0]), uint32(info.AsymAlgAbility[1])},
		SymAlgAbility:   uint32(info.SymAlgAbility),
		HashAlgAbility:  uint32(info.HashAlgAbility),
		BufferSize:      uint32(info.BufferSize),
	}
}

// GenerateRandom 生成 n 字节随机数;n<0 报 SDR_INARGERR,n==0 返回空切片
// (会话已关闭时仍先经 handles() 检查,返回 SDR_NOTSUPPORT)。
func (s *Session) GenerateRandom(n int) ([]byte, error) {
	if n < 0 {
		return nil, argErr("SDF_GenerateRandom")
	}
	ctx, h, err := s.handles("SDF_GenerateRandom")
	if err != nil {
		return nil, err
	}
	if n == 0 {
		return []byte{}, nil
	}
	buf := make([]byte, n)
	if rv := C.gen_random(ctx, h, C.UINT32(n), bytePtr(buf)); rv != 0 {
		return nil, rvErr("SDF_GenerateRandom", RV(rv))
	}
	return buf, nil
}

// Random 返回基于设备随机数发生器的 io.Reader。
func (s *Session) Random() io.Reader {
	return sessionRandom{s: s}
}

type sessionRandom struct {
	s *Session
}

func (r sessionRandom) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	b, err := r.s.GenerateRandom(len(p))
	if err != nil {
		return 0, err
	}
	return copy(p, b), nil
}

// AcquireKeyRight 获取私钥使用权限;内部私钥签名、解密前必须调用,
// 设备权限不足时返回 SDR_PARDENY(本函数不自动获取 PIN)。
func (s *Session) AcquireKeyRight(keyIndex uint32, pin []byte) error {
	const op = "SDF_GetPrivateKeyAccessRight"
	ctx, h, err := s.handles(op)
	if err != nil {
		return err
	}
	if rv := C.verify_pin(ctx, h, C.UINT32(keyIndex), bytePtr(pin), C.UINT32(len(pin))); rv != 0 {
		return rvErr(op, RV(rv))
	}
	return nil
}

// ReleaseKeyRight 释放私钥使用权限。
func (s *Session) ReleaseKeyRight(keyIndex uint32) error {
	const op = "SDF_ReleasePrivateKeyAccessRight"
	ctx, h, err := s.handles(op)
	if err != nil {
		return err
	}
	if rv := C.release_pin(ctx, h, C.UINT32(keyIndex)); rv != 0 {
		return rvErr(op, RV(rv))
	}
	return nil
}

// fileName 校验并返回文件名字节(标准 6.7.3:文件名最大 128 字节)。
func fileName(name, op string) ([]byte, error) {
	if len(name) == 0 || len(name) > 128 {
		return nil, argErr(op)
	}
	return []byte(name), nil
}

// CreateFile 在设备中创建文件。
func (s *Session) CreateFile(name string, size uint32) error {
	const op = "SDF_CreateFile"
	ctx, h, err := s.handles(op)
	if err != nil {
		return err
	}
	nb, err := fileName(name, op)
	if err != nil {
		return err
	}
	if rv := C.create_file(ctx, h, bytePtr(nb), C.UINT32(len(nb)), C.UINT32(size)); rv != 0 {
		return rvErr(op, RV(rv))
	}
	return nil
}

// ReadFile 读取文件,从 offset 起最多读 length 字节;返回值为实际读取内容
// (puiReadLength 为 in/out:入参请求长度,出参实际长度)。
func (s *Session) ReadFile(name string, offset, length uint32) ([]byte, error) {
	const op = "SDF_ReadFile"
	ctx, h, err := s.handles(op)
	if err != nil {
		return nil, err
	}
	nb, err := fileName(name, op)
	if err != nil {
		return nil, err
	}
	buf := make([]byte, length)
	actual := length
	if rv := C.read_file(ctx, h, bytePtr(nb), C.UINT32(len(nb)), C.UINT32(offset),
		(*C.UINT32)(unsafe.Pointer(&actual)), bytePtr(buf)); rv != 0 {
		return nil, rvErr(op, RV(rv))
	}
	if actual > length { // 防御设备返回越界长度
		actual = length
	}
	return buf[:actual], nil
}

// WriteFile 从 offset 起写入 data。
func (s *Session) WriteFile(name string, offset uint32, data []byte) error {
	const op = "SDF_WriteFile"
	ctx, h, err := s.handles(op)
	if err != nil {
		return err
	}
	nb, err := fileName(name, op)
	if err != nil {
		return err
	}
	if rv := C.write_file(ctx, h, bytePtr(nb), C.UINT32(len(nb)), C.UINT32(offset),
		C.UINT32(len(data)), bytePtr(data)); rv != 0 {
		return rvErr(op, RV(rv))
	}
	return nil
}

// DeleteFile 删除文件。
func (s *Session) DeleteFile(name string) error {
	const op = "SDF_DeleteFile"
	ctx, h, err := s.handles(op)
	if err != nil {
		return err
	}
	nb, err := fileName(name, op)
	if err != nil {
		return err
	}
	if rv := C.delete_file(ctx, h, bytePtr(nb), C.UINT32(len(nb))); rv != 0 {
		return rvErr(op, RV(rv))
	}
	return nil
}
