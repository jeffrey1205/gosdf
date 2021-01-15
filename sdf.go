package gosdf

/*
#cgo CFLAGS: -I.
#cgo LDFLAGS: -ldl
#include <stdio.h>
#include <dlfcn.h>

#include "sdf.h"

static void *sdf_device = NULL; //加密设备
static void *lib_handle = NULL; //so库

typedef int (* OPEN_DEVICE)(void **);
OPEN_DEVICE open_device;

typedef int (* CLOSE_DEVICE)(void *);
CLOSE_DEVICE close_device;

typedef int (* OPEN_SESSION)(void *, void **);
OPEN_SESSION open_session;

typedef int (* CLOSE_SESSION)(void *);
CLOSE_SESSION close_session;

typedef int (* HASH_INIT)(void *, unsigned int, ECCrefPublicKey *, unsigned char *, unsigned int);
HASH_INIT hash_init;

typedef int (* HASH_UPDATE)(void *, unsigned char *, unsigned int);
HASH_UPDATE hash_update;

typedef int (* HASH_FINAL)(void *, unsigned char *, unsigned int *);
HASH_FINAL hash_final;

int sdf_sym_init(char *path)
{
	lib_handle = dlopen(path, RTLD_LAZY);
	if (lib_handle == NULL)
	{
		printf("open %s error\n", path);
		return -1;
	}

	//查找符号
	open_device = (OPEN_DEVICE)dlsym(lib_handle, "SDF_OpenDevice");
	if (open_device == NULL)
	{
		printf("lookup SDF_OpenDevice error\n");
		goto error;
	}

	close_device = (CLOSE_DEVICE)dlsym(lib_handle, "SDF_CloseDevice");
	if (close_device == NULL)
	{
		printf("lookup SDF_CloseDevice error\n");
		goto error;
	}

	open_session = (OPEN_SESSION)dlsym(lib_handle, "SDF_OpenSession");
	if (open_session == NULL)
	{
		printf("lookup SDF_OpenSession error\n");
		goto error;
	}

	close_session = (CLOSE_SESSION)dlsym(lib_handle, "SDF_CloseSession");
	if (close_session == NULL)
	{
		printf("lookup SDF_CloseSession error\n");
		goto error;
	}

	hash_init = (HASH_INIT)dlsym(lib_handle, "SDF_HashInit");
	if (hash_init == NULL)
	{
		printf("lookup SDF_HashInit error\n");
		goto error;
	}

	hash_update = (HASH_UPDATE)dlsym(lib_handle, "SDF_HashUpdate");
	if (hash_update == NULL)
	{
		printf("lookup SDF_HashUpdate error\n");
		goto error;
	}

	hash_final = (HASH_FINAL)dlsym(lib_handle, "SDF_HashFinal");
	if (hash_final == NULL)
	{
		printf("lookup SDF_HashFinal error\n");
		goto error;
	}

	//打开设备
	if (!open_device(&sdf_device))
	{
		return 0;
	}
	printf("open device error\n");

error:
	dlclose(lib_handle);
	return -2;
}

void sdf_sym_exit(void)
{
	//关闭设备
	if (sdf_device != NULL)
	{
		if (close_device(sdf_device))
			printf("close device error\n");
	}

	if (lib_handle != NULL)
		dlclose(lib_handle);
}

long sdf_open_session(void)
{
	int ret;
	void *session;

	ret = open_session(sdf_device, &session);
	if (ret != 0)
	{
		return 0;
	}

	return (long)session;
}

int sdf_close_session(long session)
{
	return close_session((void *)session);
}

int sdf_hash_init(long session, unsigned int alg)
{
	return hash_init((void *)session, alg, NULL, NULL, 0);
}

int sdf_hash_update(long session, unsigned char *buf, unsigned int buf_len)
{
	return hash_update((void *)session, buf, buf_len);
}

int sdf_hash_final(long session, unsigned char *hash, unsigned int *hash_len)
{
	return hash_final((void *)session, hash, hash_len);
}
*/
import "C"
import (
	"fmt"
	"unsafe"
)

//SdfInit:模块初始化,打开device、so库,查找符号表
func SdfInit(libPath string) error {
	if ret := C.sdf_sym_init(C.CString(libPath)); ret != 0 {
		return fmt.Errorf("sdf_sym_init error: %d", ret)
	}

	return nil
}

//SdfExit:模块退出
func SdfExit() {
	C.sdf_sym_exit()
}

//SdfOpenSession:打开会话,成功返回session_id >0,失败返回0
func SdfOpenSession() int64 {
	return int64(C.sdf_open_session())
}

//SdfCloseSession:关闭会话
func SdfCloseSession(session int64) int32 {
	return int32(C.sdf_close_session(C.long(session)))
}

//SdfSm3Init:sm3 init，传入打开的会话
func SdfSm3Init(session int64) int32 {
	return int32(C.sdf_hash_init(C.long(session), C.unsigned(C.SGD_SM3)))
}

//SdfSm3Update:sm3 update
func SdfSm3Update(session int64, buf []byte, len uint32) int32 {
	return int32(C.sdf_hash_update(C.long(session), (*C.uchar)(unsafe.Pointer(&buf[0])), (C.unsigned)(len)))
}

//SdfSm3Update:sm3 final，返回32字节的hash数组
func SdfSm3Final(session int64) (int32, [32]byte) {
	var len C.unsigned
	var hash [32]byte

	ret := int32(C.sdf_hash_final(C.long(session), (*C.uchar)(unsafe.Pointer(&hash[0])), (*C.unsigned)(unsafe.Pointer(&len))))

	return ret, hash
}
