package gosdf

import (
	"bytes"
	"crypto/hmac"
	"errors"
	"hash"
	"strconv"
	"strings"
	"testing"
)

// TestSM3HashContract 回归:Sum 不得改变内部状态(可重复调用、可继续 Write),
// 且 Sum(in) 返回 in||digest。
func TestSM3HashContract(t *testing.T) {
	dev, _ := openStub(t)

	h := dev.NewSM3Hash()
	if _, err := h.Write([]byte("test")); err != nil {
		t.Fatalf("Write: %v", err)
	}
	d1 := h.Sum(nil)
	if len(d1) != 32 {
		t.Fatalf("digest length = %d, want 32", len(d1))
	}

	d2 := h.Sum(nil)
	if !bytes.Equal(d1, d2) {
		t.Fatalf("Sum(nil) not stable:\n%x\n%x", d1, d2)
	}

	prefix := []byte{0xAA, 0xBB}
	got := h.Sum(prefix)
	want := append(append([]byte{}, prefix...), d1...)
	if !bytes.Equal(got, want) {
		t.Fatalf("Sum(prefix) = %x, want %x", got, want)
	}

	// Sum 之后状态仍可继续写入
	if _, err := h.Write([]byte("!")); err != nil {
		t.Fatalf("Write after Sum: %v", err)
	}
	if d3 := h.Sum(nil); bytes.Equal(d3, d1) {
		t.Fatal("digest unchanged after Write following Sum")
	}

	// Reset 清空缓冲
	h.Reset()
	if _, err := h.Write([]byte("test")); err != nil {
		t.Fatalf("Write after Reset: %v", err)
	}
	if d4 := h.Sum(nil); !bytes.Equal(d4, d1) {
		t.Fatalf("after Reset digest = %x, want %x", d4, d1)
	}
}

// TestHmacWithStub 验证 hmac.New 闭包用法可用且确定。
func TestHmacWithStub(t *testing.T) {
	dev, _ := openStub(t)

	newHash := func() hash.Hash { return dev.NewSM3Hash() }
	mac := hmac.New(newHash, []byte("123456"))
	if _, err := mac.Write([]byte("test")); err != nil {
		t.Fatalf("Write: %v", err)
	}
	sum1 := mac.Sum(nil)
	if len(sum1) != 32 {
		t.Fatalf("HMAC length = %d, want 32", len(sum1))
	}

	mac2 := hmac.New(newHash, []byte("123456"))
	if _, err := mac2.Write([]byte("test")); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if sum2 := mac2.Sum(nil); !bytes.Equal(sum1, sum2) {
		t.Fatalf("HMAC not deterministic:\n%x\n%x", sum1, sum2)
	}
}

// TestKeyHmacAlgs 验证带密钥杂凑 API 接受 HMAC 类算法标识
// (SGD_SM3_HMAC/SGD_SHA256_HMAC),一步式与多步式结果一致且确定。
func TestKeyHmacAlgs(t *testing.T) {
	_, sess := openStub(t)
	_, key, err := sess.GenerateKeyWithKEK(1, 128, SM4_ECB)
	if err != nil {
		t.Fatalf("GenerateKeyWithKEK: %v", err)
	}

	mac, err := key.HMAC(SGD_SM3_HMAC, []byte("hello hmac"))
	if err != nil {
		t.Fatalf("HMAC(SGD_SM3_HMAC): %v", err)
	}
	if len(mac) != 32 {
		t.Fatalf("HMAC-SM3 length = %d, want 32", len(mac))
	}
	again, err := key.HMAC(SGD_SM3_HMAC, []byte("hello hmac"))
	if err != nil {
		t.Fatalf("HMAC(SGD_SM3_HMAC) second: %v", err)
	}
	if !bytes.Equal(mac, again) {
		t.Fatalf("HMAC not deterministic:\n%x\n%x", mac, again)
	}

	// 多步式 SGD_SHA256_HMAC 分块累加 == 一步式
	mac256, err := key.HMAC(SGD_SHA256_HMAC, []byte("hello hmac"))
	if err != nil {
		t.Fatalf("HMAC(SGD_SHA256_HMAC): %v", err)
	}
	if len(mac256) != 32 {
		t.Fatalf("HMAC-SHA256 length = %d, want 32", len(mac256))
	}
	h, err := key.NewHMAC(SGD_SHA256_HMAC)
	if err != nil {
		t.Fatalf("NewHMAC(SGD_SHA256_HMAC): %v", err)
	}
	if err := h.Update([]byte("hello ")); err != nil {
		t.Fatalf("Update: %v", err)
	}
	if err := h.Update([]byte("hmac")); err != nil {
		t.Fatalf("Update: %v", err)
	}
	got, err := h.Final()
	if err != nil {
		t.Fatalf("Final: %v", err)
	}
	if !bytes.Equal(got, mac256) {
		t.Fatalf("multi-part HMAC = %x, want %x", got, mac256)
	}

	// 桩记录:hmacinit 第三字段 == SGD_SHA256(与 TestHMACFlow 的 SM3 侧断言对称,
	// 钉住 hmacHashAlg 的 SGD_SHA256_HMAC→SGD_SHA256 映射)。
	var last string
	for _, line := range strings.Split(readRecord(t), "\n") {
		if strings.HasPrefix(line, "hmacinit:") {
			last = line
		}
	}
	if last == "" {
		t.Fatal("no hmacinit record")
	}
	parts := strings.Split(last, ":")
	if len(parts) != 3 {
		t.Fatalf("malformed hmacinit record %q", last)
	}
	gotAlg, err := strconv.ParseUint(parts[2], 16, 64)
	if err != nil {
		t.Fatalf("parse alg: %v", err)
	}
	if ALGID(gotAlg) != SGD_SHA256 {
		t.Errorf("SDF_HMACInit uiAlgID = %#x, want SGD_SHA256(%#x)", gotAlg, uint32(SGD_SHA256))
	}
}

// TestHashHmacAlgRejection 回归:杂凑与带密钥杂凑两侧算法标识互斥——
// NewHash 拒绝 HMAC 类标识,NewHMAC/HMAC 拒绝普通杂凑标识,
// 均返回 SDR_ALGNOTSUPPORT。
func TestHashHmacAlgRejection(t *testing.T) {
	_, sess := openStub(t)

	// NewHash 拒绝 HMAC 类标识(2012 时代 .so 上 0x08/0x10 是厂商 SHA-512/SHA-384,
	// 放行会静默错配算法);错误延迟到 Update/Final(两者同返回被钉错误,非 SDR_STEPERR)。
	for _, alg := range []ALGID{SGD_SM3_HMAC, SGD_SHA256_HMAC} {
		h := sess.NewHash(alg)
		if err := h.Update([]byte("x")); !errors.Is(err, SDR_ALGNOTSUPPORT) {
			t.Errorf("NewHash(%#x) Update error = %v, want SDR_ALGNOTSUPPORT", uint32(alg), err)
		}
		if _, err := h.Final(); !errors.Is(err, SDR_ALGNOTSUPPORT) {
			t.Errorf("NewHash(%#x) Final error = %v, want SDR_ALGNOTSUPPORT", uint32(alg), err)
		}
	}

	_, key, err := sess.GenerateKeyWithKEK(1, 128, SM4_ECB)
	if err != nil {
		t.Fatalf("GenerateKeyWithKEK: %v", err)
	}
	if _, err := key.NewHMAC(SGD_SM3); !errors.Is(err, SDR_ALGNOTSUPPORT) {
		t.Errorf("NewHMAC(SGD_SM3) error = %v, want SDR_ALGNOTSUPPORT", err)
	}
	if _, err := key.HMAC(SGD_SM3, []byte("x")); !errors.Is(err, SDR_ALGNOTSUPPORT) {
		t.Errorf("HMAC(SGD_SM3) error = %v, want SDR_ALGNOTSUPPORT", err)
	}
	if _, err := key.HMAC(SGD_SHA256, []byte("x")); !errors.Is(err, SDR_ALGNOTSUPPORT) {
		t.Errorf("HMAC(SGD_SHA256) error = %v, want SDR_ALGNOTSUPPORT", err)
	}
}

// TestHasherStepErrors 桩侧镜像 integration TestHashStepErrors:Final 之后
// Update/Final 一律 SDR_STEPERR,普通杂凑与带密钥杂凑同一状态机。
func TestHasherStepErrors(t *testing.T) {
	_, sess := openStub(t)

	h := sess.NewHash(SGD_SM3)
	if err := h.Update([]byte("x")); err != nil {
		t.Fatalf("Update: %v", err)
	}
	if _, err := h.Final(); err != nil {
		t.Fatalf("Final: %v", err)
	}
	if _, err := h.Final(); !errors.Is(err, SDR_STEPERR) {
		t.Errorf("second Final = %v, want SDR_STEPERR", err)
	}
	if err := h.Update([]byte("y")); !errors.Is(err, SDR_STEPERR) {
		t.Errorf("Update after Final = %v, want SDR_STEPERR", err)
	}

	_, key, err := sess.GenerateKeyWithKEK(1, 128, SM4_ECB)
	if err != nil {
		t.Fatalf("GenerateKeyWithKEK: %v", err)
	}
	mh, err := key.NewHMAC(SGD_SM3_HMAC)
	if err != nil {
		t.Fatalf("NewHMAC: %v", err)
	}
	if err := mh.Update([]byte("x")); err != nil {
		t.Fatalf("HMAC Update: %v", err)
	}
	if _, err := mh.Final(); err != nil {
		t.Fatalf("HMAC Final: %v", err)
	}
	if _, err := mh.Final(); !errors.Is(err, SDR_STEPERR) {
		t.Errorf("HMAC second Final = %v, want SDR_STEPERR", err)
	}
	if err := mh.Update([]byte("y")); !errors.Is(err, SDR_STEPERR) {
		t.Errorf("HMAC Update after Final = %v, want SDR_STEPERR", err)
	}
}
