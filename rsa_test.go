package gosdf

import (
	"crypto/rsa"
	"errors"
	"math/big"
	"testing"
)

// ---- RSAref 定宽字段解析与拒绝路径(纯 Go,无设备) ----

// refPubValid 返回字段合法的 1024 位 RSAref 公钥,供各拒绝路径单独破坏一个字段。
// 模数右对齐写入 256 字节数组(左半补零),指数 65537 同样右对齐。
func refPubValid() *rsaRefPublicKey {
	var pub rsaRefPublicKey
	pub.Bits = 1024
	m := make([]byte, 128)
	for i := range m {
		m[i] = byte(i + 1)
	}
	copy(pub.M[len(pub.M)-len(m):], m)
	copy(pub.E[len(pub.E)-3:], []byte{0x01, 0x00, 0x01})
	return &pub
}

// refPrivValid 返回字段合法的 1024 位 RSAref 私钥与 D/P/Q 期望值。
// P、Q 取相邻奇数(P,Q=P+2):差 2 且均为奇数 → gcd(P,Q)=1,
// 保证 privFromRSA 内部 Precompute 的 CRT 逆元存在(假数值不构成合法密钥)。
func refPrivValid() (priv *rsaRefPrivateKey, wantD, wantP, wantQ *big.Int) {
	var sk rsaRefPrivateKey
	sk.Bits = 1024

	m := make([]byte, 128)
	for i := range m {
		m[i] = byte(i + 1)
	}
	copy(sk.M[len(sk.M)-len(m):], m)

	d := make([]byte, 128)
	for i := range d {
		d[i] = byte(255 - i)
	}
	copy(sk.D[len(sk.D)-len(d):], d)

	copy(sk.E[len(sk.E)-3:], []byte{0x01, 0x00, 0x01})

	pb := make([]byte, int(RSAref_MAX_PLEN))
	for i := range pb {
		pb[i] = byte(i + 1)
	}
	pb[len(pb)-1] = 0x81 // 奇数
	p := new(big.Int).SetBytes(pb)
	q := new(big.Int).Add(p, big.NewInt(2))
	qb := q.Bytes() // +2 不进位,仍为 128 字节
	copy(sk.Prime[0][:], pb)
	copy(sk.Prime[1][:], qb)

	for i := range sk.Pexp[0] {
		sk.Pexp[0][i] = 0x11
		sk.Pexp[1][i] = 0x22
		sk.Coef[i] = 0x33
	}
	return &sk, new(big.Int).SetBytes(d), p, q
}

// TestRSARefRightAlignedParsing 回归:RSAref 全部整数字段是定宽右对齐(左补零),
// 按"有效位长从头解析"会读进左半补零区得到 0,是历史上真实踩坑的一类。
func TestRSARefRightAlignedParsing(t *testing.T) {
	// 公钥:128 字节已知值(首字节 0x00 造前导零)只写入 M 的右半;
	// 左半 128 字节全零,叠加后大端值不变。
	pub := refPubValid()
	mVal := make([]byte, 128)
	mVal[0] = 0x00
	for i := 1; i < len(mVal); i++ {
		mVal[i] = byte(i)
	}
	for i := range pub.M {
		pub.M[i] = 0
	}
	copy(pub.M[len(pub.M)-len(mVal):], mVal)

	got, err := pubFromRSA(pub)
	if err != nil {
		t.Fatalf("pubFromRSA: %v", err)
	}
	if want := new(big.Int).SetBytes(mVal); got.N.Cmp(want) != 0 {
		t.Errorf("N = %x, want %x", got.N, want)
	}
	if got.E != 65537 {
		t.Errorf("E = %d, want 65537", got.E)
	}

	// 私钥:M/D/Prime/Pexp/Coef 全部右对齐写入定宽数组。
	priv, wantD, wantP, wantQ := refPrivValid()
	sk, err := privFromRSA(priv)
	if err != nil {
		t.Fatalf("privFromRSA: %v", err)
	}
	if sk.D.Cmp(wantD) != 0 {
		t.Errorf("D = %x, want %x", sk.D, wantD)
	}
	if sk.Primes[0].Cmp(wantP) != 0 {
		t.Errorf("Primes[0] = %x, want %x", sk.Primes[0], wantP)
	}
	if sk.Primes[1].Cmp(wantQ) != 0 {
		t.Errorf("Primes[1] = %x, want %x", sk.Primes[1], wantQ)
	}
}

// TestPrivFromRSADegeneratePrimes 回归:P=1/Q=1/P=Q 必须在 Precompute 前拒绝,
// 避免旧版 crypto/rsa 的 Mod(x,0) panic 与 nil qInv。
func TestPrivFromRSADegeneratePrimes(t *testing.T) {
	for _, tc := range []struct {
		name string
		p, q byte
	}{
		{"P=1", 1, 3},
		{"Q=1", 3, 1},
		{"P=Q", 3, 3},
	} {
		priv, _, _, _ := refPrivValid()
		for i := range priv.Prime[0] {
			priv.Prime[0][i] = 0
			priv.Prime[1][i] = 0
		}
		priv.Prime[0][len(priv.Prime[0])-1] = tc.p
		priv.Prime[1][len(priv.Prime[1])-1] = tc.q
		if _, err := privFromRSA(priv); !errors.Is(err, SDR_INARGERR) {
			t.Errorf("privFromRSA(%s) error = %v, want SDR_INARGERR", tc.name, err)
		}
	}
}

// TestRSAPubRoundTripAndRejects 钉住公钥 ABI 转换的往返与全部参数拒绝路径。
func TestRSAPubRoundTripAndRejects(t *testing.T) {
	// 往返:2048 位奇数模数 pubToRSA → pubFromRSA 还原相同 N/E。
	nb := make([]byte, 256)
	nb[0] = 0xC0
	for i := 1; i < len(nb); i++ {
		nb[i] = byte(7*i + 3)
	}
	nb[len(nb)-1] |= 1 // 奇数模数
	pub := &rsa.PublicKey{N: new(big.Int).SetBytes(nb), E: 65537}
	ref, err := pubToRSA(pub)
	if err != nil {
		t.Fatalf("pubToRSA: %v", err)
	}
	back, err := pubFromRSA(ref)
	if err != nil {
		t.Fatalf("pubFromRSA: %v", err)
	}
	if back.N.Cmp(pub.N) != 0 || back.E != pub.E {
		t.Errorf("round trip N/E = (%x, %d), want (%x, %d)", back.N, back.E, pub.N, pub.E)
	}

	// pubToRSA 拒绝:nil、缺模数、超宽模数、非法指数。
	if _, err := pubToRSA(nil); !errors.Is(err, SDR_INARGERR) {
		t.Errorf("pubToRSA(nil) error = %v, want SDR_INARGERR", err)
	}
	if _, err := pubToRSA(&rsa.PublicKey{E: 3}); !errors.Is(err, SDR_INARGERR) {
		t.Errorf("pubToRSA(N=nil) error = %v, want SDR_INARGERR", err)
	}
	wide := new(big.Int).Lsh(big.NewInt(1), 2048) // 2049 位奇数
	wide.SetBit(wide, 0, 1)
	if _, err := pubToRSA(&rsa.PublicKey{N: wide, E: 65537}); !errors.Is(err, SDR_INARGERR) {
		t.Errorf("pubToRSA(2049-bit N) error = %v, want SDR_INARGERR", err)
	}
	for _, e := range []int64{0, 1, 1 << 31} {
		if _, err := pubToRSA(&rsa.PublicKey{N: pub.N, E: int(e)}); !errors.Is(err, SDR_INARGERR) {
			t.Errorf("pubToRSA(E=%d) error = %v, want SDR_INARGERR", e, err)
		}
	}

	// pubFromRSA 拒绝:位长与字段零值。
	for _, tc := range []struct {
		name string
		bits uint32
	}{
		{"bits=512", 512},   // 低于下限 1024
		{"bits=1000", 1000}, // 低于下限
		{"bits=1030", 1030}, // 非 8 的倍数(1030%8=6)
		{"bits=2056", 2056}, // 高于上限 RSAref_MAX_BITS=2048
	} {
		p := refPubValid()
		p.Bits = tc.bits
		if _, err := pubFromRSA(p); !errors.Is(err, SDR_INARGERR) {
			t.Errorf("pubFromRSA(%s) error = %v, want SDR_INARGERR", tc.name, err)
		}
	}

	p := refPubValid()
	for i := range p.M {
		p.M[i] = 0
	}
	if _, err := pubFromRSA(p); !errors.Is(err, SDR_INARGERR) {
		t.Errorf("pubFromRSA(zero M) error = %v, want SDR_INARGERR", err)
	}

	eCases := []struct {
		name string
		e    []byte
	}{
		{"E=0", make([]byte, 4)},
		{"E=1", []byte{0x01}},
		{"E=1<<31", []byte{0x80, 0x00, 0x00, 0x00}},
	}
	for _, tc := range eCases {
		p := refPubValid()
		for i := range p.E {
			p.E[i] = 0
		}
		copy(p.E[len(p.E)-len(tc.e):], tc.e)
		if _, err := pubFromRSA(p); !errors.Is(err, SDR_INARGERR) {
			t.Errorf("pubFromRSA(%s) error = %v, want SDR_INARGERR", tc.name, err)
		}
	}

	// privFromRSA 拒绝:Prime[0] 全零(rsaField 零值)。
	priv, _, _, _ := refPrivValid()
	for i := range priv.Prime[0] {
		priv.Prime[0][i] = 0
	}
	if _, err := privFromRSA(priv); !errors.Is(err, SDR_INARGERR) {
		t.Errorf("privFromRSA(zero Prime[0]) error = %v, want SDR_INARGERR", err)
	}
}

// TestCheckRSABits 直接钉 checkRSABits 三条规则(下限 1024、%8 对齐、
// 上限 RSAref_MAX_BITS=2048):任一规则被删即红。pubFromRSA 的表测试
// 隔离不了下限(512/1000 同时撞模数位宽检查),故单列此表。
func TestCheckRSABits(t *testing.T) {
	for _, tc := range []struct {
		name string
		bits uint32
		ok   bool
	}{
		{"bits=0", 0, false},
		{"bits=512", 512, false},   // 下限:低于 1024
		{"bits=1000", 1000, false}, // 下限:低于 1024(1000%8==0,纯下限规则)
		{"bits=1023", 1023, false}, // %8:非 8 的倍数
		{"bits=1030", 1030, false}, // %8:非 8 的倍数
		{"bits=2056", 2056, false}, // 上限:高于 2048
		{"bits=4096", 4096, false}, // 上限:高于 2048
		{"bits=1024", 1024, true},
		{"bits=2048", 2048, true},
	} {
		err := checkRSABits(tc.bits, "op")
		if got := err == nil; got != tc.ok {
			t.Errorf("checkRSABits(%s) error = %v, want ok=%v", tc.name, err, tc.ok)
		}
	}
}
