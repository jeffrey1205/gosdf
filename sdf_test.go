package gosdf

import (
	"fmt"
	"testing"

	"golang.org/x/exp/mmap"
)

func TestSm3(t *testing.T) {
	if err := SdfInit("/home/go-test/ccore/libsdf_crypto.so"); err != nil {
		fmt.Println("sdf init error:", err)
		return
	}
	defer SdfExit()

	session := SdfOpenSession()
	if session == 0 {
		fmt.Println("sdf open session error")
		return
	}
	defer SdfCloseSession(session)

	if ret := SdfSm3Init(session); ret != 0 {
		fmt.Println("sm3 init error:", ret)
		return
	}

	//55E12E91650D2FEC56EC74E1D3E4DDBFCE2EF3A65890C2A19ECF88A307E76A23
	if ret := SdfSm3Update(session, []byte("test"), 4); ret != 0 {
		fmt.Println("sm3 update error:", ret)
	}

	ret, hash := SdfSm3Final(session)
	var hashStr string
	for i := 0; i < len(hash); i++ {
		hashStr += fmt.Sprintf("%02X", hash[i])
	}
	fmt.Printf("sm3 final ret %d, hash: %s\n", ret, hashStr)
}

func TestSm3File(t *testing.T) {
	if err := SdfInit("/home/go-test/ccore/libsdf_crypto.so"); err != nil {
		fmt.Println("sdf init error:", err)
		return
	}
	defer SdfExit()

	session := SdfOpenSession()
	if session == 0 {
		fmt.Println("sdf open session error")
		return
	}
	defer SdfCloseSession(session)

	if ret := SdfSm3Init(session); ret != 0 {
		fmt.Println("sm3 init error:", ret)
	}

	//97ED8D6E793642DE83756D2B5A648183015BB1CF044C1EDA97F3E0A5FDC5CA60
	file, err := mmap.Open("/usr/bin/php5")
	if err != nil {
		fmt.Println("open /usr/bin/php5 error:", err)
		return
	}
	defer file.Close()

	fmt.Printf("file len %d\n", file.Len())
	buf := make([]byte, file.Len())
	rlen, err := file.ReadAt(buf, 0)
	if err != nil || rlen != file.Len() {
		fmt.Printf("read len %d error %v", rlen, err)
		return
	}

	if ret := SdfSm3Update(session, buf, uint32(rlen)); ret != 0 {
		fmt.Println("sm3 update error:", ret)
		return
	}

	ret, hash := SdfSm3Final(session)
	var hashStr string
	for i := 0; i < len(hash); i++ {
		hashStr += fmt.Sprintf("%02X", hash[i])
	}
	fmt.Printf("sm3 final ret %d, hash: %s\n", ret, hashStr)
}
