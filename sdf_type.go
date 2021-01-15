package gosdf

const (
	ECCref_MAX_BITS              int32 = 512
	ECCref_MAX_LEN               int32 = ((ECCref_MAX_BITS + 7) / 8)
	ECC_MAX_XCOORDINATE_BITS_LEN int32 = 512
	ECC_MAX_YCOORDINATE_BITS_LEN int32 = ECC_MAX_XCOORDINATE_BITS_LEN
	ECC_MAX_MODULUS_BITS_LEN     int32 = ECC_MAX_XCOORDINATE_BITS_LEN
)

type ECCrefPublicKey struct {
	bits uint32
	x    [ECCref_MAX_LEN]byte
	y    [ECCref_MAX_LEN]byte
}

type ECCrefPrivateKey struct {
	bits uint32
	K    [ECCref_MAX_LEN]byte
}

type ECCCipher struct {
	x [ECCref_MAX_LEN]byte
	y [ECCref_MAX_LEN]byte
	M [32]byte
	L uint32
	C [1]byte
}

type ECCSignature struct {
	r [ECCref_MAX_LEN]byte
	s [ECCref_MAX_LEN]byte
}

type ECCPUBLICKEYBLOB struct {
	BitLen      uint32
	XCoordinate [ECC_MAX_XCOORDINATE_BITS_LEN / 8]byte
	YCoordinate [ECC_MAX_YCOORDINATE_BITS_LEN / 8]byte
}

type ECCCIPHERBLOB struct {
	XCoordinate [ECC_MAX_XCOORDINATE_BITS_LEN / 8]byte
	YCoordinate [ECC_MAX_XCOORDINATE_BITS_LEN / 8]byte
	Hash        [32]byte
	CipherLen   uint32
	Cipher      [128]byte
}
