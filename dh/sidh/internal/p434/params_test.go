package p434

// Contains values used by tests
import (
	"testing/quick"

	. "github.com/quantumcoinproject/circl/dh/sidh/internal/common"
)

// Values computed using Sage
var (
	expectedJ = Fp2{
		A: Fp{0x38ECC0A0F53BACB4, 0xF987759E90A6C0DD, 0xC3007B353AE699F6, 0xB2B7E62A4F182414, 0xA65A854B34034F1B, 0xC71EAD20BE427422, 0xFC94F0D8DD51},
		B: Fp{0xFC3B47615764A089, 0x9D32DF1BA8CF22E5, 0x7B895EF92F44C690, 0xE83667F85BBFA475, 0xD44627DCF539CA71, 0x9619A0E7D6657401, 0x4BC5BF1D9B01},
	}

	curveA = Fp2{
		A: Fp{0x13A5A42C36E5E170, 0xC801DC4104E2C1DC, 0xB102AE39A7E24F31, 0x2FB616EA2E824C97, 0xB97073B55448AA67, 0x607266F7204D90DA, 0x1E98FE9739F27},
		B: Fp{0x000000000000742C, 0x0000000000000000, 0x0000000000000000, 0xB90FF404FC000000, 0xD801A4FB559FACD4, 0xE93254545F77410C, 0x0ECEEA7BD2EDA},
	}

	curveC = Fp2{
		A: Fp{0x8CBBA3505E5EDAB2, 0xB1DE7B91FBB77718, 0x6957392BFDC9BEB0, 0xC258E527E05FDDDE, 0x8C5FC7ADF5E50AE9, 0x1B2149FBEC2F4D18, 0x19FC2A5C79942},
		B: Fp{0x000000000000E858, 0x0000000000000000, 0x0000000000000000, 0x721FE809F8000000, 0xB00349F6AB3F59A9, 0xD264A8A8BEEE8219, 0x1D9DD4F7A5DB5},
	}

	affineXP = Fp2{
		A: Fp{0x775C29CA29E5FC3F, 0xCAB15BD1A1AB2754, 0x2C7F5B5DC58096EB, 0x2EE7B0B5A789355A, 0xBBD7BC749FF4D74E, 0x1373A265C9A9D58B, 0x5C183CE99B13},
		B: Fp{0x38CDA704EB4D517C, 0x2F8BA33C91C147D4, 0x4D17E97F04A8D431, 0x5DB8F238AE1B099F, 0x44DC758CE879824C, 0x7E95F1151F6DFA3C, 0xB59F64352B87},
	}

	affineXP2 = Fp2{
		A: Fp{0x2A5C658FD540804D, 0xA27CDB81FA7C6A5C, 0x6C36B6EB38B1B562, 0xC08642D636AF9A51, 0x36B2323A1279F346, 0x530BF3E8726D8B71, 0x61E38F638919},
		B: Fp{0x5D835C52A68FC93D, 0x9E8FAF973A68306C, 0xB3C28FE9D155F61C, 0xCCE6FA22BC1A1FBF, 0xEAB44D8952802BA5, 0xEAAC0F259AAC3A8F, 0x959B242CE01A},
	}

	affineXP4 = Fp2{
		A: Fp{0xF824931762C6DC4A, 0xA9B0FD30136F4B50, 0xAF041BBAB14DC6B1, 0x0AD52F55527A9BA2, 0x282B236D61F08C59, 0x5D3D7EC0C5EB9DCB, 0x10BBDDEA44BF7},
		B: Fp{0x77D92493AF97245B, 0xD717FEC838D464C6, 0xCAACD67DB3BF965D, 0x82D59FB89CDC0711, 0xF13CAE433F39CDE1, 0x9B55DFB11A585FFA, 0x0DC8BA1C054D3},
	}

	affineXP9 = Fp2{
		A: Fp{0x1F6F0785353A02C0, 0xCCB1B8524A63E37F, 0xB283C636B1FDD74C, 0xB76DBFF592DE6FF5, 0x15750EE706F18226, 0x50791362F26E459C, 0x1EA2A9074423},
		B: Fp{0x945C6909DA5039A3, 0x349CFD24FD84FDAF, 0x2FD2F391F2E26E75, 0xEF73E8A634EBDC76, 0x59DDA2622AC22A6C, 0xE0370B80E15F61F4, 0xB302956A0276},
	}

	// Inputs for testing 3-point-ladder
	threePointLadderInputs = []ProjectivePoint{
		// x(P)
		{
			X: Fp2{
				A: Fp{0x43941FA9244C059E, 0xD1F337D076941189, 0x6B6A8B3A8763C96A, 0x6DF569708D6C9482, 0x487EE5707A52F4AA, 0xDE396F6E2559689E, 0xE5EE3895A8991469, 0x2B0946695790A8},
				B: Fp{0xAB552C0FDAED092E, 0x7DF895E43E7DCB1C, 0x35C700E761920C4B, 0xCC5807DD70DC117A, 0x0884039A5A8DB18A, 0xD04620B3D0738052, 0xA200835605138F10, 0x3FF2E59B2FDC6A},
			},
			Z: params.OneFp2,
		},
		// x(Q)
		{
			X: Fp2{
				A: Fp{0x77015826982BA1FD, 0x44024489673471E4, 0x1CAA2A5F4D5DA63B, 0xA183C07E50738C01, 0x8B97782D4E1A0DE6, 0x9B819522FBC38280, 0x0BDA46A937FB7B8A, 0x3B3614305914DF},
				B: Fp{0xBF0366E97B3168D9, 0xAA522AC3879CEF0F, 0x0AF5EC975BD035C8, 0x1F26FEE7BBAC165C, 0xA0EE6A637724A6AB, 0xFB52101E36BA3A38, 0xD29CF5E376E17376, 0x1374A50DF57071},
			},
			Z: params.OneFp2,
		},
		// x(P-Q)
		{
			X: Fp2{
				A: Fp{0xD99279BBD41EA559, 0x35CF18E72F578214, 0x90473B1DC77F73E8, 0xBFFEA930B25D7F66, 0xFD558EA177B900B2, 0x7CFAD273A782A23E, 0x6B1F610822E0F611, 0x26D2D2EF9619B5},
				B: Fp{0x534F83651CBCC75D, 0x591FB4757AED5D08, 0x0B04353D40BED542, 0x829A94703AAC9139, 0x0F9C2E6D7663EB5B, 0x5D2D0F90C283F746, 0x34C872AA12A7676E, 0x0ECDB605FBFA16},
			},
			Z: params.OneFp2,
		},
	}
	scalar3Pt = [...]uint8{0x9f, 0x3b, 0xe7, 0xf9, 0xf4, 0x7c, 0xe6, 0xce, 0x79, 0x3e, 0x3d, 0x9f, 0x9f, 0x3b, 0xe7, 0xf9, 0xf4, 0x7c, 0xe6, 0xce, 0x79, 0x3e, 0x3d, 0x9f}
)

var quickCheckConfig = &quick.Config{
	MaxCount: (1 << 15),
}
