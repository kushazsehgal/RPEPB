// utils/utils.go
package utils

import (
	"math"
	"math/big"

	"pooled_decrypt/models"
)

// VecMatMul multiplies a vector a (length n1) by an n1×n2 matrix M modulo Order.
func VecMatMul(a []*big.Int, M [][]*big.Int) []*big.Int {
	n1 := len(M)
	if n1 == 0 {
		return nil
	}
	n2 := len(M[0])
	b := make([]*big.Int, n2)
	for j := 0; j < n2; j++ {
		b[j] = big.NewInt(0)
	}
	for i := 0; i < n1; i++ {
		for j := 0; j < n2; j++ {
			prod := new(big.Int).Mul(a[i], M[i][j])
			prod.Mod(prod, models.Order)
			b[j].Add(b[j], prod)
			b[j].Mod(b[j], models.Order)
		}
	}
	return b
}

// InnerProd computes the inner (dot) product of two equal‐length vectors modulo Order.
func InnerProd(a, b []*big.Int) *big.Int {
	if len(a) != len(b) {
		panic("vectors must have the same length")
	}
	result := big.NewInt(0)
	for i := 0; i < len(a); i++ {
		prod := new(big.Int).Mul(a[i], b[i])
		prod.Mod(prod, models.Order)
		result.Add(result, prod)
		result.Mod(result, models.Order)
	}
	return result
}

// EncodeNumber encodes an integer k using L (assumed perfect square) into two indices.
func EncodeNumber(k, L int) (int, int) {
	kBase1 := k + 1
	sqrtL := int(math.Sqrt(float64(L)))
	var k1 int
	if kBase1%sqrtL == 0 {
		k1 = kBase1 / sqrtL
	} else {
		k1 = (kBase1 / sqrtL) + 1
	}
	var k2 int
	if kBase1%sqrtL != 0 {
		k2 = kBase1 % sqrtL
	} else {
		k2 = sqrtL
	}
	return k1 - 1, k2 - 1
}

// Z encodes a message m into two vectors x and y.
// For L (a perfect square) with sqrt(L)=r, it returns x ∈ ℤₚ^(2r) and y ∈ ℤₚ^(r+1)
func Z(m int, L int) ([]*big.Int, []*big.Int) {
	sqrtL := int(math.Sqrt(float64(L)))
	x := make([]*big.Int, 2*sqrtL)
	// v_tilde: first element 0, remaining r-1 entries equal to m.
	x[0] = big.NewInt(0)
	for i := 1; i < sqrtL; i++ {
		x[i] = big.NewInt(int64(m))
	}
	// v_hat: first element m, rest 0.
	x[sqrtL] = big.NewInt(int64(m))
	for i := sqrtL + 1; i < 2*sqrtL; i++ {
		x[i] = big.NewInt(0)
	}
	// y: vector of r+1 ones.
	y := make([]*big.Int, sqrtL+1)
	for i := 0; i < sqrtL+1; i++ {
		y[i] = big.NewInt(1)
	}
	return x, y
}
func Z_bigInt(m *big.Int, L int) ([]*big.Int, []*big.Int) {
	sqrtL := int(math.Sqrt(float64(L)))
	x := make([]*big.Int, 2*sqrtL)
	// v_tilde: first element 0, remaining r-1 entries equal to m.
	x[0] = big.NewInt(0)
	for i := 1; i < sqrtL; i++ {
		x[i] = m
	}
	// v_hat: first element m, rest 0.
	x[sqrtL] = m
	for i := sqrtL + 1; i < 2*sqrtL; i++ {
		x[i] = big.NewInt(0)
	}
	// y: vector of r+1 ones.
	y := make([]*big.Int, sqrtL+1)
	for i := 0; i < sqrtL+1; i++ {
		y[i] = big.NewInt(1)
	}
	return x, y
}
func Z_im(i, m, L int) ([]*big.Int, []*big.Int) {
    i1, i2 := EncodeNumber(i, L)
	// fmt.Printf("i1: %d, i2: %d\n", i1, i2)
    sqrtL := int(math.Sqrt(float64(L)))

    // 1. Build vTilde (length sqrtL):
    //    "0 for first i1 entries, then 1"
    vTilde := make([]int, sqrtL)
    for j := 0; j < sqrtL; j++ {
        if j <= i1 {
            vTilde[j] = 0
        } else {
            vTilde[j] = 1
        }
    }

    // 2. Build vHat (length sqrtL):
    //    "1 at index i1, 0 elsewhere"
    vHat := make([]int, sqrtL)
    for j := 0; j < sqrtL; j++ {
        if j == i1 {
            vHat[j] = 1
        } else {
            vHat[j] = 0
        }
    }

    // 3. Build vBar (length sqrtL):
    //    "0 for first (i2 - 1) entries, then 1"
    vBar := make([]int, sqrtL)
    for j := 0; j < sqrtL; j++ {
        if j < i2 {
            vBar[j] = 0
        } else {
            vBar[j] = 1
        }
    }

    // 4. Form x_{i,m} = (m*vTilde, m*vHat) in {0,1,2}^{2*sqrtL}
    x := make([]*big.Int, 2*sqrtL)
    for j := 0; j < sqrtL; j++ {
        x[j] = big.NewInt(int64(m*vTilde[j])) 
        x[sqrtL+j] = big.NewInt(int64(m * vHat[j])) 
    }

    // 5. Form y_{i,m} = (1, vBar) in {0,1}^{sqrtL+1}
    y := make([]*big.Int, sqrtL+1)
    y[0] = big.NewInt(1)
    for j := 0; j < sqrtL; j++ {
        y[j+1] = big.NewInt(int64(vBar[j]))
    }
	// fmt.Printf("x: %v\n", x)
	// fmt.Printf("y: %v\n", y)
    return x, y
}

func modMul(a, b *big.Int) *big.Int {
	res := new(big.Int).Mul(a, b)
	res.Mod(res, models.Order)
	return res
}

func Z_im_bigInt(i,L int, m *big.Int) ([]*big.Int, []*big.Int) {
    i1, i2 := EncodeNumber(i, L)
	// fmt.Printf("i1: %d, i2: %d\n", i1, i2)
    sqrtL := int(math.Sqrt(float64(L)))

    // 1. Build vTilde (length sqrtL):
    //    "0 for first i1 entries, then 1"
    vTilde := make([]int, sqrtL)
    for j := 0; j < sqrtL; j++ {
        if j <= i1 {
            vTilde[j] = 0
        } else {
            vTilde[j] = 1
        }
    }

    // 2. Build vHat (length sqrtL):
    //    "1 at index i1, 0 elsewhere"
    vHat := make([]int, sqrtL)
    for j := 0; j < sqrtL; j++ {
        if j == i1 {
            vHat[j] = 1
        } else {
            vHat[j] = 0
        }
    }

    // 3. Build vBar (length sqrtL):
    //    "0 for first (i2 - 1) entries, then 1"
    vBar := make([]int, sqrtL)
    for j := 0; j < sqrtL; j++ {
        if j < i2 {
            vBar[j] = 0
        } else {
            vBar[j] = 1
        }
    }

    // 4. Form x_{i,m} = (m*vTilde, m*vHat) in {0,1,2}^{2*sqrtL}
    x := make([]*big.Int, 2*sqrtL)
    for j := 0; j < sqrtL; j++ {
        x[j] = modMul(m,big.NewInt(int64(vTilde[j])))
        x[sqrtL+j] = modMul(m,big.NewInt(int64(vHat[j])))
    }

    // 5. Form y_{i,m} = (1, vBar) in {0,1}^{sqrtL+1}
    y := make([]*big.Int, sqrtL+1)
    y[0] = big.NewInt(1)
    for j := 0; j < sqrtL; j++ {
        y[j+1] = big.NewInt(int64(vBar[j]))
    }
	// fmt.Printf("x: %v\n", x)
	// fmt.Printf("y: %v\n", y)
    return x, y
}

