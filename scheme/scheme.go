// scheme/scheme.go
package scheme

import (
	// "math"
	"math"
	"math/big"

	"pooled_decrypt/models"
	"pooled_decrypt/utils"
)

// Ciphertext is the structure holding an encryption.
type Ciphertext struct {
	C1 models.G1Element       // in G1
	C2 models.G1Element       // in G1
	C3 [][2]models.G1Element  // slice of pairs (length = n1)
	C4 [][2]models.G2Element  // slice of pairs (length = n2)
}

// Setup creates the CRS for the RQFE scheme. For L a perfect square,
// we let n1 = 2*sqrt(L) and n2 = sqrt(L)+1.
func Setup(L, polyDeg int) *models.CRS {
	sqrtL := int(math.Sqrt(float64(L)))
	n1 := 2 * sqrtL
	n2 := sqrtL + 1
	crs := models.NewCRS(L, n1, n2, polyDeg, nil, true, true, false,true)
	return crs
}

// Keygen produces a public/secret key pair for a given decryption index l.
func Keygen(crs *models.CRS, l int) (models.PublicKey, models.SecretKey) {
	// Generate s vector (length n1) and scalar w.
	s := make([]*big.Int, crs.N1)
	for i := 0; i < crs.N1; i++ {
		s[i] = models.RandomScalar()
	}
	w := models.RandomScalar()
	vVal := models.RandomScalar()

    // 6. Let V = g1^vVal  (store in public key)
    V := crs.G1.Exp(vVal)

	// dk will have one component for each k = 0,..., L-1.
	dk := make([]models.G2Element, crs.L)
	// Initialize dk with the identity (neutral element).
	for k := 0; k < crs.L; k++ {
		dk[k] = models.G2Identity()
	}

	sqrtL := int(math.Sqrt(float64(crs.L)))
	// For each k, we “encode” k into (k1, k2) and then compute:
	// dk[k] = T[0]^(s[k1]) * T[k2+1]^(s[k1+sqrtL]) * Gamma[k]^(w)
	for k := 0; k < crs.L; k++ {
		k1, k2 := utils.EncodeNumber(k, crs.L)
		term1 := crs.T[0].Exp(s[k1])
		term2 := crs.T[k2+1].Exp(s[k1+sqrtL])
		term3 := crs.Gamma[k].Exp(w)
		term4 := crs.PEvals[k].Exp(vVal)
		dk[k] = term1.Mul(term2).Mul(term3).Mul(term4)
		// dk[k] = term1.Mul(term2).Mul(term3)
	}
	// Build the public key “dk_pk_term”: dk[k] if k ≠ l, and the identity (neutral) otherwise.
	dk_pk_term := make([]models.G2Element, crs.L)
	for k := 0; k < crs.L; k++ {
		if k == l {
			dk_pk_term[k] = models.G2Identity()
		} else {
			dk_pk_term[k] = dk[k]
		}
	}
	// Compute public key S: for each i, S[i] = crs.G1 raised to s[i].
	S := make([]models.G1Element, crs.N1)
	for i := 0; i < crs.N1; i++ {
		S[i] = crs.G1.Exp(s[i])
	}
	// W = crs.G1 raised to w.
	W := crs.G1.Exp(w)
	pk := models.PublicKey{
		S:  S,
		W:  W,
		DK: dk_pk_term,
		V : V,
	}
	sk := models.SecretKey{
		DK: dk[l],
	}
	return pk, sk
}

// Aggregate combines a list of public keys into an aggregated master public key and helper secret keys.
func Aggregate(crs *models.CRS, pks []models.PublicKey) (models.MasterPublicKey, []models.HelperSecretKey) {
	// Aggregate w: multiply all pk.W.
	aggW := models.G1Identity()
	for _, pk := range pks {
		aggW = aggW.Mul(pk.W)
	}
	// Aggregate S: for each i, multiply all pk.S[i].
	aggS := make([]models.G1Element, crs.N1)
	for i := 0; i < crs.N1; i++ {
		aggS[i] = models.G1Identity()
		for _, pk := range pks {
			aggS[i] = aggS[i].Mul(pk.S[i])
		}
	}
	// Compute h1: for each i=0,…,L–1, h1[i] = ∏₍ⱼ ≠ i₎ pks[j].DK[i].
	h1 := make([]models.G2Element, crs.L)
	for i := 0; i < crs.L; i++ {
		prod := models.G2Identity()
		for j := 0; j < crs.L; j++ {
			if i != j {
				prod = prod.Mul(pks[j].DK[i])
			}
		}
		h1[i] = prod
	}
	//    aggV = product of all pk.V in G1
	aggV := models.G1Identity()
    for _, pk := range pks {
        aggV = aggV.Mul(pk.V) // pk.V = g1^{v_i}
    }

	// h2 is simply crs.Gamma.
	// Build helper secret keys.
	hsk := make([]models.HelperSecretKey, crs.L)
	for k := 0; k < crs.L; k++ {
		hsk[k] = models.HelperSecretKey{
			H1: h1[k],
			H2: crs.Gamma[k],
		}
	}
	mpk := models.MasterPublicKey{
		S: aggS,
		W: aggW,
		T: crs.T,
		V: aggV,  // <-- store aggregated V
	}
	return mpk, hsk
}

// ----------
// Some helper arithmetic functions modulo Order
// ----------

func modMul(a, b *big.Int) *big.Int {
	res := new(big.Int).Mul(a, b)
	res.Mod(res, models.Order)
	return res
}

func modSub(a, b *big.Int) *big.Int {
	res := new(big.Int).Sub(a, b)
	res.Mod(res, models.Order)
	return res
}

// invert2x2 computes the “inverse transpose” of the 2×2 matrix M = [[a,b],[c,d]]
// modulo Order. (I.e. it returns inv00, inv01, inv10, inv11 so that
// inv00 = d*det⁻¹, inv01 = –c*det⁻¹, inv10 = –b*det⁻¹, inv11 = a*det⁻¹.)
func invert2x2(a, b, c, d *big.Int) (inv00, inv01, inv10, inv11 *big.Int) {
	det := modSub(modMul(a, d), modMul(b, c))
	if det.Sign() == 0 {
		panic("matrix not invertible")
	}
	invDet := new(big.Int).ModInverse(det, models.Order)
	inv00 = modMul(d, invDet)
	inv01 = modMul(new(big.Int).Neg(c), invDet)
	inv10 = modMul(new(big.Int).Neg(b), invDet)
	inv11 = modMul(a, invDet)
	return
}

// Encrypt encrypts an integer message m. (It first “encodes” m via the Z function.)
func Encrypt(crs *models.CRS, mpk models.MasterPublicKey, x ,y []*big.Int) Ciphertext {
	// Encode m into vectors x and y.
	// Generate random scalars: alpha and components a,b,c,d for a 2×2 matrix.
	alpha := models.RandomScalar()
	a := models.RandomScalar()
	b := models.RandomScalar()
	c := models.RandomScalar()
	d := models.RandomScalar()

	// Compute the inverse (transpose) of the 2×2 matrix M = [[a,b],[c,d]].
	inv00, inv01, inv10, inv11 := invert2x2(a, b, c, d)

	// c1 = crs.G1^alpha.
	C1 := crs.G1.Exp(alpha)
	// c2 = mpk.W^alpha.
	C2 := mpk.W.Exp(alpha)

	// c3: for each i = 0,…, n1–1, compute a pair of G1 elements.
	C3 := make([][2]models.G1Element, crs.N1)
	for i := 0; i < crs.N1; i++ {
		// Compute: g1^(inv00*x[i]) * (mpk.S[i]^alpha)^(inv01)
		exp1 := modMul(inv00, x[i])
		part1 := models.G1Generator().Exp(exp1)
		exp2 := modMul(alpha, inv01)
		part2 := mpk.S[i].Exp(exp2)
		comp1 := part1.Mul(part2)

		// And similarly: g1^(inv10*x[i]) * (mpk.S[i]^alpha)^(inv11)
		exp3 := modMul(inv10, x[i])
		part3 := models.G1Generator().Exp(exp3)
		exp4 := modMul(alpha, inv11)
		part4 := mpk.S[i].Exp(exp4)
		comp2 := part3.Mul(part4)

		C3[i] = [2]models.G1Element{comp1, comp2}
	}

	// c4: for each i = 0,…, n2–1, compute a pair of G2 elements.
	C4 := make([][2]models.G2Element, crs.N2)
	for i := 0; i < crs.N2; i++ {
		// First component: g2^(a*y[i]) * (mpk.T[i]⁻¹)^(b)
		exp5 := modMul(a, y[i])
		part5 := models.G2Generator().Exp(exp5)
		part6 := mpk.T[i].Inverse().Exp(b)
		comp1 := part5.Mul(part6)

		// Second component: g2^(c*y[i]) * (mpk.T[i]⁻¹)^(d)
		exp7 := modMul(c, y[i])
		part7 := models.G2Generator().Exp(exp7)
		part8 := mpk.T[i].Inverse().Exp(d)
		comp2 := part7.Mul(part8)

		C4[i] = [2]models.G2Element{comp1, comp2}
	}
    

	return Ciphertext{
		C1: C1,
		C2: C2,
		C3: C3,
		C4: C4,
	}
}

// Decrypt uses a secret key sk and a helper secret key hsk to recover the message.
func Decrypt(crs *models.CRS, sk models.SecretKey, ind int, hsk models.HelperSecretKey, ciph Ciphertext) models.GTElement {
	// d0 = pairing(c1, hsk.H1 * sk.DK).
	d0 := models.Pair(ciph.C1, hsk.H1.Mul(sk.DK))
	// d1 = Pair(C2, hsk.H2)
	d1 := models.Pair(ciph.C2, hsk.H2)

	// Use the provided index to “encode” into two numbers.
	i1, i2 := utils.EncodeNumber(ind, crs.L)
	sqrtL := int(math.Sqrt(float64(crs.L)))

	// Compute d2 as the product of four pairings:
	// d2 = Pair(C3[i1][0], C4[0][0]) * Pair(C3[i1][1], C4[0][1])
	//    * Pair(C3[i1+sqrtL][0], C4[i2+1][0]) * Pair(C3[i1+sqrtL][1], C4[i2+1][1])
	p1 := models.Pair(ciph.C3[i1][0], ciph.C4[0][0])
	p2 := models.Pair(ciph.C3[i1][1], ciph.C4[0][1])
	p3 := models.Pair(ciph.C3[i1+sqrtL][0], ciph.C4[i2+1][0])
	p4 := models.Pair(ciph.C3[i1+sqrtL][1], ciph.C4[i2+1][1])
	d2 := p1.Mul(p2).Mul(p3).Mul(p4)

	// Recover message element: m = d0 * d2 * d1⁻¹.
	mGT := d0.Mul(d2).Mul(d1.Inverse())
	return mGT
}

// Combine implements the threshold-lagrange formula:
//
//  1) For each ℓ in J, compute Lagrange coefficient λ_ℓ^J = ∏(i∈J\ℓ) [ i / (i - ℓ ) ] mod q
//  2) Let sumλ = Σ(ℓ in J) λ_ℓ^J
//  3) Let productK = ∏(ℓ in J) ( d_ℓ ^ λ_ℓ^J )  in GT
//  4) Let K = productK ^ (1 / sumλ )   in GT
//  5) Return  C0 - K   in GT
func Combine(
    ciph    Ciphertext,         // ciphertext with ciph.C0 in GT
    partials []models.GTElement,// partial decryptions, d_ell in GT
    J       []int,              // subset of user indices (1-based typically)
    groupOrder *big.Int,        // e.g. BN254 or BLS12-381 prime
) models.GTElement {

    // 1) Compute λ_ℓ^J for each ℓ in J
    lambdas := make([]*big.Int, len(J))

    for idx, ell := range J {
        // λ_ell starts at 1
        lambdaVal := big.NewInt(1)

        // multiply over i ∈ J \ {ell}
        for _, iVal := range J {
            if iVal == ell {
                continue
            }
            // numerator = iVal mod q
            numerator := big.NewInt(int64(iVal+1))
            numerator.Mod(numerator, groupOrder)

            // denominator = (iVal - ell) mod q
            denominator := big.NewInt(int64(iVal - ell))
            // if negative, mod ensures a positive residue
            denominator.Mod(denominator, groupOrder)

            // invert denominator mod q
            invDen := new(big.Int).ModInverse(denominator, groupOrder)
            if invDen == nil {
                panic("No inverse for denominator; check groupOrder and index usage!")
            }

            // multiply λ_ell by ( iVal / (iVal - ell) ) mod q
            lambdaVal.Mul(lambdaVal, numerator)
            lambdaVal.Mod(lambdaVal, groupOrder)

            lambdaVal.Mul(lambdaVal, invDen)
            lambdaVal.Mod(lambdaVal, groupOrder)
        }
        lambdas[idx] = lambdaVal
    }

    // 2) sum up all λ_ℓ^J
    sumLambda := big.NewInt(0)
    for _, lam := range lambdas {
        sumLambda.Add(sumLambda, lam)
    }
    sumLambda.Mod(sumLambda, groupOrder)

    // 3) productK = ∏(ℓ in J) d_ℓ ^ (λ_ℓ^J)
    productK := models.GTIdentity() // identity in GT
    for idx, ell := range J {
        exponent := lambdas[idx] // λ_ell^J
        // d_ell ^ λ_ell^J in GT
        part := partials[ell].Exp(exponent)
        productK = productK.Mul(part)
    }

    // 4) Exponentiate productK by 1 / sumLambda
    //    i.e. productK^(inverseOf(sumLambda) mod q)
    invSumLambda := new(big.Int).ModInverse(sumLambda, groupOrder)
    if invSumLambda == nil {
        panic("sumLambda is 0 mod q or no inverse; cannot continue")
    }
    K := productK.Exp(invSumLambda) // K in GT


    return K
}
