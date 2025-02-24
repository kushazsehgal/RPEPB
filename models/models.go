// models.go
package models

import (
	"bytes"
	"crypto/rand"
	"encoding"
	"math/big"
	"strconv"

	"github.com/cloudflare/circl/ecc/bls12381"
)

// ---------------------------------------------------------------------
// Global Order
// ---------------------------------------------------------------------

// OrderBytes returns the curve order as bytes.
var Order *big.Int = new(big.Int).SetBytes(bls12381.Order())

func INIT() {
	// bls12381.Order() returns []byte. Convert it to *big.Int.
	Order = new(big.Int).SetBytes(bls12381.Order())
}

// ---------------------------------------------------------------------
// Helper: Convert big.Int to a Scalar
// ---------------------------------------------------------------------

// newScalar converts a *big.Int to a *bls12381.Scalar.
// (We assume that bls12381.Scalar is defined and that it has a SetBytes method.)
func newScalar(x *big.Int) *bls12381.Scalar {
    s := new(bls12381.Scalar)
    s.SetBytes(x.Bytes())
    return s
}


// ---------------------------------------------------------------------
// G1 Element Wrapper
// ---------------------------------------------------------------------

// G1Element is a wrapper around the CIRCL type G1.
type G1Element struct {
	P *bls12381.G1
}

// G1Generator returns a new G1 element equal to the generator.
func G1Generator() G1Element {
	return G1Element{P: bls12381.G1Generator()}
}

// G1Identity returns the identity (neutral) element of G1.
func G1Identity() G1Element {
	g := new(bls12381.G1)
	g.SetIdentity()
	return G1Element{P: g}
}

// Exp returns the scalar–multiplication of g by k.
// Internally it converts k (a *big.Int) to a *Scalar.
func (g G1Element) Exp(k *big.Int) G1Element {
	s := newScalar(k)
	res := new(bls12381.G1)
	// The API: func (g *G1) ScalarMult(k *Scalar, P *G1)
	res.ScalarMult(s, g.P)
	return G1Element{P: res}
}

// Add returns the sum (group addition) of g and other.
func (g G1Element) Add(other G1Element) G1Element {
	res := new(bls12381.G1)
	// The API: func (g *G1) Add(P, Q *G1)
	res.Add(g.P, other.P)
	return G1Element{P: res}
}
func (g G1Element) Mul(other G1Element) G1Element {
    res := new(bls12381.G1)
    res.Add(g.P, other.P)
    return G1Element{P: res}
}

// ---------------------------------------------------------------------
// G2 Element Wrapper
// ---------------------------------------------------------------------

// G2Element is a wrapper around the CIRCL type G2.
type G2Element struct {
	P *bls12381.G2
}

// G2Generator returns a new G2 element equal to the generator.
func G2Generator() G2Element {
	return G2Element{P: bls12381.G2Generator()}
}

// G2Identity returns the identity element in G2.
func G2Identity() G2Element {
	g := new(bls12381.G2)
	g.SetIdentity()
	return G2Element{P: g}
}

// Exp returns the scalar–multiplication of g by k.
func (g G2Element) Exp(k *big.Int) G2Element {
	s := newScalar(k)
	res := new(bls12381.G2)
	res.ScalarMult(s, g.P)
	return G2Element{P: res}
}

// Add returns the sum (group addition) of g and other.
func (g G2Element) Add(other G2Element) G2Element {
	res := new(bls12381.G2)
	res.Add(g.P, other.P)
	return G2Element{P: res}
}

// Neg returns the negation of g.
func (g G2Element) Neg() G2Element {
	res := new(bls12381.G2)
	// Copy g.P into res by getting its bytes and then re-setting.
	b := g.P.Bytes()
	res.SetBytes(b)
	res.Neg()
	return G2Element{P: res}
}
// For G2Element:
func (g G2Element) Mul(other G2Element) G2Element {
    res := new(bls12381.G2)
    res.Add(g.P, other.P)
    return G2Element{P: res}
}

func (g G2Element) Inverse() G2Element {
    return g.Neg() // assuming Neg() is defined as the inverse in multiplicative notation.
}
// ---------------------------------------------------------------------
// GT (Target Group) Element Wrapper
// ---------------------------------------------------------------------

// GTElement wraps a pairing output element (of type Gt).
type GTElement struct {
	E *bls12381.Gt
}

// GTGenerator returns the generator of GT computed as Pair(G1Generator, G2Generator).
func GTGenerator() GTElement {
	return GTElement{E: bls12381.Pair(bls12381.G1Generator(), bls12381.G2Generator())}
}

// GTIdentity returns the identity element of GT.
func GTIdentity() GTElement {
	gt := new(bls12381.Gt)
	gt.SetIdentity()
	return GTElement{E: gt}
}

func (gt GTElement) Square() GTElement{
	res := new(bls12381.Gt)
	res.Sqr(gt.E)
	return GTElement{E: res}
}
// Exp returns the exponentiation of a GT element by k.
func (gt GTElement) Exp(k *big.Int) GTElement {
	s := newScalar(k)
	res := new(bls12381.Gt)
	// API: func (z *Gt) Exp(x *Gt, n *Scalar)
	res.Exp(gt.E, s)
	return GTElement{E: res}
}

// Mul returns the product of gt and other.
func (gt GTElement) Mul(other GTElement) GTElement {
	res := new(bls12381.Gt)
	// API: func (z *Gt) Mul(x, y *Gt)
	res.Mul(gt.E, other.E)
	return GTElement{E: res}
}

// Inverse returns the inverse of gt.
func (gt GTElement) Inverse() GTElement {
	res := new(bls12381.Gt)
	res.Inv(gt.E)
	return GTElement{E: res}
}

// Pair computes the bilinear pairing of a G1 element and a G2 element.
func Pair(g1 G1Element, g2 G2Element) GTElement {
	return GTElement{E: bls12381.Pair(g1.P, g2.P)}
}

// ---------------------------------------------------------------------
// Scheme Structures
// ---------------------------------------------------------------------

// CRS (Common Reference String) holds the public parameters.
type CRS struct {
	L     int              // number of gamma elements (also helper keys)
	N1    int              // length of vector s (rows of F)
	N2    int              // length of vector t (columns of F)
	F     [][][]*big.Int   // For each l=0,…,L-1: an N1×N2 matrix of scalars
	G1    G1Element        // G1 generator (for public key parts)
	G2    G2Element        // G2 generator (for helper keys)
	Gamma []G2Element      // Gamma: list of L G2 elements
	T     []G2Element      // t: list of N2 G2 elements
	PCoeffs []G2Element // Will hold [ g2^α₁, g2^α₂, ..., g2^α_(T-1) ]
    PEvals  []G2Element // Will hold [ g2^P(1), g2^P(2), ..., g2^P(L) ]
}


// NewCRS initializes a new CRS.
func NewCRS(L, n1, n2, polyDeg int, F [][][]*big.Int, setGamma bool, setT bool, setF bool, setPoly bool,) *CRS {
	crs := &CRS{
		L:  L,
		N1: n1,
		N2: n2,
		G1: G1Generator(),
		G2: G2Generator(),
	}
	if setGamma {
		crs.Gamma = make([]G2Element, L)
		for i := 0; i < L; i++ {
			r := RandomScalar()
			crs.Gamma[i] = crs.G2.Exp(r)
		}
	}
	if setT {
		crs.T = make([]G2Element, n2)
		for i := 0; i < n2; i++ {
			r := RandomScalar()
			crs.T[i] = crs.G2.Exp(r)
		}
	}
	if setPoly {
        // (a) Sample random scalars α₁,...,α_(T-1), store g2^αᵢ in crs.PCoeffs.
        crs.PCoeffs = make([]G2Element, polyDeg)
        alpha := make([]*big.Int, polyDeg)
        for i := 0; i < polyDeg; i++ {
            alpha[i] = RandomScalar()
            crs.PCoeffs[i] = crs.G2.Exp(alpha[i])
        }

        // (b) For each i = 1..L, compute P(i) in the exponent, store g2^P(i).
        crs.PEvals = make([]G2Element, L)
        for x := 1; x <= L; x++ {
            // Evaluate P(x) = Σ (alpha[k] * x^(k+1)), for k=0..polyDeg-1
            sumVal := big.NewInt(0)
            for k := 0; k < polyDeg; k++ {
                // compute x^(k+1)
                xPow := new(big.Int).Exp(
                    big.NewInt(int64(x)),
                    big.NewInt(int64(k+1)),
                	// nil,
                    Order,

                )
                // multiply by alpha[k]
                xPow.Mul(xPow, alpha[k])
                xPow.Mod(xPow, Order) // known group order

                sumVal.Add(sumVal, xPow)
                sumVal.Mod(sumVal, Order)
            }
            // g2^P(x)
            crs.PEvals[x-1] = crs.G2.Exp(sumVal)
        }
    }
	return crs
}

// PublicKey holds the public key components.
type PublicKey struct {
	S  []G1Element // vector of G1 elements
	W  G1Element   // a single G1 element
	DK []G2Element // de–keying components (one per CRS gamma)
	V G1Element   // V = g1^vVal
}

// SecretKey holds the secret key.
type SecretKey struct {
	DK G2Element
}

// MasterPublicKey holds aggregated public key components.
type MasterPublicKey struct {
	S []G1Element // aggregated vector of G1 elements
	W G1Element   // aggregated G1 element
	T []G2Element // the same t as in the CRS
	V G1Element   // V = g1^vVal (aggregated for all users)
}

// HelperSecretKey holds a helper secret key.
type HelperSecretKey struct {
	H1 G2Element    // computed helper element
	H2 G2Element    // equals the corresponding Gamma element
}

// RandomScalar returns a random scalar in the range [1, Order–1].
func RandomScalar() *big.Int {
	n, err := rand.Int(rand.Reader, Order)
	if err != nil {
		panic(err)
	}
	if n.Sign() == 0 {
		return RandomScalar()
	}
	return n
}

func (g G1Element) MarshalBinary() ([]byte, error) {
	// Assume bls12381.G1.Bytes() returns a []byte representation.
	return g.P.Bytes(), nil
}

// ---------------------------
// G2Element
// ---------------------------
func (g G2Element) MarshalBinary() ([]byte, error) {
	return g.P.Bytes(), nil
}

// ---------------------------
// GTElement
// ---------------------------
func (gt GTElement) MarshalBinary() ([]byte, error) {
	b, err := gt.E.MarshalBinary()
	if err != nil {
		return nil, err
	}
	return b, nil
}

// ---------------------------
// CRS
// ---------------------------
// We serialize CRS by writing its simple integer fields and then appending the marshaled
// bytes of each element in its slices.
func (crs *CRS) MarshalBinary() ([]byte, error) {
	var buf bytes.Buffer

	// Write integer fields as strings (or use binary.Write for fixed-width encoding)
	buf.WriteString(strconv.Itoa(crs.L))
	buf.WriteString(strconv.Itoa(crs.N1))
	buf.WriteString(strconv.Itoa(crs.N2))

	// Write G1 and G2 generators
	if b, err := crs.G1.MarshalBinary(); err == nil {
		buf.Write(b)
	}
	if b, err := crs.G2.MarshalBinary(); err == nil {
		buf.Write(b)
	}

	// Write Gamma slice.
	for _, g := range crs.Gamma {
		if b, err := g.MarshalBinary(); err == nil {
			buf.Write(b)
		}
	}
	// Write T slice.
	for _, g := range crs.T {
		if b, err := g.MarshalBinary(); err == nil {
			buf.Write(b)
		}
	}
	// Write PCoeffs slice.
	for _, g := range crs.PCoeffs {
		if b, err := g.MarshalBinary(); err == nil {
			buf.Write(b)
		}
	}
	// Write PEvals slice.
	for _, g := range crs.PEvals {
		if b, err := g.MarshalBinary(); err == nil {
			buf.Write(b)
		}
	}
	// (We ignore F in this simple implementation.)
	return buf.Bytes(), nil
}

// ---------------------------
// PublicKey
// ---------------------------
func (pk PublicKey) MarshalBinary() ([]byte, error) {
	var buf bytes.Buffer

	// Write S (slice of G1Elements)
	for _, s := range pk.S {
		if b, err := s.MarshalBinary(); err == nil {
			buf.Write(b)
		}
	}
	// Write W (a G1Element)
	if b, err := pk.W.MarshalBinary(); err == nil {
		buf.Write(b)
	}
	// Write DK (slice of G2Elements)
	for _, d := range pk.DK {
		if b, err := d.MarshalBinary(); err == nil {
			buf.Write(b)
		}
	}
	// Write V (a G1Element)
	if b, err := pk.V.MarshalBinary(); err == nil {
		buf.Write(b)
	}
	return buf.Bytes(), nil
}

// ---------------------------
// SecretKey
// ---------------------------
func (sk SecretKey) MarshalBinary() ([]byte, error) {
	// Simply marshal the single G2Element
	return sk.DK.MarshalBinary()
}

// ---------------------------
// MasterPublicKey
// ---------------------------
func (mpk MasterPublicKey) MarshalBinary() ([]byte, error) {
	var buf bytes.Buffer

	// Write S slice (of G1Elements)
	for _, s := range mpk.S {
		if b, err := s.MarshalBinary(); err == nil {
			buf.Write(b)
		}
	}
	// Write W (G1Element)
	if b, err := mpk.W.MarshalBinary(); err == nil {
		buf.Write(b)
	}
	// Write T slice (of G2Elements)
	for _, t := range mpk.T {
		if b, err := t.MarshalBinary(); err == nil {
			buf.Write(b)
		}
	}
	// Write V (G1Element)
	if b, err := mpk.V.MarshalBinary(); err == nil {
		buf.Write(b)
	}
	return buf.Bytes(), nil
}

// ---------------------------
// HelperSecretKey
// ---------------------------
func (hsk HelperSecretKey) MarshalBinary() ([]byte, error) {
	var buf bytes.Buffer
	// Write H1 and H2 (both G2Elements)
	if b, err := hsk.H1.MarshalBinary(); err == nil {
		buf.Write(b)
	}
	if b, err := hsk.H2.MarshalBinary(); err == nil {
		buf.Write(b)
	}
	return buf.Bytes(), nil
}

// Ensure our types implement encoding.BinaryMarshaler.
var (
	_ encoding.BinaryMarshaler = G1Element{}
	_ encoding.BinaryMarshaler = G2Element{}
	_ encoding.BinaryMarshaler = GTElement{}
	_ encoding.BinaryMarshaler = &CRS{}
	_ encoding.BinaryMarshaler = PublicKey{}
	_ encoding.BinaryMarshaler = SecretKey{}
	_ encoding.BinaryMarshaler = MasterPublicKey{}
	_ encoding.BinaryMarshaler = HelperSecretKey{}
)