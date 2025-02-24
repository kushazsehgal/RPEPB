package decoder

import (
	"math/rand"

	"pooled_decrypt/models"
	"pooled_decrypt/utils"
	"pooled_decrypt/scheme"
)

// Decoder holds the decryption parameters and keys for a threshold of users.
type Decoder struct {
	crs        *models.CRS
	mpk        models.MasterPublicKey
	subset     []int                         // selected user indices (size = polyDeg+1)
	secretKeys map[int]models.SecretKey      // secret keys for all users (indexed by user)
	helperKeys map[int]models.HelperSecretKey // helper secret keys for selected users
	L          int
	polyDeg    int
}

// NewDecoder initializes a Decoder for L users and a threshold of polyDeg+1.
func NewDecoder(L, polyDeg int) *Decoder {
	// Initialize the CRS.
	crs := scheme.Setup(L, polyDeg)

	// Generate key pairs for all L users.
	publicKeys := make([]models.PublicKey, 0, L)
	secretKeys := make(map[int]models.SecretKey)
	for i := 0; i < L; i++ {
		pk, sk := scheme.Keygen(crs, i)
		publicKeys = append(publicKeys, pk)
		secretKeys[i] = sk
	}

	// Aggregate public keys to produce the master public key and helper secret keys.
	mpk, hskArr := scheme.Aggregate(crs, publicKeys)

	// Randomly sample polyDeg+1 unique user indices from 0 to L-1.
	subset := pickRandomSubset(L, polyDeg+1)

	// Store helper secret keys only for the selected users.
	helperKeys := make(map[int]models.HelperSecretKey)
	for _, idx := range subset {
		helperKeys[idx] = hskArr[idx]
	}

	return &Decoder{
		crs:        crs,
		mpk:        mpk,
		subset:     subset,
		secretKeys: secretKeys,
		helperKeys: helperKeys,
		L:          L,
		polyDeg:    polyDeg,
	}
}
func pickRandomSubset(max, count int) []int {
    if count > max {
        panic("pickRandomSubset: count > max")
    }
    set := make(map[int]bool)
    for len(set) < count {
        idx := rand.Intn(max)
        set[idx] = true
    }
    // Convert to slice
    result := make([]int, 0, count)
    for k := range set {
        result = append(result, k)
    }
    return result
}

// Decode takes a ciphertext and returns the decrypted GT element.
// It computes partial decryptions for each user in the subset and then combines them.
func (d *Decoder) Decode(ct scheme.Ciphertext) models.GTElement {
	// Create a slice for partial decryptions; indices correspond to user numbers.
	partials := make([]models.GTElement, d.L)
	// Compute partial decryption for each selected user.
	for _, u := range d.subset {
		// Each call to Decrypt produces a partial in GT.
		partials[u] = scheme.Decrypt(d.crs, d.secretKeys[u], u, d.helperKeys[u], ct)
	}
	// Combine the partial decryptions via Lagrange interpolation in GT.
	mDecGT := scheme.Combine(ct, partials, d.subset, models.Order)
	return mDecGT
}


func (d *Decoder) Encrypt() (scheme.Ciphertext, models.GTElement) {
	// Generate a random scalar psi.
	psi := models.RandomScalar()
	// Encode psi into vectors x and y.
	x, y := utils.Z_bigInt(psi, d.L)
	// Encrypt using the scheme's Encrypt function.
	ct := scheme.Encrypt(d.crs, d.mpk, x, y)
	// For verification, compute psi in GT.
	psiGT := models.GTGenerator().Exp(psi)
	return ct, psiGT
}

func (d *Decoder) TraceEncrypt(i int) (scheme.Ciphertext, models.GTElement) {
	// Generate a random scalar psi.
	psi := models.RandomScalar()
	// Encode psi into vectors x and y.
	x, y := utils.Z_im_bigInt(i,d.L, psi)
	// Encrypt using the scheme's Encrypt function.
	ct := scheme.Encrypt(d.crs, d.mpk, x, y)
	// For verification, compute psi in GT.
	psiGT := models.GTGenerator().Exp(psi)
	return ct, psiGT
}

func GTEqual(a, b models.GTElement) bool {
    aBytes, _ := a.E.MarshalBinary()
    bBytes, _ := b.E.MarshalBinary()
    return string(aBytes) == string(bBytes)
}

// TraceD iterates over i = 0..L, calls TraceEncrypt(i), decrypts,
// and checks if the decryption matches the originally encrypted value.
// If there's a mismatch, it returns (i-1). If all match, it returns L.
func (d *Decoder) TraceD() int {
	for i := 0; i <= d.L; i++ {
		ct, psiGT := d.TraceEncrypt(i)   // Encrypt a random scalar “psi” tagged with index i
		decResult := d.Decode(ct)        // Decrypt the ciphertext

		// Check if decryption matches the original GT element
		if !GTEqual(psiGT,decResult) {
			// Mismatch => return (i-1)
			return i - 1
		}
		// Otherwise, continue checking the next i
	}
	// If all i in [0..L] match, return L
	return d.L
}