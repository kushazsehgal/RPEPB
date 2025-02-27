package main

import (
	"encoding"
	"encoding/csv"
	"fmt"
	"log"
	"math"
	"math/rand"
	"os"
	"strconv"
	"time"

	"pooled_decrypt/decoder"
	"pooled_decrypt/models"
	"pooled_decrypt/scheme"
	"pooled_decrypt/utils"
)

// GTEqual compares two GT elements by marshaling them to bytes.
func GTEqual(a, b models.GTElement) bool {
	aBytes, _ := a.E.MarshalBinary()
	bBytes, _ := b.E.MarshalBinary()
	return string(aBytes) == string(bBytes)
}

// pickRandomSubset returns 'count' distinct random integers in [0..max-1].
func pickRandomSubset(count, max int) []int {
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

// sizeOf returns the number of bytes resulting from calling MarshalBinary on bm.
func sizeOf(bm encoding.BinaryMarshaler) int {
	data, err := bm.MarshalBinary()
	if err != nil {
		return 0
	}
	return len(data)
}

// testSchemeDirectly runs the scheme test for various L and polyDeg values.
// For each (L, polyDeg) it performs 5 trials, and within each trial does 5 encryption/decryption rounds.
// Results are written to "scheme_times.csv".
func testSchemeDirectly(Lvalues []int, trialsPerSetting int) {
	csvFileName := "scheme_times.csv"
	file, err := os.OpenFile(csvFileName, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		panic(err)
	}
	defer file.Close()
	writer := csv.NewWriter(file)
	defer writer.Flush()

	// CSV header
	writer.Write([]string{
		"L", "polyDeg", "trial",
		"setup_time_ms",
		"total_keygen_time_ms", "avg_keygen_time_ms",
		"aggregate_time_ms",
		"avg_enc_time_ms",
		"avg_indiv_decrypt_time_ms", "avg_combine_time_ms", "avg_total_decrypt_time_ms",
	})

	
	encRounds := 5

	for _, L := range Lvalues {
		// polyDeg = floor(2*L/3)
		polyDeg := int(math.Floor(2 * float64(L) / 3))
		if L <= polyDeg {
			fmt.Printf("Skipping L=%d, polyDeg=%d (require L > polyDeg)\n", L, polyDeg)
			continue
		}
		for trial := 1; trial <= trialsPerSetting; trial++ {
			// --- Setup ---
			startSetup := time.Now()
			crs := scheme.Setup(L, polyDeg)
			setupTime := time.Since(startSetup)

			// --- Key Generation for L users ---
			totalKeygen := time.Duration(0)
			pks := make([]models.PublicKey, L)
			sks := make([]models.SecretKey, L)
			for userIdx := 0; userIdx < L; userIdx++ {
				startKG := time.Now()
				pk, sk := scheme.Keygen(crs, userIdx)
				totalKeygen += time.Since(startKG)
				pks[userIdx] = pk
				sks[userIdx] = sk
			}
			avgKeygen := totalKeygen / time.Duration(L)

			// --- Aggregate ---
			startAgg := time.Now()
			mpk, hskArr := scheme.Aggregate(crs, pks)
			aggregateTime := time.Since(startAgg)

			// --- Encryption/Decryption Rounds ---
			var totalEncTime time.Duration
			var totalPartialDecTime time.Duration
			var totalCombineTime time.Duration
			var totalDecTime time.Duration
			for i := 0; i < encRounds; i++ {
				psi := models.RandomScalar()
				x, y := utils.Z_bigInt(psi, L)

				startEnc := time.Now()
				ct := scheme.Encrypt(crs, mpk, x, y)
				encTime := time.Since(startEnc)
				totalEncTime += encTime

				// --- Threshold Decryption ---
				// Pick polyDeg+1 distinct users.
				subset := pickRandomSubset(polyDeg+1, L)
				partials := make([]models.GTElement, L)
				var roundPartialDecTime time.Duration
				for _, u := range subset {
					startPartial := time.Now()
					partial := scheme.Decrypt(crs, sks[u], u, hskArr[u], ct)
					roundPartialDecTime += time.Since(startPartial)
					partials[u] = partial
				}
				startCombine := time.Now()
				_ = scheme.Combine(ct, partials, subset, models.Order)
				combineTime := time.Since(startCombine)

				roundDecTime := roundPartialDecTime + combineTime
				totalPartialDecTime += roundPartialDecTime
				totalCombineTime += combineTime
				totalDecTime += roundDecTime
			}

			avgEncTime := totalEncTime / time.Duration(encRounds)
			avgIndivDecTime := totalPartialDecTime / time.Duration(encRounds*(polyDeg+1))
			avgCombineTime := totalCombineTime / time.Duration(encRounds)
			avgTotalDecTime := totalDecTime / time.Duration(encRounds)

			record := []string{
				strconv.Itoa(L),
				strconv.Itoa(polyDeg),
				strconv.Itoa(trial),
				fmt.Sprintf("%.4f", float64(setupTime.Milliseconds())),
				fmt.Sprintf("%.4f", float64(totalKeygen.Milliseconds())),
				fmt.Sprintf("%.4f", float64(avgKeygen.Milliseconds())),
				fmt.Sprintf("%.4f", float64(aggregateTime.Milliseconds())),
				fmt.Sprintf("%.4f", float64(avgEncTime.Milliseconds())),
				fmt.Sprintf("%.4f", float64(avgIndivDecTime.Milliseconds())),
				fmt.Sprintf("%.4f", float64(avgCombineTime.Milliseconds())),
				fmt.Sprintf("%.4f", float64(avgTotalDecTime.Milliseconds())),
			}
			writer.Write(record)
			writer.Flush()
			fmt.Printf("Scheme Test: L=%d, polyDeg=%d, trial=%d done.\n", L, polyDeg, trial)
		}
	}
}

// testDecoderTrace runs tests using the Decoder’s trace functions.
// For each (L, polyDeg) pair it performs 5 trials, measuring:
//   - Decoder creation time,
//   - Trace encrypt time (using TraceEncrypt at an arbitrary index),
//   - Trace decrypt time (via TraceDecrypt).
// Results are written to "decoder_times.csv".
func testDecoderTrace(Lvalues []int, trialsPerSetting int) {
	csvFileName := "decoder_times.csv"
	file, err := os.OpenFile(csvFileName, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		panic(err)
	}
	defer file.Close()
	writer := csv.NewWriter(file)
	defer writer.Flush()

	writer.Write([]string{
		"L", "polyDeg", "trial",
		"decoder_creation_time_ms",
		 "trace_d_time_ms",
	})

	for _, L := range Lvalues {
		polyDeg := int(math.Floor(2 * float64(L) / 3))
		if L <= polyDeg {
			fmt.Printf("Skipping L=%d, polyDeg=%d (L <= polyDeg)\n", L, polyDeg)
			continue
		}
		for trial := 1; trial <= trialsPerSetting; trial++ {
			startDecCreation := time.Now()
			dec := decoder.NewDecoder(L, polyDeg)
			decoderCreationTime := time.Since(startDecCreation)

			startTraceD := time.Now()
			_ = dec.TraceD()
			traceDTime := time.Since(startTraceD)

			record := []string{
				strconv.Itoa(L),
				strconv.Itoa(polyDeg),
				strconv.Itoa(trial),
				fmt.Sprintf("%.4f", float64(decoderCreationTime.Milliseconds())),
				fmt.Sprintf("%.4f", float64(traceDTime.Milliseconds())),
			}
			writer.Write(record)
			writer.Flush()
			fmt.Printf("Decoder Test: L=%d, polyDeg=%d, trial=%d done.\n", L, polyDeg, trial)
		}
	}
}

// testSizes measures and logs sizes (in bytes) of representative group elements and keys.
// For each L (with polyDeg = floor(2L/3)), it logs:
//   - Size of a G1, G2, and GT element,
//   - Size of the CRS,
//   - Size of a public key,
//   - Size of the master public key,
//   - Size of a secret key,
//   - Size of a helper secret key.
// Results are written to "sizes.csv".

func testSizes(Lvalues []int) {
	csvFileName := "sizes.csv"
	file, err := os.OpenFile(csvFileName, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		panic(err)
	}
	defer file.Close()
	writer := csv.NewWriter(file)
	defer writer.Flush()

	// CSV header
	writer.Write([]string{
		"L", "polyDeg",
		"G1_size_bytes", "G2_size_bytes", "GT_size_bytes",
		"CRS_size_bytes", "PublicKey_size_bytes", "MasterPublicKey_size_bytes",
		"SecretKey_size_bytes", "HelperSecretKey_size_bytes",
	})

	g1Size := sizeOf(models.G1Generator())
	g2Size := sizeOf(models.G2Generator())
	gtSize := sizeOf(models.GTGenerator())
	
	for _, L := range Lvalues {
		polyDeg := int(math.Floor(2 * float64(L) / 3))
		if L <= polyDeg {
			fmt.Printf("Skipping sizes for L=%d, polyDeg=%d (L <= polyDeg)\n", L, polyDeg)
			continue
		}

		// Measure group element sizes using generators.
		

		// Create CRS.
		crs := scheme.Setup(L, polyDeg)
		crsSize := sizeOf(crs)

		// Generate one key pair (for user 0).
		pk, sk := scheme.Keygen(crs, 0)
		pkSize := sizeOf(pk)
		skSize := sizeOf(sk)

		// Generate keys for all L users and aggregate to obtain master public key and helper secret key.
		pks := make([]models.PublicKey, L)
		sks := make([]models.SecretKey, L)
		for i := 0; i < L; i++ {
			p, s := scheme.Keygen(crs, i)
			pks[i] = p
			sks[i] = s
		}
		mpk, hskArr := scheme.Aggregate(crs, pks)
		mpkSize := sizeOf(mpk)
		helperSize := sizeOf(hskArr[0]) // assume all helper secret keys are of similar size

		record := []string{
			strconv.Itoa(L),
			strconv.Itoa(polyDeg),
			strconv.Itoa(g1Size),
			strconv.Itoa(g2Size),
			strconv.Itoa(gtSize),
			strconv.Itoa(crsSize),
			strconv.Itoa(pkSize),
			strconv.Itoa(mpkSize),
			strconv.Itoa(skSize),
			strconv.Itoa(helperSize),
		}
		writer.Write(record)
		writer.Flush()
		fmt.Printf("Sizes recorded for L=%d, polyDeg=%d\n", L, polyDeg)
	}
}

func testCT(Lvalues []int){
	file, err := os.Create("ciphertext_sizes.csv")
	if err != nil {
		log.Fatalf("Error creating CSV file: %v", err)
	}
	defer file.Close()
	writer := csv.NewWriter(file)
	defer writer.Flush()

	// Write CSV header.
	if err := writer.Write([]string{"L", "n1", "n2", "size of ciphertext"}); err != nil {
		log.Fatalf("Error writing header to CSV: %v", err)
	}

	for _, L := range Lvalues {
		// Compute sqrtL, n1, and n2.
		sqrtL := int(math.Sqrt(float64(L)))
		n1 := 2 * sqrtL
		n2 := sqrtL + 1

		// Build the slices.
		C3 := make([][2]models.G1Element, n1)
		for i := 0; i < n1; i++ {
			C3[i] = [2]models.G1Element{models.G1Generator(), models.G1Generator()}
		}
		C4 := make([][2]models.G2Element, n2)
		for i := 0; i < n2; i++ {
			C4[i] = [2]models.G2Element{models.G2Generator(), models.G2Generator()}
		}

		// Create the ciphertext.
		ct := scheme.Ciphertext{
			C1: models.G1Generator(),
			C2: models.G1Generator(),
			C3: C3,
			C4: C4,
		}

		// Marshal the ciphertext.
		marshaled, err := ct.MarshalBinary()
		if err != nil {
			log.Fatalf("Error marshaling ciphertext: %v", err)
		}
		size := len(marshaled)

		// Write the computed values as a row in the CSV file.
		record := []string{
			fmt.Sprintf("%d", L),
			fmt.Sprintf("%d", n1),
			fmt.Sprintf("%d", n2),
			fmt.Sprintf("%d", size),
		}
		if err := writer.Write(record); err != nil {
			log.Fatalf("Error writing record to CSV: %v", err)
		}

		fmt.Printf("L=%d, n1=%d, n2=%d, size of ciphertext: %d bytes\n", L, n1, n2, size)
	}
}
func main() {
	rand.Seed(time.Now().UnixNano())

	// Lvalues := []int{16,64}
	// trialsPerSetting := 2
	Lvalues := []int{16, 64, 256, 1024}
	trialsPerSetting := 3

	fmt.Println("Measuring sizes for ciphertexts...")
	testCT(Lvalues)
	fmt.Println("Ciphertext size measurements completed.")
	fmt.Println("Measuring sizes for group elements and keys...")
	testSizes(Lvalues)
	fmt.Println("Size measurements completed.")
	
	fmt.Println("Starting scheme direct tests...")
	testSchemeDirectly(Lvalues, trialsPerSetting)
	fmt.Println("Scheme tests completed.")

	fmt.Println("Starting decoder trace tests...")
	testDecoderTrace(Lvalues, trialsPerSetting)
	fmt.Println("Decoder tests completed.")

	
	
}
