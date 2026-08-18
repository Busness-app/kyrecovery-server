package crypto

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// Galois Field GF(2^8) with generator 0x03 and irreducible polynomial 0x11B (AES field).
var (
	gfExp [512]byte
	gfLog [256]byte
)

func init() {
	x := byte(1)
	for i := 0; i < 255; i++ {
		gfExp[i] = x
		gfExp[i+255] = x
		gfLog[x] = byte(i)
		// Multiply by 0x03 in GF(2^8)
		x = gfMulRaw(x, 0x03)
	}
	gfExp[510] = 1
	gfExp[511] = 1
}

func gfMulRaw(a, b byte) byte {
	var p byte
	for i := 0; i < 8; i++ {
		if b&1 != 0 {
			p ^= a
		}
		hi := a & 0x80
		a <<= 1
		if hi != 0 {
			a ^= 0x1b // x^8 + x^4 + x^3 + x + 1
		}
		b >>= 1
	}
	return p
}

func gfAdd(a, b byte) byte {
	return a ^ b
}

func gfSub(a, b byte) byte {
	return a ^ b
}

func gfMul(a, b byte) byte {
	if a == 0 || b == 0 {
		return 0
	}
	return gfExp[int(gfLog[a])+int(gfLog[b])]
}

func gfDiv(a, b byte) byte {
	if b == 0 {
		panic("division by zero in GF(2^8)")
	}
	if a == 0 {
		return 0
	}
	logA := int(gfLog[a])
	logB := int(gfLog[b])
	return gfExp[(logA-logB+255)%255]
}

// Share represents a single custodian share of a secret.
type Share struct {
	Index byte   `json:"index"` // 1-indexed (x value)
	Value []byte `json:"value"` // f(x) bytes
}

// String encodes the share as "index-hexValue"
func (s Share) String() string {
	return fmt.Sprintf("%d-%s", s.Index, hex.EncodeToString(s.Value))
}

// ParseShare decodes a share from "index-hexValue"
func ParseShare(encoded string) (Share, error) {
	parts := strings.SplitN(strings.TrimSpace(encoded), "-", 2)
	if len(parts) != 2 {
		return Share{}, errors.New("invalid share format, expected '<index>-<hex>'")
	}
	idx, err := strconv.Atoi(parts[0])
	if err != nil || idx < 1 || idx > 255 {
		return Share{}, fmt.Errorf("invalid share index %q: must be between 1 and 255", parts[0])
	}
	val, err := hex.DecodeString(parts[1])
	if err != nil {
		return Share{}, fmt.Errorf("invalid share hex payload: %w", err)
	}
	if len(val) == 0 {
		return Share{}, errors.New("empty share payload")
	}
	return Share{Index: byte(idx), Value: val}, nil
}

// Split divides a secret into 'total' shares such that any 'threshold' shares can reconstruct it.
func Split(secret []byte, threshold, total int) ([]Share, error) {
	if threshold < 2 {
		return nil, errors.New("threshold must be at least 2")
	}
	if threshold > total {
		return nil, errors.New("threshold cannot exceed total shares")
	}
	if total > 255 {
		return nil, errors.New("total shares cannot exceed 255 in GF(2^8)")
	}
	if len(secret) == 0 {
		return nil, errors.New("secret cannot be empty")
	}

	secretLen := len(secret)
	shares := make([]Share, total)
	for i := 0; i < total; i++ {
		shares[i] = Share{
			Index: byte(i + 1),
			Value: make([]byte, secretLen),
		}
	}

	// For each byte in the secret, create a random polynomial of degree (threshold - 1)
	poly := make([]byte, threshold)
	for byteIdx, secByte := range secret {
		poly[0] = secByte
		// Random coefficients for x^1 ... x^(threshold-1)
		if _, err := rand.Read(poly[1:]); err != nil {
			return nil, fmt.Errorf("failed to generate random coefficients: %w", err)
		}

		// Evaluate polynomial at x = 1 ... total
		for i := 0; i < total; i++ {
			x := shares[i].Index
			y := evalPoly(poly, x)
			shares[i].Value[byteIdx] = y
		}
	}

	return shares, nil
}

// evalPoly evaluates polynomial poly at x in GF(2^8) using Horner's method
func evalPoly(poly []byte, x byte) byte {
	if len(poly) == 0 {
		return 0
	}
	result := poly[len(poly)-1]
	for i := len(poly) - 2; i >= 0; i-- {
		result = gfAdd(gfMul(result, x), poly[i])
	}
	return result
}

// Combine reconstructs the secret using Lagrange interpolation at x = 0.
func Combine(shares []Share, threshold int) ([]byte, error) {
	if len(shares) < threshold {
		return nil, fmt.Errorf("insufficient shares: got %d, require at least %d", len(shares), threshold)
	}
	if threshold < 2 {
		return nil, errors.New("threshold must be at least 2")
	}

	// Use the first 'threshold' shares and ensure no duplicate indices
	usedShares := make([]Share, 0, threshold)
	seen := make(map[byte]bool)
	var expectedLen int

	for _, s := range shares {
		if s.Index == 0 {
			return nil, errors.New("share index cannot be 0")
		}
		if seen[s.Index] {
			continue // skip duplicate index
		}
		if len(usedShares) == 0 {
			expectedLen = len(s.Value)
			if expectedLen == 0 {
				return nil, errors.New("empty share payload")
			}
		} else if len(s.Value) != expectedLen {
			return nil, errors.New("mismatched share lengths")
		}
		seen[s.Index] = true
		usedShares = append(usedShares, s)
		if len(usedShares) == threshold {
			break
		}
	}

	if len(usedShares) < threshold {
		return nil, fmt.Errorf("insufficient unique shares: got %d unique shares, required %d", len(usedShares), threshold)
	}

	secret := make([]byte, expectedLen)

	// Precompute Lagrange basis polynomials at x = 0:
	// l_i(0) = \prod_{j \neq i} \frac{0 - x_j}{x_i - x_j} = \prod_{j \neq i} \frac{x_j}{x_i \oplus x_j}
	basis := make([]byte, threshold)
	for i := 0; i < threshold; i++ {
		xi := usedShares[i].Index
		l := byte(1)
		for j := 0; j < threshold; j++ {
			if i == j {
				continue
			}
			xj := usedShares[j].Index
			num := xj
			den := gfSub(xi, xj)
			term := gfDiv(num, den)
			l = gfMul(l, term)
		}
		basis[i] = l
	}

	// Reconstruct secret byte by byte
	for byteIdx := 0; byteIdx < expectedLen; byteIdx++ {
		var val byte
		for i := 0; i < threshold; i++ {
			term := gfMul(usedShares[i].Value[byteIdx], basis[i])
			val = gfAdd(val, term)
		}
		secret[byteIdx] = val
	}

	return secret, nil
}
