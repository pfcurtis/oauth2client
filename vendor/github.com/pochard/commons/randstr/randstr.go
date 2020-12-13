/**
* @date 2020-09-04
* @author pengpengzhou <philip_chow@163.com>
 */

package randstr

import (
	"math/rand"
	"time"
)

const numbers string = "0123456789"
const letters string = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
const specials = "~!@#$%^*()_+-=[]{}|;:,./<>?"
const alphanumberic string = letters + numbers
const ascii string = alphanumberic + specials


func Random(n int, chars string) string {
	if n <= 0 {
		return ""
	}
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	bytes := make([]byte, n, n)
	l := len(chars)
	for i := 0; i < n; i++ {
		bytes[i] = chars[r.Intn(l)]
	}
	return string(bytes)
}

func RandomAlphanumeric(n int) string {
	return Random(n, alphanumberic)
}

func RandomAlphabetic(n int) string {
	return Random(n, letters)
}

func RandomNumeric(n int) string {
	return Random(n, numbers)
}

func RandomAscii(n int) string {
	return Random(n, ascii)
}
