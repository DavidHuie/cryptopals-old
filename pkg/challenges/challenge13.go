package challenges

import (
	"fmt"

	"strings"

	"github.com/DavidHuie/cryptopals/pkg/crypto"
)

func ParseProfile(s string) map[string]string {
	profile := make(map[string]string)
	tokens := strings.Split(s, "&")
	for _, token := range tokens {
		v := strings.Split(token, "=")
		profile[v[0]] = v[1]
	}
	return profile
}

func filterProfile(s string) string {
	var newS []byte
	for _, v := range s {
		if v == '=' || v == '&' {
			continue
		}
		newS = append(newS, byte(v))
	}

	return string(newS)
}

func ProfileFor(email string) string {
	filtered := filterProfile(email)
	return fmt.Sprintf("email=%s&uid=10&role=user", filtered)
}

var challenge11Key []byte

func Challenge11Encrypt(email string) []byte {
	if len(challenge11Key) == 0 {
		challenge11Key = crypto.GetRandBytes(16)
	}
	return crypto.ECBEncrypt([]byte(email), challenge11Key)
}

func Challenge11Decrypt(ct []byte) map[string]string {
	if len(challenge11Key) == 0 {
		challenge11Key = crypto.GetRandBytes(16)
	}
	return ParseProfile(string(crypto.ECBDecrypt(ct, challenge11Key)))
}

func GenerateAdminProfile() {
	// Locate
	var profile string
	account := "dahuie"
	label := "+a"
	rest := "@gmail.com"
	for i := 0; i < 1000; i++ {
		email := account + label + rest
		profile = ProfileFor(email)
		blocks := len(profile) / 16
		lastBlock := profile[blocks*16:]
		if lastBlock == "user" {
			break
		}
		label += "a"
	}
	fmt.Println(profile)
}
