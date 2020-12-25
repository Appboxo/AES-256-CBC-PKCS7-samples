package main

import (
   "bytes"
   "crypto/aes"
   "io"
   "crypto/rand"
   "crypto/cipher"
   "encoding/base64"
   "fmt"
)

const secret_key = "u9Qd9wV0Z6Ho9_TzCYyVW_WwBJwL7KvSl4k8fmfaLyE="
const CIPHER_KEY = "abcdefghijklmnopqrstuvwxyz012345"
const phrase = `{"name":"Bob","email":"user@example.com","address":"Singapore"}`

 // Use PKCS7 to fill, IOS is also 7
func PKCS7Padding(ciphertext []byte, blockSize int) []byte {
   padding := blockSize - len(ciphertext) % blockSize
   padtext := bytes.Repeat([]byte{byte(padding)}, padding)
   return append(ciphertext, padtext...)
}

func PKCS7UnPadding(origData []byte) []byte {
   length := len(origData)
   unpadding := int(origData[length-1])
   return origData[:(length - unpadding)]
}

 //aes encryption, filling the 16 bits of the key key, 24, 32 respectively corresponding to AES-128, AES-192, or AES-256.
func AesCBCEncrypt(rawData,key []byte) ([]byte, error) {
   block, err := aes.NewCipher(key)
   if err != nil {
       panic(err)
   }

       //fill the original
   blockSize := block.BlockSize()
   rawData = PKCS7Padding(rawData, blockSize)
       // Initial vector IV must be unique, but does not need to be kept secret
   cipherText := make([]byte,blockSize+len(rawData))
       //block size 16
   iv := cipherText[:blockSize]
   if _, err := io.ReadFull(rand.Reader,iv); err != nil {
       panic(err)
   }

       //block size and initial vector size must be the same
   mode := cipher.NewCBCEncrypter(block,iv)
   mode.CryptBlocks(cipherText[blockSize:],rawData)

   return cipherText, nil
}

func AesCBCDncrypt(encryptData, key []byte) ([]byte,error) {
   block, err := aes.NewCipher(key)
   if err != nil {
       panic(err)
   }

   blockSize := block.BlockSize()

   if len(encryptData) < blockSize {
       panic("ciphertext too short")
   }
   iv := encryptData[:blockSize]
   encryptData = encryptData[blockSize:]

   // CBC mode always works in whole blocks.
   if len(encryptData)%blockSize != 0 {
       panic("ciphertext is not a multiple of the block size")
   }

   mode := cipher.NewCBCDecrypter(block, iv)

   // CryptBlocks can work in-place if the two arguments are the same.
   mode.CryptBlocks(encryptData, encryptData)
       // Unfill
   encryptData = PKCS7UnPadding(encryptData)
   return encryptData,nil
}


func Encrypt(rawData,key []byte) (string,error) {
   data, err:= AesCBCEncrypt(rawData,key)
   if err != nil {
       return "",err
   }
   return base64.StdEncoding.EncodeToString(data),nil
}

func Dncrypt(rawData string,key []byte) (string,error) {
   data,err := base64.StdEncoding.DecodeString(rawData)
   if err != nil {
       return "",err
   }
   dnData,err := AesCBCDncrypt(data,key)
   if err != nil {
       return "",err
   }
   return string(dnData),nil
}

func Encrypt2(unencrypted string, key []byte) (string, error) {
	plainText := []byte(unencrypted)
	plainText = PKCS7Padding(plainText, aes.BlockSize) //pkcs7.Pad(plainText, )
	if len(plainText)%aes.BlockSize != 0 {
		err := fmt.Errorf(`plainText: "%s" has the wrong block size`, plainText)
		return "", err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	cipherText := make([]byte, aes.BlockSize+len(plainText))
	iv := cipherText[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return "", err
	}

	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(cipherText[aes.BlockSize:], plainText)

	return base64.StdEncoding.EncodeToString(cipherText), nil
}

func main() {
    data,err := base64.URLEncoding.DecodeString(secret_key)
    if err != nil {
       fmt.Println(err)
    } else {
       fmt.Println(Encrypt([]byte(phrase), data))
       fmt.Println(Encrypt2(phrase, data))
    }
}