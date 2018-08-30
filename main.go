package main

import (
    cryptorand "crypto/rand"
    "crypto"
    "encoding/hex"
    "github.com/wsddn/go-ecdh"
    "diffie/helpers"
    "fmt"
    "os/exec"
    "log"
    "encoding/json"
)

func main() {
    privMy, pubMy, _ := ecdh.NewCurve25519ECDH().GenerateKey(cryptorand.Reader)
    hexMy:= ToHex(pubMy)
    
    cmd := exec.Command("node", "main.js", hexMy)
    
    stdout, err := cmd.StdoutPipe()
    if err != nil {
        log.Fatal(err)
    }
    if err := cmd.Start(); err != nil {
        log.Fatal(err)
    }
    var data struct {
        Pub string
        Encrypt  string
    }
    if err := json.NewDecoder(stdout).Decode(&data); err != nil {
        log.Fatal(err)
    }
    if err := cmd.Wait(); err != nil {
        log.Fatal(err)
    }
    
    pub,_:= FromHex(data.Pub)
    secret,err:=calcSecret(privMy,pub)
    if err != nil {
        log.Fatal(err)
    }
    
    key:=hex.EncodeToString(secret)
    
    decrypted := helpers.KeyDecrypt(key, data.Encrypt)
    fmt.Println(decrypted)
}

func ToHex(public interface{}) string {
    return hex.EncodeToString(ecdh.NewCurve25519ECDH().Marshal(public))
}

func FromHex(public string) (interface{},bool) {
    fa,_:=hex.DecodeString(public)
    return ecdh.NewCurve25519ECDH().Unmarshal(fa)
}

func calcSecret(priv crypto.PrivateKey, pub1 crypto.PublicKey) ([]byte, error) {
    return ecdh.NewCurve25519ECDH().GenerateSharedSecret(priv, pub1)
}

