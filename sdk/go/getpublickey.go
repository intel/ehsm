package ehsm

import (
    "crypto"
    hmac "crypto/hmac"
    sha256 "crypto/sha256"
    "encoding/base64"
    "encoding/json"
    "fmt"
    ioutil "io/ioutil"
    "time"
    "strconv"
    "errors"
    "crypto/x509"
    "encoding/pem"

    "github.com/iancoleman/orderedmap"
)

type GetPublicKeyResponse struct {
    Code int `json:"code"`
    Message string `json:"message"`
    Result struct {
        Keyid string `json:"keyid"`
        Pubkey string `json:"pubkey"`
    } `json:"result"`
}

type PEMType string

const (
    // PublicKeyPEMType is the string "PUBLIC KEY" to be used during PEM encoding and decoding
    PublicKeyPEMType PEMType = "PUBLIC KEY"
    // PKCS1PublicKeyPEMType is the string "RSA PUBLIC KEY" used to parse PKCS#1-encoded public keys
    PKCS1PublicKeyPEMType PEMType = "RSA PUBLIC KEY"
)

func (c *Client) GetPublicKey(keyid string) (crypto.PublicKey, error) {
    // make JSON for getpubkey
    payload := orderedmap.New()
    if keyid != ""{
        payload.Set("keyid", keyid)
    } else {
        return "", fmt.Errorf("Please input keyid.")
    }

    params := orderedmap.New()

    params.Set("appid", c.appid)
    params.Set("payload", payload)
    params.Set("timestamp", strconv.FormatInt(time.Now().UnixNano()/int64(time.Millisecond), 10))

    signString := paramsSortStr(params)

    hmacSha256 := hmac.New(sha256.New, []byte(c.apikey))
    hmacSha256.Write([]byte(signString))
    sign := base64.StdEncoding.EncodeToString(hmacSha256.Sum(nil))

    params.Set("sign", sign)

    c.modifyLock.Lock()
    defer c.modifyLock.Unlock()

    c.action = "GetPublicKey"
    c.resquest = params
    
    // call ehsm kms    
    resp, err := c.ehsmHttpAction()
    if err != nil {
        fmt.Println("ehsmHttpAction error:", err)
        return "", err
    }

    defer resp.Body.Close()

    body, err := ioutil.ReadAll(resp.Body)
    if err != nil {
        fmt.Println("ReadAll error:", err)
        return "", err
    }

    // parse response for cosign
    var getPublicKeyResponse GetPublicKeyResponse

    str := string(body)

    err = json.Unmarshal([]byte(str), &getPublicKeyResponse)
    if err != nil{
        fmt.Println("Unmarshal error:", err)
        return "", err
    }

    if getPublicKeyResponse.Code != 200 {
        return "", fmt.Errorf(getPublicKeyResponse.Message)
    }

    // parse keyblob to crypto.x509
    // support EH_RSA_x and EH_EC_P256 
    pemBytes := []byte(getPublicKeyResponse.Result.Pubkey)
    derBytes, _ := pem.Decode(pemBytes)
    if derBytes == nil {
        return nil, errors.New("PEM decoding failed")
    }
    switch derBytes.Type {
    case string(PublicKeyPEMType):
        return x509.ParsePKIXPublicKey(derBytes.Bytes)
    case string(PKCS1PublicKeyPEMType):
        return x509.ParsePKCS1PublicKey(derBytes.Bytes)
    default:
        return nil, fmt.Errorf("unknown Public key PEM file type: %v. Are you passing the correct public key?",
            derBytes.Type)
    }
}