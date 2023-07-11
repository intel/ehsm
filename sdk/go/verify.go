package ehsm

import (
    hmac "crypto/hmac"
    sha256 "crypto/sha256"
    "encoding/base64"
    "encoding/json"
    "fmt"
    ioutil "io/ioutil"
    "time"
    "strconv"

    "github.com/iancoleman/orderedmap"
)

type VerifyResponse struct {
    Code int `json:"code"`
    Message string `json:"message"`
    Result struct {
        Result bool `json:"result"`
    } `json:"result"`
}

func (c *Client) Verify(keyid, digest, signature string) (bool, error) {
    // make JSON for verify
    payload := orderedmap.New()
    if keyid != ""{
        payload.Set("keyid", keyid)
    } else {
        return false, fmt.Errorf("Please input keyid.")
    }
    if digest != ""{
        payload.Set("digest", digest)
    } else {
        return false, fmt.Errorf("Please input digest.")
    }
    if signature != ""{
        payload.Set("signature", signature)
    } else {
        return false, fmt.Errorf("Please input signature.")
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

    c.action = "Verify"
    c.resquest = params
    
    // call ehsm kms
    resp, err := c.ehsmHttpAction()
    if err != nil {
        fmt.Println("ehsmHttpAction error:", err)
        return false, err
    }

    defer resp.Body.Close()

    body, err := ioutil.ReadAll(resp.Body)
    if err != nil {
        fmt.Println("ReadAll error:", err)
        return false, err
    }
    
    // parse response for cosign
    var verifyResponse VerifyResponse

    str := string(body)

    err = json.Unmarshal([]byte(str), &verifyResponse)
    if err != nil{
        fmt.Println("Unmarshal error:", err)
        return false, err
    }

    if verifyResponse.Code != 200 {
        return false, fmt.Errorf(verifyResponse.Message)
    }

    return verifyResponse.Result.Result, nil
}