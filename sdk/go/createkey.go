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

type CreateKeyResponse struct {
    Code int `json:"code"`
    Message string `json:"message"`
    Result struct {
        Keyid string `json:"keyid"`
    } `json:"result"`
}

func (c *Client) CreateKey(keyspec, origin, purpose, padding_mode string) (string, error){
    // make JSON for createkey
    payload := orderedmap.New()
    if keyspec != ""{
        payload.Set("keyspec", keyspec)
    } else {
        return "", fmt.Errorf("Please input keyspec.")
    }
    if origin != ""{
        payload.Set("origin", origin)
    } else {
        return "", fmt.Errorf("Please input origin.")
    }

    if purpose != ""{
        payload.Set("purpose", purpose)
    }
    if padding_mode != ""{
        payload.Set("padding_mode", padding_mode)
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

    c.action = "CreateKey"
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
    var createKeyResponse CreateKeyResponse

    str := string(body)

    err = json.Unmarshal([]byte(str), &createKeyResponse)
    if err != nil{
        fmt.Println("Unmarshal error:", err)
        return "", err
    }

    if createKeyResponse.Code != 200 {
        return "", fmt.Errorf(createKeyResponse.Message)
    }

    return createKeyResponse.Result.Keyid, nil
}
