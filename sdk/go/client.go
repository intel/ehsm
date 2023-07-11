package ehsm

import (
    tls "crypto/tls"
    "encoding/json"
    "fmt"
    http "net/http"
    "sort"
    "os"
    "bytes"
    "sync"

    "github.com/iancoleman/orderedmap"
)

type Client struct {
    modifyLock              sync.RWMutex
    addr                    string
    apikey                  string
    appid                   string
    action                  string
    resquest       *orderedmap.OrderedMap
}

func NewClient() (*Client, error) {
    c := new(Client)
    c.modifyLock.Lock()
    defer c.modifyLock.Unlock()

    c.addr = os.Getenv("EHSM_ADDR")
    if c.addr == "" {
        return nil, fmt.Errorf("Please export EHSM_ADDR.")
    }
    c.appid = os.Getenv("EHSM_APPID")
    if c.appid == "" {
        return nil, fmt.Errorf("Please export EHSM_APPID.")
    }
    c.apikey = os.Getenv("EHSM_APIKEY")
    if c.apikey == "" {
        return nil, fmt.Errorf("Please export EHSM_APIKEY.")
    }

    return c, nil
}

func (c *Client) ehsmHttpAction() (*http.Response, error) {
    // create an insecure Transport
    tr := &http.Transport{
        TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
    }

    // create an insecure Client
    client := &http.Client{Transport: tr}

    requestBody, err := json.Marshal(c.resquest)
    
    // call ehsm kms
    resp, err := client.Post(c.addr + "/ehsm?Action=" + c.action, "application/json", bytes.NewBuffer(requestBody))

    return resp, err
}

func sortMap(oldmap *orderedmap.OrderedMap) *orderedmap.OrderedMap {
    newmap := orderedmap.New()
    keys := oldmap.Keys()
    sort.Strings(keys)
    for _, key := range keys {
        value, _ := oldmap.Get(key)
        newmap.Set(key, value)
    }
    return newmap
}
func paramsSortStr(signParams *orderedmap.OrderedMap) string {
    var str string
    sortedSignParams := sortMap(signParams)
    for _, k := range sortedSignParams.Keys() {
        v, _ := sortedSignParams.Get(k)
        if k == "payload" {
            payload := v.(*orderedmap.OrderedMap)
            str += "&" + k + "=" + paramsSortStr(payload)
        } else {
            str += fmt.Sprintf("&%s=%v", k, v)
        }
    }
    if len(str) > 0 {
        str = str[1:] // Remove leading "&"
    }
    return str
}