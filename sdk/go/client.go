package ehsm

import (
	"bytes"
	"crypto"
	hmac "crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	sha256 "crypto/sha256"
	tls "crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	ioutil "io/ioutil"
	http "net/http"
	"os"
	"sort"
	"strconv"
	"sync"
	"time"

	"github.com/iancoleman/orderedmap"
)

type Client struct {
	modifyLock sync.RWMutex
	addr       string
	apikey     string
	appid      string
}

// For production environment, the web server should request a formally issued
// certificate, and change the below skipVerify to False.
const skipVerify = true

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

func (c *Client) doPost(resquest *orderedmap.OrderedMap, action string) (map[string]interface{}, error) {
	// create an insecure Transport
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: skipVerify},
	}

	// create an insecure Client
	client := &http.Client{Transport: tr}

	requestBody, err := json.Marshal(resquest)
	if err != nil {
		return nil, err
	}

	// call ehsm kms
	resp, err := client.Post(c.addr+"/ehsm?Action="+action, "application/json", bytes.NewBuffer(requestBody))
	if err != nil {
		return nil, err
	}

	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var respJSON map[string]interface{}

	err = json.Unmarshal(body, &respJSON)
	if err != nil {
		return nil, err
	}

	if respJSON["code"].(float64) != 200 {
		return nil, fmt.Errorf(respJSON["message"].(string))
	}

	return respJSON, nil
}

func isBase64(s string) bool {
	_, err := base64.StdEncoding.DecodeString(s)
	return err == nil
}

func (c *Client) initParams(payload *orderedmap.OrderedMap) *orderedmap.OrderedMap {
	params := orderedmap.New()
	params.Set("appid", c.appid)
	params.Set("payload", payload)
	params.Set("timestamp", strconv.FormatInt(time.Now().UnixNano()/int64(time.Millisecond), 10))

	signString := paramsSortStr(params)
	hmacSha256 := hmac.New(sha256.New, []byte(c.apikey))
	hmacSha256.Write([]byte(signString))
	sign := base64.StdEncoding.EncodeToString(hmacSha256.Sum(nil))

	params.Set("sign", sign)
	return params
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

func generateRandomKey(keyspec string) ([]byte, error) {
	switch keyspec {
	case "EH_AES_GCM_128", "EH_SM4_CBC", "EH_SM4_CTR":
		key := make([]byte, 16)
		return key, nil
	case "EH_AES_GCM_192":
		key := make([]byte, 24)
		return key, nil
	case "EH_AES_GCM_256":
		key := make([]byte, 32)
		return key, nil
	default:
		return nil, fmt.Errorf("Invalid keyspec")
	}
}

func rsaEncrypt(pubkey crypto.PublicKey, key []byte, padding_mode string) ([]byte, error) {
	if padding_mode == "EH_RSA_PKCS1" {
		key_material, err := rsa.EncryptPKCS1v15(rand.Reader, pubkey.(*rsa.PublicKey), []byte(key))
		if err != nil {
			return nil, fmt.Errorf("EncryptPKCS1v15 failed.")
		}
		return key_material, nil
	} else if padding_mode == "EH_RSA_PKCS1_OAEP" {
		key_material, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, pubkey.(*rsa.PublicKey), []byte(key), nil)
		if err != nil {
			return nil, fmt.Errorf("EncryptOAEP failed.")
		}
		return key_material, nil
	}
	return nil, fmt.Errorf("The padding mode is not supported.")
}
