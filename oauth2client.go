// Package example (an authclient plugin).
package oauth2client

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"

	"net/url"
	"strings"
	"time"

	"github.com/gomodule/redigo/redis"
	"github.com/pochard/commons/randstr"
)

var pool *redis.Pool

//当启动程序时，就初始化连接池
func init() {
	pool = &redis.Pool{
		MaxIdle:     8,   //最大空闲连接数
		MaxActive:   0,   //表示和数据库的最大连接数，0表示没有限制
		IdleTimeout: 100, //最大空闲时间
		Dial: func() (redis.Conn, error) { //初始化连接，连接到哪个ip的redis数据库
			return redis.Dial("tcp", "localhost:6379")
		},
	}

}

// Config the plugin configuration.
type Config struct {

	// ...
	AuthURL      string `json:"authURL,omitempty"`
	ClientID     string `json:"clientID,omitempty"`
	UserInfo     string `json:"userinfo,omitempty"`
	ResponseType string `json:"responsetype,omitempty"`
	RedirectURL  string `json:"redirectURL,omitempty"`
}

// CreateConfig creates the default plugin configuration.
//创建默认的参数配置
func CreateConfig() *Config {
	return &Config{}
}

// Example a plugin.
//插件的结构体
type OauthClient struct {
	next        http.Handler
	name        string
	redirectURL string

	authURL      string
	responseType string
	clientID     string
	userinfor    string

	// ...
}

// New created a new plugin.

func New(ctx context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {

	return &OauthClient{
		// ...
		next: next,
		name: name,

		authURL:      config.AuthURL,
		redirectURL:  config.RedirectURL,
		responseType: config.ResponseType,
		clientID:     config.ClientID,

		userinfor: config.UserInfo,
	}, nil
}

//存储state-request

func (oc *OauthClient) storeStateAndRequest(state string, req *http.Request) {
	con := pool.Get()
	defer con.Close()
	rec, err := con.Do("Set", state, req)
	if err != nil {
		//
	}
	fmt.Println(req)

}

func (oc *OauthClient) auth(rw http.ResponseWriter, req *http.Request) int {

	authorization := "no"

	for header, value := range req.Header {
		if header == "Authorization" {
			authorization = value[0]
		}
	}
	if authorization == "no" {
		return 0
	}
	kv := strings.Split(authorization, " ")
	if len(kv) != 2 || kv[0] != "Bearer" {
		return 0
	}
	claims := get(oc.userinfor, authorization)
	if claims == "error" {
		return 0
	}

	m := make(map[string]string)
	err := json.Unmarshal([]byte(claims), &m)
	if err != nil {
		return 0

	}
	for k, v := range m {
		if k == "sub" {
			req.Header.Set("gridname", v)
			return 1
		}
	}

	//收到一个请求，有authorization，请求userinfo，收到sub并且写入头中，返回1
	//有Authorization 和sub，并且和userinfo核对后正常，返回1
	//其余情况返回0

}

//具体的http服务
func (oc *OauthClient) ServeHTTP(rw http.ResponseWriter, req *http.Request) {

	ok := oc.auth(rw, req)
	if ok {
		oc.next.ServeHTTP(rw, req)
	} else {
		state := randstr.RandomAlphanumeric(24)
		oc.storeStateAndRequest(state, req)
		escapeUrl := url.QueryEscape(oc.redirectURL)
		loginURL := oc.authURL + "?response_type=" + oc.responseType + "&client_id=" + oc.clientID + "&scope=openid&state=" + oc.state + "&redirect_uri=" + escapeUrl
		http.Redirect(rw, req, loginURL, http.StatusTemporaryRedirect)
	}

}

// 发送GET请求
// url：         请求地址
// response：    请求返回的内容
func get(url string, token string) string {

	// 超时时间：5秒

	client := &http.Client{Timeout: 5 * time.Second}

	request, err := http.NewRequest("GET", url, nil)

	request.Header.Add("Authorization", token)

	resp, err := client.Do(request)

	if err != nil {
		fmt.Println("error:userinfo!!!")
		return "error"
	}
	defer resp.Body.Close()
	var buffer [512]byte
	result := bytes.NewBuffer(nil)
	for {
		n, err := resp.Body.Read(buffer[0:])
		result.Write(buffer[0:n])
		if err != nil && err == io.EOF {
			break
		} else if err != nil {
			panic(err)
		}
	}

	return result.String()
}
