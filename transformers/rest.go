package transformers

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"time"

	"github.com/dmachard/go-dnscollector/dnsutils"
	"github.com/dmachard/go-dnscollector/pkgconfig"
	"github.com/dmachard/go-logger"
)

type RestTransform struct {
	GenericTransformer
	httpclient *http.Client
}

func NewRestTransform(config *pkgconfig.ConfigTransformers, logger *logger.Logger, name string, instance int, nextWorkers []chan dnsutils.DNSMessage) *RestTransform {
	t := &RestTransform{GenericTransformer: NewTransformer(config, logger, "rest", name, instance, nextWorkers)}
	return t
}

func (t *RestTransform) GetTransforms() ([]Subtransform, error) {
	subtransforms := []Subtransform{}
	if t.config.Rest.Enable {
		t.Setup()
		subtransforms = append(subtransforms, Subtransform{name: "rest:request", processFunc: t.Request})
	}
	return subtransforms, nil
}

func (t *RestTransform) Setup() {
	tr := &http.Transport{
		MaxIdleConns:        10,
		MaxIdleConnsPerHost: 10,
		IdleConnTimeout:     30 * time.Second,
	}

	t.httpclient = &http.Client{
		Timeout:   time.Duration(t.config.Rest.Timeout) * time.Second,
		Transport: tr,
	}
}

func (t *RestTransform) Request(dm *dnsutils.DNSMessage) (int, error) {
	if dm.Rest == nil {
		dm.Rest = &dnsutils.TransformRest{Failed: true, Response: ""}
	}

	payload, err := json.Marshal(dm)
	if err != nil {
		t.LogError("JSON marshal failed: %s", err)
		return ReturnKeep, nil
	}

	post, err := http.NewRequest("POST", t.config.Rest.URL, bytes.NewBuffer(payload))
	if err != nil {
		t.LogError("HTTP error: %s", err)
		return ReturnKeep, nil
	}

	post.Header.Set("Content-Type", "application/json")

	if t.config.Rest.BasicAuthEnabled {
		post.SetBasicAuth(t.config.Rest.BasicAuthLogin, t.config.Rest.BasicAuthPwd)
	}

	resp, err := t.httpclient.Do(post)
	if err != nil {
		t.LogError("HTTP request failed: %s", err)
		return ReturnKeep, nil
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.LogError("invalid HTTP status code: %d", resp.StatusCode)
		return ReturnKeep, nil
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.LogError("HTTP body read failed: %s", err)
		return ReturnKeep, nil
	}

	dm.Rest.Failed = false
	dm.Rest.Response = string(body)

	return ReturnKeep, nil
}
