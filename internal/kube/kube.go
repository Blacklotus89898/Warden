// Package kube is Warden's only door to the Kubernetes API (Homelab ADR 0011
// §1–2): GET requests on a fixed catalogue of paths. Even if the ServiceAccount
// were ever over-granted, this client cannot read a Secret or a ConfigMap,
// exec into a pod, or write anything — the allowlist is checked before any
// request leaves the process, and tools_test pins it.
package kube

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"
)

const name = `[a-z0-9]([-a-z0-9.]*[a-z0-9])?`

// Catalogue is every API path Warden may GET. Nothing else.
var Catalogue = []*regexp.Regexp{
	regexp.MustCompile(`^/api/v1/namespaces/` + name + `/pods$`),
	regexp.MustCompile(`^/api/v1/namespaces/` + name + `/pods/` + name + `/log$`),
	regexp.MustCompile(`^/api/v1/namespaces/` + name + `/events$`),
	regexp.MustCompile(`^/api/v1/nodes$`),
	regexp.MustCompile(`^/apis/argoproj\.io/v1alpha1/namespaces/argocd/applications$`),
}

// ErrNotInCatalogue refuses any path outside Catalogue.
var ErrNotInCatalogue = errors.New("kube: path not in Warden's read-only catalogue")

// Allowed reports whether path (without query) is in the catalogue.
func Allowed(path string) bool {
	for _, re := range Catalogue {
		if re.MatchString(path) {
			return true
		}
	}
	return false
}

// Client talks to the API server with the pod's ServiceAccount token.
type Client struct {
	Base  string // https://kubernetes.default.svc
	Token string
	HTTP  *http.Client
}

const saDir = "/var/run/secrets/kubernetes.io/serviceaccount"

// InCluster builds a client from the mounted ServiceAccount.
func InCluster() (*Client, error) {
	tok, err := os.ReadFile(saDir + "/token")
	if err != nil {
		return nil, err
	}
	ca, err := os.ReadFile(saDir + "/ca.crt")
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(ca) {
		return nil, errors.New("kube: bad CA bundle")
	}
	host, port := os.Getenv("KUBERNETES_SERVICE_HOST"), os.Getenv("KUBERNETES_SERVICE_PORT")
	if host == "" {
		return nil, errors.New("kube: not in a cluster")
	}
	return &Client{
		Base:  "https://" + host + ":" + port,
		Token: strings.TrimSpace(string(tok)),
		HTTP: &http.Client{Timeout: 15 * time.Second, Transport: &http.Transport{
			TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12},
		}},
	}, nil
}

// Get fetches a catalogue path; q may be nil.
func (c *Client) Get(ctx context.Context, path string, q url.Values) ([]byte, error) {
	if !Allowed(path) {
		return nil, fmt.Errorf("%w: %s", ErrNotInCatalogue, path)
	}
	u := c.Base + path
	if len(q) > 0 {
		u += "?" + q.Encode()
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	if c.Token != "" {
		req.Header.Set("Authorization", "Bearer "+c.Token)
	}
	hc := c.HTTP
	if hc == nil {
		hc = &http.Client{Timeout: 15 * time.Second}
	}
	resp, err := hc.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("kube: GET %s: HTTP %d: %s", path, resp.StatusCode, strings.TrimSpace(string(body[:min(len(body), 200)])))
	}
	return body, nil
}

// GetJSON fetches and decodes.
func (c *Client) GetJSON(ctx context.Context, path string, q url.Values, out any) error {
	b, err := c.Get(ctx, path, q)
	if err != nil {
		return err
	}
	return json.Unmarshal(b, out)
}

// ---- the few shapes Warden reads ----

// ContainerState is one of waiting/running/terminated.
type ContainerState struct {
	Waiting *struct {
		Reason  string `json:"reason"`
		Message string `json:"message"`
	} `json:"waiting,omitempty"`
	Running *struct {
		StartedAt time.Time `json:"startedAt"`
	} `json:"running,omitempty"`
	Terminated *struct {
		Reason     string    `json:"reason"`
		ExitCode   int       `json:"exitCode"`
		FinishedAt time.Time `json:"finishedAt"`
	} `json:"terminated,omitempty"`
}

// Pod is the subset of a Pod Warden uses.
type Pod struct {
	Metadata struct {
		Name      string            `json:"name"`
		Namespace string            `json:"namespace"`
		Labels    map[string]string `json:"labels"`
	} `json:"metadata"`
	Spec struct {
		NodeName string `json:"nodeName"`
	} `json:"spec"`
	Status struct {
		Phase      string `json:"phase"`
		Reason     string `json:"reason"`
		Conditions []struct {
			Type   string `json:"type"`
			Status string `json:"status"`
		} `json:"conditions"`
		ContainerStatuses []struct {
			Name         string         `json:"name"`
			Ready        bool           `json:"ready"`
			RestartCount int            `json:"restartCount"`
			State        ContainerState `json:"state"`
			LastState    ContainerState `json:"lastState"`
		} `json:"containerStatuses"`
	} `json:"status"`
}

// Event is the subset of a core/v1 Event Warden uses.
type Event struct {
	Type           string `json:"type"`
	Reason         string `json:"reason"`
	Message        string `json:"message"`
	Count          int    `json:"count"`
	InvolvedObject struct {
		Kind string `json:"kind"`
		Name string `json:"name"`
	} `json:"involvedObject"`
	LastTimestamp time.Time `json:"lastTimestamp"`
	EventTime     time.Time `json:"eventTime"`
}

// Node is the subset of a Node Warden uses.
type Node struct {
	Metadata struct {
		Name string `json:"name"`
	} `json:"metadata"`
	Spec struct {
		Unschedulable bool `json:"unschedulable"`
	} `json:"spec"`
	Status struct {
		Conditions []struct {
			Type    string `json:"type"`
			Status  string `json:"status"`
			Message string `json:"message"`
		} `json:"conditions"`
	} `json:"status"`
}

// Application is the subset of an ArgoCD Application Warden uses.
type Application struct {
	Metadata struct {
		Name string `json:"name"`
	} `json:"metadata"`
	Spec struct {
		Destination struct {
			Namespace string `json:"namespace"`
		} `json:"destination"`
	} `json:"spec"`
	Status struct {
		Sync struct {
			Status   string `json:"status"`
			Revision string `json:"revision"`
		} `json:"sync"`
		Health struct {
			Status  string `json:"status"`
			Message string `json:"message"`
		} `json:"health"`
		Conditions []struct {
			Type    string `json:"type"`
			Message string `json:"message"`
		} `json:"conditions"`
		OperationState *struct {
			Phase   string `json:"phase"`
			Message string `json:"message"`
		} `json:"operationState,omitempty"`
	} `json:"status"`
}

// List wraps the items of a list response.
type List[T any] struct {
	Items []T `json:"items"`
}
