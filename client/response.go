package client

import (
	"encoding/json"
	"io/ioutil"
	"net/http"
)

type Response struct {
	*http.Response
}

// DecodeJSON will decode the response body to a JSON structure. This
// will consume the response body, but will not close it. Close must
// still be called.
func (r *Response) DecodeJSON(out interface{}) error {
	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return err
	}

	if err := json.Unmarshal(body, &out); err != nil {
		return err
	}

	return nil
}
