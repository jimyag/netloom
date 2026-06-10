package ovn_test

import "encoding/base64"

func endpointExternalID(vpc, endpoint string) string {
	return base64.RawURLEncoding.EncodeToString([]byte(vpc + "\x00" + endpoint))
}
