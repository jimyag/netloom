package ovnnb

import (
	"encoding/json"

	"github.com/ovn-kubernetes/libovsdb/ovsdb"
)

func DatabaseSchema() (ovsdb.DatabaseSchema, error) {
	var out ovsdb.DatabaseSchema
	if err := json.Unmarshal([]byte(schema), &out); err != nil {
		return ovsdb.DatabaseSchema{}, err
	}
	return out, nil
}
