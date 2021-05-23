package dstore

import (
	"github.com/google/go-cmp/cmp"
	"github.com/pkg/errors"
)

func compare(op string, v1 interface{}, v2 interface{}) (bool, error) {
	switch op {
	case "==":
		return cmp.Equal(v1, v2), nil
	// case ">":
	// 	switch v := v1.(type) {
	// 	case string:
	// 		s2, ok := v2.(string)
	// 		if !ok {
	// 			return false, errors.Errorf("invalid compare type")
	// 		}
	// 		return v > s2, nil
	// 	case time.Time:
	// 		t2, ok := v2.(time.Time)
	// 		if !ok {
	// 			return false, errors.Errorf("invalid compare type")
	// 		}
	// 		return v.After(t2), nil
	// 	default:
	// 		return false, errors.Errorf("unsupported compare type: %T", v1)
	// 	}
	// case ">=":
	// 	switch v := v1.(type) {
	// 	case string:
	// 		s2, ok := v2.(string)
	// 		if !ok {
	// 			return false, errors.Errorf("invalid compare type")
	// 		}
	// 		return v >= s2, nil
	// 	case time.Time:
	// 		t2, ok := v2.(time.Time)
	// 		if !ok {
	// 			return false, errors.Errorf("invalid compare type")
	// 		}
	// 		return v.Equal(t2) || v.After(t2), nil
	// 	default:
	// 		return false, errors.Errorf("unsupported compare type: %T", v1)
	// 	}
	default:
		return false, errors.Errorf("unsupported op")
	}

}
