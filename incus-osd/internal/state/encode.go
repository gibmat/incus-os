package state

import (
	"bytes"
	"fmt"
	"reflect"
	"strings"
)

// Encode encodes a given state.
func Encode(s *State) ([]byte, error) {
	var b bytes.Buffer

	_, err := fmt.Fprintf(&b, "#Version: %d\n", stateVersion)
	if err != nil {
		return []byte{}, err
	}

	err = encodeHelper(&b, []string{}, reflect.ValueOf(s))
	if err != nil {
		return []byte{}, err
	}

	return b.Bytes(), nil
}

func encodeHelper(b *bytes.Buffer, keyPrefix []string, v reflect.Value) error {
	// Skip serializing any zero values.
	if v.IsZero() {
		return nil
	}

	//gracefully handle parse errors
	//add simple version header
	//test upgrade logic like migration-manager and incus schema updates

	switch v.Kind() { //nolint:exhaustive
	case reflect.Bool:
		_, err := fmt.Fprintf(b, "%s: %v\n", strings.Join(keyPrefix, "."), v.Bool())
		if err != nil {
			return err
		}
	case reflect.Float32, reflect.Float64:
		_, err := fmt.Fprintf(b, "%s: %f\n", strings.Join(keyPrefix, "."), v.Float())
		if err != nil {
			return err
		}
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		_, err := fmt.Fprintf(b, "%s: %d\n", strings.Join(keyPrefix, "."), v.Int())
		if err != nil {
			return err
		}
	case reflect.Map:
		keyBase := keyPrefix[len(keyPrefix)-1]
		iter := v.MapRange()
		for iter.Next() {
			keyPrefix[len(keyPrefix)-1] = fmt.Sprintf("%s[%s]", keyBase, iter.Key())
			err := encodeHelper(b, keyPrefix, iter.Value())
			if err != nil {
				return err
			}
		}
	case reflect.Pointer:
		if v.IsNil() {
			return nil
		}

		return encodeHelper(b, keyPrefix, v.Elem())
	case reflect.Slice:
		keyBase := keyPrefix[len(keyPrefix)-1]
		for i := range v.Len() {
			keyPrefix[len(keyPrefix)-1] = fmt.Sprintf("%s[%d]", keyBase, i)
			err := encodeHelper(b, keyPrefix, v.Index(i))
			if err != nil {
				return err
			}
		}
	case reflect.String:
		_, err := fmt.Fprintf(b, "%s: %s\n", strings.Join(keyPrefix, "."), v.String())
		if err != nil {
			return err
		}
	case reflect.Struct:
		fields := reflect.VisibleFields(v.Type())

		for _, field := range fields {
			if field.IsExported() {
				// Skip any fields that shouldn't be marshalled.
				if field.Tag.Get("json") == "-" || field.Tag.Get("incusos") == "-" {
					continue
				}

				err := encodeHelper(b, append(keyPrefix, field.Name), v.FieldByIndex(field.Index))
				if err != nil {
					return err
				}
			}
		}
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		_, err := fmt.Fprintf(b, "%s: %d\n", strings.Join(keyPrefix, "."), v.Uint())
		if err != nil {
			return err
		}
	default:
		return fmt.Errorf("%s: unhandled kind '%s'", strings.Join(keyPrefix, "."), v.Kind())
	}

	return nil
}
