package state

import (
	"fmt"
	"reflect"
	"strconv"
	"strings"
)

// Decode reconstitutes a given state.
func Decode(b []byte) (*State, error) {
	ret := new(State)

	lines := strings.Split(string(b), "\n")

	// Check if we need to run any update logic.
	if strings.HasPrefix(lines[0], "#Version: ") {

	}

	// Parse each line.
	for _, line := range lines {
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		parts := strings.SplitN(line, ": ", 2)
		if len(parts) != 2 {
			return ret, fmt.Errorf("malformed line '%s'", line)
		}

		err := decodeHelper(reflect.ValueOf(ret), strings.Split(parts[0], "."), parts[1])
		if err != nil {
			return ret, err
		}
	}

	return ret, nil
}

func decodeHelper(v reflect.Value, keys []string, value string) error {
	// Walk the state struct to the appropriate location.
	for keyIndex, key := range keys {
		if reflect.Indirect(v).Kind() != reflect.Struct {
			return fmt.Errorf("unsupported kind '%s'", reflect.Indirect(v).Kind())
		}

		parts := strings.Split(key, "[")
		if len(parts) == 2 {
			parts[1] = strings.TrimSuffix(parts[1], "]")
		}

		field := reflect.Indirect(v).FieldByName(parts[0])

		if !field.IsValid() {
			return fmt.Errorf("invalid field '%s' for struct '%s'", key, v.Type())
		}

		switch field.Kind() { //nolint:exhaustive
		case reflect.Map:
			if field.IsNil() {
				field.Set(reflect.MakeMap(field.Type()))
			}

			mapField := field.MapIndex(reflect.ValueOf(parts[1]))
			if !mapField.IsValid() {
				mapField = reflect.New(field.Type().Elem()).Elem()
			} else {
				newMapField := reflect.New(field.Type().Elem()).Elem()
				newMapField.Set(mapField)
				mapField = newMapField
			}

			err := decodeHelper(mapField, keys[keyIndex+1:], value)
			if err != nil {
				return err
			}

			field.SetMapIndex(reflect.ValueOf(parts[1]), mapField)

			return nil
		case reflect.Pointer:
			if field.IsNil() {
				field.Set(reflect.New(field.Type().Elem()))
			}
		case reflect.Slice:
			index, err := strconv.Atoi(parts[1])
			if err != nil {
				return err
			}

			if field.IsNil() {
				field.Set(reflect.MakeSlice(field.Type(), 0, 0))
			}

			for field.Len() <= index {
				t := field.Type().Elem()
				field.Set(reflect.Append(field, reflect.Zero(t)))
			}

			field = field.Index(index)
		}

		v = field
	}

	return setValue(v, value)
}

func setValue(v reflect.Value, value string) error {
	// Set the value
	switch v.Kind() { //nolint:exhaustive
	case reflect.Bool:
		bVal, err := strconv.ParseBool(value)
		if err != nil {
			return err
		}
		v.SetBool(bVal)
	case reflect.Float32:
		fVal, err := strconv.ParseFloat(value, 32)
		if err != nil {
			return err
		}
		v.SetFloat(fVal)
	case reflect.Float64:
		fVal, err := strconv.ParseFloat(value, 64)
		if err != nil {
			return err
		}
		v.SetFloat(fVal)
	case reflect.Int:
		iVal, err := strconv.ParseInt(value, 10, 64)
		if err != nil {
			return err
		}
		v.SetInt(iVal)
	case reflect.Int8:
		iVal, err := strconv.ParseInt(value, 10, 8)
		if err != nil {
			return err
		}
		v.SetInt(iVal)
	case reflect.Int16:
		iVal, err := strconv.ParseInt(value, 10, 16)
		if err != nil {
			return err
		}
		v.SetInt(iVal)
	case reflect.Int32:
		iVal, err := strconv.ParseInt(value, 10, 32)
		if err != nil {
			return err
		}
		v.SetInt(iVal)
	case reflect.Int64:
		iVal, err := strconv.ParseInt(value, 10, 64)
		if err != nil {
			return err
		}
		v.SetInt(iVal)
	case reflect.String:
		v.SetString(value)
	case reflect.Uint:
		uVal, err := strconv.ParseUint(value, 10, 64)
		if err != nil {
			return err
		}
		v.SetUint(uVal)
	case reflect.Uint8:
		uVal, err := strconv.ParseUint(value, 10, 8)
		if err != nil {
			return err
		}
		v.SetUint(uVal)
	case reflect.Uint16:
		uVal, err := strconv.ParseUint(value, 10, 16)
		if err != nil {
			return err
		}
		v.SetUint(uVal)
	case reflect.Uint32:
		uVal, err := strconv.ParseUint(value, 10, 32)
		if err != nil {
			return err
		}
		v.SetUint(uVal)
	case reflect.Uint64:
		uVal, err := strconv.ParseUint(value, 10, 64)
		if err != nil {
			return err
		}
		v.SetUint(uVal)
	default:
		return fmt.Errorf("unhandled kind '%s'", v.Kind())
	}

	return nil
}
