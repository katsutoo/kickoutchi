package validator

import (
	"reflect"
	"strings"

	validatorv10 "github.com/go-playground/validator/v10"
)

type Validator struct {
	validate *validatorv10.Validate
}

func New() *Validator {
	validate := validatorv10.New()
	validate.RegisterTagNameFunc(func(field reflect.StructField) string {
		tag := field.Tag.Get("json")
		if tag == "" {
			return field.Name
		}

		name, _, _ := strings.Cut(tag, ",")
		if name == "" || name == "-" {
			return field.Name
		}

		return name
	})

	return &Validator{validate: validate}
}

func (v *Validator) Struct(value any) error {
	return v.validate.Struct(value)
}
