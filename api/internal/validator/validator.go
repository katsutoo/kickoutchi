package validator

import validatorv10 "github.com/go-playground/validator/v10"

type Validator struct {
	validate *validatorv10.Validate
}

func New() *Validator {
	return &Validator{validate: validatorv10.New()}
}

func (v *Validator) Struct(value any) error {
	return v.validate.Struct(value)
}
