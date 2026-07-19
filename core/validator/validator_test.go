package validator

import "testing"

func TestPasswordValidation(t *testing.T) {
	type s struct {
		Password string `validate:"passwordPattern"`
	}

	tests := []struct {
		name    string
		value   string
		wantErr bool
	}{
		{"valid — mixed chars", "1qazXSW@", false},
		{"valid — min length 8", "Abcd1234", false},
		{"valid — max length 64", "Abcd1234Abcd1234Abcd1234Abcd1234Abcd1234Abcd1234Abcd1234Abcd1234", false},
		{"too short — 7 chars", "Abc123!", true},
		{"too long — 65 chars", "Abcd1234Abcd1234Abcd1234Abcd1234Abcd1234Abcd1234Abcd1234Abcd12345", true},
		{"invalid char — space", "Abcd 123", true},
		{"invalid char — unicode", "Abcd123ก", true},
		{"empty", "", true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateStruct(&s{tc.value})
			if (err != nil) != tc.wantErr {
				t.Errorf("wantErr=%v, got err=%v", tc.wantErr, err)
			}
		})
	}
}

func TestHasWordValidation(t *testing.T) {
	type twoWords struct {
		Scope string `validate:"has_word=openid email"`
	}
	type oneWord struct {
		Scope string `validate:"has_word=openid"`
	}

	tests := []struct {
		name    string
		value   string
		obj     any
		wantErr bool
	}{
		{"all required words present", "openid email profile", &twoWords{"openid email profile"}, false},
		{"exact match", "openid email", &twoWords{"openid email"}, false},
		{"missing one word", "openid profile", &twoWords{"openid profile"}, true},
		{"missing all words", "profile phone", &twoWords{"profile phone"}, true},
		{"empty field", "", &twoWords{""}, true},
		{"single param — word present", "openid profile", &oneWord{"openid profile"}, false},
		{"single param — word absent", "profile phone", &oneWord{"profile phone"}, true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateStruct(tc.obj)
			if (err != nil) != tc.wantErr {
				t.Errorf("wantErr=%v, got err=%v", tc.wantErr, err)
			}
		})
	}
}

func TestHasAnyWordValidation(t *testing.T) {
	type s struct {
		Scope string `validate:"has_any_word=openid email"`
	}

	tests := []struct {
		name    string
		value   string
		wantErr bool
	}{
		{"first word present", "openid profile", false},
		{"second word present", "email profile", false},
		{"both words present", "openid email profile", false},
		{"no words present", "profile phone", true},
		{"empty field", "", true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateStruct(&s{tc.value})
			if (err != nil) != tc.wantErr {
				t.Errorf("wantErr=%v, got err=%v", tc.wantErr, err)
			}
		})
	}
}
