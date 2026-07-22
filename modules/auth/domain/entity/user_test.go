package entity

import (
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"
)

func TestUserAccountLockout(t *testing.T) {
	newUser := func(t *testing.T) *User {
		t.Helper()
		u, err := NewUser(UserArgs{Username: "u", Nickname: "n", Password: "Password1!", Email: "u@example.com"})
		if err != nil {
			t.Fatalf("NewUser: %v", err)
		}
		return u
	}

	t.Run("below threshold — not locked", func(t *testing.T) {
		u := newUser(t)
		for i := 0; i < MaxFailedLoginAttempts-1; i++ {
			u.RecordFailedLogin()
		}
		if u.IsLockedOut() || u.LockedUntil != nil {
			t.Errorf("must not lock below threshold, attempts=%d locked=%v", u.FailedLoginAttempts, u.LockedUntil)
		}
	})

	t.Run("at threshold — locked for the base duration", func(t *testing.T) {
		u := newUser(t)
		for i := 0; i < MaxFailedLoginAttempts; i++ {
			u.RecordFailedLogin()
		}
		if !u.IsLockedOut() {
			t.Fatal("must be locked at threshold")
		}
		d := time.Until(*u.LockedUntil)
		if d <= 0 || d > lockoutBaseDuration {
			t.Errorf("lockout duration = %v, want ≈%v", d, lockoutBaseDuration)
		}
	})

	t.Run("backoff doubles and is capped", func(t *testing.T) {
		tests := []struct {
			over int
			want time.Duration
		}{
			{over: 0, want: 1 * time.Minute},
			{over: 1, want: 2 * time.Minute},
			{over: 3, want: 8 * time.Minute},
			{over: 6, want: lockoutMaxDuration},
			{over: 50, want: lockoutMaxDuration},
		}
		for _, tc := range tests {
			if got := lockoutDuration(tc.over); got != tc.want {
				t.Errorf("lockoutDuration(%d) = %v, want %v", tc.over, got, tc.want)
			}
		}
	})

	t.Run("expired lock — no longer locked out", func(t *testing.T) {
		u := newUser(t)
		u.FailedLoginAttempts = MaxFailedLoginAttempts
		u.LockedUntil = new(time.Now().Add(-time.Second))
		if u.IsLockedOut() {
			t.Error("expired lock must not count as locked out")
		}
	})

	t.Run("reset clears attempts and lock", func(t *testing.T) {
		u := newUser(t)
		for i := 0; i < MaxFailedLoginAttempts+2; i++ {
			u.RecordFailedLogin()
		}
		u.ResetFailedLogins()
		if u.FailedLoginAttempts != 0 || u.LockedUntil != nil {
			t.Errorf("reset must clear state, got attempts=%d locked=%v", u.FailedLoginAttempts, u.LockedUntil)
		}
	})
}

func TestPasswordHashCost(t *testing.T) {
	const correctPassword = "Password1!"

	t.Run("NewUser hashes with passwordHashCost", func(t *testing.T) {
		u, err := NewUser(UserArgs{Username: "u", Nickname: "n", Password: correctPassword, Email: "u@example.com"})
		if err != nil {
			t.Fatalf("NewUser: %v", err)
		}
		cost, err := bcrypt.Cost([]byte(u.Password))
		if err != nil {
			t.Fatalf("bcrypt.Cost: %v", err)
		}
		if cost != passwordHashCost {
			t.Errorf("hash cost = %d, want %d", cost, passwordHashCost)
		}
	})

	t.Run("cost-10 hash — rehash returns true and new cost is 12", func(t *testing.T) {
		hash, err := bcrypt.GenerateFromPassword([]byte(correctPassword), 10)
		if err != nil {
			t.Fatalf("GenerateFromPassword: %v", err)
		}
		u := &User{Password: string(hash)}
		if !u.RehashPasswordIfNeeded(correctPassword) {
			t.Fatal("RehashPasswordIfNeeded should return true for cost-10 hash")
		}
		cost, err := bcrypt.Cost([]byte(u.Password))
		if err != nil {
			t.Fatalf("bcrypt.Cost after rehash: %v", err)
		}
		if cost != passwordHashCost {
			t.Errorf("rehashed cost = %d, want %d", cost, passwordHashCost)
		}
		if err := u.ValidatePassword(correctPassword); err != nil {
			t.Errorf("ValidatePassword after rehash: %v", err)
		}
	})

	t.Run("hash already at cost 12 — returns false, Password unchanged", func(t *testing.T) {
		hash, err := bcrypt.GenerateFromPassword([]byte(correctPassword), 12)
		if err != nil {
			t.Fatalf("GenerateFromPassword: %v", err)
		}
		u := &User{Password: string(hash)}
		original := u.Password
		if u.RehashPasswordIfNeeded(correctPassword) {
			t.Fatal("RehashPasswordIfNeeded should return false for already cost-12 hash")
		}
		if u.Password != original {
			t.Error("Password should be unchanged when already at target cost")
		}
	})

	t.Run("invalid hash — returns false, Password unchanged", func(t *testing.T) {
		u := &User{Password: "not-a-valid-bcrypt-hash"}
		original := u.Password
		if u.RehashPasswordIfNeeded(correctPassword) {
			t.Fatal("RehashPasswordIfNeeded should return false for invalid hash")
		}
		if u.Password != original {
			t.Error("Password should be unchanged for invalid hash")
		}
	})
}
