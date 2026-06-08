package binding

import (
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

func init() {
	gin.SetMode(gin.TestMode)
}

// ── helpers ───────────────────────────────────────────────────────────────────

func newCtx(method, target, body, contentType string) *gin.Context {
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	var req *http.Request
	if body != "" {
		req = httptest.NewRequest(method, target, strings.NewReader(body))
	} else {
		req = httptest.NewRequest(method, target, nil)
	}
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	c.Request = req
	return c
}

// ── Bind ──────────────────────────────────────────────────────────────────────

func TestBind_QueryParams(t *testing.T) {
	type Q struct {
		Name string `form:"name"`
		Age  int    `form:"age"`
	}
	c := newCtx(http.MethodGet, "/?name=alice&age=30", "", "")
	var q Q
	if err := Bind(c, &q); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if q.Name != "alice" || q.Age != 30 {
		t.Errorf("got %+v, want {alice 30}", q)
	}
}

func TestBind_JSONBody(t *testing.T) {
	type B struct {
		Name string `json:"name"`
		Age  int    `json:"age"`
	}
	c := newCtx(http.MethodPost, "/", `{"name":"bob","age":25}`, "application/json")
	var b B
	if err := Bind(c, &b); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if b.Name != "bob" || b.Age != 25 {
		t.Errorf("got %+v, want {bob 25}", b)
	}
}

func TestBind_FormBody(t *testing.T) {
	type F struct {
		Username string `form:"username"`
	}
	c := newCtx(http.MethodPost, "/", "username=charlie", "application/x-www-form-urlencoded")
	var f F
	if err := Bind(c, &f); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if f.Username != "charlie" {
		t.Errorf("got %q, want charlie", f.Username)
	}
}

func TestBind_HeaderField(t *testing.T) {
	type H struct {
		Token string `header:"X-Token"`
	}
	c := newCtx(http.MethodGet, "/", "", "")
	c.Request.Header.Set("X-Token", "secret")
	var h H
	if err := Bind(c, &h); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if h.Token != "secret" {
		t.Errorf("got %q, want secret", h.Token)
	}
}

func TestBind_EmptyBody_NoError(t *testing.T) {
	type E struct{ Name string }
	c := newCtx(http.MethodPost, "/", "", "application/json")
	var e E
	if err := Bind(c, &e); err != nil {
		t.Fatalf("empty body should not error, got: %v", err)
	}
}

func TestBind_CtxTag(t *testing.T) {
	type C struct {
		UserID string `ctx:"user_id"`
	}
	c := newCtx(http.MethodGet, "/", "", "")
	c.Set("user_id", "u-123")
	var out C
	if err := Bind(c, &out); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if out.UserID != "u-123" {
		t.Errorf("got %q, want u-123", out.UserID)
	}
}

func TestBind_CtxTag_Missing(t *testing.T) {
	type C struct {
		UserID string `ctx:"user_id"`
	}
	c := newCtx(http.MethodGet, "/", "", "")
	var out C
	if err := Bind(c, &out); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if out.UserID != "" {
		t.Errorf("expected empty string, got %q", out.UserID)
	}
}

func TestBind_CookieTag(t *testing.T) {
	type C struct {
		Token string `cookie:"refresh_token"`
	}
	c := newCtx(http.MethodGet, "/", "", "")
	c.Request.AddCookie(&http.Cookie{Name: "refresh_token", Value: "cookie-value"})
	var out C
	if err := Bind(c, &out); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if out.Token != "cookie-value" {
		t.Errorf("got %q, want cookie-value", out.Token)
	}
}

func TestBind_CookieTag_Missing(t *testing.T) {
	type C struct {
		Token string `cookie:"refresh_token"`
	}
	c := newCtx(http.MethodGet, "/", "", "")
	var out C
	if err := Bind(c, &out); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if out.Token != "" {
		t.Errorf("expected empty string when cookie absent, got %q", out.Token)
	}
}

func TestBind_FileTag(t *testing.T) {
	type F struct {
		Upload *multipart.FileHeader `file:"upload"`
	}
	// Without a real multipart upload, the file field stays nil — not an error.
	// Use a valid boundary so Gin can parse the (empty) multipart body.
	c := newCtx(http.MethodPost, "/", "--boundary--\r\n", "multipart/form-data; boundary=boundary")
	var f F
	if err := Bind(c, &f); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if f.Upload != nil {
		t.Error("expected nil file header when no file uploaded")
	}
}

// ── normalize:"uri" tag ───────────────────────────────────────────────────────

func TestBind_NormalizeURI(t *testing.T) {
	type Q struct {
		RedirectURI string `form:"redirect_uri" normalize:"uri"`
	}
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{"already canonical", "https://app.example.com/callback", "https://app.example.com/callback"},
		{"uppercase scheme is lowercased", "HTTPS://app.example.com/callback", "https://app.example.com/callback"},
		{"fragment preserved for validator to reject", "https://app.example.com/callback#frag", "https://app.example.com/callback#frag"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			c := newCtx(http.MethodGet, "/?redirect_uri="+tc.input, "", "")
			var q Q
			if err := Bind(c, &q); err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if q.RedirectURI != tc.want {
				t.Errorf("got %q, want %q", q.RedirectURI, tc.want)
			}
		})
	}
}

func TestBind_NormalizeURI_EmptyFieldUnchanged(t *testing.T) {
	type Q struct {
		RedirectURI string `form:"redirect_uri" normalize:"uri"`
	}
	c := newCtx(http.MethodGet, "/", "", "")
	var q Q
	if err := Bind(c, &q); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if q.RedirectURI != "" {
		t.Errorf("empty field should stay empty, got %q", q.RedirectURI)
	}
}

// ── bindFromContext ───────────────────────────────────────────────────────────

func TestBindFromContext_NilPointer(t *testing.T) {
	c := newCtx(http.MethodGet, "/", "", "")
	if err := bindFromContext(c, (*struct{})(nil)); err == nil {
		t.Fatal("expected error for nil pointer, got nil")
	}
}

func TestBindFromContext_NonPointer(t *testing.T) {
	c := newCtx(http.MethodGet, "/", "", "")
	if err := bindFromContext(c, struct{}{}); err == nil {
		t.Fatal("expected error for non-pointer, got nil")
	}
}

// ── traverseFields ────────────────────────────────────────────────────────────

func TestTraverseFields_NestedStruct(t *testing.T) {
	c := newCtx(http.MethodGet, "/", "", "")
	c.Set("inner_val", "hello")

	type InnerCtx struct {
		Value string `ctx:"inner_val"`
	}
	type OuterCtx struct {
		Inner InnerCtx
	}
	var o OuterCtx
	if err := Bind(c, &o); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if o.Inner.Value != "hello" {
		t.Errorf("got %q, want hello", o.Inner.Value)
	}
}

func TestTraverseFields_Slice(t *testing.T) {
	c := newCtx(http.MethodGet, "/", "", "")
	c.Set("tag", "go")

	type Item struct {
		Tag string `ctx:"tag"`
	}
	type Req struct {
		Items []Item
	}
	r := &Req{Items: []Item{{}, {}}}
	if err := Bind(c, r); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for i, item := range r.Items {
		if item.Tag != "go" {
			t.Errorf("items[%d].Tag = %q, want go", i, item.Tag)
		}
	}
}

func TestTraverseFields_Map(t *testing.T) {
	c := newCtx(http.MethodGet, "/", "", "")
	c.Set("role", "admin")

	type Entry struct {
		Role string `ctx:"role"`
	}
	type Req struct {
		Entries map[string]Entry
	}
	r := &Req{Entries: map[string]Entry{"a": {}, "b": {}}}
	if err := Bind(c, r); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for k, e := range r.Entries {
		if e.Role != "admin" {
			t.Errorf("entries[%q].Role = %q, want admin", k, e.Role)
		}
	}
}

// ── hasTag ────────────────────────────────────────────────────────────────────

func TestHasTag(t *testing.T) {
	type S struct {
		A string `ctx:"val"`
		B string `ctx:""`
		C string `ctx:"-"`
	}
	st := reflect.TypeOf(S{})
	cases := []struct {
		field string
		want  bool
	}{
		{"A", true},
		{"B", false},
		{"C", false},
	}
	for _, tc := range cases {
		f, _ := st.FieldByName(tc.field)
		got := hasTag(f, "ctx")
		if got != tc.want {
			t.Errorf("field %s: hasTag=%v, want %v", tc.field, got, tc.want)
		}
	}
}

// ── setField ──────────────────────────────────────────────────────────────────

func TestSetField_Assignable(t *testing.T) {
	type S struct{ Name string }
	s := &S{}
	fv := reflect.ValueOf(s).Elem().Field(0)
	setField(fv, "hello")
	if s.Name != "hello" {
		t.Errorf("got %q, want hello", s.Name)
	}
}

func TestSetField_Convertible(t *testing.T) {
	type S struct{ Count int64 }
	s := &S{}
	fv := reflect.ValueOf(s).Elem().Field(0)
	setField(fv, int(42))
	if s.Count != 42 {
		t.Errorf("got %d, want 42", s.Count)
	}
}

func TestSetField_InvalidValue(t *testing.T) {
	type S struct{ Name string }
	s := &S{Name: "original"}
	fv := reflect.ValueOf(s).Elem().Field(0)
	setField(fv, nil)
	if s.Name != "original" {
		t.Errorf("nil val should not change field, got %q", s.Name)
	}
}
