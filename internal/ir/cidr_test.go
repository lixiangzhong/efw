package ir

import (
	"reflect"
	"testing"
)

// TestMergePrefixes 验证元素归并：去重、重叠合并、相邻折叠、按族拆分。
func TestMergePrefixes(t *testing.T) {
	cases := []struct {
		name string
		in   []string
		v4   []string
		v6   []string
	}{
		{"去重", []string{"1.1.1.1", "1.1.1.1"}, []string{"1.1.1.1"}, nil},
		{"重叠", []string{"1.1.1.0/25", "1.1.1.22"}, []string{"1.1.1.0/25"}, nil},
		{"相邻折叠", []string{"10.0.0.0/25", "10.0.0.128/25"}, []string{"10.0.0.0/24"}, nil},
		{"乱序", []string{"10.0.0.2", "10.0.0.1"}, []string{"10.0.0.1", "10.0.0.2"}, nil},
		{"全零前缀", []string{"0.0.0.0/0"}, []string{"0.0.0.0/0"}, nil},
		{"v6 单地址", []string{"2001:db8::1"}, nil, []string{"2001:db8::1"}},
		{"v6 相邻", []string{"2001:db8::/127", "2001:db8::2/127"}, nil, []string{"2001:db8::/126"}},
		{"混合族拆分", []string{"1.1.1.1", "2001:db8::1"}, []string{"1.1.1.1"}, []string{"2001:db8::1"}},
		{"非法元素忽略", []string{"nope", "1.1.1.1"}, []string{"1.1.1.1"}, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			v4, v6 := MergePrefixes(tc.in)
			if !reflect.DeepEqual(v4, tc.v4) || !reflect.DeepEqual(v6, tc.v6) {
				t.Fatalf("MergePrefixes(%v) = %v / %v，期望 %v / %v", tc.in, v4, v6, tc.v4, tc.v6)
			}
		})
	}
}
