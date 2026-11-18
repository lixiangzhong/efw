package ir

import (
	"math/big"
	"net/netip"
	"sort"
	"strings"
)

// MergePrefixes 把同一集合的 IPv4/IPv6 元素归并成最少的 CIDR 列表：
// 去重、排序、合并重叠与相邻区间，再折叠为最小前缀集合。
//
// 必须在编译期归并：nft 的 interval 集合遇到重叠元素会拒绝加载
// （conflicting intervals specified），而 nft 0.8 没有 auto-merge 可用。
// 元素由解析器保证是已规范化的 IP 或 CIDR 文本。
func MergePrefixes(elements []string) (v4, v6 []string) {
	var ranges4, ranges6 []prefixRange
	for _, text := range elements {
		prefix, ok := parsePrefix(text)
		if !ok {
			continue
		}
		if prefix.Addr().Is4() {
			ranges4 = append(ranges4, prefixRangeOf(prefix, 32))
			continue
		}
		ranges6 = append(ranges6, prefixRangeOf(prefix, 128))
	}
	return summarizeRanges(ranges4, 32), summarizeRanges(ranges6, 128)
}

// prefixRange 是一个闭区间 [start, end]。
type prefixRange struct {
	start *big.Int
	end   *big.Int
}

// parsePrefix 把 "a.b.c.d" 或 "a.b.c.d/len" 解析成前缀；裸地址按 /32、/128 处理。
func parsePrefix(text string) (netip.Prefix, bool) {
	if strings.Contains(text, "/") {
		prefix, err := netip.ParsePrefix(text)
		if err != nil {
			return netip.Prefix{}, false
		}
		return prefix.Masked(), true
	}
	addr, err := netip.ParseAddr(text)
	if err != nil {
		return netip.Prefix{}, false
	}
	return netip.PrefixFrom(addr, addr.BitLen()), true
}

// prefixRangeOf 把前缀换算成整数闭区间。
func prefixRangeOf(prefix netip.Prefix, bits int) prefixRange {
	start := addrToInt(prefix.Addr())
	size := new(big.Int).Lsh(big.NewInt(1), uint(bits-prefix.Bits()))
	end := new(big.Int).Sub(new(big.Int).Add(start, size), big.NewInt(1))
	return prefixRange{start: start, end: end}
}

// addrToInt 把地址转成大端整数。
func addrToInt(addr netip.Addr) *big.Int {
	if addr.Is4() {
		b := addr.As4()
		return new(big.Int).SetBytes(b[:])
	}
	b := addr.As16()
	return new(big.Int).SetBytes(b[:])
}

// intToAddr 把整数还原成地址（bits 决定 4/16 字节）。
func intToAddr(value *big.Int, bits int) netip.Addr {
	if bits == 32 {
		var b [4]byte
		value.FillBytes(b[:])
		return netip.AddrFrom4(b)
	}
	var b [16]byte
	value.FillBytes(b[:])
	return netip.AddrFrom16(b)
}

// summarizeRanges 合并重叠/相邻区间后，逐段折叠成最小 CIDR 列表。
func summarizeRanges(ranges []prefixRange, bits int) []string {
	if len(ranges) == 0 {
		return nil
	}
	sort.Slice(ranges, func(i, j int) bool {
		if c := ranges[i].start.Cmp(ranges[j].start); c != 0 {
			return c < 0
		}
		return ranges[i].end.Cmp(ranges[j].end) < 0
	})

	merged := make([]prefixRange, 0, len(ranges))
	for _, r := range ranges {
		if n := len(merged); n > 0 {
			// +1 表示把「相邻」也并进来（/25 + /25 → /24）。
			adjacent := new(big.Int).Add(merged[n-1].end, big.NewInt(1))
			if r.start.Cmp(adjacent) <= 0 {
				if r.end.Cmp(merged[n-1].end) > 0 {
					merged[n-1].end = r.end
				}
				continue
			}
		}
		merged = append(merged, prefixRange{
			start: new(big.Int).Set(r.start),
			end:   new(big.Int).Set(r.end),
		})
	}

	var out []string
	for _, r := range merged {
		out = append(out, summarizeRange(r.start, r.end, bits)...)
	}
	return out
}

// summarizeRange 把一个闭区间拆成最少的 CIDR（按起始地址升序）。
func summarizeRange(start, end *big.Int, bits int) []string {
	var out []string
	one := big.NewInt(1)
	cur := new(big.Int).Set(start)
	for cur.Cmp(end) <= 0 {
		// 对齐块：起始地址的尾部零位数，受剩余长度限制。
		align := uint(bits)
		if cur.Sign() != 0 {
			align = cur.TrailingZeroBits()
			if align > uint(bits) {
				align = uint(bits)
			}
		}
		remaining := new(big.Int).Sub(end, cur)
		remaining.Add(remaining, one)
		if remLog := uint(remaining.BitLen() - 1); remLog < align {
			align = remLog
		}
		prefixLen := bits - int(align)
		addr := intToAddr(cur, bits)
		if prefixLen == bits {
			// 单个地址输出裸 IP（与现有 ACL 写法一致），不加 /32、/128。
			out = append(out, addr.String())
		} else {
			out = append(out, netip.PrefixFrom(addr, prefixLen).String())
		}
		cur.Add(cur, new(big.Int).Lsh(one, align))
	}
	return out
}
