package search

import (
	"github.com/pagnet-code/pagnet/fabric"
	"sort"
	"strings"
	"unicode"
)

type term struct {
	name string
	tf   uint32
}
type impact struct {
	count     uint64
	maxTF     uint32
	minLength uint32
}
type indexed struct {
	doc          fabric.SearchDocument
	terms        []term
	keys         []string
	length       uint32
	encodedBytes uint64
}

// A bounded leaf decodes at most 32 physical current versions. Immutable
// readers keep their prior leaf; overwrites never mix revisions or liveness.
type node struct {
	left, right *node
	leaf        []*indexed
	summaries   *dictionary[impact]
	minRef      string
	count       uint64
}
type idSet struct {
	left, right *idSet
	bits        uint32
	count       uint64
}

func tokenize(text string) []string {
	return strings.FieldsFunc(strings.ToLower(text), func(r rune) bool { return !unicode.IsLetter(r) && !unicode.IsNumber(r) })
}
func frequency(terms []term, name string) uint32 {
	pos := sort.Search(len(terms), func(i int) bool { return terms[i].name >= name })
	if pos < len(terms) && terms[pos].name == name {
		return terms[pos].tf
	}
	return 0
}
func combine(a, b impact) impact {
	if a.count == 0 {
		return b
	}
	if b.count == 0 {
		return a
	}
	r := impact{count: a.count + b.count, maxTF: a.maxTF, minLength: a.minLength}
	if b.maxTF > r.maxTF {
		r.maxTF = b.maxTF
	}
	if b.minLength < r.minLength {
		r.minLength = b.minLength
	}
	return r
}
func summary(n *node, key string) impact {
	if n == nil {
		return impact{}
	}
	v, _ := get(n.summaries, key)
	return v
}
func recordImpact(d *indexed, key string) impact {
	if d == nil {
		return impact{}
	}
	if strings.HasPrefix(key, "t:") {
		tf := frequency(d.terms, key[2:])
		if tf == 0 {
			return impact{}
		}
		return impact{1, tf, d.length}
	}
	pos := sort.SearchStrings(d.keys, key)
	if pos < len(d.keys) && d.keys[pos] == key {
		return impact{1, 1, d.length}
	}
	return impact{}
}
func updateNode(old *node, lo, span, id uint64, d *indexed, keys []string, work *PublicationWork) *node {
	n := &node{}
	if old != nil {
		*n = *old
	}
	work.HierarchyNodes++
	if span == leafSize {
		n.leaf = make([]*indexed, leafSize)
		if old != nil {
			copy(n.leaf, old.leaf)
		}
		n.leaf[id-lo] = d
	} else {
		half := span / 2
		if id < lo+half {
			n.left = updateNode(n.left, lo, half, id, d, keys, work)
		} else {
			n.right = updateNode(n.right, lo+half, half, id, d, keys, work)
		}
	}
	n.count = 0
	n.minRef = ""
	if span == leafSize {
		for _, r := range n.leaf {
			if r != nil {
				n.count++
				ref := r.doc.Ref.String()
				if n.minRef == "" || ref < n.minRef {
					n.minRef = ref
				}
			}
		}
	} else {
		for _, child := range []*node{n.left, n.right} {
			if child != nil {
				n.count += child.count
				if child.minRef != "" && (n.minRef == "" || child.minRef < n.minRef) {
					n.minRef = child.minRef
				}
			}
		}
	}
	for _, key := range keys {
		v := impact{}
		if span == leafSize {
			for _, r := range n.leaf {
				v = combine(v, recordImpact(r, key))
			}
		} else {
			v = combine(summary(n.left, key), summary(n.right, key))
		}
		if v.count == 0 {
			n.summaries = remove(n.summaries, key)
		} else {
			n.summaries = put(n.summaries, key, v)
		}
		work.SummaryUpdates++
	}
	if n.count == 0 {
		return nil
	}
	return n
}
func setAdd(n *idSet, lo, span, id uint64, work *PublicationWork) *idSet {
	work.HierarchyNodes++
	if n == nil {
		n = &idSet{}
	}
	if span == leafSize {
		mask := uint32(1) << (id - lo)
		if n.bits&mask == 0 {
			n.bits |= mask
			n.count++
		}
		return n
	}
	half := span / 2
	if id < lo+half {
		n.left = setAdd(n.left, lo, half, id, work)
	} else {
		n.right = setAdd(n.right, lo+half, half, id, work)
	}
	n.count = 0
	if n.left != nil {
		n.count += n.left.count
	}
	if n.right != nil {
		n.count += n.right.count
	}
	return n
}
func keysUnion(a, b *indexed) []string {
	m := map[string]bool{}
	for _, d := range []*indexed{a, b} {
		if d != nil {
			for _, t := range d.terms {
				m["t:"+t.name] = true
			}
			for _, key := range d.keys {
				m[key] = true
			}
		}
	}
	keys := make([]string, 0, len(m))
	for key := range m {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}
