package search

// An immutable AVL dictionary gives sparse summaries/stats/ref sidecars
// logarithmic updates without copying a corpus-sized map on each publication.
type dictionary[V any] struct {
	key         string
	value       V
	left, right *dictionary[V]
	height      int
}

func height[V any](n *dictionary[V]) int {
	if n == nil {
		return 0
	}
	return n.height
}
func makeDictionary[V any](key string, value V, l, r *dictionary[V]) *dictionary[V] {
	h := height(l)
	if height(r) > h {
		h = height(r)
	}
	return &dictionary[V]{key, value, l, r, h + 1}
}
func get[V any](n *dictionary[V], key string) (zero V, ok bool) {
	for n != nil {
		if key < n.key {
			n = n.left
		} else if key > n.key {
			n = n.right
		} else {
			return n.value, true
		}
	}
	return
}
func put[V any](n *dictionary[V], key string, value V) *dictionary[V] {
	if n == nil {
		return makeDictionary(key, value, nil, nil)
	}
	if key < n.key {
		n = makeDictionary(n.key, n.value, put(n.left, key, value), n.right)
	} else if key > n.key {
		n = makeDictionary(n.key, n.value, n.left, put(n.right, key, value))
	} else {
		return makeDictionary(key, value, n.left, n.right)
	}
	return balance(n)
}
func balance[V any](n *dictionary[V]) *dictionary[V] {
	if height(n.left)-height(n.right) > 1 {
		l := n.left
		if height(l.left) < height(l.right) {
			r := l.right
			l = makeDictionary(r.key, r.value, makeDictionary(l.key, l.value, l.left, r.left), r.right)
		}
		return makeDictionary(l.key, l.value, l.left, makeDictionary(n.key, n.value, l.right, n.right))
	}
	if height(n.right)-height(n.left) > 1 {
		r := n.right
		if height(r.right) < height(r.left) {
			l := r.left
			r = makeDictionary(l.key, l.value, l.left, makeDictionary(r.key, r.value, l.right, r.right))
		}
		return makeDictionary(r.key, r.value, makeDictionary(n.key, n.value, n.left, r.left), r.right)
	}
	return n
}

func remove[V any](n *dictionary[V], key string) *dictionary[V] {
	if n == nil {
		return nil
	}
	if key < n.key {
		return balance(makeDictionary(n.key, n.value, remove(n.left, key), n.right))
	}
	if key > n.key {
		return balance(makeDictionary(n.key, n.value, n.left, remove(n.right, key)))
	}
	if n.left == nil {
		return n.right
	}
	if n.right == nil {
		return n.left
	}
	successor := n.right
	for successor.left != nil {
		successor = successor.left
	}
	return balance(makeDictionary(successor.key, successor.value, n.left, remove(n.right, successor.key)))
}
