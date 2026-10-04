// Package fabric defines transport-independent Pagnet network contracts.
//
// Pagnet discovers; the caller decides; Pagnet invokes. Discovery and
// description never execute endpoints. Invocation selects exactly one stable
// reference and returns failures without inventing an alternative. Application
// reasoning, task state and authorization policies belong to actors/extensions.
// Plaintext processing belongs inside an explicitly trusted node, not a relay.
package fabric
