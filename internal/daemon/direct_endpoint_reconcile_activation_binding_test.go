//go:build linux || darwin

package daemon

import (
	"testing"
	"time"

	"github.com/pagnet-code/pagnet/internal/directhttp"
)

func TestDirectReconcileActivationBinding(t *testing.T) {
	for _, role := range []string{"S", "P"} {
		t.Run(role, func(t *testing.T) {
			f := newReconcileMaterialFixture(t, role)
			fresh := func() (directEndpointReconcileBinding, directhttp.Enrollment, directhttp.Activation, time.Time) {
				e := publishedEnrollment(f.enrollment, f.vector.Publication)
				e.Challenge = &directhttp.EnrollmentChallenge{}
				e.Proof = &directhttp.EnrollmentProof{ReceivedAt: f.now.Add(time.Second)}
				value := directhttp.Activation{ChannelID: f.binding.Authority.ChannelID, ActivatedAt: f.now.Add(2 * time.Second), ExpiresAt: f.binding.Authority.ExpiresAt}
				return f.binding, e, value, value.ActivatedAt
			}
			for _, name := range []string{"valid", "local upper", "receipt equality"} {
				t.Run(name, func(t *testing.T) {
					b, e, value, upper := fresh()
					if name == "local upper" {
						upper = upper.In(time.FixedZone("local", 3600))
					}
					if name == "receipt equality" {
						value.ActivatedAt = e.Proof.ReceivedAt
					}
					if err := validateDirectReconcileActivation(b, e, value, upper); err != nil {
						t.Fatal(err)
					}
				})
			}
			changes := map[string]func(*directEndpointReconcileBinding, *directhttp.Enrollment, *directhttp.Activation, *time.Time){
				"missing publication": func(_ *directEndpointReconcileBinding, e *directhttp.Enrollment, _ *directhttp.Activation, _ *time.Time) {
					e.PublicationHash = nil
				},
				"missing challenge": func(_ *directEndpointReconcileBinding, e *directhttp.Enrollment, _ *directhttp.Activation, _ *time.Time) {
					e.Challenge = nil
				},
				"missing proof": func(_ *directEndpointReconcileBinding, e *directhttp.Enrollment, _ *directhttp.Activation, _ *time.Time) {
					e.Proof = nil
				},
				"receipt zero": func(_ *directEndpointReconcileBinding, e *directhttp.Enrollment, _ *directhttp.Activation, _ *time.Time) {
					e.Proof.ReceivedAt = time.Time{}
				},
				"receipt non UTC": func(_ *directEndpointReconcileBinding, e *directhttp.Enrollment, _ *directhttp.Activation, _ *time.Time) {
					e.Proof.ReceivedAt = e.Proof.ReceivedAt.In(time.FixedZone("local", 3600))
				},
				"activation before receipt": func(_ *directEndpointReconcileBinding, e *directhttp.Enrollment, v *directhttp.Activation, _ *time.Time) {
					v.ActivatedAt = e.Proof.ReceivedAt.Add(-time.Nanosecond)
				},
				"activation future": func(_ *directEndpointReconcileBinding, _ *directhttp.Enrollment, v *directhttp.Activation, u *time.Time) {
					v.ActivatedAt = u.Add(time.Nanosecond)
				},
				"activation zero": func(_ *directEndpointReconcileBinding, _ *directhttp.Enrollment, v *directhttp.Activation, _ *time.Time) {
					v.ActivatedAt = time.Time{}
				},
				"activation non UTC": func(_ *directEndpointReconcileBinding, _ *directhttp.Enrollment, v *directhttp.Activation, _ *time.Time) {
					v.ActivatedAt = v.ActivatedAt.In(time.FixedZone("local", 3600))
				},
				"expiry mismatch": func(_ *directEndpointReconcileBinding, _ *directhttp.Enrollment, v *directhttp.Activation, _ *time.Time) {
					v.ExpiresAt = v.ExpiresAt.Add(time.Nanosecond)
				},
				"expiry zero": func(_ *directEndpointReconcileBinding, _ *directhttp.Enrollment, v *directhttp.Activation, _ *time.Time) {
					v.ExpiresAt = time.Time{}
				},
				"expiry equals activation": func(_ *directEndpointReconcileBinding, _ *directhttp.Enrollment, v *directhttp.Activation, _ *time.Time) {
					v.ExpiresAt = v.ActivatedAt
				},
				"expiry before activation": func(_ *directEndpointReconcileBinding, _ *directhttp.Enrollment, v *directhttp.Activation, _ *time.Time) {
					v.ExpiresAt = v.ActivatedAt.Add(-time.Nanosecond)
				},
				"expiry non UTC": func(_ *directEndpointReconcileBinding, _ *directhttp.Enrollment, v *directhttp.Activation, _ *time.Time) {
					v.ExpiresAt = v.ExpiresAt.In(time.FixedZone("local", 3600))
				},
				"channel mismatch": func(_ *directEndpointReconcileBinding, _ *directhttp.Enrollment, v *directhttp.Activation, _ *time.Time) {
					v.ChannelID += "x"
				},
				"enrollment channel": func(_ *directEndpointReconcileBinding, e *directhttp.Enrollment, _ *directhttp.Activation, _ *time.Time) {
					e.Authority.ChannelID += "x"
				},
				"binding channel": func(b *directEndpointReconcileBinding, _ *directhttp.Enrollment, _ *directhttp.Activation, _ *time.Time) {
					b.Authority.ChannelID += "x"
				},
				"enrollment expiry": func(_ *directEndpointReconcileBinding, e *directhttp.Enrollment, _ *directhttp.Activation, _ *time.Time) {
					e.Authority.ExpiresAt = e.Authority.ExpiresAt.Add(time.Nanosecond)
				},
				"binding expiry": func(b *directEndpointReconcileBinding, _ *directhttp.Enrollment, _ *directhttp.Activation, _ *time.Time) {
					b.Authority.ExpiresAt = b.Authority.ExpiresAt.Add(time.Nanosecond)
				},
				"descriptor bytes": func(b *directEndpointReconcileBinding, _ *directhttp.Enrollment, _ *directhttp.Activation, _ *time.Time) {
					b.DescriptorBytes = nil
				},
				"descriptor hash": func(b *directEndpointReconcileBinding, _ *directhttp.Enrollment, _ *directhttp.Activation, _ *time.Time) {
					b.DescriptorHash[0] ^= 1
				},
				"descriptor invalid": func(b *directEndpointReconcileBinding, _ *directhttp.Enrollment, _ *directhttp.Activation, _ *time.Time) {
					b.Descriptor.ExpiresAt = "invalid"
				},
				"upper zero": func(_ *directEndpointReconcileBinding, _ *directhttp.Enrollment, _ *directhttp.Activation, u *time.Time) {
					*u = time.Time{}
				},
			}
			for name, change := range changes {
				t.Run(name, func(t *testing.T) {
					b, e, value, upper := fresh()
					change(&b, &e, &value, &upper)
					if err := validateDirectReconcileActivation(b, e, value, upper); err != errDirectEndpointReconcileBinding {
						t.Fatalf("got %v, want binding rejection", err)
					}
				})
			}
		})
	}
}
