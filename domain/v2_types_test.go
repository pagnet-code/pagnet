package domain

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// TestPrincipalWireFormat pins the Principal wire shape: the two kinds,
// the ownership fields and the service provider identity.
func TestPrincipalWireFormat(t *testing.T) {
	p := Principal{
		ID:             MustParseID("01900000-0000-7000-8000-000000000001"),
		OwningTenantID: MustParseID("01900000-0000-7000-8000-000000000002"),
		OwnershipScope: OwnershipScopePersonal,
		Kind:           PrincipalKindAgent,
		Name:           "planner",
		Visibility:     PrincipalVisibilityPrivate,
	}
	b, err := json.Marshal(p)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	for _, key := range []string{
		`"Kind":"agent"`,
		`"OwnershipScope":"personal"`,
		`"Name":"planner"`,
		`"Visibility":"private"`,
	} {
		if !strings.Contains(string(b), key) {
			t.Fatalf("marshaled principal %s does not carry %s", b, key)
		}
	}

	svc := Principal{
		ID:           MustParseID("01900000-0000-7000-8000-000000000003"),
		Kind:         PrincipalKindService,
		Name:         "continente",
		Visibility:   PrincipalVisibilityPublic,
		ProviderName: "Continente",
		ProviderURL:  "https://continente.example",
	}
	sb, err := json.Marshal(svc)
	if err != nil {
		t.Fatalf("marshal service: %v", err)
	}
	for _, key := range []string{`"Kind":"service"`, `"ProviderName":"Continente"`, `"ProviderURL":"https://continente.example"`} {
		if !strings.Contains(string(sb), key) {
			t.Fatalf("marshaled service %s does not carry %s", sb, key)
		}
	}
}

// TestPrincipalKindValid verifies the kind/visibility helpers.
func TestPrincipalKindValid(t *testing.T) {
	if !PrincipalKindAgent.Valid() || !PrincipalKindService.Valid() {
		t.Error("agent and service must be valid principal kinds")
	}
	for _, k := range []PrincipalKind{"worker", "representative", "system", "connector", ""} {
		if k.Valid() {
			t.Errorf("kind %q must NOT be valid (only agent|service)", k)
		}
	}
	if !PrincipalVisibilityPrivate.Valid() || !PrincipalVisibilityPublic.Valid() {
		t.Error("private and public must be valid visibilities")
	}
	if PrincipalVisibility("bogus").Valid() {
		t.Error("bogus visibility must not be valid")
	}
}

// TestNetworkMembershipWireFormat pins the membership wire shape and the
// permission vocabulary.
func TestNetworkMembershipWireFormat(t *testing.T) {
	revoked := time.Date(2026, 9, 19, 0, 0, 0, 0, time.UTC)
	m := NetworkMembership{
		ID:          MustParseID("01900000-0000-7000-8000-000000000011"),
		NetworkID:   MustParseID("01900000-0000-7000-8000-000000000012"),
		PrincipalID: MustParseID("01900000-0000-7000-8000-000000000013"),
		State:       MembershipRevoked,
		Permissions: []NetworkPermission{PermCommunicate, PermTaskRead, PermOperate},
		JoinedAt:    time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC),
		RevokedAt:   &revoked,
	}
	b, err := json.Marshal(m)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	for _, key := range []string{
		`"State":"revoked"`,
		`"Permissions":["communicate","task_read","operate"]`,
	} {
		if !strings.Contains(string(b), key) {
			t.Fatalf("marshaled membership %s does not carry %s", b, key)
		}
	}
}

// TestNetworkPermissionValid verifies the permission vocabulary.
func TestNetworkPermissionValid(t *testing.T) {
	valid := []NetworkPermission{
		PermDiscover, PermCommunicate, PermInvoke, PermEventPublish,
		PermEventSubscribe, PermTaskRead, PermTaskWrite, PermOperate,
	}
	for _, p := range valid {
		if !p.Valid() {
			t.Errorf("permission %q must be valid", p)
		}
	}
	for _, p := range []NetworkPermission{"observe", "delegate", "", "invoke_everything"} {
		if p.Valid() {
			t.Errorf("permission %q must NOT be valid (v1 grant vocabulary is gone)", p)
		}
	}
	if !HasPermission([]NetworkPermission{PermTaskRead}, PermTaskRead) {
		t.Error("HasPermission must find a present permission")
	}
	if HasPermission([]NetworkPermission{PermTaskRead}, PermInvoke) {
		t.Error("HasPermission must not find an absent permission")
	}
}

// TestMembershipStateValid verifies the membership state machine values.
func TestMembershipStateValid(t *testing.T) {
	for _, s := range []MembershipState{MembershipActive, MembershipSuspended, MembershipRevoked} {
		if !s.Valid() {
			t.Errorf("state %q must be valid", s)
		}
	}
	if MembershipState("bogus").Valid() {
		t.Error("bogus state must not be valid")
	}
}

// TestCapabilityWireFormat pins the versioned capability descriptor: the
// new fields (version, schemas, tags) marshal with the camelCase wire names
// and omit when empty.
func TestCapabilityWireFormat(t *testing.T) {
	c := Capability{
		ID:           "documents.extract",
		Version:      1,
		Name:         "Extract text",
		Description:  "Extracts text from a document",
		InputSchema:  json.RawMessage(`{"type":"object"}`),
		OutputSchema: json.RawMessage(`{"type":"string"}`),
		Tags:         []string{"documents", "ocr"},
	}
	b, err := json.Marshal(c)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	for _, key := range []string{
		`"id":"documents.extract"`,
		`"version":1`,
		`"name":"Extract text"`,
		`"inputSchema":{"type":"object"}`,
		`"outputSchema":{"type":"string"}`,
		`"tags":["documents","ocr"]`,
	} {
		if !strings.Contains(string(b), key) {
			t.Fatalf("marshaled capability %s does not carry %s", b, key)
		}
	}

	// Empty optional fields must be omitted (wire stability for trivial
	// capabilities).
	minimal, err := json.Marshal(Capability{ID: "echo.say", Version: 1, Name: "Say"})
	if err != nil {
		t.Fatalf("marshal minimal: %v", err)
	}
	for _, absent := range []string{`"inputSchema"`, `"outputSchema"`, `"tags"`, `"metadata"`, `"description"`} {
		if strings.Contains(string(minimal), absent) {
			t.Fatalf("minimal capability %s must omit %s", minimal, absent)
		}
	}

	if got := CapabilityNames([]Capability{c, {ID: "x", Version: 1, Name: "X"}}); len(got) != 2 || got[0] != "Extract text" {
		t.Fatalf("CapabilityNames = %v", got)
	}
}

// TestCapabilityInvocationWireFormat pins the invocation record shape.
func TestCapabilityInvocationWireFormat(t *testing.T) {
	inv := CapabilityInvocation{
		ID:                MustParseID("01900000-0000-7000-8000-000000000021"),
		NetworkID:         MustParseID("01900000-0000-7000-8000-000000000022"),
		CallerPrincipalID: MustParseID("01900000-0000-7000-8000-000000000023"),
		TargetPrincipalID: MustParseID("01900000-0000-7000-8000-000000000024"),
		CapabilityID:      "documents.extract",
		CapabilityVersion: 1,
		State:             InvocationDispatched,
		IdempotencyKey:    "key-1",
		ProtectedInput:    json.RawMessage(`{"version":1}`),
		PublicResultCode:  "",
	}
	b, err := json.Marshal(inv)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	for _, key := range []string{
		`"State":"dispatched"`,
		`"CapabilityID":"documents.extract"`,
		`"CapabilityVersion":1`,
		`"IdempotencyKey":"key-1"`,
		`"ProtectedInput":{"version":1}`,
	} {
		if !strings.Contains(string(b), key) {
			t.Fatalf("marshaled invocation %s does not carry %s", b, key)
		}
	}
}

// TestInvocationStateValid verifies the invocation state machine values.
func TestInvocationStateValid(t *testing.T) {
	for _, s := range []InvocationState{
		InvocationPending, InvocationDispatched, InvocationRunning,
		InvocationCompleted, InvocationFailed, InvocationCancelled,
	} {
		if !s.Valid() {
			t.Errorf("state %q must be valid", s)
		}
	}
	if InvocationState("bogus").Valid() {
		t.Error("bogus state must not be valid")
	}
	if !InvocationCompleted.Terminal() || !InvocationFailed.Terminal() || !InvocationCancelled.Terminal() {
		t.Error("completed/failed/cancelled must be terminal")
	}
	if InvocationPending.Terminal() || InvocationDispatched.Terminal() || InvocationRunning.Terminal() {
		t.Error("pending/dispatched/running must not be terminal")
	}
}

// TestEventSubscriptionWireFormat pins the subscription + delivery shapes.
func TestEventSubscriptionWireFormat(t *testing.T) {
	s := EventSubscription{
		ID:                    MustParseID("01900000-0000-7000-8000-000000000031"),
		NetworkID:             MustParseID("01900000-0000-7000-8000-000000000032"),
		SubscriberPrincipalID: MustParseID("01900000-0000-7000-8000-000000000033"),
		EventPattern:          "task.*",
		DeliveryMode:          DeliveryWake,
		Enabled:               true,
	}
	b, err := json.Marshal(s)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	for _, key := range []string{`"EventPattern":"task.*"`, `"DeliveryMode":"wake"`, `"Enabled":true`} {
		if !strings.Contains(string(b), key) {
			t.Fatalf("marshaled subscription %s does not carry %s", b, key)
		}
	}

	d := EventDelivery{
		ID:                    MustParseID("01900000-0000-7000-8000-000000000034"),
		SubscriptionID:        s.ID,
		EventID:               MustParseID("01900000-0000-7000-8000-000000000035"),
		SubscriberPrincipalID: s.SubscriberPrincipalID,
		State:                 DeliveryStatePending,
		Attempt:               0,
		AvailableAt:           time.Date(2026, 9, 19, 0, 0, 0, 0, time.UTC),
	}
	db, err := json.Marshal(d)
	if err != nil {
		t.Fatalf("marshal delivery: %v", err)
	}
	for _, key := range []string{`"State":"pending"`, `"Attempt":0`} {
		if !strings.Contains(string(db), key) {
			t.Fatalf("marshaled delivery %s does not carry %s", db, key)
		}
	}
}

// TestEventDeliveryModes verifies the delivery mode/state vocabularies.
func TestEventDeliveryModes(t *testing.T) {
	if !DeliveryDeliver.Valid() || !DeliveryWake.Valid() {
		t.Error("deliver and wake must be valid delivery modes")
	}
	if EventDeliveryMode("bogus").Valid() {
		t.Error("bogus delivery mode must not be valid")
	}
	for _, s := range []EventDeliveryState{
		DeliveryStatePending, DeliveryStateDispatched,
		DeliveryStateAcknowledged, DeliveryStateFailed,
	} {
		if !s.Valid() {
			t.Errorf("delivery state %q must be valid", s)
		}
	}
	if EventDeliveryState("bogus").Valid() {
		t.Error("bogus delivery state must not be valid")
	}
}

// TestPrincipalEndpointWireFormat pins the endpoint shape.
func TestPrincipalEndpointWireFormat(t *testing.T) {
	e := PrincipalEndpoint{
		ID:          MustParseID("01900000-0000-7000-8000-000000000041"),
		PrincipalID: MustParseID("01900000-0000-7000-8000-000000000042"),
		Kind:        EndpointKindSDK,
		Region:      "eu-west",
		Status:      EndpointStatusOnline,
		Inflight:    2,
		SDKVersion:  "v0.3.0",
		PublicKey:   "base64pub",
		LastSeenAt:  time.Date(2026, 9, 19, 0, 0, 0, 0, time.UTC),
		StartedAt:   time.Date(2026, 9, 19, 0, 0, 0, 0, time.UTC),
		CreatedAt:   time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC),
	}
	b, err := json.Marshal(e)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	for _, key := range []string{
		`"Kind":"sdk"`,
		`"Status":"online"`,
		`"Inflight":2`,
		`"SDKVersion":"v0.3.0"`,
		`"PublicKey":"base64pub"`,
	} {
		if !strings.Contains(string(b), key) {
			t.Fatalf("marshaled endpoint %s does not carry %s", b, key)
		}
	}
	if !EndpointKindManagedAgent.Valid() || !EndpointKindSDK.Valid() {
		t.Error("managed_agent and sdk must be valid endpoint kinds")
	}
	if PrincipalEndpointKind("host").Valid() {
		t.Error("host must NOT be an endpoint kind (hosts are not participants)")
	}
	if !EndpointStatusOnline.Valid() || !EndpointStatusOffline.Valid() {
		t.Error("online and offline must be valid endpoint statuses")
	}
}

// TestServiceDefinitionWireFormat pins the service definition shape.
func TestServiceDefinitionWireFormat(t *testing.T) {
	s := ServiceDefinition{
		ID:           MustParseID("01900000-0000-7000-8000-000000000051"),
		PrincipalID:  MustParseID("01900000-0000-7000-8000-000000000052"),
		ProviderName: "Continente",
		ProviderURL:  "https://continente.example",
		JoinPolicy:   JoinPolicyApprovalRequired,
	}
	b, err := json.Marshal(s)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	for _, key := range []string{`"JoinPolicy":"approval_required"`, `"ProviderName":"Continente"`} {
		if !strings.Contains(string(b), key) {
			t.Fatalf("marshaled service definition %s does not carry %s", b, key)
		}
	}
	if !JoinPolicyAutoAccept.Valid() || !JoinPolicyApprovalRequired.Valid() {
		t.Error("auto_accept and approval_required must be valid join policies")
	}
	if ServiceJoinPolicy("bogus").Valid() {
		t.Error("bogus join policy must not be valid")
	}
}

// TestUserRepresentativeWireFormat pins the representative binding shape:
// it is a plain user<->agent-principal link (no grant table).
func TestUserRepresentativeWireFormat(t *testing.T) {
	r := UserRepresentative{
		ID:               MustParseID("01900000-0000-7000-8000-000000000061"),
		UserID:           MustParseID("01900000-0000-7000-8000-000000000062"),
		AgentPrincipalID: MustParseID("01900000-0000-7000-8000-000000000063"),
		IsDefault:        true,
	}
	b, err := json.Marshal(r)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	for _, key := range []string{`"IsDefault":true`, `"AgentPrincipalID":"01900000-0000-7000-8000-000000000063"`} {
		if !strings.Contains(string(b), key) {
			t.Fatalf("marshaled user representative %s does not carry %s", b, key)
		}
	}
}

// TestAgentDefinitionV2Shape pins the cutover definition: principal-bound,
// execution-mode aware, no network/kind/profile/capabilities fields.
func TestAgentDefinitionV2Shape(t *testing.T) {
	d := AgentDefinition{
		ID:             MustParseID("01900000-0000-7000-8000-000000000071"),
		PrincipalID:    MustParseID("01900000-0000-7000-8000-000000000072"),
		ExecutionMode:  ExecutionModeManaged,
		DefaultRuntime: RuntimeQwenCode,
		Mission:        "plan the release",
		Instruction:    "always verify",
		ExecutionSettings: map[string]any{
			"maxConcurrentTurns": 1,
			"transcriptLevel":    TranscriptNetwork,
		},
	}
	b, err := json.Marshal(d)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	for _, key := range []string{
		`"PrincipalID":"01900000-0000-7000-8000-000000000072"`,
		`"ExecutionMode":"managed"`,
		`"DefaultRuntime":"qwen-code"`,
	} {
		if !strings.Contains(string(b), key) {
			t.Fatalf("marshaled definition %s does not carry %s", b, key)
		}
	}
	for _, gone := range []string{`"Kind"`, `"NetworkID"`, `"Profile"`, `"Capabilities"`, `"Name"`, `"Description"`} {
		if strings.Contains(string(b), gone) {
			t.Fatalf("marshaled definition %s still carries removed field %s", b, gone)
		}
	}

	if !ExecutionModeManaged.Valid() || !ExecutionModeExternal.Valid() {
		t.Error("managed and external must be valid execution modes")
	}
	if AgentExecutionMode("bogus").Valid() {
		t.Error("bogus execution mode must not be valid")
	}

	// The instance keeps its execution fields and gains PrincipalID.
	inst := AgentInstance{
		ID:           MustParseID("01900000-0000-7000-8000-000000000073"),
		NetworkID:    MustParseID("01900000-0000-7000-8000-000000000074"),
		DefinitionID: d.ID,
		PrincipalID:  d.PrincipalID,
		HostID:       MustParseID("01900000-0000-7000-8000-000000000075"),
		Status:       AgentStatusIdle,
	}
	ib, err := json.Marshal(inst)
	if err != nil {
		t.Fatalf("marshal instance: %v", err)
	}
	if !strings.Contains(string(ib), `"PrincipalID":"01900000-0000-7000-8000-000000000072"`) {
		t.Fatalf("marshaled instance %s does not carry PrincipalID", ib)
	}
	if strings.Contains(string(ib), "SelfCapabilities") {
		t.Fatalf("marshaled instance %s still carries SelfCapabilities (removed in V2)", ib)
	}
}

// TestMessageTaskPrincipalFields pins the principal-first message/task
// shapes: principal ids are canonical, instance ids are provenance, and the
// v1 *AgentName fields are gone.
func TestMessageTaskPrincipalFields(t *testing.T) {
	sender := MustParseID("01900000-0000-7000-8000-000000000081")
	recipient := MustParseID("01900000-0000-7000-8000-000000000082")
	m := Message{
		ID:                   MustParseID("01900000-0000-7000-8000-000000000083"),
		NetworkID:            MustParseID("01900000-0000-7000-8000-000000000084"),
		ThreadID:             MustParseID("01900000-0000-7000-8000-000000000085"),
		Kind:                 MessageKindAsk,
		SenderPrincipalID:    &sender,
		RecipientPrincipalID: &recipient,
		Parts:                []MessagePart{TextPart("hi")},
	}
	b, err := json.Marshal(m)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	for _, key := range []string{
		`"SenderPrincipalID":"01900000-0000-7000-8000-000000000081"`,
		`"RecipientPrincipalID":"01900000-0000-7000-8000-000000000082"`,
	} {
		if !strings.Contains(string(b), key) {
			t.Fatalf("marshaled message %s does not carry %s", b, key)
		}
	}
	for _, gone := range []string{`"SenderAgentName"`, `"RecipientAgentName"`} {
		if strings.Contains(string(b), gone) {
			t.Fatalf("marshaled message %s still carries removed field %s", b, gone)
		}
	}

	creator := MustParseID("01900000-0000-7000-8000-000000000086")
	target := MustParseID("01900000-0000-7000-8000-000000000087")
	assigned := MustParseID("01900000-0000-7000-8000-000000000088")
	tk := Task{
		ID:                  MustParseID("01900000-0000-7000-8000-000000000089"),
		NetworkID:           MustParseID("01900000-0000-7000-8000-000000000090"),
		Title:               "do the thing",
		CreatorPrincipalID:  &creator,
		TargetPrincipalID:   &target,
		AssignedPrincipalID: &assigned,
		Status:              TaskStatusPending,
	}
	tb, err := json.Marshal(tk)
	if err != nil {
		t.Fatalf("marshal task: %v", err)
	}
	for _, key := range []string{
		`"CreatorPrincipalID":"01900000-0000-7000-8000-000000000086"`,
		`"TargetPrincipalID":"01900000-0000-7000-8000-000000000087"`,
		`"AssignedPrincipalID":"01900000-0000-7000-8000-000000000088"`,
	} {
		if !strings.Contains(string(tb), key) {
			t.Fatalf("marshaled task %s does not carry %s", tb, key)
		}
	}
	for _, gone := range []string{`"CreatorAgentName"`, `"TargetAgentName"`, `"AssignedAgentName"`} {
		if strings.Contains(string(tb), gone) {
			t.Fatalf("marshaled task %s still carries removed field %s", tb, gone)
		}
	}

	// Thread is created by a principal, not an instance.
	th := Thread{
		ID:                   MustParseID("01900000-0000-7000-8000-000000000091"),
		NetworkID:            MustParseID("01900000-0000-7000-8000-000000000092"),
		CreatedByPrincipalID: &sender,
		Subject:              "thread",
	}
	thb, err := json.Marshal(th)
	if err != nil {
		t.Fatalf("marshal thread: %v", err)
	}
	if !strings.Contains(string(thb), `"CreatedByPrincipalID":"01900000-0000-7000-8000-000000000081"`) {
		t.Fatalf("marshaled thread %s does not carry CreatedByPrincipalID", thb)
	}
	if strings.Contains(string(thb), "CreatedByInstanceID") {
		t.Fatalf("marshaled thread %s still carries CreatedByInstanceID (removed in V2)", thb)
	}
}

// TestEventV2Shape pins the event cutover: the v1 audit fields keep their
// names, the v2 routing fields are added, and the protected payload rides
// as an opaque envelope.
func TestEventV2Shape(t *testing.T) {
	producer := MustParseID("01900000-0000-7000-8000-0000000000a1")
	target := MustParseID("01900000-0000-7000-8000-0000000000a2")
	network := MustParseID("01900000-0000-7000-8000-0000000000a3")
	ev := NewEvent(context.Background(), MustParseID("01900000-0000-7000-8000-0000000000a4"), &network,
		"pagnet.task.created", ActorSystem, "system", "task", "task-1", nil)
	ev.ProducerPrincipalID = &producer
	ev.TargetPrincipalID = &target
	ev.SchemaVersion = 1
	ev.ProtectedPayload = json.RawMessage(`{"version":1}`)

	if ev.ID.IsZero() || ev.Timestamp.IsZero() || ev.OccurredAt.IsZero() {
		t.Fatal("NewEvent must fill ID, Timestamp and OccurredAt")
	}
	if ev.Metadata == nil {
		t.Fatal("NewEvent must default Metadata to an empty map")
	}

	b, err := json.Marshal(ev)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	for _, key := range []string{
		`"EventType":"pagnet.task.created"`,
		`"SchemaVersion":1`,
		`"ProducerPrincipalID":"01900000-0000-7000-8000-0000000000a1"`,
		`"TargetPrincipalID":"01900000-0000-7000-8000-0000000000a2"`,
		`"ProtectedPayload":{"version":1}`,
		`"ActorType":"system"`,
		`"OccurredAt"`,
	} {
		if !strings.Contains(string(b), key) {
			t.Fatalf("marshaled event %s does not carry %s", b, key)
		}
	}

	// Correlation/causation still flow from ctx.
	ctx := WithCorrelationID(context.Background(), MustParseID("01900000-0000-7000-8000-0000000000a5"))
	ctx = WithCausationID(ctx, MustParseID("01900000-0000-7000-8000-0000000000a6"))
	ev2 := NewEvent(ctx, ev.TenantID, &network, "pagnet.task.completed", ActorAgent, "inst-1", "", "", nil)
	if ev2.CorrelationID == nil || *ev2.CorrelationID != MustParseID("01900000-0000-7000-8000-0000000000a5") {
		t.Fatalf("CorrelationID = %v, want the ctx value", ev2.CorrelationID)
	}
	if ev2.CausationID == nil || *ev2.CausationID != MustParseID("01900000-0000-7000-8000-0000000000a6") {
		t.Fatalf("CausationID = %v, want the ctx value", ev2.CausationID)
	}
}

// TestClaimArtifactGroupPrincipalFields pins the remaining principal
// cutover fields.
func TestClaimArtifactGroupPrincipalFields(t *testing.T) {
	owner := MustParseID("01900000-0000-7000-8000-0000000000b1")
	c := Claim{
		ID:               MustParseID("01900000-0000-7000-8000-0000000000b2"),
		NetworkID:        MustParseID("01900000-0000-7000-8000-0000000000b3"),
		ScopeType:        ClaimScopePath,
		Scope:            "src/**",
		OwnerPrincipalID: &owner,
		TTLSeconds:       60,
		ExpiresAt:        time.Now().Add(time.Minute),
	}
	cb, err := json.Marshal(c)
	if err != nil {
		t.Fatalf("marshal claim: %v", err)
	}
	if !strings.Contains(string(cb), `"OwnerPrincipalID":"01900000-0000-7000-8000-0000000000b1"`) {
		t.Fatalf("marshaled claim %s does not carry OwnerPrincipalID", cb)
	}
	if strings.Contains(string(cb), "OwnerAgentName") {
		t.Fatalf("marshaled claim %s still carries OwnerAgentName (removed in V2)", cb)
	}

	publisher := MustParseID("01900000-0000-7000-8000-0000000000b4")
	endpoint := MustParseID("01900000-0000-7000-8000-0000000000b5")
	a := Artifact{
		ID:                     MustParseID("01900000-0000-7000-8000-0000000000b6"),
		NetworkID:              MustParseID("01900000-0000-7000-8000-0000000000b7"),
		PublishedByPrincipalID: &publisher,
		PublishedByEndpointID:  &endpoint,
		Type:                   ArtifactPullRequest,
		URI:                    "https://github.com/x/pull/1",
	}
	ab, err := json.Marshal(a)
	if err != nil {
		t.Fatalf("marshal artifact: %v", err)
	}
	for _, key := range []string{
		`"PublishedByPrincipalID":"01900000-0000-7000-8000-0000000000b4"`,
		`"PublishedByEndpointID":"01900000-0000-7000-8000-0000000000b5"`,
	} {
		if !strings.Contains(string(ab), key) {
			t.Fatalf("marshaled artifact %s does not carry %s", ab, key)
		}
	}

	gm := GroupMember{
		GroupID:     MustParseID("01900000-0000-7000-8000-0000000000b8"),
		PrincipalID: MustParseID("01900000-0000-7000-8000-0000000000b9"),
	}
	gmb, err := json.Marshal(gm)
	if err != nil {
		t.Fatalf("marshal group member: %v", err)
	}
	if !strings.Contains(string(gmb), `"PrincipalID":"01900000-0000-7000-8000-0000000000b9"`) {
		t.Fatalf("marshaled group member %s does not carry PrincipalID", gmb)
	}
	if strings.Contains(string(gmb), "AgentDefinitionID") {
		t.Fatalf("marshaled group member %s still carries AgentDefinitionID (removed in V2)", gmb)
	}
}
