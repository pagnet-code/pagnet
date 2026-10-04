package sessionworker

import "github.com/pagnet-code/pagnet/internal/nativeauthority"

// AuthorityScope is the closed comparable ownership boundary. Scope below stays
// the genuine existing cloud representation so existing journals/capture AAD are
// never rewritten as local authority. Local journal/owner composition must use
// the separately authenticated authority constructor before any native effects.
type AuthorityScope = nativeauthority.Scope

const LocalProtocol = "pagnet-session-worker-local-v1"

func (j *Journal) authorityScope() AuthorityScope { return j.authority }
func (j *Journal) instanceID() string             { return j.authority.WorkerID() }
func (j *Journal) ownershipGeneration() string    { return j.authority.OwnershipGeneration() }
func (j *Journal) isLocal() bool                  { return j.authority.Kind() == nativeauthority.Local }
