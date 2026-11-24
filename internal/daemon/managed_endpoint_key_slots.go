//go:build linux || darwin

package daemon

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"

	"github.com/pagnet-code/pagnet/domain"
	"github.com/pagnet-code/pagnet/transport"
)

// Keep the original allocation fence and filename even though identity now
// checks every endpoint incarnation field before allowing key reuse.
func managedEndpointKeyScope(installation domain.ID, server string, subject transport.ManagedEndpointBindingIntent) string {
	raw, _ := json.Marshal(struct {
		Installation                                              domain.ID
		Server                                                    string
		Tenant, Account, Principal, Instance, Endpoint, Admission domain.ID
		Generation                                                uint64
	}{installation, server, subject.TenantID, subject.AccountID, subject.PrincipalID, subject.InstanceID, subject.EndpointID, subject.NativeAdmissionID, 1})
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

func managedEndpointSlotIdentity(installation domain.ID, server string, subject transport.ManagedEndpointBindingIntent) []byte {
	raw, _ := subject.CanonicalBytes()
	var fields map[string]json.RawMessage
	_ = json.Unmarshal(raw, &fields)
	for _, name := range []string{"id", "directIntentId", "state", "createdAt", "expiresAt"} {
		delete(fields, name)
	}
	identity, _ := json.Marshal(struct {
		Installation domain.ID                  `json:"installationId"`
		Server       string                     `json:"serverUrl"`
		Subject      map[string]json.RawMessage `json:"subject"`
	}{installation, server, fields})
	return identity
}

func validateManagedEndpointRequest(raw []byte) (transport.ManagedEndpointBindingIntent, string, error) {
	var request struct {
		Server  string                                 `json:"serverUrl"`
		Subject transport.ManagedEndpointBindingIntent `json:"subject"`
	}
	if json.Unmarshal(raw, &request) != nil {
		return request.Subject, "", errManagedEndpointKey
	}
	canonical, err := request.Subject.CanonicalBytes()
	if err != nil || json.Unmarshal(canonical, &request.Subject) != nil || textServiceServer(request.Server) != request.Server || legacyTextServiceServer(request.Server) != request.Server || request.Server == "" {
		return request.Subject, "", errManagedEndpointKey
	}
	encoded, _ := json.Marshal(request)
	if !bytes.Equal(encoded, raw) {
		return request.Subject, "", errManagedEndpointKey
	}
	return request.Subject, request.Server, nil
}

type managedEndpointSlotKeyRecord struct {
	Version  int    `json:"version"`
	Identity []byte `json:"identity"`
	X25519   string `json:"x25519"`
	Private  []byte `json:"private"`
}

func loadManagedEndpointSlotKey(file *os.File, identity []byte) (string, error) {
	record, err := loadManagedEndpointSlotRecord(file, identity)
	defer clear(record.Private)
	if err != nil {
		return "", err
	}
	return record.X25519, nil
}

func loadManagedEndpointSlotRecord(file *os.File, identity []byte) (record managedEndpointSlotKeyRecord, err error) {
	valid := false
	defer func() {
		if !valid {
			clear(record.Private)
		}
	}()
	raw, err := io.ReadAll(io.LimitReader(file, nativeShareHolderMaxBytes+1))
	if err != nil {
		return record, err
	}
	defer clear(raw)
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if len(raw) > nativeShareHolderMaxBytes || decoder.Decode(&record) != nil || decoder.Decode(new(any)) != io.EOF {
		return record, errManagedEndpointKey
	}
	encoded, _ := json.Marshal(record)
	defer clear(encoded)
	if !bytes.Equal(raw, encoded) || record.Version != 2 || !bytes.Equal(record.Identity, identity) {
		return record, errManagedEndpointKey
	}
	key, err := ecdh.X25519().NewPrivateKey(record.Private)
	if err != nil || record.X25519 != hex.EncodeToString(key.PublicKey().Bytes()) {
		return record, errManagedEndpointKey
	}
	valid = true
	return record, nil
}

func (s *ManagedEndpointKeyStore) completeManagedEndpointReference(conn *sql.Conn, id domain.ID, scope, installation string, request, reservation, identity []byte, public string) error {
	result, err := conn.ExecContext(context.Background(), `UPDATE native_managed_endpoint_keys SET reservation=? WHERE enrollment_id=? AND scope=? AND installation_id=? AND request=? AND reservation IS NULL AND EXISTS(SELECT 1 FROM native_registry_metadata WHERE name='installation_id' AND value=?) AND EXISTS(SELECT 1 FROM native_managed_endpoint_key_slots WHERE scope=? AND installation_id=? AND identity=? AND key_generation=1 AND x25519=?)`, reservation, id, scope, installation, request, installation, scope, installation, identity, public)
	if err != nil {
		return err
	}
	if n, err := result.RowsAffected(); err != nil || n != 1 {
		return errManagedEndpointKey
	}
	return nil
}

// Called inside the installation transaction. No private file is rewritten or
// created here, and failed validation rolls back every schema and data change.
func migrateManagedEndpointKeySlots(conn *sql.Conn) error {
	var version string
	err := conn.QueryRowContext(context.Background(), `SELECT value FROM native_registry_metadata WHERE name='managed_endpoint_keys_schema'`).Scan(&version)
	if err == nil {
		if version != "2" {
			return errManagedEndpointKey
		}
		return nil
	}
	if err != sql.ErrNoRows {
		return err
	}
	type legacyRow struct {
		id, scope, installation string
		request, reservation    []byte
	}
	rows, err := conn.QueryContext(context.Background(), `SELECT enrollment_id,scope,installation_id,request,reservation FROM native_managed_endpoint_keys`)
	if err != nil {
		return err
	}
	var legacy []legacyRow
	for rows.Next() {
		var row legacyRow
		if err = rows.Scan(&row.id, &row.scope, &row.installation, &row.request, &row.reservation); err != nil {
			break
		}
		legacy = append(legacy, row)
	}
	if err == nil {
		err = rows.Err()
	}
	rows.Close()
	if err != nil {
		return err
	}
	for _, row := range legacy {
		subject, server, err := validateManagedEndpointRequest(row.request)
		installation := domain.ID(row.installation)
		if err != nil || !nativeShareEpochStageID(installation) || subject.ID.String() != row.id || managedEndpointKeyScope(installation, server, subject) != row.scope {
			return errManagedEndpointKey
		}
		var public any
		if row.reservation != nil {
			reservation, err := transport.DecodeManagedEndpointKeyReservation(row.reservation)
			canonical, canonicalErr := reservation.CanonicalBytes()
			if err != nil || canonicalErr != nil || !bytes.Equal(canonical, row.reservation) || reservation.Subject != subject || reservation.ServerURL != server || reservation.InstallationID != installation || reservation.KeyGeneration != 1 {
				return errManagedEndpointKey
			}
			public = reservation.X25519
		}
		if _, err = conn.ExecContext(context.Background(), `INSERT INTO native_managed_endpoint_key_slots(scope,installation_id,identity,key_generation,file_format,legacy_enrollment_id,x25519) VALUES(?,?,?,1,1,?,?)`, row.scope, row.installation, managedEndpointSlotIdentity(installation, server, subject), row.id, public); err != nil {
			return err
		}
	}
	for _, query := range []string{
		`ALTER TABLE native_managed_endpoint_keys RENAME TO native_managed_endpoint_keys_legacy`,
		`CREATE TABLE native_managed_endpoint_keys(enrollment_id TEXT PRIMARY KEY,scope TEXT NOT NULL,installation_id TEXT NOT NULL,request BLOB NOT NULL,reservation BLOB)`,
		`INSERT INTO native_managed_endpoint_keys SELECT enrollment_id,scope,installation_id,request,reservation FROM native_managed_endpoint_keys_legacy`,
		`DROP TABLE native_managed_endpoint_keys_legacy`,
		`INSERT INTO native_registry_metadata(name,value) VALUES('managed_endpoint_keys_schema','2')`,
	} {
		if _, err := conn.ExecContext(context.Background(), query); err != nil {
			return err
		}
	}
	return nil
}
