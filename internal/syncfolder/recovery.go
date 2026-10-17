package syncfolder

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// Recovery is the recovery key every computer syncing through a folder
// shares: its public key, which each wraps its own vault key to, or none
// once it's removed. Count goes up with each change, so an older record put
// back is told from a newer one.
type Recovery struct {
	Made      time.Time `json:"made"`
	Computer  string    `json:"computer"`
	PublicKey []byte    `json:"public_key,omitempty"`
	Count     uint64    `json:"count"`
}

// Same says whether r and o are the same change: one count, one key.
func (r Recovery) Same(o Recovery) bool {
	return r.Count == o.Count && bytes.Equal(r.PublicKey, o.PublicKey)
}

// SealedRecovery is a Recovery as InfoFile holds it: sealed with the key
// of the key record whose ID is Key, bound to the folder, so no one
// without that key can make one, nor move one from another folder.
type SealedRecovery struct {
	Key  string `json:"key"`
	Data []byte `json:"data"`
	Salt []byte `json:"salt"`
}

// maxRecoveryKey is the most a recovery key's public key may be: a P-256
// key, uncompressed, is 65 bytes.
const maxRecoveryKey = 256

func recoveryAAD(folderID, keyID string) []byte {
	return []byte("sesh-recovery-v1\x00" + folderID + "\x00" + keyID)
}

// SealRecovery seals r for the folder folderID with s, the key of the key
// record keyID.
func SealRecovery(s Sealer, folderID, keyID string, r Recovery) (*SealedRecovery, error) {
	b, err := json.Marshal(r)
	if err != nil {
		return nil, err
	}
	data, salt, err := s.EncryptEntry(b, recoveryAAD(folderID, keyID))
	if err != nil {
		return nil, fmt.Errorf("seal the recovery key record: %w", err)
	}
	return &SealedRecovery{Key: keyID, Data: data, Salt: salt}, nil
}

// OpenRecovery opens sr, sealed for the folder folderID, with s, the key
// of the key record sr.Key.
func OpenRecovery(s Sealer, folderID string, sr *SealedRecovery) (Recovery, error) {
	b, err := s.DecryptEntry(sr.Data, sr.Salt, recoveryAAD(folderID, sr.Key))
	if err != nil {
		return Recovery{}, fmt.Errorf("open the sync folder's recovery key record: %w", err)
	}
	var r Recovery
	if err := json.Unmarshal(b, &r); err != nil {
		return Recovery{}, fmt.Errorf("read the sync folder's recovery key record: %w", err)
	}
	if len(r.PublicKey) > maxRecoveryKey {
		return Recovery{}, errors.New("the sync folder's recovery key record has a key too long to be one")
	}
	return r, nil
}
