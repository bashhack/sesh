package syncfolder

import (
	"bytes"
	"encoding/json"
	"maps"
	"slices"
	"strings"
	"time"

	"github.com/bashhack/sesh/internal/secure"
	"github.com/bashhack/sesh/internal/vault"
)

// Typed is what this computer's user changed in an entry from one version
// (pre, the one agreed) to the next (post, sent with the count N), kept so
// it can be made again on another computer's version of the entry
// (Rebase): after a master password change taken here, only what was
// typed here is trusted, not what was taken from the folder under the old
// key, which anyone with the old password could have written.
//
// Of what's secret, the secret, notes and fields, it keeps only hashes
// (Forget): of what was typed, so it's made again from the entry here
// only while that's still what the entry has (From), and of what that
// replaced, to tell whether another version still has it. What isn't
// secret it keeps as it is.
type Typed struct {
	// Keys are what was typed: "name", "url", "folder", "mfa", "totp",
	// "notes", "secret", "file name", "deleted", "purged", "forgotten",
	// "field:<name>" and "tag:<tag>", names in lower case.
	Keys []string `json:"keys"`
	// Hash is, by key, the hash of the secret, notes or field replaced;
	// "" when it isn't known (forgotten since).
	Hash map[string]string `json:"hash,omitempty"`
	// Typed is, by key, the hash of the secret, notes or field typed.
	Typed map[string]string `json:"typed,omitempty"`
	// Contents are the hashes (ContentHash) of the versions typed over,
	// this one's and those of the earlier ones folded into it (Fold): a
	// deletion for good stands over any of them.
	Contents []string `json:"contents,omitempty"`
	// Pre holds what the typed values replaced, where that isn't secret:
	// the name, URL, folder, settings, trash state.
	Pre Record `json:"pre"`
	// Post holds the typed values that aren't secret only; the rest is
	// zero until From fills it in.
	Post Record `json:"post"`
	// N is the count of this computer's change it was sent with; 0 for
	// one not sent yet.
	N uint64 `json:"n,omitempty"`
	// Created says the entry was made here: pre was none.
	Created bool `json:"created,omitempty"`
}

// unknown stands for a replaced value no version holds as it was: what
// Rebase gives a merge as the base where a typed value replaced one it
// can't tell, so both sides count as changed.
const unknown = "\x00sesh: unknown"

// Has says whether t typed key.
func (t *Typed) Has(key string) bool { return slices.Contains(t.Keys, key) }

func (t *Typed) drop(key string) {
	t.Keys = slices.DeleteFunc(t.Keys, func(k string) bool { return k == key })
	delete(t.Hash, key)
	delete(t.Typed, key)
}

// Diff is what was typed from pre (nil for an entry made here) to post.
func Diff(pre, post *Record) *Typed {
	t := &Typed{Hash: map[string]string{}, Typed: map[string]string{}, Created: pre == nil}
	if pre == nil || !pre.Purged.IsZero() {
		pre = &Record{}
	}
	t.Contents = []string{ContentHash(pre)}
	if !post.Purged.IsZero() {
		if pre.Kind != "" {
			t.Keys = []string{"purged"}
			t.Post.Purged = post.Purged
		}
		return t
	}
	t.Post.Changed, t.Post.Computer = post.Changed, post.Computer
	if pre.Kind != post.Kind || pre.Service != post.Service || pre.Username != post.Username {
		t.Keys = append(t.Keys, "name")
		t.Pre.Kind, t.Pre.Service, t.Pre.Username = pre.Kind, pre.Service, pre.Username
		t.Post.Kind, t.Post.Service, t.Post.Username = post.Kind, post.Service, post.Username
	}
	if pre.URL != post.URL {
		t.Keys = append(t.Keys, "url")
		t.Pre.URL, t.Post.URL = pre.URL, post.URL
	}
	if pre.Folder != post.Folder {
		t.Keys = append(t.Keys, "folder")
		t.Pre.Folder, t.Post.Folder = pre.Folder, post.Folder
	}
	if pre.Settings.AWSMFADevice != post.Settings.AWSMFADevice {
		t.Keys = append(t.Keys, "mfa")
		t.Pre.Settings.AWSMFADevice, t.Post.Settings.AWSMFADevice = pre.Settings.AWSMFADevice, post.Settings.AWSMFADevice
	}
	if pre.Settings.TOTP != post.Settings.TOTP {
		t.Keys = append(t.Keys, "totp")
		t.Pre.Settings.TOTP, t.Post.Settings.TOTP = pre.Settings.TOTP, post.Settings.TOTP
	}
	if !bytes.Equal(pre.Notes, post.Notes) {
		t.Keys = append(t.Keys, "notes")
		t.Hash["notes"], t.Typed["notes"] = Forget(pre.Notes), Forget(post.Notes)
	}
	if !bytes.Equal(pre.Secret, post.Secret) {
		t.Keys = append(t.Keys, "secret")
		t.Hash["secret"], t.Typed["secret"] = Forget(pre.Secret), Forget(post.Secret)
		t.Post.Updated, t.Post.SetAt = post.Updated, post.SetAt
		t.Pre.Settings.FileName, t.Post.Settings.FileName = pre.Settings.FileName, post.Settings.FileName
	} else if pre.Settings.FileName != post.Settings.FileName {
		t.Keys = append(t.Keys, "file name")
		t.Pre.Settings.FileName, t.Post.Settings.FileName = pre.Settings.FileName, post.Settings.FileName
	}
	if !pre.Deleted.Equal(post.Deleted) {
		t.Keys = append(t.Keys, "deleted")
		t.Pre.Deleted, t.Post.Deleted = pre.Deleted, post.Deleted
	}
	for _, name := range fieldNames(pre.Fields, post.Fields) {
		b, inB := findField(pre.Fields, name)
		p, inP := findField(post.Fields, name)
		if inB == inP && (!inB || sameField(b, p)) {
			continue
		}
		key := "field:" + strings.ToLower(name)
		t.Keys = append(t.Keys, key)
		t.Hash[key], t.Typed[key] = fieldHash(b, inB), fieldHash(p, inP)
	}
	preTags, postTags := vault.NormalizeTags(pre.Tags), vault.NormalizeTags(post.Tags)
	for _, tag := range vault.NormalizeTags(slices.Concat(preTags, postTags)) {
		if slices.Contains(preTags, tag) != slices.Contains(postTags, tag) {
			t.Keys = append(t.Keys, "tag:"+tag)
			if slices.Contains(postTags, tag) {
				t.Post.Tags = append(t.Post.Tags, tag)
			}
		}
	}
	for _, f := range post.Forgotten {
		if !slices.ContainsFunc(pre.Forgotten, func(g Forgotten) bool { return g.Hash == f.Hash && !f.At.After(g.At) }) {
			t.Post.Forgotten = append(t.Post.Forgotten, f)
		}
	}
	if len(t.Post.Forgotten) > 0 {
		t.Keys = append(t.Keys, "forgotten")
	}
	return t
}

// From is t made from local, the entry here: the typed secret, notes and
// fields as local has them, and only what local still has as it was
// typed. What it no longer has was replaced since, by an edit here (kept
// in a later Typed) or a change taken and merged: not made again.
func (t *Typed) From(local *Record) *Typed {
	c := *t
	c.Keys, c.Hash, c.Typed = slices.Clone(t.Keys), maps.Clone(t.Hash), maps.Clone(t.Typed)
	c.Post.Fields, c.Post.Tags = nil, slices.Clone(t.Post.Tags)
	for _, k := range t.Keys {
		switch {
		case k == "purged" || k == "forgotten":
		case k == "notes":
			if Forget(local.Notes) != t.Typed[k] {
				c.drop(k)
				continue
			}
			c.Post.Notes = bytes.Clone(local.Notes)
		case k == "secret":
			if !local.Purged.IsZero() || Forget(local.Secret) != t.Typed[k] {
				c.drop(k)
				continue
			}
			c.Post.Secret = bytes.Clone(local.Secret)
		case strings.HasPrefix(k, "field:"):
			f, in := findField(local.Fields, strings.TrimPrefix(k, "field:"))
			if fieldHash(f, in) != t.Typed[k] {
				c.drop(k)
				continue
			}
			if in {
				f.Value = bytes.Clone(f.Value)
				c.Post.Fields = append(c.Post.Fields, f)
			}
		case strings.HasPrefix(k, "tag:"):
			tag := strings.TrimPrefix(k, "tag:")
			if slices.Contains(vault.NormalizeTags(local.Tags), tag) != slices.Contains(t.Post.Tags, tag) {
				c.drop(k)
			}
		default:
			if !local.Purged.IsZero() || scalar(local, k) != scalar(&t.Post, k) {
				c.drop(k)
			}
		}
	}
	return &c
}

// Empty says whether t typed nothing.
func (t *Typed) Empty() bool { return len(t.Keys) == 0 }

// Fold takes t, typed after each of olds, in: each typed value is kept
// only by the latest that typed it, olds left with nothing are dropped,
// and a deletion for good drops them all. A typed value replacing one an
// old typed takes that one's replaced value as its own, as nothing came
// between. What t takes the place of passes on to it: the versions typed
// over, and that the entry was made here. Secrets t forgets are taken out
// of the olds.
func Fold(olds []*Typed, t *Typed) []*Typed {
	takeOver := func(o *Typed) {
		t.Contents = append(slices.Clone(o.Contents), t.Contents...)
		t.Created = t.Created || o.Created
	}
	if t.Has("purged") {
		for _, o := range slices.Backward(olds) {
			takeOver(o)
		}
		return []*Typed{t}
	}
	forgot := func(h string) bool {
		return h != "" && slices.ContainsFunc(t.Post.Forgotten, func(f Forgotten) bool { return f.Hash == h })
	}
	var out []*Typed
	for _, o := range olds {
		for _, k := range slices.Clone(t.Keys) {
			if k == "forgotten" || !o.Has(k) {
				continue
			}
			if t.Hash[k] != "" && t.Hash[k] == o.postHash(k) {
				t.Hash[k] = o.Hash[k]
			} else if k == "name" || k == "url" || k == "folder" || k == "mfa" || k == "totp" || k == "file name" || k == "deleted" {
				if o.postScalar(k) == t.preScalar(k) {
					t.setPreScalar(k, o)
				}
			}
			o.drop(k)
			o.clearPost(k)
		}
		if o.Has("secret") && forgot(o.Typed["secret"]) {
			o.drop("secret")
		}
		for k, h := range o.Hash {
			if forgot(h) {
				o.Hash[k] = ""
			}
		}
		if o.Empty() {
			takeOver(o)
			continue
		}
		out = append(out, o)
	}
	for k, h := range t.Hash {
		if forgot(h) {
			t.Hash[k] = ""
		}
	}
	return append(out, t)
}

// postHash is the hash of what t typed for key k, as Hash keeps what it
// replaced.
func (t *Typed) postHash(k string) string { return t.Typed[k] }

// scalar is the value of key k (one not secret) in r, to compare.
func scalar(r *Record, k string) string {
	var v any
	switch k {
	case "name":
		v = [3]string{string(r.Kind), r.Service, r.Username}
	case "url":
		v = r.URL
	case "folder":
		v = r.Folder
	case "mfa":
		v = r.Settings.AWSMFADevice
	case "totp":
		v = r.Settings.TOTP
	case "file name":
		v = r.Settings.FileName
	case "deleted":
		v = r.Deleted
	}
	b, _ := json.Marshal(v) //nolint:errcheck // plain values
	return string(b)
}

func (t *Typed) postScalar(k string) string { return scalar(&t.Post, k) }
func (t *Typed) preScalar(k string) string  { return scalar(&t.Pre, k) }

// setPreScalar takes o's replaced value for key k as t's.
func (t *Typed) setPreScalar(k string, o *Typed) {
	setScalar(&t.Pre, &o.Pre, k)
}

// setScalar copies key k's value from src to dst.
func setScalar(dst, src *Record, k string) {
	switch k {
	case "name":
		dst.Kind, dst.Service, dst.Username = src.Kind, src.Service, src.Username
	case "url":
		dst.URL = src.URL
	case "folder":
		dst.Folder = src.Folder
	case "mfa":
		dst.Settings.AWSMFADevice = src.Settings.AWSMFADevice
	case "totp":
		dst.Settings.TOTP = src.Settings.TOTP
	case "file name":
		dst.Settings.FileName = src.Settings.FileName
	case "deleted":
		dst.Deleted = src.Deleted
	}
}

// clearPost zeroes what t typed for key k.
func (t *Typed) clearPost(k string) {
	switch {
	case k == "notes":
		t.Post.Notes = nil
	case k == "secret":
		t.Post.Secret, t.Post.Updated, t.Post.SetAt = nil, time.Time{}, time.Time{}
	case strings.HasPrefix(k, "field:"):
		name := strings.TrimPrefix(k, "field:")
		t.Post.Fields = slices.DeleteFunc(t.Post.Fields, func(f Field) bool { return strings.EqualFold(f.Name, name) })
	case strings.HasPrefix(k, "tag:"):
		tag := strings.TrimPrefix(k, "tag:")
		t.Post.Tags = slices.DeleteFunc(t.Post.Tags, func(g string) bool { return g == tag })
	default:
		setScalar(&t.Post, &Record{}, k)
	}
}

// Rebase is what to merge to make t's typed changes again on r, another
// computer's version of the entry (not deleted for good): a base and an
// ours (its own) that both hold r's values for what t didn't type, so a
// merge with r as theirs (Merge(base, ours, r)) keeps r's for those and
// settles only what was typed. Where t typed a value replacing one that r
// no longer holds as it was, the base holds a value neither has, so the
// merge settles both as changed. Ours is made when t was typed, here.
func (t *Typed) Rebase(r *Record) (base, ours *Record) {
	base, ours = copyOf(r).Record, copyOf(r).Record
	ours.Changed, ours.Computer = t.Post.Changed, t.Post.Computer
	ours.Forgotten = mergeForgotten(r.Forgotten, t.Post.Forgotten)
	for _, k := range t.Keys {
		switch {
		case k == "notes":
			base.Notes = rebased(r.Notes, t.Hash[k])
			ours.Notes = bytes.Clone(t.Post.Notes)
		case k == "secret":
			base.Secret = rebased(r.Secret, t.Hash[k])
			ours.Secret = bytes.Clone(t.Post.Secret)
			ours.Updated, ours.SetAt = t.Post.Updated, t.Post.SetAt
			base.Settings.FileName, ours.Settings.FileName = t.Pre.Settings.FileName, t.Post.Settings.FileName
		case strings.HasPrefix(k, "field:"):
			name := strings.TrimPrefix(k, "field:")
			rf, inR := findField(r.Fields, name)
			base.Fields = slices.DeleteFunc(base.Fields, func(f Field) bool { return strings.EqualFold(f.Name, name) })
			switch {
			case fieldHash(rf, inR) == t.Hash[k]:
				if inR {
					base.Fields = append(base.Fields, rf)
				}
			default:
				base.Fields = append(base.Fields, Field{Name: name, Value: []byte(unknown)})
			}
			ours.Fields = slices.DeleteFunc(ours.Fields, func(f Field) bool { return strings.EqualFold(f.Name, name) })
			if pf, inP := findField(t.Post.Fields, name); inP {
				pf.Value = bytes.Clone(pf.Value)
				ours.Fields = append(ours.Fields, pf)
			}
		case strings.HasPrefix(k, "tag:"):
			tag := strings.TrimPrefix(k, "tag:")
			without := func(tags []string) []string {
				return slices.DeleteFunc(slices.Clone(tags), func(g string) bool { return strings.EqualFold(g, tag) })
			}
			base.Tags, ours.Tags = without(base.Tags), without(ours.Tags)
			if slices.Contains(t.Post.Tags, tag) {
				ours.Tags = append(ours.Tags, tag)
			} else {
				base.Tags = append(base.Tags, tag)
			}
		case k == "forgotten" || k == "purged":
		default:
			setScalar(base, &t.Pre, k)
			setScalar(ours, &t.Post, k)
		}
	}
	return base, ours
}

// rebased is the base value for a typed one whose replaced value hashed
// to h: r's, when it's that one; else one neither side has.
func rebased(r []byte, h string) []byte {
	if h != "" && Forget(r) == h {
		return bytes.Clone(r)
	}
	return []byte(unknown)
}

// ContentHash is a hash of what r's entry holds (as edited compares), to
// tell later whether another version still holds just that.
func ContentHash(r *Record) string {
	b, _ := json.Marshal(struct { //nolint:errcheck,gosec // plain values; hashed, then zeroed, never written
		Kind              vault.Kind
		Service, Username string
		URL, Folder       string
		Secret, Notes     []byte
		Tags              []string
		Fields            []Field
		Settings          vault.Settings
	}{r.Kind, r.Service, r.Username, r.URL, r.Folder, r.Secret, r.Notes, vault.NormalizeTags(r.Tags), r.Fields, r.Settings})
	defer secure.SecureZeroBytes(b)
	return Forget(b)
}

// fieldNames are the names of the fields in a and b, each once, in any
// case.
func fieldNames(a, b []Field) []string {
	var names []string
	for _, f := range slices.Concat(a, b) {
		if !slices.ContainsFunc(names, func(n string) bool { return strings.EqualFold(n, f.Name) }) {
			names = append(names, f.Name)
		}
	}
	return names
}

func findField(fs []Field, name string) (Field, bool) {
	i := slices.IndexFunc(fs, func(f Field) bool { return strings.EqualFold(f.Name, name) })
	if i < 0 {
		return Field{}, false
	}
	return fs[i], true
}

// fieldHash is the hash Typed keeps of a field (in says it's there).
func fieldHash(f Field, in bool) string {
	if !in {
		return Forget([]byte("\x00absent"))
	}
	b, _ := json.Marshal(f) //nolint:errcheck // plain values
	defer secure.SecureZeroBytes(b)
	return Forget(b)
}
