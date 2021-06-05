package secrets

import (
	"container/heap"
	"crypto/sha1"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"
)

func CreateSecret(UploadedSecret *AllSecrets, SecretContent string, ExpireAfterViews, ExpireAfterTime int32) (Secret, error) {
	secret := new(Secret)
	secret.SecretText = SecretContent
	secret.RemainingViews = ExpireAfterViews

	// try up to 9 times to find unused hash
	for i := 0; i < 9; i++ {
		secret.CreatedAt = time.Now()
		if ExpireAfterTime > 0 {
			secret.ExpiresAt = secret.CreatedAt.Add(time.Minute * time.Duration(ExpireAfterTime))
			secret.doesExpire = true
		} else {
			secret.doesExpire = false
		}
		secret.Hash = FHash(secret)

		// if hash not used put pointer to secret in map
		UploadedSecret.mu.Lock()
		if _, ok := UploadedSecret.mp[secret.Hash]; !ok {

			UploadedSecret.mp[secret.Hash] = secret
			UploadedSecret.mu.Unlock()

			UploadedSecret.PqMux.Lock()
			heap.Push(&UploadedSecret.pq, secret)
			UploadedSecret.PqMux.Unlock()
			return *secret, nil
		}
		UploadedSecret.mu.Unlock()
	}
	return *secret, errors.New("creating secret: can't find space in map")
}

func FHash(secret *Secret) string {
	// join content of secret with it's time of creation
	s := strings.Join([]string{secret.SecretText, secret.CreatedAt.Format(time.RFC3339Nano)}, "")

	h := sha1.New()
	h.Write([]byte(s))
	HashedSecret := h.Sum(nil)

	// return hash as base 16, with lower-case letters
	return fmt.Sprintf("%x", HashedSecret)
}

func WriteSecret(w http.ResponseWriter, secret Secret) {
	SecretJson, err := json.Marshal(secret)
	if err != nil {
		log.Println(err)
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Write(SecretJson)
}

func DeleteExpired(UploadedSecret *AllSecrets, CrrTime time.Time) {
	var Scr *Secret
	UploadedSecret.PqMux.Lock()
	defer UploadedSecret.PqMux.Unlock()

	// stop if queue is empty
	for UploadedSecret.pq.Len() > 0 {
		// finding first to delete secret that hasn't been deleted yet(by limit of views)
		for Scr = heap.Pop(&UploadedSecret.pq).(*Secret); Scr == nil; Scr = heap.Pop(&UploadedSecret.pq).(*Secret) {
		}

		// when all expired secrets are deleted return current secret to queue and stop
		if !Scr.doesExpire || CrrTime.Before(Scr.ExpiresAt) {
			heap.Push(&UploadedSecret.pq, Scr)
			break
		}

		//free space in map
		UploadedSecret.mu.Lock()
		delete(UploadedSecret.mp, Scr.Hash)
		UploadedSecret.mu.Unlock()

		//delete expired secret
		Scr = nil
	}
}

func FindSecret(UploadedSecret *AllSecrets, w http.ResponseWriter, Hash string) {
	UploadedSecret.mu.Lock()
	defer UploadedSecret.mu.Unlock()
	UploadedSecret.PqMux.Lock()
	defer UploadedSecret.PqMux.Unlock()

	if Scr, ok := UploadedSecret.mp[Hash]; ok && Scr != nil {
		//response
		Scr.RemainingViews--
		WriteSecret(w, *Scr)

		if Scr.RemainingViews <= 0 {
			//free space in map
			delete(UploadedSecret.mp, Hash)
		}

	} else {
		//free space in map
		delete(UploadedSecret.mp, Hash)

		w.WriteHeader(http.StatusNotFound)
	}
}
