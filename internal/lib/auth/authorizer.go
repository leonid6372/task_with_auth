package auth

import (
	"context"
	"encoding/base64"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"time"

	resp "auth/internal/lib/api/response"
	"auth/internal/lib/logger/sl"

	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/render"
	"github.com/gofrs/uuid"
	"github.com/golang-jwt/jwt"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"golang.org/x/crypto/bcrypt"
)

type Authorizer struct {
	SecretKey []byte
	TokenTTL  time.Duration
}

func NewAuthorizer(secret []byte, tokenTTL time.Duration) *Authorizer {
	return &Authorizer{
		SecretKey: secret,
		TokenTTL:  tokenTTL,
	}
}

type Credentials struct {
	GUID string `json:"guid" validate:"required"`
}

type Claims struct {
	GUID string `json:"guid"`
	jwt.StandardClaims
}

type Record struct {
	GIUD         string `bson:"guid"`
	RefreshToken string `bson:"refresh_token"`
}

func (a *Authorizer) LogIn(ctx context.Context, log *slog.Logger, storage *mongo.Collection) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		const op = "lib.auth.authorizer.Login"

		log := log.With(
			slog.String("op", op),
			slog.String("request_id", middleware.GetReqID(r.Context())),
		)

		var cred Credentials

		// Decode credentials from request
		err := render.DecodeJSON(r.Body, &cred)
		// Unique error for empty request
		if errors.Is(err, io.EOF) {
			log.Error("empty request")
			w.WriteHeader(400)
			render.JSON(w, r, resp.Error("empty request"))
			return
		}
		if err != nil {
			log.Error("failed to decode request", sl.Err(err))
			w.WriteHeader(400)
			render.JSON(w, r, resp.Error("failed to decode request: "+err.Error()))
			return
		}

		// TO DO: check is sent guid allowed

		// Set JWT claims
		expirationTime := time.Now().Add(a.TokenTTL)
		claims := &Claims{
			GUID: cred.GUID,
			StandardClaims: jwt.StandardClaims{
				ExpiresAt: expirationTime.Unix(),
			},
		}

		// Generate JWT with SHA512 algorithm
		access := jwt.NewWithClaims(jwt.SigningMethodHS512, claims)
		strAccess, err := access.SignedString(a.SecretKey)
		if err != nil {
			log.Error("failed to create jwt", sl.Err(err))
			w.WriteHeader(500)
			render.JSON(w, r, resp.Error("failed to create jwt: "+err.Error()))
			return
		}

		// Generate Universally Unique Identifier as refresh token and hash it using bcrypt method
		refresh := uuid.Must(uuid.NewV4()).Bytes()
		hashedRefresh, err := bcrypt.GenerateFromPassword(refresh, bcrypt.DefaultCost)
		if err != nil {
			log.Error("failed to hash refresh token", sl.Err(err))
			w.WriteHeader(500)
			render.JSON(w, r, resp.Error("failed to hash refresh token: "+err.Error()))
			return
		}

		// Save refresh token in mongoDB
		filter := bson.D{{"guid", cred.GUID}}
		record := Record{GIUD: cred.GUID, RefreshToken: string(hashedRefresh)}
		result := storage.FindOne(ctx, filter) // Check if record is already exist
		if result.Err() == mongo.ErrNoDocuments {
			_, err = storage.InsertOne(ctx, record)
			if err != nil {
				log.Error("failed to save refresh token in mongoDB", sl.Err(err))
				w.WriteHeader(500)
				render.JSON(w, r, resp.Error("failed to save refresh token in mongoDB: "+err.Error()))
				return
			}
		} else {
			_, err = storage.ReplaceOne(ctx, filter, record)
			if err != nil {
				log.Error("failed to save refresh token in mongoDB", sl.Err(err))
				w.WriteHeader(500)
				render.JSON(w, r, resp.Error("failed to save refresh token in mongoDB: "+err.Error()))
				return
			}
		}

		// Write tokens in cookie
		http.SetCookie(w,
			&http.Cookie{
				Name:  "access_token",
				Value: strAccess,
			})
		http.SetCookie(w,
			&http.Cookie{
				Name:  "refresh_token",
				Value: base64.StdEncoding.EncodeToString(refresh), // Send in base64 format
			})

		log.Info("user successfully logged in")

		render.JSON(w, r, resp.OK())
	}
}

func (a *Authorizer) Refresh(ctx context.Context, log *slog.Logger, storage *mongo.Collection) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		const op = "lib.auth.authorizer.Refresh"

		log := log.With(
			slog.String("op", op),
			slog.String("request_id", middleware.GetReqID(r.Context())),
		)

		// Read JWT from cookie
		cookie, err := r.Cookie("access_token")
		if err != nil {
			switch {
			case errors.Is(err, http.ErrNoCookie):
				log.Error("cookie not found")
				w.WriteHeader(http.StatusBadRequest)
				render.JSON(w, r, resp.Error("cookie not found"))
				return
			default:
				log.Error("server error", sl.Err(err))
				w.WriteHeader(http.StatusInternalServerError)
				render.JSON(w, r, resp.Error("server error: "+err.Error()))
				return
			}
		}
		oldJWT := cookie.Value

		// Decode JWT
		claims := &Claims{}
		access, err := jwt.ParseWithClaims(oldJWT, claims,
			func(t *jwt.Token) (interface{}, error) {
				return a.SecretKey, nil
			})
		if err == jwt.ErrSignatureInvalid {
			log.Error("invalid JWT signature", sl.Err(err))
			w.WriteHeader(401)
			render.JSON(w, r, resp.Error("invalid JWT signature: "+err.Error()))
			return
		}

		var record Record

		// Check GUID from JWT in mongoDB
		filter := bson.D{{"guid", claims.GUID}}
		err = storage.FindOne(ctx, filter).Decode(&record)
		if err == mongo.ErrNoDocuments {
			log.Error("guid not found in DB")
			w.WriteHeader(401)
			render.JSON(w, r, resp.Error("guid not found in DB"))
			return
		}
		if err != nil {
			log.Error("mongoDB error while searching", sl.Err(err))
			w.WriteHeader(500)
			render.JSON(w, r, resp.Error("mongoDB error while searching: "+err.Error()))
			return
		}

		// Read refresh token from cookie
		cookie, err = r.Cookie("refresh_token")
		if err != nil {
			switch {
			case errors.Is(err, http.ErrNoCookie):
				log.Error("cookie not found")
				w.WriteHeader(http.StatusBadRequest)
				render.JSON(w, r, resp.Error("cookie not found"))
				return
			default:
				log.Error("server error", sl.Err(err))
				w.WriteHeader(http.StatusInternalServerError)
				render.JSON(w, r, resp.Error("server error: "+err.Error()))
				return
			}
		}
		oldRefresh, err := base64.StdEncoding.DecodeString(cookie.Value) // Decode received base64 format
		if err != nil {
			log.Error("decode refresh token from cookie error", sl.Err(err))
			w.WriteHeader(500)
			render.JSON(w, r, resp.Error("decode refresh token from cookie error: "+err.Error()))
			return
		}

		// Check is refresh token valid
		if err := bcrypt.CompareHashAndPassword([]byte(record.RefreshToken), []byte(oldRefresh)); err != nil {
			log.Error("refresh token is not valid", sl.Err(err))
			w.WriteHeader(401)
			render.JSON(w, r, resp.Error("refresh token is not valid: "+err.Error()))
			return
		}

		// Update JWT
		expirationTime := time.Now().Add(a.TokenTTL)
		claims = &Claims{
			GUID: record.GIUD,
			StandardClaims: jwt.StandardClaims{
				ExpiresAt: expirationTime.Unix(),
			},
		}
		access = jwt.NewWithClaims(jwt.SigningMethodHS512, claims)
		strAccess, err := access.SignedString(a.SecretKey)
		if err != nil {
			log.Error("failed to create jwt", sl.Err(err))
			w.WriteHeader(500)
			render.JSON(w, r, resp.Error("failed to create jwt: "+err.Error()))
			return
		}

		// Update refresh token
		refresh := uuid.Must(uuid.NewV4()).Bytes()
		hashedRefresh, err := bcrypt.GenerateFromPassword(refresh, bcrypt.DefaultCost)
		if err != nil {
			log.Error("failed to hash refresh token", sl.Err(err))
			w.WriteHeader(500)
			render.JSON(w, r, resp.Error("failed to hash refresh token: "+err.Error()))
			return
		}

		// Find old refresh token in mongoDB and update by new refresh token
		filter = bson.D{{"refresh_token", record.RefreshToken}}
		record = Record{GIUD: claims.GUID, RefreshToken: string(hashedRefresh)}
		result, err := storage.ReplaceOne(ctx, filter, record)
		if err != nil {
			log.Error("mongoDB error while replacing", sl.Err(err))
			w.WriteHeader(500)
			render.JSON(w, r, resp.Error("mongoDB error while replacing: "+err.Error()))
			return
		}
		if result.MatchedCount == 0 {
			log.Error("refresh token not found in DB")
			w.WriteHeader(401)
			render.JSON(w, r, resp.Error("refresh token not found in DB"))
			return
		}

		// Write new tokens in cookie
		http.SetCookie(w,
			&http.Cookie{
				Name:  "access_token",
				Value: strAccess,
			})
		http.SetCookie(w,
			&http.Cookie{
				Name:  "refresh_token",
				Value: base64.StdEncoding.EncodeToString(refresh), // Send in base64 format
			})

		log.Info("tokens successfully updated")

		render.JSON(w, r, resp.OK())
	}
}

func (a *Authorizer) Authorize(ctx context.Context, log *slog.Logger, storage *mongo.Collection) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			const op = "lib.auth.authorizer.Authorize"

			log := log.With(
				slog.String("op", op),
				slog.String("request_id", middleware.GetReqID(r.Context())),
			)

			// Read JWT from cookie
			cookie, err := r.Cookie("access_token")
			if err != nil {
				switch {
				case errors.Is(err, http.ErrNoCookie):
					log.Error("cookie not found")
					w.WriteHeader(http.StatusBadRequest)
					render.JSON(w, r, resp.Error("cookie not found"))
					return
				default:
					log.Error("server error", sl.Err(err))
					w.WriteHeader(http.StatusInternalServerError)
					render.JSON(w, r, resp.Error("server error: "+err.Error()))
					return
				}
			}
			access := cookie.Value

			// Decode and verify JWT
			claims := &Claims{}
			tkn, err := jwt.ParseWithClaims(access, claims,
				func(t *jwt.Token) (interface{}, error) {
					return a.SecretKey, nil
				})
			if err != nil {
				if err == jwt.ErrSignatureInvalid {
					log.Error("invalid JWT signature", sl.Err(err))
					w.WriteHeader(401)
					render.JSON(w, r, resp.Error("invalid JWT signature: "+err.Error()))
					return
				}
				log.Error("verifying token error", sl.Err(err))
				w.WriteHeader(401)
				render.JSON(w, r, resp.Error("verifying token error: "+err.Error()))
				return
			}
			if !tkn.Valid {
				log.Error("JWT is not valid")
				w.WriteHeader(400)
				render.JSON(w, r, resp.Error("JWT is not valid"))
				return
			}

			log.Info("authorization success")

			next.ServeHTTP(w, r)
		})
	}
}
