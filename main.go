package main

import (
	"crypto/rand"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"math/big"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/dgrijalva/jwt-go"
	_ "github.com/go-sql-driver/mysql"
	"github.com/gorilla/context"
	"github.com/gorilla/handlers"
	"github.com/gorilla/mux"
	"github.com/sendgrid/sendgrid-go"
	"github.com/sendgrid/sendgrid-go/helpers/mail"
	PaytmChecksum "github.com/venkatesh01071999ravi/go_learning/sendGrid/Paytm_Go_Checksum/paytm"
	"golang.org/x/crypto/bcrypt"
)

var db, err = sql.Open("mysql", "root:@tcp(127.0.0.1:3306)/sendgrid")

type history struct {
	Token string `json:"token"`
	Call  int    `json:"call"`
}

type user struct {
	Email    string `json:"email"`
	Password string `json:"pass"`
}

type token struct {
	Token string `json:"token"`
}

type sendmail struct {
	Token   string `json:"token"`
	Apikey  string `json:"api"`
	To      string `json:"to"`
	Subject string `json:"subject"`
	Body    string `json:"body"`
}

type paid struct {
	OrderId      string `json:"ORDERID"`
	Mid          string `json:"MID"`
	TxnId        string `json:"TXNID"`
	TxnAmount    string `json:"TXNAMOUNT"`
	PaymentMode  string `json:"PAYMENTMODE"`
	Currency     string `json:"CURRENCY"`
	TxnDate      string `json:"TXNDATE"`
	Status       string `json:"STATUS"`
	RespCode     string `json:"RESPCODE"`
	RespMsg      string `json:"RESPMSG"`
	Gateway      string `json:"GATEWAY"`
	BankTxnId    string `json:"BANKTXNID"`
	BankName     string `json:"BANKNAME"`
	CheckSumhash string `json:"CHECKSUMHASH"`
}

func extractClaims(tokenStr string) (jwt.MapClaims, bool, error) {
	token, err := jwt.Parse(tokenStr, func(token *jwt.Token) (interface{}, error) {

		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte("venki"), nil

	})

	if err != nil {

		return nil, false, err

	}

	claims, _ := token.Claims.(jwt.MapClaims)
	return claims, true, nil

}

func jwtverify(f func(w http.ResponseWriter, r *http.Request)) func(w http.ResponseWriter, r *http.Request) {

	return func(w http.ResponseWriter, r *http.Request) {

		var claim jwt.MapClaims
		var not bool
		var typeof error
		var mainerr string
		var req sendmail
		var hist history
		var jwttok token
		if r.URL.Path == "/fetch" || r.URL.Path == "/verify" || r.URL.Path == "/" {

			_ = json.NewDecoder(r.Body).Decode(&jwttok)
			claim, not, typeof = extractClaims(jwttok.Token)

		} else if r.URL.Path == "/send" {

			_ = json.NewDecoder(r.Body).Decode(&req)
			claim, not, typeof = extractClaims(req.Token)

		} else if r.URL.Path == "/history" {

			_ = json.NewDecoder(r.Body).Decode(&hist)
			claim, not, typeof = extractClaims(hist.Token)

		}

		if not == false {

			mainerr = typeof.Error()
			if mainerr != "Token is expired" {

				w.WriteHeader(http.StatusForbidden)

			} else {

				w.WriteHeader(http.StatusBadRequest)

			}
		} else {

			if r.URL.Path == "/fetch" || r.URL.Path == "/" || r.URL.Path == "/verify" {

				context.Set(r, "email", claim["user_mail"])
				f(w, r)

			} else if r.URL.Path == "/send" {

				context.Set(r, "api", req.Apikey)
				context.Set(r, "to", req.To)
				context.Set(r, "subject", req.Subject)
				context.Set(r, "body", req.Body)
				f(w, r)

			} else if r.URL.Path == "/history" {

				context.Set(r, "mail", claim["user_mail"])
				context.Set(r, "call", hist.Call)
				f(w, r)

			}

		}
	}

}

func tokenGenerator() string {
	b := make([]byte, 15)
	rand.Read(b)
	return fmt.Sprintf("%x", b)
}

func signup(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	var newuser user
	err = json.NewDecoder(r.Body).Decode(&newuser)
	var api string
	err = db.QueryRow("SELECT api_id FROM users where email=?", newuser.Email).Scan(&api)
	if err != nil {

		if err != sql.ErrNoRows {

			w.WriteHeader(http.StatusInternalServerError)

		}

	}
	if api == "" {

		hash, err := bcrypt.GenerateFromPassword([]byte(newuser.Password), bcrypt.DefaultCost)
		if err != nil {

			w.WriteHeader(http.StatusInternalServerError)

		}
		original := string(hash)
		a := tokenGenerator()
		_, err = db.Exec("INSERT INTO users(api_id,email,password) VALUES(?,?,?)", a, newuser.Email, original)
		if err != nil {

			fmt.Println(err)
			w.WriteHeader(http.StatusInternalServerError)

		}

	} else {

		w.WriteHeader(http.StatusBadRequest)

	}

}

func signin(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	var signuser user
	err = json.NewDecoder(r.Body).Decode(&signuser)
	var password string
	err = db.QueryRow("SELECT password FROM users where email=?", signuser.Email).Scan(&password)
	if err != nil {

		if err != sql.ErrNoRows {

			w.WriteHeader(http.StatusInternalServerError)

		} else if err == sql.ErrNoRows {

			w.WriteHeader(http.StatusBadRequest)

		}

	} else if err == nil {

		err := bcrypt.CompareHashAndPassword([]byte(password), []byte(signuser.Password))
		if err != nil {

			w.WriteHeader(http.StatusBadRequest)
		} else if err == nil {

			var err error
			//Creating Access Token
			os.Setenv("ACCESS_SECRET", "venki") //this should be in an env file
			atClaims := jwt.MapClaims{}
			atClaims["authorized"] = true
			atClaims["user_mail"] = signuser.Email
			atClaims["exp"] = time.Now().Add(time.Minute * 720).Unix()
			at := jwt.NewWithClaims(jwt.SigningMethodHS256, atClaims)
			token, err := at.SignedString([]byte(os.Getenv("ACCESS_SECRET")))
			if err != nil {

				w.WriteHeader(http.StatusInternalServerError)

			} else {

				json.NewEncoder(w).Encode(token)

			}

		}

	}
}

func fetch(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	email := fmt.Sprintf("%v", context.Get(r, "email"))
	var api string
	var count int
	_ = db.QueryRow("SELECT api_id,count FROM users WHERE email=?", email).Scan(&api, &count)
	if count == 2147483647 {

		acct := map[string]string{"premium": strconv.Itoa(1), "api": api, "count": "unlimited", "email": email}
		json.NewEncoder(w).Encode(&acct)

	} else {

		acct := map[string]string{"premium": strconv.Itoa(0), "api": api, "count": strconv.Itoa(count), "email": email}
		json.NewEncoder(w).Encode(&acct)

	}

}

func send(w http.ResponseWriter, r *http.Request) {

	w.Header().Set("Content-Type", "application/json")
	api := fmt.Sprintf("%v", context.Get(r, "api"))
	tos := fmt.Sprintf("%s", context.Get(r, "to"))
	sub := fmt.Sprintf("%v", context.Get(r, "subject"))
	body := fmt.Sprintf("%v", context.Get(r, "body"))
	currdate := time.Now()
	var fromsend string
	var count int
	_ = db.QueryRow("SELECT email,count FROM users where api_id=?", api).Scan(&fromsend, &count)
	if fromsend != "" {

		if count != 0 {

			from := mail.NewEmail(fromsend, "venkatesh@codingmart.com")
			subject := sub
			to := mail.NewEmail("", tos)
			plainTextContent := body
			htmlContent := body
			messages := mail.NewSingleEmail(from, subject, to, plainTextContent, htmlContent)
			client := sendgrid.NewSendClient("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")
			response, err := client.Send(messages)
			if err != nil {

				fmt.Println(err)
				w.WriteHeader(http.StatusInternalServerError)

			} else if response.StatusCode == 200 || response.StatusCode == 202 {

				_, err = db.Query("INSERT INTO mail_list(api_id,email_to,subject,message,date) VALUES(?,?,?,?,?)", api, tos, sub, body, currdate.Format("01-02-2006"))
				fmt.Println(err)
				if count != 2147483647 {

					currcount := count - 1
					_, _ = db.Query("UPDATE users SET count=? WHERE api_id=?", currcount, api)
					json.NewEncoder(w).Encode("Your mail is successfully sent")

				} else {

					json.NewEncoder(w).Encode("Your mail is successfully sent")

				}
			} else {

				w.WriteHeader(http.StatusInternalServerError)

			}

		} else {

			w.WriteHeader(http.StatusBadRequest)

		}
	} else {

		w.WriteHeader(http.StatusForbidden)

	}

}

func verify(w http.ResponseWriter, r *http.Request) {

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode("Success")
}

func histFunc(w http.ResponseWriter, r *http.Request) {

	w.Header().Set("Content-Type", "application/json")
	call := context.Get(r, "call")
	user := fmt.Sprintf("%v", context.Get(r, "mail"))
	var rows *sql.Rows
	var err error
	if call == 0 {

		rows, err = db.Query("SELECT No,email_to,subject,message,date FROM users INNER JOIN mail_list ON users.api_id = mail_list.api_id WHERE users.email=? ORDER BY No DESC LIMIT 4", user)
		if err != nil {

			w.WriteHeader(http.StatusInternalServerError)

		}
		defer rows.Close()

	} else {

		rows, err = db.Query("SELECT No,email_to,subject,message,date FROM users INNER JOIN mail_list ON users.api_id = mail_list.api_id WHERE users.email=? AND mail_list.No<? ORDER BY No DESC LIMIT 4", user, call)
		if err != nil {

			fmt.Println(err)
			w.WriteHeader(http.StatusInternalServerError)

		}
		defer rows.Close()

	}
	det := []interface{}{}
	for rows.Next() {

		var id int
		var email string
		var body string
		var message string
		var date string
		var inn []interface{}
		_ = rows.Scan(&id, &email, &body, &message, &date)
		inn = append(inn, id, email, body, message, date)
		det = append(det, inn)

	}
	json.NewEncoder(w).Encode(det)
}

func payment(w http.ResponseWriter, r *http.Request) {

	w.Header().Set("Content-Type", "text/html")
	params := mux.Vars(r)
	claims, _, _ := extractClaims(params["token"])
	email := fmt.Sprintf("%s", claims["user_mail"])
	rand, _ := rand.Int(rand.Reader, big.NewInt(1000))
	random := rand.String()
	paytmParams := map[string]string{
		"MID":              "AKLWEb63460936258085",
		"ORDER_ID":         "ORD" + random,
		"CUST_ID":          email,
		"INDUSTRY_TYPE_ID": "Retail",
		"CHANNEL_ID":       "WEB",
		"TXN_AMOUNT":       "1.00",
		"WEBSITE":          "WEBSTAGING",
		"CALLBACK_URL":     "http://localhost:8000/callback",
		"EMAIL":            "venkatesh@codingmart.com",
		"MOBILE_NO":        "9443376466",
		"PAYMENT_TYPE_ID":  "PPI",
	}

	paytmChecksum := PaytmChecksum.GenerateSignature(paytmParams, "iI9oku7BGrX_rDtJ")
	txnurl := "https://securegw-stage.paytm.in/order/process"
	formfield := ""
	for x, y := range paytmParams {

		formfield += fmt.Sprintf(`<input type="hidden" name=%s value=%s >`, x, y)

	}
	formfield += fmt.Sprintf(`<input type="hidden" name="CHECKSUMHASH" value=%s>`, paytmChecksum)
	html := fmt.Sprintf(`<html><body><center><h1>Please Wait do not refresh the page!!!</h1><center><form method="post" action=%s name="f1">%s</form><script type="text/javascript">document.f1.submit()</script></body></html>`, txnurl, formfield)
	fmt.Fprint(w, html)
	_, _ = db.Exec("INSERT INTO payments(email,OrderId,Status) VALUES(?,?,?)", email, "ORD"+random, "initiated")

}

func callback(w http.ResponseWriter, r *http.Request) {

	w.Header().Set("Content-Type", "text/html")
	parse := r.ParseForm()
	if parse != nil {

		fmt.Println(parse)

	}
	contents := r.Form
	fmt.Println(contents["ORDERID"][0])
	if contents["RESPCODE"][0] == "01" {
		fmt.Println(contents["ORDERID"][0])
		var email string
		_ = db.QueryRow("SELECT email FROM payments WHERE OrderId=?", contents["ORDERID"][0]).Scan(&email)
		_, _ = db.Exec(`UPDATE payments SET Status="successful" WHERE OrderId=?`, contents["ORDERID"][0])
		_, _ = db.Exec(`INSERT INTO ispremium(email) VALUES(?)`, email)
		_, _ = db.Exec("UPDATE users SET count=? WHERE email=?", 2147483647, email)
		fmt.Fprintf(w, `<html><body><script>alert("transaction successfull");window.location.href="http://localhost:3000/panel";</script></body></html>`)

	} else {
		_, _ = db.Exec(`UPDATE payments SET Status="failure" WHERE OrderId=?`, contents["ORDERID"][0])
		fmt.Fprintf(w, `<html><body><script>alert("transaction failed");window.location.href="http://localhost:3000/panel";</script></body></html>`)

	}

}

func main() {

	r := mux.NewRouter()
	r.HandleFunc("/signUp", signup).Methods("POST")
	r.HandleFunc("/", signin).Methods("POST")
	r.HandleFunc("/send", jwtverify(send)).Methods("POST")
	r.HandleFunc("/verify", jwtverify(verify)).Methods("POST")
	r.HandleFunc("/fetch", jwtverify(fetch)).Methods("POST")
	r.HandleFunc("/history", jwtverify(histFunc)).Methods("POST")
	r.HandleFunc("/payment/{token}", payment).Methods("GET")
	r.HandleFunc("/callback", callback).Methods("POST")
	fmt.Println("hosted")
	if err != nil {

		panic("could not connect to db")

	} else {

		fmt.Println("db connected")

	}
	headersOk := handlers.AllowedHeaders([]string{"X-Requested-With", "Content-Type", "x-www-form-urlencoded", "xhtml+xml"})
	originsOk := handlers.AllowedOrigins([]string{"*"})
	methodsOk := handlers.AllowedMethods([]string{"GET", "HEAD", "POST", "PUT", "OPTIONS"})

	log.Fatal(http.ListenAndServe(":8000", handlers.CORS(originsOk, headersOk, methodsOk)(r)))

}
