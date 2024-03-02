package main

import (
	"context"
	"crypto/rand"
	"database/sql"
	"fmt"
	"gorm.io/gorm"
	"html/template"
	"io"
	"math/big"
	"net/http"
	"net/smtp"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	_ "github.com/lib/pq"
	"github.com/sirupsen/logrus"
	"golang.org/x/time/rate"
)

// Product structure represents a product in the store
type Task struct {
	gorm.Model
	Title     string
	Completed bool
}

// User structure represents a user in the system
type User struct {
	Username string
	Email    string
	Password string
	Role     string
	otp      string
}

var (
	db        *sql.DB
	log       *logrus.Logger
	limiter   = rate.NewLimiter(1, 3) // Rate limit of 1 request per second with a burst of 3 requests
	templates = template.Must(template.ParseGlob("templates/*.html"))
)

func initDB() *sql.DB {
	connStr := "user=postgres password=Aruzhan7 dbname=amina sslmode=disable"
	db, err := sql.Open("postgres", connStr)
	if err != nil {
		log.Fatal("Error opening database connection:", err)
		panic(err)
	}

	err = db.Ping()
	if err != nil {
		log.Fatal("Error connecting to the database:", err)
		panic(err)
	}

	log.Info("Connected to the database")

	// Create the users and products table if it doesn't exist
	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS users (
		username TEXT PRIMARY KEY,
		email TEXT UNIQUE,
		password TEXT,
		role TEXT,
		otp TEXT
	); CREATE TABLE IF NOT EXISTS tasks (
		title TEXT,
		completed BOOLEAN
	);`)
	if err != nil {
		log.Fatal(err)
	}

	return db
}

func fetchProductsFromDB(filter, sortBy string, page, pageSize int) ([]Task, error) {
	var tasks []Task

	var query string
	var args []interface{}

	if filter != "" {
		query = "SELECT title, completed FROM tasks WHERE name ILIKE $1"
		args = append(args, "%"+filter+"%")
	} else {
		query = "SELECT title, completed FROM tasks"
	}

	if sortBy != "" {
		if sortBy == "title" {
			query += " ORDER BY title"
		} else {
			query += " ORDER BY " + sortBy
		}
	}

	if filter != "" {
		query += " LIMIT $2 OFFSET $3"
		args = append(args, int64(pageSize), int64((page-1)*pageSize))
	} else {
		// Вычисляем смещение на основе количества элементов на странице (pageSize) и номера страницы
		offset := (page - 1) * pageSize

		// Определяем значение для смещения (offset)
		if offset > 0 {
			query += " LIMIT $1 OFFSET $" + strconv.Itoa(len(args)+1)
			args = append(args, int64(pageSize), int64(offset))
		} else {
			query += " LIMIT $1 OFFSET $2"
			args = append(args, int64(pageSize), int64(offset))
		}
	}

	rows, err := db.Query(query, args...)
	if err != nil {
		log.Error("Error fetching tasks from the database:", err)
		return nil, err
	}
	defer rows.Close()

	for rows.Next() {
		var t Task
		if err := rows.Scan(&t.Title, &t.Completed); err != nil {
			log.Error("Error scanning task row:", err)
			continue
		}
		tasks = append(tasks, t)
	}

	if err := rows.Err(); err != nil {
		log.Error("Error iterating over task rows:", err)
		return nil, err
	}

	return tasks, nil
}

// AuthMiddleware is a middleware to check if the user is authenticated and has the admin role
func AuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check authentication
		cookie, err := r.Cookie("username")
		if err != nil {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}

		username := cookie.Value

		// Fetch user from the database based on the username
		var user User
		err = db.QueryRow("SELECT username, email, role FROM users WHERE username = $1", username).Scan(&user.Username, &user.Email, &user.Role)
		if err != nil {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}

		// Check if the user has admin role
		if user.Role != "admin" {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		// Call the next handler
		next.ServeHTTP(w, r)
	})
}

func sendEmail(to, subject, body string) error {
	from := "aminamukanova2701@gmail.com"
	password := "ezzb rglv dqmz zkea"
	smtpHost := "smtp.gmail.com"
	smtpPort := "587"

	// Compose the email message
	message := "From: " + from + "\n" +
		"To: " + to + "\n" +
		"Subject: " + subject + "\n\n" +
		body

	// Connect to the SMTP server
	auth := smtp.PlainAuth("", from, password, smtpHost)
	err := smtp.SendMail(smtpHost+":"+smtpPort, auth, from, []string{to}, []byte(message))
	if err != nil {
		return err
	}

	return nil
}

// GenerateOTP generates a random OTP consisting of 6 digits
func GenerateOTP() string {
	randomNum, err := rand.Int(rand.Reader, big.NewInt(900000))
	if err != nil {
		panic(err)
	}
	randomNum.Add(randomNum, big.NewInt(100000))
	return randomNum.String()
}

func IsLoggedIn(r *http.Request) bool {
	cookie, err := r.Cookie("username")
	if err == nil && cookie != nil && cookie.Value != "" {
		return true
	}
	return false
}

func RegisterHandler(w http.ResponseWriter, r *http.Request) {
	// Parse the HTML template file
	tmpl := templates.Lookup("register.html")
	if tmpl == nil {
		http.Error(w, "Template not found", http.StatusInternalServerError)
		return
	}

	// Execute the template
	tmpl.Execute(w, nil)
}

// RegisterHandler handles user registration
func RegisterPostHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not supported", http.StatusMethodNotAllowed)
		return
	}

	username := r.FormValue("username")
	email := r.FormValue("email")
	password := r.FormValue("password")
	role := ""
	otp := GenerateOTP()

	// Basic validation
	if username == "" || password == "" {
		http.Error(w, "Username and password are required", http.StatusBadRequest)
		return
	}

	if username == "amina" || username == "aruzhan" {
		role = "admin"
	} else {
		role = "user"
	}

	// Insert the new user into the database
	_, err := db.Exec("INSERT INTO users (username, email, password, role, otp) VALUES ($1, $2, $3, $4, $5)", username, email, password, role, otp)
	if err != nil {
		log.Println("Error registering user:", err)
		http.Error(w, "Registration failed", http.StatusInternalServerError)
		return
	}

	sendEmail(email, "To do list", "Welcome! You have been registered! Your OTP is "+otp)

	fmt.Fprintf(w, "User %s successfully registered", username)
}

func LoginHandler(w http.ResponseWriter, r *http.Request) {
	// Parse the HTML template file
	tmpl := templates.Lookup("login.html")
	if tmpl == nil {
		http.Error(w, "Template not found", http.StatusInternalServerError)
		return
	}

	// Execute the template
	tmpl.Execute(w, nil)
}

// LoginHandler handles user login
func LoginPostHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not supported", http.StatusMethodNotAllowed)
		return
	}

	username := r.FormValue("username")
	password := r.FormValue("password")
	otp := r.FormValue("otp")

	// Basic validation
	if username == "" || password == "" {
		http.Error(w, "Username and password are required", http.StatusBadRequest)
		return
	}

	// Check if user exists in the database
	var user User
	err := db.QueryRow("SELECT username, email, role FROM users WHERE username = $1 AND password = $2 AND otp = $3", username, password, otp).
		Scan(&user.Username, &user.Email, &user.Role)
	if err != nil {
		log.Println("Error logging in:", err)
		http.Error(w, "Login failed", http.StatusUnauthorized)
		return
	}

	otp = GenerateOTP()
	_, err = db.Exec("UPDATE users SET otp = $1 WHERE username = $2", otp, username)

	// Simulate session management by setting a cookie
	expiration := time.Now().Add(24 * time.Hour)
	cookie := http.Cookie{Name: "username", Value: username, Expires: expiration}
	http.SetCookie(w, &cookie)

	sendEmail(user.Email, "OTP Update", "You have been logged in! Your new OTP is "+otp)

	// Redirect based on user role
	if user.Role == "admin" {
		http.Redirect(w, r, "/admin", http.StatusSeeOther)
	} else {
		http.Redirect(w, r, "/profile-edit", http.StatusSeeOther)
	}
}

func LogoutHandler(w http.ResponseWriter, r *http.Request) {
	// Clear the username cookie to log out the user
	cookie := http.Cookie{
		Name:    "username",
		Value:   "",
		Expires: time.Now().Add(-time.Hour), // Set expiration in the past to delete the cookie
	}
	http.SetCookie(w, &cookie)

	// Redirect to the login page or any other page
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func IndexHandler(w http.ResponseWriter, r *http.Request) {
	filter := r.URL.Query().Get("filter")
	sortBy := r.URL.Query().Get("sort")

	page, err := strconv.Atoi(r.URL.Query().Get("page"))
	if err != nil || page < 1 {
		page = 1
	}

	pageSize, err := strconv.Atoi(r.URL.Query().Get("pageSize"))
	if err != nil || pageSize < 1 {
		pageSize = 10
	}

	isLoggedIn := IsLoggedIn(r)

	// Rate limiting check
	if !limiter.Allow() {
		http.Error(w, "Rate limit exceeded", http.StatusTooManyRequests)
		return
	}

	// Fetch products from the database
	task, err := fetchProductsFromDB(filter, sortBy, page, pageSize)
	if err != nil {
		log.Error("Error fetching task from the database:", err)
		http.Error(w, "Error fetching task from the database", http.StatusInternalServerError)
		return
	}

	// Prepare data for the template
	tmpl := templates.Lookup("index.html")
	if tmpl == nil {
		http.Error(w, "Template not found", http.StatusInternalServerError)
		return
	}

	data := struct {
		Filter     string
		SortBy     string
		Task       []Task
		Page       int
		PrevPage   int
		NextPage   int
		PageSize   int
		IsLoggedIn bool
	}{
		Filter:     filter,
		SortBy:     sortBy,
		Task:       task,
		Page:       page,
		PrevPage:   page - 1,
		NextPage:   page + 1,
		PageSize:   pageSize,
		IsLoggedIn: isLoggedIn,
	}

	// Render the template with the data
	tmpl.Execute(w, data)
}

// ProfileEditHandler handles displaying the profile edit form
func ProfileEditHandler(w http.ResponseWriter, r *http.Request) {
	// Fetch user profile information from the database based on the logged-in user
	cookie, err := r.Cookie("username")
	if err != nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	username := cookie.Value

	var user User
	err = db.QueryRow("SELECT username, email FROM users WHERE username = $1", username).Scan(&user.Username, &user.Email)
	if err != nil {
		log.Error("Error fetching user profile from the database:", err)
		http.Error(w, "Error fetching user profile from the database", http.StatusInternalServerError)
		return
	}

	// Parse the HTML template file
	tmpl := templates.Lookup("profile-edit.html")
	if tmpl == nil {
		http.Error(w, "Template not found", http.StatusInternalServerError)
		return
	}

	// Execute the template with user profile data
	tmpl.Execute(w, user)
}

// ProfileEditPostHandler handles updating the user's profile information
func ProfileEditPostHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not supported", http.StatusMethodNotAllowed)
		return
	}

	// Fetch user profile information from the form submission
	username := r.FormValue("username")
	email := r.FormValue("email")
	password := r.FormValue("password")

	// Update the user's profile in the database
	if password != "" {
		_, err := db.Exec("UPDATE users SET email=$1 AND password=$2 WHERE username=$3", email, password, username)
		if err != nil {
			log.Println("Error updating user profile in database:", err)
			http.Error(w, "Error updating user profile in database", http.StatusInternalServerError)
			return
		}
	} else {
		_, err := db.Exec("UPDATE users SET email=$1 WHERE username=$2", email, username)
		if err != nil {
			log.Println("Error updating user profile in database:", err)
			http.Error(w, "Error updating user profile in database", http.StatusInternalServerError)
			return
		}
	}

	// Redirect to the profile page or any other page after successful update
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func AdminHandler(w http.ResponseWriter, r *http.Request) {
	filter := r.URL.Query().Get("filter")
	sortBy := r.URL.Query().Get("sort")

	page, err := strconv.Atoi(r.URL.Query().Get("page"))
	if err != nil || page < 1 {
		page = 1
	}

	pageSize, err := strconv.Atoi(r.URL.Query().Get("pageSize"))
	if err != nil || pageSize < 1 {
		pageSize = 10
	}

	// Rate limiting check
	if !limiter.Allow() {
		http.Error(w, "Rate limit exceeded", http.StatusTooManyRequests)
		return
	}

	tasks, err := fetchProductsFromDB(filter, sortBy, page, pageSize)
	if err != nil {
		log.Error("Error fetching products from the database:", err)
		http.Error(w, "Error fetching products from the database", http.StatusInternalServerError)
		return
	}

	tmpl := templates.Lookup("admin.html")
	if tmpl == nil {
		http.Error(w, "Template not found", http.StatusInternalServerError)
		return
	}

	data := struct {
		Filter   string
		SortBy   string
		Task     []Task
		Page     int
		PrevPage int
		NextPage int
		PageSize int
	}{
		Filter:   filter,
		SortBy:   sortBy,
		Task:     tasks,
		Page:     page,
		PrevPage: page - 1,
		NextPage: page + 1,
		PageSize: pageSize,
	}

	tmpl.Execute(w, data)
}

func DeleteHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not supported", http.StatusMethodNotAllowed)
		return
	}

	id := r.URL.Path[len("/delete/"):]
	taskTitle, err := strconv.Atoi(id)
	if err != nil {
		log.Error("Invalid product ID:", err)
		http.Error(w, "Invalid product ID", http.StatusBadRequest)
		return
	}

	_, err = db.Exec("DELETE FROM Task WHERE id = $1", taskTitle)
	if err != nil {
		log.Error("Error deleting from database:", err)
		http.Error(w, "Error deleting from database", http.StatusInternalServerError)
		return
	}

	log.Printf("Task deleted with Title: %d\n", taskTitle)

	http.Redirect(w, r, "/admin", http.StatusSeeOther)
}
func AddProductHandler(w http.ResponseWriter, r *http.Request) {
	tmpl := templates.Lookup("add-product.html")
	if tmpl == nil {
		http.Error(w, "Template not found", http.StatusInternalServerError)
		return
	}

	tmpl.Execute(w, nil)
}

func AddProductPostHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not supported", http.StatusMethodNotAllowed)
		return
	}

	_, err := db.Exec("INSERT INTO Task (Title, completed) VALUES ($1, $2)",
		r.FormValue("Title"), r.FormValue("completed"))
	if err != nil {
		fmt.Println("Error inserting into database:", err)
		http.Error(w, "Error inserting into database", http.StatusInternalServerError)
		return
	}

	fmt.Printf("New task added: Title=%s, completed=%s\n", r.FormValue("Title"), r.FormValue("completed"))

	http.Redirect(w, r, "/admin", http.StatusSeeOther)
}

func EditProductHandler(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Path[len("/edit/"):]
	taskTitle, err := strconv.Atoi(id)
	if err != nil {
		http.Error(w, "Invalid task title", http.StatusBadRequest)
		return
	}

	var task Task
	err = db.QueryRow("SELECT Title, completed FROM Task WHERE Title = $1", taskTitle).
		Scan(&task.Title, &task.Completed)
	if err != nil {
		fmt.Println("Error fetching task details:", err)
		http.Error(w, "Error fetching task details", http.StatusInternalServerError)
		return
	}

	tmpl := templates.Lookup("edit-product.html")
	if tmpl == nil {
		http.Error(w, "Template not found", http.StatusInternalServerError)
		return
	}

	tmpl.Execute(w, task)
}

func EditProductPostHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not supported", http.StatusMethodNotAllowed)
		return
	}

	id := r.URL.Path[len("/edit-product-post/"):]
	taskTitle, err := strconv.Atoi(id)
	if err != nil {
		http.Error(w, "Invalid task Title", http.StatusBadRequest)
		return
	}

	_, err = db.Exec("UPDATE task SET completed=$1 WHERE Title=$2",
		r.FormValue("comleted"), taskTitle)
	if err != nil {
		fmt.Println("Error updating task in database:", err)
		http.Error(w, "Error updating task in database", http.StatusInternalServerError)
		return
	}

	fmt.Printf("Task updated with title: %d\n", taskTitle)

	http.Redirect(w, r, "/admin", http.StatusSeeOther)
}
func main() {
	// Initialize logger
	log = logrus.New()
	log.SetFormatter(&logrus.JSONFormatter{})
	file, err := os.OpenFile("logfile.log", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)

	if err == nil {
		log.SetOutput(io.MultiWriter(file, os.Stdout))
	} else {
		log.Error("Failed to log to file, using default stderr")
	}

	// Initialize database
	db = initDB()
	defer db.Close()

	// Set up HTTP server
	server := &http.Server{
		Addr:    "127.0.0.1:8080",
		Handler: nil, // Your handler will be set later
	}

	http.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.Dir("static"))))

	// Set up routes
	http.HandleFunc("/register", RegisterHandler)
	http.HandleFunc("/login", LoginHandler)
	http.HandleFunc("/register-post", RegisterPostHandler)
	http.HandleFunc("/login-post", LoginPostHandler)
	http.HandleFunc("/logout", LogoutHandler)
	http.HandleFunc("/", IndexHandler)
	http.Handle("/admin", AuthMiddleware(http.HandlerFunc(AdminHandler)))
	http.HandleFunc("/profile-edit", ProfileEditHandler)
	http.HandleFunc("/profile-edit-post", ProfileEditPostHandler)
	http.HandleFunc("/delete/", DeleteHandler)
	http.HandleFunc("/add-product", AddProductHandler)
	http.HandleFunc("/add-product-post", AddProductPostHandler)
	http.HandleFunc("/edit/", EditProductHandler)
	http.HandleFunc("/edit-product-post/", EditProductPostHandler)

	// Run server in a goroutine for graceful shutdown
	go func() {
		log.Println("Server is running at http://127.0.0.1:8080")
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatal("Server error:", err)
		}
	}()

	// Handle graceful shutdown
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	log.Info("Server is shutting down...")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := server.Shutdown(ctx); err != nil {
		log.Fatal("Server shutdown error:", err)
	}

	log.Info("Server has stopped")
}
