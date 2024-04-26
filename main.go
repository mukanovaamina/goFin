package main

import (
	"context"
	"database/sql"
	_ "github.com/lib/pq"
	"github.com/sirupsen/logrus"
	"golang.org/x/time/rate"
	//"fmt"
	"html/template"
	"io"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"
)

// Product structure represents a product in the store
type Task struct {
	Title     string
	Completed bool
}
type User struct {
	Username string
	Email    string
	Role     string
}

var (
	db        *sql.DB
	log       *logrus.Logger
	limiter   = rate.NewLimiter(1, 3) // Rate limit of 1 request per second with a burst of 3 requests
	templates = template.Must(template.ParseGlob("templates/*.html"))
)

func initDB(log *logrus.Logger) *sql.DB {
	connStr := "user=postgres password=Aruzhan7 dbname=amina sslmode=disable"
	db, err := sql.Open("postgres", connStr)
	if err != nil {
		log.Fatal("Error opening database connection:", err)
	}

	err = db.Ping()
	if err != nil {
		log.Fatal("Error connecting to the database:", err)
	}

	log.Info("Connected to the database")

	// Create the tasks table if it doesn't exist
	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS tasks (
		title TEXT,
		completed BOOLEAN
	);`)
	if err != nil {
		log.Fatal(err)
	}

	return db
}

func fetchTasksFromDB(filter, sortBy string, page, pageSize int) ([]Task, error) {
	var tasks []Task

	var query string
	var args []interface{}

	if filter != "" {
		query = "SELECT title, completed FROM tasks WHERE title ILIKE $1"
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
		args = append(args, pageSize, (page-1)*pageSize)
	} else {
		query += " LIMIT $1 OFFSET $2"
		args = append(args, pageSize, (page-1)*pageSize)
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

func AuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check authentication
		cookie, err := r.Cookie("username")
		if err != nil {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}

		// Fetch user from the database based on the username
		var user User
		err = db.QueryRow("SELECT username, email, role FROM users WHERE username = $1", cookie.Value).Scan(&user.Username, &user.Email, &user.Role)
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

func AdminHandlerWithAuth(w http.ResponseWriter, r *http.Request) {
	AuthMiddleware(http.HandlerFunc(AdminHandler)).ServeHTTP(w, r)
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

	tasks, err := fetchTasksFromDB(filter, sortBy, page, pageSize)
	if err != nil {
		log.Error("Error fetching tasks from the database:", err)
		http.Error(w, "Error fetching tasks from the database", http.StatusInternalServerError)
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
		Tasks    []Task
		Page     int
		PrevPage int
		NextPage int
		PageSize int
	}{
		Filter:   filter,
		SortBy:   sortBy,
		Tasks:    tasks,
		Page:     page,
		PrevPage: page - 1,
		NextPage: page + 1,
		PageSize: pageSize,
	}

	tmpl.Execute(w, data)
}

func AddProductPostHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not supported", http.StatusMethodNotAllowed)
		return
	}

	title := r.FormValue("title")
	completed := r.FormValue("completed") == "on"

	// Use a channel for synchronization
	done := make(chan struct{})

	// Launch a goroutine to insert data into the database
	go func() {
		defer close(done)
		_, err := db.Exec("INSERT INTO tasks (title, completed) VALUES ($1, $2)", title, completed)
		if err != nil {
			log.Error("Error inserting task into database:", err)
		}
	}()

	// Wait for the goroutine to finish
	<-done

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
	db = initDB(log)
	defer db.Close()

	// Set up HTTP server
	server := &http.Server{
		Addr:    "127.0.0.1:8080",
		Handler: nil, // Your handler will be set later
	}

	http.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.Dir("static"))))

	// Set up routes
	http.HandleFunc("/admin", AdminHandlerWithAuth)
	http.HandleFunc("/add-product-post", AddProductPostHandler)

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
