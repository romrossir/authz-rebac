package router

import (
	"net/http"
	"strings"
)

type HandlerFunc func(http.ResponseWriter, *http.Request, map[string]string)
type Middleware func(HandlerFunc) HandlerFunc

type route struct {
	method     string
	pattern    string
	handler    HandlerFunc
	middleware []Middleware
}

type Router struct {
	routes           []route
	globalMiddleware []Middleware
}

func NewRouter() *Router {
	return &Router{}
}

func (r *Router) AddGlobalMiddleware(m Middleware) {
	r.globalMiddleware = append(r.globalMiddleware, m)
}

func (r *Router) Handle(method, pattern string, handler HandlerFunc, middleware ...Middleware) {
	r.routes = append(r.routes, route{
		method:     method,
		pattern:    pattern,
		handler:    handler,
		middleware: middleware,
	})
}

func (r *Router) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	for _, rt := range r.routes {
		if req.Method != rt.method {
			continue
		}

		params, ok := match(rt.pattern, req)
		if ok {
			// Start with the base handler
			h := rt.handler

			// Apply route-specific middleware (reverse order)
			for i := len(rt.middleware) - 1; i >= 0; i-- {
				h = rt.middleware[i](h)
			}

			// Apply global middleware (reverse order)
			for i := len(r.globalMiddleware) - 1; i >= 0; i-- {
				h = r.globalMiddleware[i](h)
			}

			// Call final handler
			h(w, req, params)
			return
		}
	}
	http.NotFound(w, req)
}

func match(pattern string, req *http.Request) (map[string]string, bool) {
	patternParts := strings.Split(strings.Trim(pattern, "/"), "/")
	pathParts := strings.Split(strings.Trim(req.URL.Path, "/"), "/")

	if len(patternParts) != len(pathParts) {
		return nil, false
	}

	// Extract path parameters
	params := make(map[string]string)
	for i := range patternParts {
		if strings.HasPrefix(patternParts[i], "{") && strings.HasSuffix(patternParts[i], "}") {
			paramName := patternParts[i][1 : len(patternParts[i])-1]
			params[paramName] = pathParts[i]
		} else if patternParts[i] != pathParts[i] {
			return nil, false
		}
	}

	// Parse the form data (includes both query params and POST form data)
	if err := req.ParseForm(); err != nil {
		return nil, false
	}
	for key, values := range req.Form {
		if len(values) > 0 {
			params[key] = values[0] // Take the first value
		}
	}

	return params, true
}
