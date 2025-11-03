# Multi-threaded API Web Server

This repository contains a from-scratch HTTP/1.1 server that powers a single-page message board application for COMP 3010 Assignment 2.

## Features

* Multi-threaded TCP server implemented directly with Python's `socket` module.
* Serves static assets for a login-protected single page application.
* Implements JSON API endpoints for registering, logging in/out, posting, listing, and deleting messages.
* Integrates with the remote assignment database using the required length-prefixed JSON protocol.
* Resilient to database rate limiting and transient connectivity issues.

## Project layout

```
├── a2.html          # Assignment description (reference only)
├── server.py        # Main server implementation
├── static/
│   ├── index.html   # SPA shell and layout
│   ├── app.js       # Frontend logic using XMLHttpRequest
│   └── styles.css   # Styling for the UI
└── README.md
```

## Requirements

* Python 3.9 or newer.
* Network access to one of the instructor-provided database hosts on port `50042`.

## Usage

```bash
python3 server.py --host 0.0.0.0 --port 8080 --db-host hawk.cs.umanitoba.ca
```

Command-line flags:

* `--host` – Interface to bind (defaults to `0.0.0.0`).
* `--port` – TCP port to listen on (defaults to `8080`).
* `--db-host` – Assignment database hostname (required).
* `--db-port` – Assignment database port (defaults to `50042`).
* `--static` – Directory containing static assets (defaults to `static`).

Once running, visit `http://localhost:8080/` in your browser. The application will automatically poll for new messages every five seconds. Message interactions require a valid login session stored in an `HttpOnly` cookie.

## Notes

* All HTTP handling (parsing requests, routing, formatting responses) is performed manually without using higher-level frameworks.
* Sessions are stored in-memory; restarting the server will clear active sessions.
* The server honours the database rate-limiting response (status code `271`) by backing off exponentially before retrying.
