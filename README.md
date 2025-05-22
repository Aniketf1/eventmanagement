# Collaborative Event Management API

This project is a RESTful API backend for a collaborative event management application built using FastAPI. It supports secure user authentication, event creation and management, role-based access control, event versioning with rollback, and a diff tool to compare changes between event versions.

## Table of Contents

- [Features](#features)
- [Tech Stack](#tech-stack)
- [Installation](#installation)

## Features

- **User Authentication:**  
  Secure registration and login using JWT tokens.
- **Event Management:**  
  Create, update, list, delete, and batch-create events.
- **Role-based Access Control:**  
  Manage collaboration with granular permissions (Owner, Editor, Viewer).
- **Versioning & Audit Trail:**  
  Record changes to events with version history; rollback to previous versions.
- **Diff Functionality:**  
  Compare two versions of an event with a detailed diff.

## Tech Stack

- **Language:** Python 3.7+
- **Framework:** FastAPI
- **Database / ORM:** SQLAlchemy with SQLite (development – switch to PostgreSQL or another RDBMS for production)
- **Authentication:** JWT via python-jose
- **Data Validation:** Pydantic

## Installation

1. **Clone the repository:**

   ```bash
   git clone [eventmanagement](https://github.com/Aniketf1/eventmanagement.git)
   cd eventmanagement
   python -m venv venv
   pip install requirements.txt
   fastapi run dev
