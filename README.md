# 海大活動報名系統 (NTOU Event Registration System)

## 📌 Project Overview
**海大活動報名系統** is a web-based event registration platform designed for National Taiwan Ocean University (NTOU).  
The system allows users to browse events, apply or retract participation, and enables authorized users to manage events and users based on role-based access control.

This project is developed as part of a **Software Engineering course**, following iterative development and formal software documentation practices.

---

## 🎯 Project Objectives
- Provide a centralized platform for campus event management
- Support role-based access control (User / Advanced User / Admin)
- Allow event creation, application, management, and history tracking
- Ensure usability, maintainability, and scalability

---

## 👥 User Roles & Permissions

### 1. Regular User
- View all events
- View event details
- Apply for events
- Retract event applications
- Change password

### 2. Advanced User (Event Organizer)
Includes all **Regular User** permissions, plus:
- Create new events
- Edit existing events
- Delete events
- Set:
  - Event title
  - Date & time
  - Location
  - Participant limits
  - Event image
  - Allowed applicant occupation (Organizer / Student / Teacher)

### 3. Administrator (Admin)
Includes **all system permissions**, plus:
- View full user list
- Modify user roles (User ↔ Advanced User)
- Delete users  
⚠️ Admin **cannot promote or demote another administrator**

---

## 🧭 System Features

### 🔐 Authentication
- User registration
- User login
- Password change
- Role-based access control

### 📅 Event Management
- Event listing on index page
- Event detail view
- Apply / Retract participation
- Sorting options:
  - By name
  - By date
  - Ascending / Descending
- Keyword search

### 📂 Sidebar Navigation (Hamburger Menu)

| Role | Sidebar Items |
|---|---|
| User | Events, Change Password |
| Advanced User | Events, Applications, History, Change Password |
| Admin | Events, Applications, History, User List, Change Password |

---

## 🧪 Testing & Validation
- Functional test cases written in **table-based format**
- Each requirement is mapped to test cases
- Severity levels assigned per test case
- Test documentation maintained in HackMD

---

## 📄 Documentation Links

### 🔁 Iteration Documents
- **Iteration 1**  
  https://hackmd.io/lYkWPSOwSaS3PgQJhLul-Q?view

- **Iteration 2 – Software System Design (SSD)**  
  https://hackmd.io/NVJgdSBOQyuyguEDUxMW7A?view#Sofware-System-Design-SSD

- **Test Acceptance Criteria**  
  https://hackmd.io/1h5HWfSETlmT7pAnrwkq6A?view

---

### 📋 Project Requirements
- https://hackmd.io/@ldhxSaJmSG-Jmp2kxBS7mA/SyQvraa5gl
- https://hackmd.io/@ldhxSaJmSG-Jmp2kxBS7mA/Sk7PNiDybg

---

## 🚀 Deployment
The system is deployed using **Vercel**.

🔗 Live Demo:  
https://ntou-event-registration-system2.vercel.app/index.html

---

## 🛠️ Tech Stack
- Frontend: HTML, CSS, JavaScript
- Backend: RESTful API (Node.js / Express)
- Database: MongoDB
- Authentication: JWT
- Deployment: Vercel

---

## 👨‍💻 Contributors
  - 康德明 (01257166)
  - 許家豪 (01257168)
  - 洪振銘 (01257068)
  - 林彥汶 (01257067)
  - 姚俊吉 (01257167)

---

## 📌 Notes
- This project follows **iterative software development**
- All features are implemented according to documented requirements
- Admin privileges are intentionally restricted to prevent privilege escalation
