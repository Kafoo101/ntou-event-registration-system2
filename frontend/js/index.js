const API_URL = 'https://ntou-event-registration-system2-five.vercel.app/';

const headerButtons = document.getElementById('headerButtons');
const eventsList = document.getElementById('eventsList');
const searchInput = document.getElementById('searchInput');
const hamburgerMenu = document.getElementById('hamburgerMenu');
const sidePanel = document.getElementById('sidePanel');
const sideMenu = document.getElementById('sideMenu');
const closeSidePanel = document.getElementById('closeSidePanel');
const pageTitle = document.getElementById('pageTitle');

let allEvents = [];       // Original events
let searchMode = 'events';
let editingUserId = null;
let sortCat = "date";
let sortOrd = "asc";

function closeSlidePanel() {
    sidePanel.classList.remove('open');
}

function parseJwt(token) {
    try {
        const base64Url = token.split('.')[1];
        const base64 = base64Url.replace(/-/g, '+').replace(/_/g, '/');
        const jsonPayload = decodeURIComponent(atob(base64).split('').map(c =>
            '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2)
        ).join(''));
        return JSON.parse(jsonPayload);
    } catch (e) {
        return null;
    }
}

// Check if user is logged in
const token = localStorage.getItem('authToken');
let currentUser = null;

if (token) {
    const userData = parseJwt(token);
    if (userData && userData.email) {
        currentUser = userData;
    } else {
        // Invalid or expired token
        localStorage.removeItem('authToken');
    }
}

let newChild = document.createElement('li');
newChild.className = "menu-item events";
newChild.textContent = "Events";
sideMenu.appendChild(newChild);

// Update header based on login status
if (currentUser) {
    let htmlDesc = `<span class='logo'>你好, `+ currentUser.name+`</span>`;
    if(currentUser.role != 'User')
        htmlDesc += `<a href="manage_events.html"><button>Manage Events</button></a>`;
    htmlDesc += `<button class="ghost" id="logoutBtn">Logout</button>`;

    headerButtons.innerHTML = htmlDesc;
    const logoutBtn = document.getElementById('logoutBtn');
    logoutBtn.addEventListener('click', () => {
        localStorage.removeItem('authToken');
        alert('You have successfully logged out!');
        window.location.reload();
    });

    const className = ["menu-item applications", "menu-item history", "menu-item past", "menu-item user", "separator", "menu-item changePass"];
    const textContent = ["Applications", "History", "Past Events", "User List", null, "Change Password"]

    for(let i = 0; i < className.length; i++)
    {
        newChild = document.createElement('li');
        newChild.className = className[i];

        if(className[i] == "separator")
        {
            const hr = document.createElement('hr');
            newChild.appendChild(hr);
        }
        else
        {
            newChild.textContent = textContent[i];
        }
        sideMenu.appendChild(newChild);
    }

    // Add "My Events" for Advanced Users only
    if(currentUser.role === "Advanced User") {
        const myEventsItem = document.createElement('li');
        myEventsItem.className = "menu-item myEvents";
        myEventsItem.textContent = "My Events";
        // Insert after Applications, before History
        const applicationsItem = document.querySelector(".menu-item.applications");
        if (applicationsItem && applicationsItem.nextSibling) {
            sideMenu.insertBefore(myEventsItem, applicationsItem.nextSibling);
        } else {
            sideMenu.appendChild(myEventsItem);
        }
    }

    if(currentUser.role != "Administrator")
    {
        let userLi = document.querySelector(".menu-item.past");
        if (userLi) userLi.style.display = "none";
        userLi = document.querySelector(".menu-item.user");
        if (userLi) userLi.style.display = "none";
    }
}

// Load and display events
async function loadEvents() {
    pageTitle.textContent = "活動列表 (Events)";
    searchMode = 'events';
    searchInput.placeholder = (searchMode === 'users') 
    ? "Search users by name..." 
    : "Search events by title...";
    try {
        const response = await fetch(`${API_URL}/events`);
        const events = await response.json();
        
        if (response.ok) {
            allEvents = events; // Store all events
            displayEvents(events);
        } else {
            eventsList.innerHTML = '<p style="color: var(--muted);">Failed to load events.</p>';
        }
    } catch (err) {
        console.error(err);
        eventsList.innerHTML = '<p style="color: var(--muted);">No events available.</p>';
    }
}

async function loadHistory() {
    pageTitle.textContent = "歷史活動 (History)";
    searchMode = 'events';
    searchInput.placeholder = (searchMode === 'users') 
    ? "Search users by name..." 
    : "Search events by title...";
    try {
        const response = await fetch(`${API_URL}/history`, {
            headers: { 'Authorization': `Bearer ${token}` }
        });
        const events = await response.json();

        if (response.ok) {
            allEvents = events; 
            displayEvents(events);
        } else {
            eventsList.innerHTML = '<p style="color: var(--muted);">Failed to load history.</p>';
        }
    } catch (err) {
        console.error(err);
        eventsList.innerHTML = '<p style="color: var(--muted);">No history available.</p>';
    }
}

async function loadPastEvents() {
    pageTitle.textContent = "已結束活動 (Past Events)";
    searchMode = 'events';
    searchInput.placeholder = (searchMode === 'users') 
    ? "Search users by name..." 
    : "Search events by title...";
    try {
        const response = await fetch(`${API_URL}/past`, {
            headers: { 'Authorization': `Bearer ${token}` }
        });
        const events = await response.json();

        if (response.ok) {
            allEvents = events; 
            displayEvents(events);
        } else {
            eventsList.innerHTML = '<p style="color: var(--muted);">Failed to load past events.</p>';
        }
    } catch (err) {
        console.error(err);
        eventsList.innerHTML = '<p style="color: var(--muted);">No past events available.</p>';
    }
}

async function loadApplications() {
    pageTitle.textContent = "我的申請 (My Applications)";
    searchMode = 'events';
    searchInput.placeholder = (searchMode === 'users') 
    ? "Search users by name..." 
    : "Search events by title...";
    try {
        const response = await fetch(`${API_URL}/applications`, {
            headers: { 'Authorization': `Bearer ${token}` }
        });
        const events = await response.json();

        if (response.ok) {
            allEvents = events; 
            displayEvents(events);
        } else {
            eventsList.innerHTML = '<p style="color: var(--muted);">Failed to load applications.</p>';
        }
    } catch (err) {
        console.error(err);
        eventsList.innerHTML = '<p style="color: var(--muted);">No applications available.</p>';
    }
}

async function loadMyEvents() {
    pageTitle.textContent = "我的活動 (My Events)";
    searchMode = 'events';
    searchInput.placeholder = (searchMode === 'users') 
    ? "Search users by name..." 
    : "Search events by title...";
    try {
        const response = await fetch(`${API_URL}/my-events`, {
            headers: { 'Authorization': `Bearer ${token}` }
        });
        const events = await response.json();

        if (response.ok) {
            allEvents = events; 
            displayMyEvents(events);
        } else {
            eventsList.innerHTML = '<p style="color: var(--muted);">Failed to load my events.</p>';
        }
    } catch (err) {
        console.error(err);
        eventsList.innerHTML = '<p style="color: var(--muted);">No events found.</p>';
    }
}

async function loadUserList() {
    pageTitle.textContent = "使用者名單 (User List)";
    searchMode = 'users';
    searchInput.placeholder = (searchMode === 'users') 
    ? "Search users by name..." 
    : "Search events by title...";
    try {
        const response = await fetch(`${API_URL}/users`, {
            headers: { 'Authorization': `Bearer ${token}` }
        });
        const users = await response.json();

        if(response.ok) {
            allEvents = users;
            displayUsers(users);
        } else {
            eventsList.innerHTML = '<p style="color: var(--muted);">Failed to load user list.</p>';
        }
    } catch (err) {
        console.error(err);
        eventsList.innerHTML = '<p style="color: var(--muted);">No users available.</p>';
    }
}

// ------------- Edit User ---------------------------------------- Edit User --------------------------------- Edit User -----------------------

function editUser(e) {
    e.stopPropagation();

    const card = e.target.closest(".user-card");
    if (!card) return;
    
    const targetRole = card.dataset.role;

    // --- BLOCK: Advanced User cannot edit Administrator ---
    if (currentUser.role === "Advanced User" && targetRole === "Administrator") {
        alert("You are not allowed to edit Administrator users.");
        return; // stop function here
    }

    const formBox = card.querySelector(".edit-form");
    
    // Toggle: if form is already visible, hide it and exit
    if (formBox.style.display === "block") {
        formBox.style.display = "none";
        return;
    }
    
    // close all other open forms - always put below the toggle
    document.querySelectorAll(".edit-form").forEach(f => f.style.display = "none");

    const id = e.target.closest(".user-card").getAttribute("data-id");
    const uid = e.target.closest(".user-card").getAttribute("data-userid");

    // Build the role dropdown dynamically
    let roleDropdown = '';
    if (targetRole === "Administrator") {
        // Fixed Administrator, uneditable
        roleDropdown = `<select id="role-${id}" disabled 
                            style="padding:6px 8px; border-radius:6px; background:#999999ff; color:#ffffffff; cursor:not-allowed;"
                            title="Administrator role cannot be changed">
                            <option value="Administrator">Administrator</option>
                        </select>`;
    } else {
        // Normal editable roles
        roleDropdown = `<select id="role-${id}" style="padding:6px 8px; border-radius:6px;">
                            <option value="User">User</option>
                            <option value="Advanced User">Advanced User</option>
                        </select>`;

        // Advanced User cannot downgrade other Advanced Users
        if (currentUser.role === "Advanced User" && targetRole === "Advanced User") {
            // create a temporary container to parse the roleDropdown
            const tempDiv = document.createElement('div');
            tempDiv.innerHTML = roleDropdown;

            const selectEl = tempDiv.querySelector('select');
            if (selectEl) {
                const userOption = selectEl.querySelector('option[value="User"]');
                if (userOption) {
                    userOption.disabled = true; // disable User
                    userOption.style.background = "#999999ff"; // gray background
                    userOption.style.color = "#ffffffff";      // white text
                }
            }

            roleDropdown = tempDiv.innerHTML; // keep the <select> wrapper
        }
    }

    formBox.innerHTML = `
        <form onsubmit="submitEdit(event, '${id}', '${uid}')"
            style="
                margin-top:15px;
                padding:16px;
                border-radius:12px;
                border: 0px;
                background: #222230ff;
                box-shadow: 0 4px 12px rgba(0,0,0,0.08);
            ">

            <div style="margin-bottom:12px;">
                <label style="display:inline-block; width:90px; font-weight:600;">Name:</label>
                <input type="text" id="name-${id}" value="${card.dataset.name}"
                    style="padding:6px 8px; border-radius:6px;">
            </div>

            <div style="margin-bottom:12px;">
                <label style="display:inline-block; width:90px; font-weight:600;">Role:</label>
                ${roleDropdown}
            </div>

            <div style="margin-bottom:14px;">
                <label style="display:inline-block; width:90px; font-weight:600;">Occupation:</label>
                <select id="occupation-${id}" style="padding:6px 8px; border-radius:6px;">
                    <option value="Organizer">Organizer</option>
                    <option value="Teacher">Teacher</option>
                    <option value="Student">Student</option>
                </select>
            </div>

            <button type="submit" class="edit-btn" style="margin-right:8px;">Save</button>
            <button type="button" class="delete-btn"
                    onclick="this.closest('.edit-form').style.display='none'">
                Cancel
            </button>
        </form>
    `;

    formBox.style.display = "block";

    // Set dropdown values to match the user's actual data
    const roleSelect = formBox.querySelector(`#role-${id}`);
    const occupationSelect = formBox.querySelector(`#occupation-${id}`);
    if (roleSelect) roleSelect.value = targetRole;
    if (occupationSelect) occupationSelect.value = card.dataset.occupation;
}

async function showEditUserForm(id) {
    try {
        window.scrollTo(0, 0);
        
        const response = await fetch(`${API_URL}/users/${id}/retrieve`, {
            headers: { 'Authorization': `Bearer ${token}` }
        });

        if (!response.ok) {
            throw new Error(`HTTP ${response.status}`);
        }
        const user = await response.json();

        showForm(user);
    } catch (err) {
        console.error(err);
        alert('Failed to load user data');
    }
}

async function submitEdit(e, id, userId) {
    e.preventDefault();

    const name = document.getElementById(`name-${id}`).value.trim();
    const role = document.getElementById(`role-${id}`).value;
    const occupation = document.getElementById(`occupation-${id}`).value;
    const isSelf = currentUser && currentUser.id === parseInt(userId);

    try {
        const res = await fetch(`${API_URL}/users/${id}/send`, {
            method: "PUT",
            headers: {
                "Authorization": `Bearer ${token}`,
                "Content-Type": "application/json"
            },
            body: JSON.stringify({ name, role, occupation, isSelf })
        });

        const data = await res.json();
        if (!res.ok) throw new Error(data.message);

        if (isSelf && data.token) {
            localStorage.setItem('authToken', data.token);
            const userData = parseJwt(data.token);
            if (userData && userData.email) {
                currentUser = userData;
            } else {
                // Invalid or expired token
                localStorage.removeItem('authToken');
            }
        }

        alert("User updated");
        loadUserList(); // refresh list

    } catch (err) {
        console.error(err);
        alert("Update failed");
    }
}

// -----------------------------------------------------------------------------------------------------------------------------------------

// Delete User
async function deleteUser(e) {
    e.stopPropagation();

    const userDiv = e.target.closest(".event");
    const id = userDiv.dataset.id;
    const uid = userDiv.dataset.userid;
    const userId = parseInt(uid);
    const targetRole = userDiv.dataset.role;
    
    // BLOCK: cannot delete Administrator unless it's yourself
    if (targetRole === "Administrator" && !(currentUser && userId === currentUser.id)) {
        alert("Administrator account cannot be deleted by other users.");
        return;
    }

    // diff msg for self-deletion
    const isSelf = currentUser && userId === currentUser.id;

    const confirmMsg = isSelf
        ? "⚠️ You are about to permanently delete YOUR OWN account.\n\nThis will:\n• Log you out immediately\n• Disable all your applications\n• Cannot be undone\n\nAre you absolutely sure?"
        : "Delete this user and disable all related applications?\n\nThis action cannot be undone.";

    if (!confirm(confirmMsg)) return;

    //double-protection for self-destruct
    if (isSelf && !confirm("Click OK once more to confirm self-deletion")) return;

    try {
        const res = await fetch(`${API_URL}/users/${id}`, {
            method: "DELETE",
            headers: { 'Authorization': `Bearer ${token}` }
        });

        const data = await res.json();

        if (!res.ok) {
            alert(data.message || "Delete failed.");
            return;
        }

        // !!! SELF-DELETE CHECK !!!
        if (currentUser && userId === currentUser.id) {
            alert("Your account has been deleted. You will be logged out.");
            localStorage.removeItem("authToken");
            window.location.href = "signin.html";
            return;
        }

        // normal delete (admin deleting others)
        alert("User deleted. Applications set to inactive.");
        userDiv.remove();

    } catch (err) {
        console.error(err);
        alert("Server error!");
    }
}

function sortList(type, category, order) {
    const items = Array.from(eventsList.children);

    function getEventDateValue(item) {
        let raw =
            item.dataset.date ||
            item.querySelector(".event-date")?.textContent.trim() ||
            "";

        if (!raw) return 0;

        // normalize separators
        raw = raw.replace(/\//g, "-");

        const parts = raw.split("-").map(Number);

        let yyyy, mm, dd;

        // YYYY-MM-DD
        if (parts[0] > 1000) {
            [yyyy, mm, dd] = parts;
        }
        // MM-DD-YYYY
        else {
            [mm, dd, yyyy] = parts;
        }

        return yyyy * 10000 + mm * 100 + dd;
    }

    items.sort((a, b) => {
        if (category === "date" && type === "events") {
            const A = getEventDateValue(a);
            const B = getEventDateValue(b);

            return order === "asc" ? A - B : B - A;
        }

        const valA = a.dataset[category] || "";
        const valB = b.dataset[category] || "";

        return order === "asc"
            ? valA.localeCompare(valB)
            : valB.localeCompare(valA);
    });

    items.forEach(item => eventsList.appendChild(item));
}

function searchEvents(query) {
    if (!query.trim()) {
        // If search is empty, display all events
        if (searchMode == 'events')
            displayEvents(allEvents);
        else
            displayUsers(allEvents);
        return;
    }
    
    // Filter events by title (case-insensitive)
    let filteredEvents = [];
    if(searchMode == 'events') {
        filteredEvents = allEvents.filter(event => 
            event.title.toLowerCase().includes(query.toLowerCase())
        );
        
        displayEvents(filteredEvents);
    }
    else {
        filteredEvents = allEvents.filter(event =>
            event.name.toLowerCase().includes(query.toLowerCase())
        );

        displayUsers(filteredEvents);
    }
}

function triggerSearch() {
    const query = searchInput.value;
    searchEvents(query);
}

function displayEvents(events) {
    if (events.length === 0) {
        eventsList.innerHTML = '<p style="color: var(--muted);">No data found.</p>';
        return;
    }
    
    const formatCreationDate = (dateString) => {
        if (!dateString) return 'N/A';
        const date = new Date(dateString);
        return date.toLocaleDateString('en-US', { year: 'numeric', month: 'short', day: 'numeric' });
    };
    
    eventsList.innerHTML = events.map(event => {
        const participantCount = event.participantCount || 0;
        const maxParticipants = event.participationLimit || 0;
        
        return `
        <div class="event" style="cursor: pointer; position: relative;" 
            data-name="${event.title.toLowerCase()}" 
            data-date="${event.date}" 
            onclick="window.location.href='event.html?id=${event.id}'"
        >
            <h3>${event.title}</h3>
            ${event.imagePath ? `<img src="${event.imagePath}" alt="${event.title}" style="max-width:220px; border-radius:6px; display:block; margin-bottom:8px;">` : ''}
            <small>📅 ${formatDate(event.date)} ｜ 📍 ${event.location} ｜ 👥 ${participantCount}/${maxParticipants}</small>
            ${event.description ? `<p style="color: var(--text); margin-top: 8px; font-size: 0.9rem;">${event.description}</p>` : ''}
            <div style="margin-top: 10px; padding-top: 8px; border-top: 1px solid #475569; display: flex; justify-content: flex-end; gap: 15px; font-size: 0.8rem; color: var(--muted);">
                ${event.ownerEmail ? `<span>👤 ${event.ownerEmail}</span>` : ''}
                ${event.createdAt ? `<span>📅 ${formatCreationDate(event.createdAt)}</span>` : ''}
            </div>
        </div>
    `;
    }).join('');

    //set default order list for events
    document.getElementById('ddlCat').textContent = "Date";
    document.getElementById('ddlOrd').textContent = "Ascending";
    sortCat = "date"; sortOrd = "asc";    // sorting by date closest before displaying data
    sortList("events", sortCat, sortOrd);
}

function displayMyEvents(events) {
    if (events.length === 0) {
        eventsList.innerHTML = '<p style="color: var(--muted);">No events found. Create your first event!</p>';
        return;
    }
    
    const formatCreationDate = (dateString) => {
        if (!dateString) return 'N/A';
        const date = new Date(dateString);
        return date.toLocaleDateString('en-US', { year: 'numeric', month: 'short', day: 'numeric' });
    };
    
    eventsList.innerHTML = events.map(event => {
        const participantCount = event.participantCount || 0;
        const maxParticipants = event.participationLimit || 0;
        
        return `
        <div class="event" style="cursor: pointer; position: relative;" 
            data-name="${event.title.toLowerCase()}" 
            data-date="${event.date}" 
            onclick="window.location.href='event.html?id=${event.id}'"
        >
            <h3>${event.title}</h3>
            ${event.imagePath ? `<img src="${event.imagePath}" alt="${event.title}" style="max-width:220px; border-radius:6px; display:block; margin-bottom:8px;">` : ''}
            <small>📅 ${formatDate(event.date)} ｜ 📍 ${event.location} ｜ 👥 Participants: ${participantCount}/${maxParticipants}</small>
            ${event.description ? `<p style="color: var(--text); margin-top: 8px; font-size: 0.9rem;">${event.description}</p>` : ''}
            <div style="margin-top: 10px; padding-top: 8px; border-top: 1px solid #475569; display: flex; justify-content: flex-end; gap: 15px; font-size: 0.8rem; color: var(--muted);">
                ${event.ownerEmail ? `<span>👤 ${event.ownerEmail}</span>` : ''}
                ${event.createdAt ? `<span>📅 ${formatCreationDate(event.createdAt)}</span>` : ''}
            </div>
        </div>
    `;
    }).join('');

    //set default order list for events
    document.getElementById('ddlCat').textContent = "Date";
    document.getElementById('ddlOrd').textContent = "Ascending";
    sortCat = "date"; sortOrd = "asc";    // sorting by date closest before displaying data
    sortList("events", sortCat, sortOrd);
}

function displayUsers(users) {
    if (users.length === 0) {
        eventsList.innerHTML = '<p style="color: var(--muted);">No data found.</p>';
        return;
    }

    eventsList.innerHTML = users.map(user => `
        <div class="event user-card" style="cursor: pointer;"
            data-id="${user._id}"
            data-userid="${user.id}"
            data-name="${user.name}" 
            data-role="${user.role}"
            data-occupation="${user.occupation}"
            data-date="${user.created_at}"
        >
            <div class="horizontal-view" style="justify-content: space-between; align-items: center;">
                <div>
                    <div class="horizontal-view">
                        <h3>${getUserIcon(user.role)} ${user.name}</h3>
                        <small style="color: var(--muted);">📧${user.email}</small>
                    </div>
                    <small style="">⭐Role: ${user.role} | 💼Occupation: ${user.occupation} | 🕙Created At: ${user.created_at}</small>
                </div>
                <div>
                    <button class="edit-btn" onclick="editUser(event)">Edit ✏️</button>
                    <button class="delete-btn" onclick="deleteUser(event)">Delete 🗑️</button>
                </div>
            </div>

            <!-- EDIT FORM GOES HERE -->
            <div class="edit-form" style="display:none;"></div>
        </div>
    `).join('');

    //set default order list for users
    document.getElementById('ddlCat').textContent = "Name";
    document.getElementById('ddlOrd').textContent = "Ascending";
    sortCat = "name"; sortOrd = "asc";   // sorting by alphabetical order before displaying data
    sortList("users", sortCat, sortOrd);
}

function formatDate(dateString) {
    const date = new Date(dateString);
    const year = date.getFullYear();
    const month = String(date.getMonth() + 1).padStart(2, '0');
    const day = String(date.getDate()).padStart(2, '0');
    return `${year}/${month}/${day}`;
}

function getUserIcon(role) {
    if (role === 'User') return '👤';
    if (role === 'Advanced User') return '🧑‍💻';
    if (role === 'Administrator') return '🛡️';
    return '❓'; // if this ever happens, there's something wrong...
}

// Load events on page load
loadEvents();

// Search functionality
if (searchInput) {
    searchInput.addEventListener('input', (e) => {
        searchEvents(e.target.value);
    });
}

function clearSearch() {
    document.getElementById('searchInput').value = "";
    triggerSearch(); // Reload full list after clearing
}

// Apply for an event
async function applyEvent(eventId, eventTitle) {
    if (!currentUser) {
        alert('Please sign in to apply for events');
        window.location.href = 'signin.html';
        return;
    }

    try {
        const response = await fetch(`${API_URL}/events/${eventId}/apply`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${token}`
            },
            body: JSON.stringify({ userId: currentUser.id })
        });

        const data = await response.json();

        if (response.ok) {
            alert(`Successfully applied for "${eventTitle}"!`);
        } else {
            alert(data.error || 'Failed to apply for event');
        }
    } catch (err) {
        console.error(err);
        alert('Connection error. Please try again.');
    }
}

hamburgerMenu.addEventListener('click', () => {
    sidePanel.classList.add('open');
});

// Close panel
closeSidePanel.addEventListener('click', () => {
    closeSlidePanel();
});

// Clicking outside closes it (optional)
document.addEventListener('click', (e) => {
    if (!sidePanel.contains(e.target) && !hamburgerMenu.contains(e.target)) {
        closeSlidePanel();
    }
});

document.querySelectorAll(".ddl").forEach(function (dropdown) {
    const selected = dropdown.querySelector(".ddlselected");
    const options = dropdown.querySelector(".ddloptions");

    //toggle this dropdown only
    selected.addEventListener("click", function (e) {
        e.stopPropagation();

        //close other dropdowns
        document.querySelectorAll(".ddloptions").forEach(function (opt) {
            if (opt !== options) opt.style.display = "none";
        });
        
        options.style.display = options.style.display === "block" ? "none" : "block";
    });

    //option click
    options.querySelectorAll("li").forEach(function (item) {
        item.addEventListener("click", function () {
            selected.textContent = this.textContent;
            options.style.display = "none";

            //sort var update
            if(this.dataset.sort) {
                sortOrd = this.dataset.sort; //order
            }
            if(this.dataset.value) {
                sortCat = this.dataset.value; //category
            }

            //call sort func
            sortList(searchMode, sortCat, sortOrd);
        });
    });
});

//out-focus click of dropdowns closes them
document.addEventListener("click", function () {
    document.querySelectorAll(".ddloptions").forEach(function (opt) {
        opt.style.display = "none";
    });
});

sideMenu.addEventListener("click", e => {

    const item = e.target.closest(".menu-item");
    if (!item) return;  // click wasn't on an li

    clearSearch();
    
    if (item.classList.contains("events")) {
        loadEvents();
    }
    if (item.classList.contains("applications")) {
        loadApplications();
    }
    if (item.classList.contains("myEvents")) {
        loadMyEvents();
    }
    if (item.classList.contains("history")) {
        loadHistory();
    }
    if (item.classList.contains("past")) {
        loadPastEvents();
    }
    if (item.classList.contains("user")) {
        loadUserList();
    }
    if (item.classList.contains("changePass")) {
        window.location.href = 'changePass.html';
    }

    closeSlidePanel();
});

window.editUser = editUser;
window.showEditUserForm = showEditUserForm;