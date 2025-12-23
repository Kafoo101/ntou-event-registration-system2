const API_URL = '';
const errorMsg = document.getElementById('errorMsg');
const successMsg = document.getElementById('successMsg');

let occupations = ['Organizer', 'Teacher', 'Student'];

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

function showError(msg) {
    errorMsg.textContent = msg;
    errorMsg.style.display = 'block';
    successMsg.style.display = 'none';
    setTimeout(() => errorMsg.style.display = 'none', 5000);
}

function showSuccess(msg) {
    successMsg.textContent = msg;
    successMsg.style.display = 'block';
    errorMsg.style.display = 'none';
    setTimeout(() => successMsg.style.display = 'none', 3000);
}

function isPastEvent(eventDateString) {
    const now = new Date();
    
    const todayLocal = new Date(
        now.getFullYear(),
        now.getMonth(),
        now.getDate()
    );

    const evDate = new Date(eventDateString);
    const eventLocal = new Date(
        evDate.getFullYear(),
        evDate.getMonth(),
        evDate.getDate()
    );

    return eventLocal < todayLocal;
}


const token = localStorage.getItem('authToken');
let currentUser = null;
if (token) {
    const userData = parseJwt(token);
    if (userData && userData.email) currentUser = userData;
}

const eventContainer = document.getElementById('eventContainer');
const eventParticipationContainer = document.getElementById('eventParticipantContainer');
const messageBox = document.getElementById('message');

function getQueryParam(name) {
    const params = new URLSearchParams(window.location.search);
    return params.get(name);
}

function showMessage(txt, isError = false) {
    messageBox.style.display = 'block';
    messageBox.textContent = txt;
    messageBox.style.color = isError ? 'var(--danger)' : 'var(--accent)';
    setTimeout(() => { messageBox.style.display = 'none'; }, 4000);
}

async function loadParticipant() {
    const id = getQueryParam('id');
    const res = await fetch(`${API_URL}/eventParticipants/${encodeURIComponent(id)}`, {
        headers: {
            'Authorization': `Bearer ${token}`
        }
    });
    
    const event = await res.json();
    if (!res.ok) {
        eventParticipationContainer.innerHTML = `<p style="color: var(--muted);">${event.error || 'Participant not found'}</p>`;
        return;
    }

    eventParticipationContainer.style.display = "block";
    const participants = event.participants || [];
    if (participants.length === 0) {
        eventParticipationContainer.innerHTML =
            `<p style="color: var(--muted);">There are no participants.</p>`;
        return;
    }

    let html = `<p><strong>Participants:</strong></p><ol style="padding-left: 0; margin: 0; list-style-position: inside;">`;
    participants.forEach(p => {
        html += `<li>${p.name}</li>`;
    });
    html += `</ol>`;

    eventParticipationContainer.innerHTML = html;
}

function isUserAllowed(eventPermission, currentUser) {
    if (currentUser?.role === "Administrator") {
        return true;
    }

    // Safety checks
    if (!eventPermission == null) {
        return false;
    }

    const index = occupations.indexOf(currentUser.occupation);
    if (index === -1) {
        return false;
    }
    return eventPermission[index] === "1";
}

async function loadEvent() {
    const id = getQueryParam('id');
    if (!id) {
        eventContainer.innerHTML = '<p style="color: var(--muted);">No event specified.</p>';
        return;
    }

    try {
        let res = await fetch(`${API_URL}/events/${encodeURIComponent(id)}`);
        let event = await res.json();
        if (!res.ok) {
            eventContainer.innerHTML = `<p style="color: var(--muted);">${event.error || 'Event not found'}</p>`;
            return;
        }
        renderEvent(event);
        // Only load participants if user is logged in and is Administrator
        if(currentUser && currentUser.role == "Administrator") {
            loadParticipant();
        }
    } catch (err) {
        console.error(err);
        eventContainer.innerHTML = '<p style="color: var(--muted);">Connection error. Make sure server is running.</p>';
    }
}

async function renderEvent(event) {
    const imgSrc = event.imagePath;

    const past = isPastEvent(event.date);
    const participantCount = event.participantCount || 0;
    const maxParticipants = event.participationLimit || 0;
    const isLimitReached = participantCount >= maxParticipants;

    let applyStatus = 0;
    if (currentUser && !past) {
        try {
            const resp = await fetch(`${API_URL}/events/${event.id}/applied`, {
                headers: { 'Authorization': `Bearer ${token}` }
            });
            if (!resp.ok) throw new Error("Failed to fetch status");

            const data = await resp.json();
            applyStatus = data.status;
        } catch (err) {
            console.error('Check applied error:', err);
        }
    }

    const formatDate = (dateString) => {
        if (!dateString) return 'N/A';
        const date = new Date(dateString);
        return date.toLocaleDateString('en-US', { year: 'numeric', month: 'short', day: 'numeric' });
    };

    eventContainer.innerHTML = `
        <div class="event-detail-card">
            <h2 style="margin-top:12px; color: white;">${event.title}</h2>
            ${imgSrc ? `<img src="${imgSrc}" alt="Event Image" style="width:100%; object-fit:cover; border-radius:6px;"/>` : ``}
            <p><strong>📅</strong> ${new Date(event.date).toLocaleDateString()} &nbsp; <strong>📍</strong> ${event.location}</p>
            <p><strong>👥</strong> Participants: ${participantCount} / ${maxParticipants}</p>
            ${event.description ? `<p style="margin-top:8px;">${event.description}</p>` : ''}

            <div style="margin-top:16px;">
                ${past
                    ? `<button class="submit-btn" disabled style="background-color:gray; cursor:not-allowed;">Event Ended</button>`
                    : (
                        currentUser
                        ? (
                            isUserAllowed(event.permission, currentUser)
                            ? (
                                isLimitReached && applyStatus === 0
                                    ? `<button class="submit-btn" disabled style="background-color:gray; cursor:not-allowed;">Limit reached</button>`
                                    : `<button id="actionBtn" class="submit-btn" style="${
                                        applyStatus === 1 || applyStatus === 2 ? 'background-color:red;' : ''
                                    }" ${isLimitReached && applyStatus === 0 ? 'disabled' : ''}>
                                        ${
                                        applyStatus === 1
                                            ? 'Retract' : applyStatus === 2
                                            ? 'Retract from waiting list' : 'Apply'
                                        }
                                    </button>`
                            )
                            : `<button class="submit-btn" disabled style="background-color:gray; cursor:not-allowed;">
                                Not eligible to apply
                            </button>`
                        )
                        : `<a href="signin.html"><button class="submit-btn" ${isLimitReached ? 'disabled style="background-color:gray; cursor:not-allowed;">Limit reached' : '>Sign in to apply'}</button></a>`
                    )
                }
            </div>
            
            <div style="margin-top:20px; padding-top:15px; border-top:1px solid #475569; display:flex; justify-content:flex-end; gap:15px; font-size:0.85rem; color:var(--muted);">
                ${event.ownerEmail ? `<span>👤 Owner: ${event.ownerEmail}</span>` : ''}
                ${event.createdAt ? `<span>📅 Created: ${formatDate(event.createdAt)}</span>` : ''}
            </div>
        </div>
    `;

    attachButtonHandler(event, applyStatus);
}

function attachButtonHandler(event, applyStatus)
{
    const actionBtn = document.getElementById('actionBtn');
    if(!actionBtn || actionBtn.disabled) return;

    if (applyStatus === 0) {
        actionBtn.addEventListener('click', () => applyEvent(event));
    } else {
        actionBtn.addEventListener('click', () => retractEvent(event));
    }
}

async function applyEvent(event)
{
    try {
        const response = await fetch(`${API_URL}/events/${event.id}/apply`, {
            method: 'POST',
            headers: { 'Authorization': `Bearer ${token}` }
        });
        const data = await response.json();

        if (!response.ok) {
            showError(data.error || 'Failed to apply for event');
            return;
        }

        showSuccess(data.message || 'Applied successfully!');
        // Fetch updated event data and re-render
        await loadEvent();
    } catch (err) {
        console.error('Apply error:', err);
        showError('Connection error. Make sure your server is running.');
    }
}

async function retractEvent(event)
{
    try {
        const response = await fetch(`${API_URL}/events/${event.id}/apply`, {
            method: 'PATCH',
            headers: { 
                'Authorization': `Bearer ${token}`,
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ status: 0 })
        });
        const data = await response.json();

        if (!response.ok) {
            showError(data.error || 'Failed to retract application');
            return;
        }

        showSuccess(data.message || 'Application retracted.');
        // Fetch updated event data and re-render
        await loadEvent();
    } catch (err) {
        console.error('Retract error:', err);
        showError('Connection error. Make sure your server is running.');
    }
}

loadEvent();
