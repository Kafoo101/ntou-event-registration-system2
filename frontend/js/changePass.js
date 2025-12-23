const API_URL = 'https://ntou-event-registration-system2-hggmckqj8-kafoos-projects.vercel.app';
const errorMsg = document.getElementById('errorMsg');
const successMsg = document.getElementById('successMsg');
const nicknameInput = document.getElementById('nickname');
const oldPasswordInput = document.getElementById('oldPassword');
const newPasswordInput = document.getElementById('newPassword');
const confirmPasswordInput = document.getElementById('confirmPassword');
const changePassForm = document.getElementById('changePassForm');

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

// Retrieve token and user info
const token = localStorage.getItem('authToken');
let currentUser = null;
if (token) {
    const userData = parseJwt(token);
    if (userData && userData.email) currentUser = userData;
}

// Fill nickname on page load
if (currentUser) {
    nicknameInput.value = currentUser.name || '';
    nicknameInput.disabled = true;
} else {
    showError('You must be signed in to change account info.');
    changePassForm.querySelector('button').disabled = true;
}

// Handle form submission
changePassForm.addEventListener('submit', async (e) => {
    e.preventDefault();

    const oldPassword = oldPasswordInput.value.trim();
    const newPassword = newPasswordInput.value.trim();
    const confirmPassword = confirmPasswordInput.value.trim();

    if (!oldPassword || !newPassword || !confirmPassword) {
        showError('Please fill in all fields.');
        return;
    }

    if (newPassword !== confirmPassword) {
        showError('New password and confirm password do not match.');
        return;
    }

    if (newPassword == oldPassword) {
        showError('New password and current password must be different.');
        return;
    }

    try {
        // 1. Verify old password
        const verifyResp = await fetch(`${API_URL}/users/verify-password`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${token}`
            },
            body: JSON.stringify({ oldPassword })
        });
        const verifyData = await verifyResp.json();
        if (!verifyResp.ok) {
            showError(verifyData.error || 'Old password is incorrect.');
            return;
        }

        // 2. Update password
        const updateResp = await fetch(`${API_URL}/users/update-password`, {
            method: 'PATCH',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${token}`
            },
            body: JSON.stringify({ newPassword })
        });
        const updateData = await updateResp.json();
        if (!updateResp.ok) {
            showError(updateData.error || 'Failed to update password.');
            return;
        }
        showSuccess(updateData.message || 'Password changed successfully!');
        setTimeout(() => {
            window.location.href = 'index.html'; 
        }, 200);
    } catch (err) {
        console.error('Change password error:', err);
        showError('Connection error. Please try again later.');
    }
});
