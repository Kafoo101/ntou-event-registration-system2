const API_URL = 'process.env.NEXT_PUBLIC_API_URL';

const signForm = document.getElementById('signForm');
const submitBtn = document.getElementById('submit-btn');
const errorMsg = document.getElementById('errorMsg');
const successMsg = document.getElementById('successMsg');

function showError(msg) {
    errorMsg.textContent = msg;
    errorMsg.style.display = 'block';
    successMsg.style.display = 'none';
}
function showSuccess(msg) {
    successMsg.textContent = msg;
    successMsg.style.display = 'block';
    errorMsg.style.display = 'none';
}

async function signInUser(emailOrPhone, password) {
    try {
        const response = await fetch(`${API_URL}/signin`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ email_or_phone: emailOrPhone, password })
        });

        const data = await response.json();

        if (response.ok && data.token) {
            localStorage.setItem('authToken', data.token);
            
            showSuccess('Sign in successful! Redirecting...');
            setTimeout(() => {
                // redirect after successful sign in
                window.location.href = 'index.html'; 
            }, 200);
        } else {
            showError(data.error || 'Sign in failed');
        }
    } catch (err) {
        console.error(err);
        showError('Connection error. Make sure your server is running.');
    } finally {
        submitBtn.disabled = false;
        submitBtn.textContent = 'Sign In';
    }
}

// Password toggle functionality
const togglePassword = document.getElementById('togglePassword');
const passwordInput = document.getElementById('password');

if (togglePassword && passwordInput) {
    togglePassword.addEventListener('click', () => {
        const type = passwordInput.getAttribute('type') === 'password' ? 'text' : 'password';
        passwordInput.setAttribute('type', type);
        togglePassword.textContent = type === 'password' ? '👁️' : '👁️‍🗨️';
    });
}

signForm.addEventListener('submit', async (e) => {
    e.preventDefault();

    const emailOrPhone = document.getElementById('emailOrPhone').value.trim();
    const password = document.getElementById('password').value;

    submitBtn.disabled = true;
    submitBtn.textContent = 'Processing...';

    signInUser(emailOrPhone, password);
    console.log("Sign in form submitted");
});
