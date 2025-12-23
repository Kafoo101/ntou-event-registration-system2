const API_URL = 'https://ntou-event-registration-system2-five.vercel.app/';

const regiForm = document.getElementById('regiForm');
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

async function fetchNextId() {
    try {
        const response = await fetch(`${API_URL}/nextId`); // backend endpoint for next ID
        const data = await response.json();
        return data.nextId;
    } catch (err) {
        console.error(err);
        showError('Could not fetch next ID.');
        throw err;
    }
}

async function registerUser(nickname, emailOrPhone, password, occupation) {
    try {
        const response = await fetch(`${API_URL}/register`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ nickname, email_or_phone: emailOrPhone, password, occupation })
        });

        const data = await response.json();

        if (response.ok) {
            showSuccess('Registration successful! Redirecting to login...');
            setTimeout(() => {
                window.location.href = 'signin.html';
            }, 200);
        } else {
            showError(data.error || 'Registration failed');
        }
    } catch (err) {
        console.error(err);
        showError('Connection error. Make sure your server is running.');
    } finally {
        submitBtn.disabled = false;
        submitBtn.textContent = 'Register';
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

regiForm.addEventListener('submit', async (e) => {
    e.preventDefault();

    const nickname = document.getElementById('nickname').value.trim();
    const emailOrPhone = document.getElementById('emailOrPhone').value.trim();
    const password = document.getElementById('password').value;
    const occupation = document.getElementById("ddlOrd").textContent;

    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(emailOrPhone)) {
        showError('Please enter a valid email.');
        return;
    }

    if(password.length < 8){
        showError('Password should be at least 8 characters.');
        return;
    }

    submitBtn.disabled = true;
    submitBtn.textContent = 'Processing...';

    registerUser(nickname, emailOrPhone, password, occupation);
    console.log("Form submitted");
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
        });
    });
});

//out-focus click of dropdowns closes them
document.addEventListener("click", function () {
    document.querySelectorAll(".ddloptions").forEach(function (opt) {
        opt.style.display = "none";
    });
});
