// Toast notification
function showToast(message, type = 'info') {
    let toast = document.querySelector('.toast');
    if (!toast) {
        toast = document.createElement('div');
        toast.className = 'toast';
        document.body.appendChild(toast);
    }
    toast.textContent = message;
    toast.style.background = type === 'error'
        ? 'linear-gradient(90deg, #ff5858 0%, #f09819 100%)'
        : 'linear-gradient(90deg, #6dd5fa 0%, #3498db 100%)';
    toast.classList.add('show');
    setTimeout(() => toast.classList.remove('show'), 3000);
}

// Loading spinner
function showSpinner(container) {
    if (!container) return;
    container.innerHTML = '<div class="spinner"></div>';
}

// Handle login form submission
const loginForm = document.getElementById('login-form');
if (loginForm) {
    const loginBtn = loginForm.querySelector('button[type="submit"]');
    loginForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        // Disable button and show spinner
        loginBtn.disabled = true;
        const originalBtnHTML = loginBtn.innerHTML;
        loginBtn.innerHTML = '<span class="spinner" style="width:20px;height:20px;margin-right:8px;"></span> Logging in...';
        const formData = new FormData(loginForm);
        const data = new URLSearchParams(formData);
        const res = await fetch('/login', {
            method: 'POST',
            body: data,
        });
        loginBtn.disabled = false;
        loginBtn.innerHTML = originalBtnHTML;
        if (res.redirected) {
            showToast('Login successful!', 'success');
            window.location.href = res.url;
        } else {
            const text = await res.text();
            document.getElementById('login-error').innerText = text;
            showToast(text, 'error');
        }
    });
}

// Handle registration form submission
const registerForm = document.getElementById('register-form');
if (registerForm) {
    const registerBtn = registerForm.querySelector('button[type="submit"]');
    registerForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        // Disable button and show spinner
        registerBtn.disabled = true;
        const originalBtnHTML = registerBtn.innerHTML;
        registerBtn.innerHTML = '<span class="spinner" style="width:20px;height:20px;margin-right:8px;"></span> Registering...';
        const formData = new FormData(registerForm);
        const data = new URLSearchParams(formData);
        const res = await fetch('/register', {
            method: 'POST',
            body: data,
        });
        registerBtn.disabled = false;
        registerBtn.innerHTML = originalBtnHTML;
        if (res.redirected) {
            showToast('Registration successful!', 'success');
            window.location.href = res.url;
        } else {
            const text = await res.text();
            document.getElementById('register-error').innerText = text;
            showToast(text, 'error');
        }
    });
}

// AJAX Search
const searchForm = document.querySelector('.search-form');
const resultsContainer = document.querySelector('.results-container');
if (searchForm && resultsContainer) {
    searchForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        showSpinner(resultsContainer);
        const q = searchForm.querySelector('input[name="q"]').value;
        const res = await fetch(`/api/search?q=${encodeURIComponent(q)}`);
        const results = await res.json();
        renderResults(q, results);
        if (results.length === 0) {
            showToast('No results found for your query.', 'error');
        } else {
            showToast('Search complete!', 'success');
        }
    });
}

function renderResults(query, results) {
    let html = `<h2>Search Results for \"${query}\"</h2>`;
    if (!Array.isArray(results)) {
        results = [];
    }
    if (results.length > 0) {
        html += '<div class="results-list">';
        results.forEach(r => {
            html += `<div class="result-item animate">\n                <h3>${r.document.title}</h3>\n                <p>${r.document.content}</p>\n                <div class="result-meta"><span class="score">Relevance: ${r.score}</span></div>\n            </div>`;
        });
        html += '</div>';
    } else {
        html += '<p class="no-results">No results found for your query.</p>';
    }
    resultsContainer.innerHTML = html;
}

// AJAX History
const historyList = document.querySelector('.history-list');
if (historyList) {
    showSpinner(historyList);
    fetch('/api/history').then(res => res.json()).then(history => {
        let html = '';
        if (history.length > 0) {
            history.forEach(h => {
                html += `<div class="history-item animate">\n                    <a href="/search?q=${encodeURIComponent(h.query)}" class="history-query">${h.query}</a>\n                    <span class="history-time">${new Date(h.timestamp).toLocaleString()}</span>\n                </div>`;
            });
        } else {
            html = '<p class="no-history">No search history found.</p>';
        }
        historyList.innerHTML = html;
        showToast('History loaded!', 'success');
    });
}

// Optionally, you can add AJAX for fetching history or other features here. 