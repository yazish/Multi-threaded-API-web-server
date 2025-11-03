(function () {
    const authSection = document.getElementById('auth-section');
    const authForms = document.getElementById('auth-forms');
    const sessionInfo = document.getElementById('session-info');
    const sessionUsername = document.getElementById('session-username');
    const authStatus = document.getElementById('auth-status');
    const loginForm = document.getElementById('login-form');
    const registerForm = document.getElementById('register-form');
    const logoutButton = document.getElementById('logout-button');
    const composer = document.getElementById('composer');
    const messageForm = document.getElementById('message-form');
    const messageStatus = document.getElementById('message-status');
    const messagesCard = document.getElementById('messages');
    const messagesStatus = document.getElementById('messages-status');
    const messageList = document.getElementById('message-list');

    let lastTimestamp = null;
    let currentUser = null;
    let pollTimer = null;

    function setStatus(element, message, isError) {
        element.textContent = message || '';
        element.classList.toggle('error', Boolean(isError));
    }

    function toggleAuthUI(isAuthenticated) {
        if (isAuthenticated) {
            authForms.classList.add('hidden');
            sessionInfo.classList.remove('hidden');
            composer.classList.remove('hidden');
            messagesCard.classList.remove('hidden');
        } else {
            authForms.classList.remove('hidden');
            sessionInfo.classList.add('hidden');
            composer.classList.add('hidden');
            messagesCard.classList.add('hidden');
        }
    }

    function xhrRequest(method, url, body, callback) {
        const xhr = new XMLHttpRequest();
        xhr.open(method, url, true);
        xhr.withCredentials = true;
        xhr.setRequestHeader('Accept', 'application/json');
        if (body !== null && body !== undefined) {
            xhr.setRequestHeader('Content-Type', 'application/json');
        }
        xhr.onreadystatechange = function () {
            if (xhr.readyState === XMLHttpRequest.DONE) {
                let payload = null;
                try {
                    payload = xhr.responseText ? JSON.parse(xhr.responseText) : null;
                } catch (err) {
                    payload = null;
                }
                callback(xhr.status, payload, xhr);
            }
        };
        xhr.send(body ? JSON.stringify(body) : null);
    }

    function handleLogin(event) {
        event.preventDefault();
        const formData = new FormData(loginForm);
        const username = formData.get('username').trim();
        const password = formData.get('password');
        setStatus(authStatus, 'Signing in…');
        xhrRequest('POST', '/api/login', { username, password }, function (status, payload) {
            if (status === 200) {
                currentUser = payload.user.username;
                sessionUsername.textContent = currentUser;
                toggleAuthUI(true);
                setStatus(authStatus, 'Signed in successfully.');
                startPolling();
                fetchMessages(true);
            } else {
                setStatus(authStatus, payload && payload.error ? payload.error : 'Login failed.', true);
            }
        });
    }

    function handleRegister(event) {
        event.preventDefault();
        const formData = new FormData(registerForm);
        const username = formData.get('username').trim();
        const password = formData.get('password');
        setStatus(authStatus, 'Creating account…');
        xhrRequest('POST', '/api/user', { username, password }, function (status, payload) {
            if (status === 200) {
                setStatus(authStatus, 'Account created! You can now log in.');
                registerForm.reset();
            } else {
                const message = payload && payload.error ? payload.error : 'Registration failed.';
                setStatus(authStatus, message, true);
            }
        });
    }

    function handleLogout() {
        xhrRequest('DELETE', '/api/login', null, function () {
            currentUser = null;
            stopPolling();
            toggleAuthUI(false);
            sessionUsername.textContent = '';
            messageList.innerHTML = '';
            lastTimestamp = null;
            setStatus(authStatus, 'Signed out.');
        });
    }

    function handleMessageSubmit(event) {
        event.preventDefault();
        const formData = new FormData(messageForm);
        const message = formData.get('message').trim();
        if (!message) {
            return;
        }
        setStatus(messageStatus, 'Posting message…');
        xhrRequest('POST', '/api/messages', { message }, function (status, payload) {
            if (status === 201) {
                setStatus(messageStatus, 'Message posted.');
                messageForm.reset();
                fetchMessages(true);
            } else {
                const messageText = payload && payload.error ? payload.error : 'Failed to post message.';
                setStatus(messageStatus, messageText, true);
            }
        });
    }

    function deleteMessage(messageId) {
        xhrRequest('DELETE', '/api/messages/' + messageId, null, function (status, payload) {
            if (status === 200) {
                setStatus(messagesStatus, 'Message deleted.');
                fetchMessages(true);
            } else {
                const messageText = payload && payload.error ? payload.error : 'Failed to delete message.';
                setStatus(messagesStatus, messageText, true);
            }
        });
    }

    function renderMessages(messages) {
        if (!Array.isArray(messages) || messages.length === 0) {
            messageList.innerHTML = '<p class="empty">No messages yet.</p>';
            return;
        }
        const fragment = document.createDocumentFragment();
        messages.forEach(function (message) {
            const wrapper = document.createElement('article');
            wrapper.className = 'message';

            const header = document.createElement('header');
            const author = document.createElement('span');
            author.className = 'author';
            author.textContent = message.author;
            const timestamp = document.createElement('time');
            timestamp.className = 'timestamp';
            const date = new Date(Number(message.time) / 1e6);
            timestamp.textContent = date.toLocaleString();
            header.appendChild(author);
            header.appendChild(document.createTextNode(' · '));
            header.appendChild(timestamp);
            wrapper.appendChild(header);

            const body = document.createElement('p');
            body.className = 'body';
            body.textContent = message.msg;
            wrapper.appendChild(body);

            if (message.owned) {
                const actions = document.createElement('div');
                actions.className = 'actions';
                const deleteButton = document.createElement('button');
                deleteButton.type = 'button';
                deleteButton.textContent = 'Delete';
                deleteButton.addEventListener('click', function () {
                    deleteMessage(message.id);
                });
                actions.appendChild(deleteButton);
                wrapper.appendChild(actions);
            }

            fragment.appendChild(wrapper);
        });
        messageList.innerHTML = '';
        messageList.appendChild(fragment);
    }

    function fetchMessages(force) {
        if (!currentUser) {
            return;
        }
        let url = '/api/messages';
        if (lastTimestamp && !force) {
            url += '?last=' + encodeURIComponent(lastTimestamp);
        }
        xhrRequest('GET', url, null, function (status, payload) {
            if (status === 200 && payload) {
                const messages = payload.messages || [];
                if (messages.length > 0) {
                    const latest = messages[messages.length - 1];
                    lastTimestamp = latest.time;
                }
                renderMessages(messages);
                setStatus(messagesStatus, '');
            } else if (status === 401) {
                handleLogout();
            } else {
                const messageText = payload && payload.error ? payload.error : 'Unable to load messages.';
                setStatus(messagesStatus, messageText, true);
            }
        });
    }

    function startPolling() {
        if (pollTimer) {
            clearInterval(pollTimer);
        }
        pollTimer = setInterval(function () {
            fetchMessages(false);
        }, 5000);
    }

    function stopPolling() {
        if (pollTimer) {
            clearInterval(pollTimer);
            pollTimer = null;
        }
    }

    function checkSession() {
        xhrRequest('GET', '/api/login', null, function (status, payload) {
            if (status === 200 && payload && payload.authenticated) {
                currentUser = payload.user.username;
                sessionUsername.textContent = currentUser;
                toggleAuthUI(true);
                setStatus(authStatus, 'Welcome back!');
                startPolling();
                fetchMessages(true);
            } else {
                toggleAuthUI(false);
            }
        });
    }

    loginForm.addEventListener('submit', handleLogin);
    registerForm.addEventListener('submit', handleRegister);
    logoutButton.addEventListener('click', handleLogout);
    messageForm.addEventListener('submit', handleMessageSubmit);

    checkSession();
})();
