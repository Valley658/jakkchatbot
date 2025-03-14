// Server status monitoring script

// Configuration
const CHECK_INTERVAL = 5000; // Check every 5 seconds
let serverWasDown = false;
let notificationShown = false;
let notificationElement = null;

// Function to check server status
function checkServerStatus() {
    fetch('/health_check', { 
        method: 'GET',
        cache: 'no-store',
        headers: {
            'Cache-Control': 'no-cache',
            'Pragma': 'no-cache'
        }
    })
    .then(response => {
        if (response.ok) {
            // Server is up
            if (serverWasDown) {
                console.log('Server is back online, refreshing...');
                location.reload();
            }
            serverWasDown = false;
            hideNotification();
        } else {
            // Server responded with error
            serverWasDown = true;
            showServerDownNotification();
        }
    })
    .catch(error => {
        // Failed to connect to server
        console.log('Server connection error:', error);
        serverWasDown = true;
        showServerDownNotification();
    });
}

// Function to show notification
function showServerDownNotification() {
    if (notificationShown) return;

    // Create notification if it doesn't exist
    if (!notificationElement) {
        notificationElement = document.createElement('div');
        notificationElement.classList.add('server-notification');
        notificationElement.style.position = 'fixed';
        notificationElement.style.top = '0';
        notificationElement.style.left = '0';
        notificationElement.style.right = '0';
        notificationElement.style.backgroundColor = '#f44336';
        notificationElement.style.color = 'white';
        notificationElement.style.textAlign = 'center';
        notificationElement.style.padding = '15px';
        notificationElement.style.zIndex = '9999';
        notificationElement.textContent = '서버가 다시 시작되는 중입니다. 잠시만 기다려주세요...';
        document.body.appendChild(notificationElement);
    }

    notificationElement.style.display = 'block';
    notificationShown = true;
}

// Function to hide notification
function hideNotification() {
    if (notificationElement) {
        notificationElement.style.display = 'none';
        notificationShown = false;
    }
}

// Start monitoring when document is loaded
document.addEventListener('DOMContentLoaded', () => {
    // Initial check
    checkServerStatus();
    
    // Set interval for regular checks
    setInterval(checkServerStatus, CHECK_INTERVAL);
});
