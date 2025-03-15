/**
 * Server monitor script to handle server restarts and reconnections
 */
document.addEventListener('DOMContentLoaded', function() {
    // Check if Socket.IO is loaded
    if (typeof io === 'undefined') {
        console.error('Socket.IO is not loaded. Server monitoring is disabled.');
        return;
    }
    
    // Connect to server
    const socket = io();
    
    // Server restart handling
    socket.on('server_restart', function(data) {
        console.log('Server restart detected:', data.message);
        
        // Show notification
        const notification = document.createElement('div');
        notification.className = 'server-notification';
        notification.innerHTML = `
            <div class="server-notification-content">
                <i class="fas fa-sync fa-spin"></i> ${data.message}
            </div>
        `;
        document.body.appendChild(notification);
        
        // Schedule page refresh
        setTimeout(function() {
            window.location.reload();
        }, 3000);
    });
    
    // Server disconnect handling
    socket.on('disconnect', function() {
        console.log('Disconnected from server');
        
        // Add reconnection indicator
        const indicator = document.createElement('div');
        indicator.className = 'connection-indicator disconnected';
        indicator.innerHTML = 'Disconnected';
        document.body.appendChild(indicator);
    });
    
    // Server reconnect handling
    socket.on('connect', function() {
        console.log('Connected to server');
        
        // Remove any existing indicators
        const indicators = document.querySelectorAll('.connection-indicator');
        indicators.forEach(el => el.remove());
        
        // Clean up any notifications
        const notifications = document.querySelectorAll('.server-notification');
        notifications.forEach(el => el.remove());
    });
});

// Add CSS for notifications
const style = document.createElement('style');
style.textContent = `
.server-notification {
    position: fixed;
    top: 20px;
    left: 50%;
    transform: translateX(-50%);
    background-color: rgba(0, 0, 0, 0.8);
    color: white;
    padding: 12px 20px;
    border-radius: 8px;
    z-index: 9999;
    box-shadow: 0 4px 12px rgba(0, 0, 0, 0.2);
}

.connection-indicator {
    position: fixed;
    bottom: 20px;
    right: 20px;
    padding: 8px 12px;
    border-radius: 4px;
    font-size: 12px;
    z-index: 1000;
}

.connection-indicator.disconnected {
    background-color: #f44336;
    color: white;
}
`;
document.head.appendChild(style);
