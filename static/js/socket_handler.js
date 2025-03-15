document.addEventListener('DOMContentLoaded', function() {
    // Connect to Socket.IO server
    const socket = io();
    
    // Listen for server restart events
    socket.on('server_restart', function(data) {
        // Create overlay for restart notification
        const overlay = document.createElement('div');
        overlay.style.position = 'fixed';
        overlay.style.top = '0';
        overlay.style.left = '0';
        overlay.style.width = '100%';
        overlay.style.height = '100%';
        overlay.style.backgroundColor = 'rgba(0, 0, 0, 0.8)';
        overlay.style.zIndex = '9999';
        overlay.style.display = 'flex';
        overlay.style.justifyContent = 'center';
        overlay.style.alignItems = 'center';
        
        // Create message element
        const message = document.createElement('div');
        message.innerHTML = data.message;
        message.style.color = 'white';
        message.style.fontSize = '32px';
        message.style.textAlign = 'center';
        message.style.fontWeight = 'bold';
        message.style.padding = '20px';
        
        // Add message to overlay
        overlay.appendChild(message);
        
        // Add overlay to body
        document.body.appendChild(overlay);
        
        // Auto refresh after 3 seconds
        setTimeout(function() {
            window.location.reload();
        }, 3000);
    });
});
