// This assumes the file exists - if not, create it with this content

$(document).ready(function() {
    // Existing code initialization...
    
    // Setup socket.io connection for server restart notifications
    const socket = io();
    
    socket.on('connect', function() {
        console.log('Connected to server');
    });
    
    socket.on('disconnect', function() {
        console.log('Disconnected from server');
        // Optional: show a disconnected message
        showStatusMessage('Disconnected from server. Attempting to reconnect...');
    });
    
    socket.on('server_restart', function(data) {
        console.log('Server is restarting:', data.message);
        showStatusMessage('Server is restarting. Page will refresh in 3 seconds...');
        
        // Refresh the page after short delay
        setTimeout(function() {
            window.location.reload();
        }, 3000);
    });
    
    function showStatusMessage(message) {
        // Create status message element if it doesn't exist
        if (!$('.status-message').length) {
            $('<div class="status-message"></div>')
                .css({
                    'position': 'fixed',
                    'top': '10px',
                    'left': '50%',
                    'transform': 'translateX(-50%)',
                    'background-color': 'rgba(0,0,0,0.7)',
                    'color': 'white',
                    'padding': '10px 20px',
                    'border-radius': '5px',
                    'z-index': '9999'
                })
                .appendTo('body');
        }
        
        // Update message
        $('.status-message').text(message).fadeIn();
    }
    
    // Function to add a message to the chat interface
    function addMessage(message, isUser) {
        // Create message container inside chat-main div
        const messageHtml = isUser 
            ? `
                <div class="user-message-container">
                    <div class="user-icon">U</div>
                    <div class="user-message">${message}</div>
                </div>
            `
            : `
                <div class="bot-message-container">
                    <div class="bot-icon">B</div>
                    <div class="bot-message">${message}</div>
                </div>
            `;
            
        // Append to chat-main instead of wherever it was appending before
        $('.chat-main').append(messageHtml);
        
        // Scroll to bottom of chat
        $('.chat-main').scrollTop($('.chat-main')[0].scrollHeight);
    }
    
    // Handle form submission
    $('#message-form').submit(function(event) {
        event.preventDefault();
        const userInput = $('#message-input').val().trim();
        
        if (userInput !== '') {
            // Add user message to chat
            addMessage(userInput, true);
            
            // Clear input field
            $('#message-input').val('');
            
            // Send message to server
            $.ajax({
                type: 'POST',
                url: '/chat',
                data: {
                    message: userInput,
                    model: currentModel
                },
                headers: {
                    'X-Requested-With': 'XMLHttpRequest'
                },
                success: function(response) {
                    // Add bot response to chat
                    addMessage(response.response, false);
                    
                    // Handle TTS if enabled
                    if (response.tts_enabled) {
                        // TTS code...
                    }
                },
                error: function() {
                    addMessage("Sorry, I couldn't process your request.", false);
                }
            });
        }
    });
    
    // Load initial messages if any
    function loadInitialMessages(history) {
        if (history && history.length > 0) {
            $('.chat-main').empty(); // Clear existing messages
            
            history.forEach(function(msg) {
                const isUser = msg.role === 'user';
                addMessage(msg.content, isUser);
            });
        }
    }
    
    // Other event handlers...
});
