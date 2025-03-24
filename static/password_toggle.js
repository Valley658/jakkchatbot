document.addEventListener('DOMContentLoaded', function() {
    // Function to set up password toggle for a specific field
    function setupPasswordToggle(passwordField, toggleIcon) {
        toggleIcon.addEventListener('click', function() {
            // Toggle between password and text
            const type = passwordField.getAttribute('type') === 'password' ? 'text' : 'password';
            passwordField.setAttribute('type', type);
            
            // Toggle icon class between eye and eye-slash
            toggleIcon.classList.toggle('fa-eye');
            toggleIcon.classList.toggle('fa-eye-slash');
        });
    }
    
    // Set up all password toggle fields on the page
    const passwordContainers = document.querySelectorAll('.password-field');
    passwordContainers.forEach(container => {
        const passwordField = container.querySelector('input[type="password"]');
        const toggleIcon = container.querySelector('.password-toggle');
        if (passwordField && toggleIcon) {
            setupPasswordToggle(passwordField, toggleIcon);
        }
    });
});
