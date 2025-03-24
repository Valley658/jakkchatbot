# jakkChatBOT

## Overview
jakkChatBOT is an advanced chatbot application meticulously crafted using Flask, SQLAlchemy, and state-of-the-art machine learning models such as GPT-2 and T5. This versatile application supports multiple languages and integrates features like speech-to-text and text-to-speech to ensure a seamless user experience. Key functionalities include user authentication, language detection, and comprehensive system status monitoring. **The application is designed to be implemented in both Python and JavaScript environments.**

## Features
- **User Authentication and Registration:** Secure user authentication and registration system to manage user access.
- **Persistent Chat Memory:** Conversations are stored in a database, allowing the chatbot to maintain context across sessions.
- **Automatic Language Detection and Translation:** Effortlessly detect and translate languages to facilitate multilingual interactions.
- **Speech-to-Text and Text-to-Speech Functionality:** Convert spoken language to text and vice versa, enhancing accessibility and user engagement.
- **System Status Monitoring:** Real-time monitoring of CPU, memory, and GPU usage to ensure optimal performance.
- **Admin Dashboard:** A comprehensive dashboard for administrators to manage users and monitor system status.
- **Cross-Platform Support:** Seamlessly supports both Python and JavaScript implementations.

## Setup

### Prerequisites
- OPENAI_API_KEY
- Python 3.10 or higher
- Flask
- SQLAlchemy
- TensorFlow
- PyTorch

### Installation

#### Python
1. **Install the required packages:**
    ```sh
    pip install -r requirements.txt
    ```

2. **Set up the database:**
    ```sh
    flask db upgrade
    ```

3. **Run the application:**
    ```sh
    flask run
    ```

#### JavaScript
1. **Clone the repository:**
    ```sh
    git clone https://github.com/Valley658/jakkChatBOT.git
    ```

2. **Run the Express application:**
    ```sh
    npm start
    ```

3. **Important Note:** When running start.bat, please make sure to run it as an administrator for proper functionality.

## Usage
- **Access the application:** Navigate to `http://localhost:80` in your web browser.
- **User Registration and Login:** Register a new user or log in with an existing account to start interacting with the chatbot.
- **Chat Interface:** Use the intuitive chat interface to communicate with the chatbot.
- **Admin Dashboard:** Admin users can access the dashboard at `http://localhost:80/dashboard` for user and system management.

## Additional Features
- **Text-to-Speech:** Convert text to speech and play it directly in the browser for an enhanced interactive experience.
- **System Status Monitoring:** Keep track of CPU, memory, and GPU usage to ensure the system is running efficiently.

## License
This project is licensed under the [MIT License](LICENSE).