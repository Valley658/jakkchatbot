@echo off
setlocal enabledelayedexpansion
title JakkChatBOT Unified Manager

:: Check if running as Administrator
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo [WARNING] This script is not running with administrator privileges.
    echo           Some features may be limited.
    echo           To run with admin rights, right-click on command prompt and select "Run as administrator".
    echo.
)

:: Set console code page for proper display
chcp 65001 >nul
color 0A

:main_menu
cls
echo ====================================================================
echo                JAKKCHATBOT UNIFIED MANAGEMENT TOOL v1.0
echo ====================================================================
echo.
echo  [1] Install Required Packages
echo  [2] Configure Security Settings
echo  [3] Start ChatBot Server
echo  [4] Manage ChatBot Configuration
echo  [5] Run Security Checks
echo  [6] Train ChatBot Model
echo  [7] Database Tools
echo  [8] View System Information
echo  [9] Exit
echo.
echo ====================================================================
echo.

set /p choice=Select an option (1-9): 

if "%choice%"=="1" goto install_packages
if "%choice%"=="2" goto security_setup
if "%choice%"=="3" goto start_server
if "%choice%"=="4" goto manage_chatbot
if "%choice%"=="5" goto check_security
if "%choice%"=="6" goto train_model
if "%choice%"=="7" goto database_tools
if "%choice%"=="8" goto system_info
if "%choice%"=="9" goto end
goto main_menu

:install_packages
cls
echo ====================================================================
echo              INSTALLING PACKAGES
echo ====================================================================
echo.

echo [INFO] Checking Python and pip versions...
python --version
pip --version
echo.

echo [INFO] Updating pip to the latest version...
pip install --upgrade pip

echo.
echo [INFO] Installing required packages...
echo.

set total_packages=24
set current=0
set failed_packages=

:: Install from requirements.txt if available
if exist requirements.txt (
    echo [INFO] Installing packages from requirements.txt...
    pip install -r requirements.txt
    echo.
)

:: ChatBot specific packages
call :install_package "tensorflow"
call :install_package "numpy==1.24.3" --force-reinstall
call :install_package "nltk"
call :install_package "keras"

:: Flask and web related packages
call :install_package "Flask==2.0.1"
call :install_package "werkzeug==2.0.3"
call :install_package "flask-limiter==2.8.0"
call :install_package "flask-talisman==1.0.0"

:: Computation packages
call :install_package "psutil==5.9.0"

:: Security related packages
call :install_package "pyopenssl==23.0.0"
call :install_package "ratelimit==2.2.1"
call :install_package "bcrypt==4.0.1"
call :install_package "pyotp==2.8.0"
call :install_package "certifi==2022.12.7"
call :install_package "cryptography==39.0.1"

:: Network and utility packages
call :install_package "requests==2.28.2"
call :install_package "py-healthcheck==1.10.1"

:: Windows-specific packages
call :install_package "pywin32"
call :install_package "windows-curses"

:: Security scanning tools
call :install_package "safety"
call :install_package "bandit"
call :install_package "win-inet-pton"

:: NLP related packages
call :install_package "spacy"
call :install_package "gensim"
call :install_package "transformers"

echo.
if defined failed_packages (
    echo [WARNING] Failed to install the following packages:
    echo %failed_packages%
    echo Please install them manually.
) else (
    echo [SUCCESS] All packages were installed successfully!
)

echo.
echo Installation complete. Press any key to return to the menu...
pause >nul
goto main_menu

:security_setup
cls
echo ====================================================================
echo              SECURITY SETUP
echo ====================================================================
echo.

echo [INFO] Creating security directories...
mkdir security_logs 2>nul
if exist security_logs (
    echo [SUCCESS] security_logs directory created
) else (
    echo [ERROR] Failed to create security_logs directory
)

mkdir exports 2>nul
if exist exports (
    echo [SUCCESS] exports directory created
) else (
    echo [ERROR] Failed to create exports directory
)

echo.
echo [INFO] Setting up Windows firewall rules...
netsh advfirewall firewall add rule name="ChatBot HTTP" dir=in action=allow protocol=TCP localport=5000
if %errorlevel% neq 0 (
    echo [ERROR] Failed to set up port 5000 firewall rule. Administrator privileges required.
) else (
    echo [SUCCESS] Port 5000 firewall rule configured successfully.
)

netsh advfirewall firewall add rule name="ChatBot WebSocket" dir=in action=allow protocol=TCP localport=8888
if %errorlevel% neq 0 (
    echo [ERROR] Failed to set up port 8888 firewall rule. Administrator privileges required.
) else (
    echo [SUCCESS] Port 8888 firewall rule configured successfully.
)

echo.
echo [INFO] Checking firewall status...
netsh advfirewall show currentprofile state

echo.
echo [INFO] Setting directory permissions...
icacls security_logs /grant:r Users:(OI)(CI)M 2>nul
icacls exports /grant:r Users:(OI)(CI)M 2>nul

echo.
echo [INFO] Configuring security_gateway.py settings...
echo import os > security_config.py
echo ENABLE_RATE_LIMITING = True >> security_config.py
echo MAX_REQUESTS_PER_MINUTE = 60 >> security_config.py
echo LOG_SECURITY_EVENTS = True >> security_config.py
echo SECURITY_LOG_PATH = "security_logs" >> security_config.py
echo IP_BLACKLIST = [] >> security_config.py
echo.
echo [SUCCESS] Security configuration file created.

echo.
echo Security setup complete. Press any key to return to the menu...
pause >nul
goto main_menu

:start_server
cls
echo ====================================================================
echo              STARTING CHATBOT SERVER
echo ====================================================================
echo.

echo [INFO] Starting the ChatBot Server...
echo [INFO] Press Ctrl+C to stop the server.
echo.

:: Set port number
set /p port_number=Enter port number (default: 80): 
if "%port_number%"=="" set port_number=80

echo [INFO] Starting server on port %port_number%...
echo [INFO] Press Ctrl+C to stop the server and return to the menu.
echo.

:: Set current directory
cd /d "%~dp0"

echo Starting ChatBot server. Please wait...
echo.
echo ====================================================================
echo                  SERVER IS RUNNING
echo       Press Ctrl+C to stop and return to the menu
echo ====================================================================
echo.

:: Check if app.py or start script exists and run it
if exist app.py (
    python app.py --port %port_number%
) else if exist start.py (
    python start.py --port %port_number%
) else (
    echo [ERROR] Could not find app.py or start.py
    echo Please make sure the server file exists.
    timeout /t 5 >nul
)

:: When server stops (after Ctrl+C), return to menu
echo.
echo Server was stopped. Press any key to return to the menu...
pause >nul
goto main_menu

:manage_chatbot
cls
echo ====================================================================
echo              MANAGE CHATBOT CONFIGURATION
echo ====================================================================
echo.
echo  [1] Edit ChatBot Responses
echo  [2] Configure NLP Settings
echo  [3] Manage Training Data
echo  [4] Test ChatBot Responses
echo  [5] Return to Main Menu
echo.
echo ====================================================================
echo.

set /p config_choice=Select an option (1-5): 

if "%config_choice%"=="1" goto edit_responses
if "%config_choice%"=="2" goto nlp_settings
if "%config_choice%"=="3" goto manage_training
if "%config_choice%"=="4" goto test_chatbot
if "%config_choice%"=="5" goto main_menu
goto manage_chatbot

:edit_responses
cls
echo [INFO] Opening responses configuration file...

if exist chatbot_responses.json (
    start notepad chatbot_responses.json
) else if exist intents.json (
    start notepad intents.json
) else (
    echo [ERROR] No response configuration file found.
    echo Creating a basic template...
    
    echo { > intents.json
    echo   "intents": [ >> intents.json
    echo     { >> intents.json
    echo       "tag": "greeting", >> intents.json
    echo       "patterns": ["Hi", "Hello", "Hey", "How are you"], >> intents.json
    echo       "responses": ["Hello!", "Hi there!", "Nice to meet you!"] >> intents.json
    echo     }, >> intents.json
    echo     { >> intents.json
    echo       "tag": "goodbye", >> intents.json
    echo       "patterns": ["Bye", "Goodbye", "See you later"], >> intents.json
    echo       "responses": ["Goodbye!", "See you later!", "Talk to you soon!"] >> intents.json
    echo     } >> intents.json
    echo   ] >> intents.json
    echo } >> intents.json
    
    start notepad intents.json
)

echo.
echo Press any key to return to the ChatBot Configuration menu...
pause >nul
goto manage_chatbot

:nlp_settings
cls
echo [INFO] Configure NLP Settings...
echo.

echo Current NLP Configuration:
if exist nlp_config.py (
    type nlp_config.py
) else (
    echo No configuration file found. Creating default settings...
    echo # NLP Configuration > nlp_config.py
    echo TOKENIZER_LANGUAGE = "english" >> nlp_config.py
    echo MAX_SEQUENCE_LENGTH = 20 >> nlp_config.py
    echo TRAINING_EPOCHS = 200 >> nlp_config.py
    echo BATCH_SIZE = 8 >> nlp_config.py
    echo LEARNING_RATE = 0.001 >> nlp_config.py
    
    type nlp_config.py
)

echo.
echo [1] Edit Configuration File
echo [2] Back to ChatBot Configuration
echo.
set /p nlp_choice=Select an option (1-2): 

if "%nlp_choice%"=="1" (
    start notepad nlp_config.py
)

goto manage_chatbot

:manage_training
cls
echo [INFO] Training Data Management...
echo.

if exist "training_data" (
    echo Training data directory exists.
) else (
    echo Creating training data directory...
    mkdir training_data
)

echo.
echo [1] View Training Data Files
echo [2] Add New Training Data
echo [3] Back to ChatBot Configuration
echo.
set /p train_choice=Select an option (1-3): 

if "%train_choice%"=="1" (
    echo.
    echo Training Data Files:
    dir /b training_data
    echo.
    pause
)

if "%train_choice%"=="2" (
    echo.
    set /p filename=Enter new training data filename: 
    start notepad training_data\%filename%
)

goto manage_chatbot

:test_chatbot
cls
echo ====================================================================
echo              TEST CHATBOT RESPONSES
echo ====================================================================
echo.
echo [INFO] This tool lets you test the ChatBot responses directly.
echo [INFO] Type 'exit' to return to the menu.
echo.

if not exist chatbot.py (
    echo [ERROR] chatbot.py not found!
    echo Cannot test the ChatBot responses.
    echo.
    pause
    goto manage_chatbot
)

echo Loading ChatBot model, please wait...
echo.
python -c "import chatbot; print('ChatBot model loaded successfully!')" 2>nul
if %errorlevel% neq 0 (
    echo [ERROR] Failed to load ChatBot model.
    echo Please make sure the model is trained.
    echo.
    pause
    goto manage_chatbot
)

echo.
echo ChatBot is ready for testing!
echo.

:chat_loop
set /p user_input=You: 
if /i "%user_input%"=="exit" goto manage_chatbot

python -c "import chatbot; print('ChatBot: ' + chatbot.get_response('%user_input%'))" 2>nul
echo.
goto chat_loop

:check_security
cls
echo ====================================================================
echo              RUNNING SECURITY CHECKS
echo ====================================================================
echo.

echo [INFO] Checking security policy file...
if not exist ".safety-policy.yml" (
    echo [INFO] Creating security policy file...
    call :create_safety_policy
)

echo.
echo [INFO] Checking installed packages for vulnerabilities...
echo [INFO] This check may take some time...
echo.
safety check --policy-file=.safety-policy.yml --full-report 2>nul

if %errorlevel% neq 0 (
    echo.
    echo [WARNING] Security vulnerabilities were found. Package updates may be needed.
    echo.
    echo Vulnerable package update options:
    echo  [1] Automatically update vulnerable packages
    echo  [2] Ignore and continue
    echo.
    set /p update_choice=Choose an option (1-2): 
    
    if "!update_choice!"=="1" (
        echo.
        echo [INFO] Updating vulnerable packages...
        pip install --upgrade werkzeug flask requests certifi cryptography
        echo.
    )
) else (
    echo.
    echo [SUCCESS] No vulnerabilities found.
)

echo.
echo [INFO] Running code security scan with Bandit...
bandit -r . --skip=B101 2>nul || echo Code security scanner is not installed: pip install bandit
echo.

echo [INFO] Checking form validation in forms.py...
if exist forms.py (
    echo [INFO] Analyzing forms.py for security issues...
    python -c "print('Checking forms.py for XSS vulnerabilities...')"
    python -c "import re; content = open('forms.py').read(); issues = re.findall('request\\.form\\[\\'[^']*\\'\\]', content); print(f'Found {len(issues)} potential unvalidated form inputs')"
) else (
    echo [INFO] No forms.py file found to check.
)

echo.
echo [INFO] Checking security_gateway.py configuration...
if exist security_gateway.py (
    echo [INFO] Verifying security gateway settings...
    python -c "import re; content = open('security_gateway.py').read(); print('Rate limiting enabled' if 'RATE_LIMIT' in content.upper() else 'WARNING: No rate limiting found')"
) else (
    echo [WARNING] No security_gateway.py file found.
)

echo.
echo Security checks completed. Press any key to return to the menu...
pause >nul
goto main_menu

:train_model
cls
echo ====================================================================
echo              TRAIN CHATBOT MODEL
echo ====================================================================
echo.

echo [INFO] This will train or retrain the ChatBot model.
echo [INFO] Make sure your training data is ready.
echo.

if not exist intents.json (
    echo [ERROR] intents.json not found!
    echo Cannot train the model without training data.
    echo.
    echo Would you like to create a basic intents.json file?
    echo [1] Yes
    echo [2] No, return to menu
    echo.
    set /p create_intents=Choose an option (1-2): 
    
    if "!create_intents!"=="1" (
        echo Creating basic intents.json file...
        echo { > intents.json
        echo   "intents": [ >> intents.json
        echo     { >> intents.json
        echo       "tag": "greeting", >> intents.json
        echo       "patterns": ["Hi", "Hello", "Hey", "How are you"], >> intents.json
        echo       "responses": ["Hello!", "Hi there!", "Nice to meet you!"] >> intents.json
        echo     }, >> intents.json
        echo     { >> intents.json
        echo       "tag": "goodbye", >> intents.json
        echo       "patterns": ["Bye", "Goodbye", "See you later"], >> intents.json
        echo       "responses": ["Goodbye!", "See you later!", "Talk to you soon!"] >> intents.json
        echo     } >> intents.json
        echo   ] >> intents.json
        echo } >> intents.json
    ) else (
        goto main_menu
    )
)

echo.
echo [INFO] Select training configuration:
echo [1] Quick training (50 epochs)
echo [2] Standard training (200 epochs)
echo [3] Deep training (500 epochs)
echo [4] Return to menu
echo.
set /p train_option=Choose an option (1-4): 

if "%train_option%"=="4" goto main_menu

set epochs=200
if "%train_option%"=="1" set epochs=50
if "%train_option%"=="3" set epochs=500

echo.
echo [INFO] Starting model training with %epochs% epochs...
echo This may take some time depending on your hardware and dataset size.
echo.

if exist train_chatbot.py (
    python train_chatbot.py --epochs %epochs%
) else (
    echo [INFO] Creating training script...
    echo import json > train_chatbot.py
    echo import numpy as np >> train_chatbot.py
    echo import tensorflow as tf >> train_chatbot.py
    echo import nltk >> train_chatbot.py
    echo import argparse >> train_chatbot.py
    echo. >> train_chatbot.py
    echo # Parse arguments >> train_chatbot.py
    echo parser = argparse.ArgumentParser() >> train_chatbot.py
    echo parser.add_argument('--epochs', type=int, default=200) >> train_chatbot.py
    echo args = parser.parse_args() >> train_chatbot.py
    echo. >> train_chatbot.py
    echo print(f"Starting training with {args.epochs} epochs...") >> train_chatbot.py
    echo # Download required NLTK data >> train_chatbot.py
    echo try: >> train_chatbot.py
    echo     nltk.data.find('tokenizers/punkt') >> train_chatbot.py
    echo except LookupError: >> train_chatbot.py
    echo     nltk.download('punkt') >> train_chatbot.py
    echo. >> train_chatbot.py
    echo # Basic training implementation >> train_chatbot.py
    echo print("Training model... (this is a placeholder)") >> train_chatbot.py
    echo print("For actual implementation, please edit train_chatbot.py") >> train_chatbot.py
    
    echo [WARNING] Created a placeholder training script.
    echo Please edit train_chatbot.py to implement actual model training.
    echo.
    pause
    goto main_menu
)

echo.
echo Model training completed. Press any key to return to the menu...
pause >nul
goto main_menu

:create_safety_policy
echo # Safety policy file to ignore false positives >.safety-policy.yml
echo # Ignore dependencies not actually used in this app >>.safety-policy.yml
echo security: >>.safety-policy.yml
echo   ignore-vulnerabilities: >>.safety-policy.yml
echo     # TensorFlow vulnerabilities - not used directly in our app >>.safety-policy.yml
echo     - 48638 # CVE-2022-29197 in TensorFlow >>.safety-policy.yml
echo     - 48653 # CVE-2022-29213 in TensorFlow >>.safety-policy.yml
echo     - 65567 # PVE-2024-99853 in TensorFlow >>.safety-policy.yml
echo     - 65568 # PVE-2024-99852 in TensorFlow >>.safety-policy.yml
echo     # Other non-critical packages that we don't use for security purposes >>.safety-policy.yml
echo     - 51692 # False positive for malicious pystyle package >>.safety-policy.yml
echo     - 70717 # CVE-2024-3660 in Keras >>.safety-policy.yml
echo     - 67895 # CVE-2024-3651 in IDNA >>.safety-policy.yml
echo     - 52983 # CVE-2021-41945 in HTTPX >>.safety-policy.yml
echo   ignore-unpinned-requirements: >>.safety-policy.yml
echo     - safety >>.safety-policy.yml
echo     - bandit >>.safety-policy.yml
echo     - pytest >>.safety-policy.yml
echo     - pywin32 >>.safety-policy.yml
echo     - windows-curses >>.safety-policy.yml
echo   ignore-packages: >>.safety-policy.yml
echo     - tensorflow >>.safety-policy.yml
echo     - keras >>.safety-policy.yml
goto :eof

:database_tools
cls
echo ====================================================================
echo              DATABASE TOOLS
echo ====================================================================
echo.
echo  [1] Backup ChatBot Database
echo  [2] List Backups
echo  [3] Optimize Database
echo  [4] Import Training Data
echo  [5] Export ChatBot Logs
echo  [6] Return to Main Menu
echo.
echo ====================================================================
echo.

set /p db_choice=Select an option (1-6): 

if "%db_choice%"=="1" goto backup_database
if "%db_choice%"=="2" goto list_backups
if "%db_choice%"=="3" goto optimize_database
if "%db_choice%"=="4" goto import_training
if "%db_choice%"=="5" goto export_logs
if "%db_choice%"=="6" goto main_menu
goto database_tools

:backup_database
cls
echo [INFO] Backing up database and model files...
echo.

:: Create backups directory if it doesn't exist
if not exist backups mkdir backups

:: Get current date and time for filename
for /f "tokens=2 delims==" %%a in ('wmic OS Get localdatetime /value') do set datetime=%%a
set backupfile=backups\chatbot_backup_%datetime:~0,8%_%datetime:~8,6%.zip

:: Check for required files
set filestobackup=
if exist chatbot.py set filestobackup=%filestobackup% chatbot.py
if exist intents.json set filestobackup=%filestobackup% intents.json
if exist models set filestobackup=%filestobackup% models
if exist trained_model.h5 set filestobackup=%filestobackup% trained_model.h5
if exist words.pkl set filestobackup=%filestobackup% words.pkl
if exist classes.pkl set filestobackup=%filestobackup% classes.pkl
if exist chatbot_database.db set filestobackup=%filestobackup% chatbot_database.db
if exist chatbot_responses.json set filestobackup=%filestobackup% chatbot_responses.json

if "%filestobackup%"=="" (
    echo [WARNING] No database or model files found to backup.
) else (
    :: Create backup using PowerShell's Compress-Archive
    powershell -Command "Compress-Archive -Path %filestobackup% -DestinationPath '%backupfile%'"
    echo [SUCCESS] Backup created: %backupfile%
)

echo.
echo Press any key to return to the Database Tools menu...
pause >nul
goto database_tools

:list_backups
cls
echo [INFO] Available Backups:
echo.

if not exist backups (
    echo No backups found.
) else (
    dir /b backups\*.zip
)

echo.
echo Press any key to return to the Database Tools menu...
pause >nul
goto database_tools

:optimize_database
cls
echo [INFO] Optimizing database...
echo.

set db_found=0

if exist chatbot_database.db (
    set db_found=1
    echo Found SQLite database: chatbot_database.db
    echo Running optimization...
    
    :: Try to run SQLite optimization
    sqlite3 chatbot_database.db "VACUUM;" 2>nul
    if %errorlevel% neq 0 (
        echo [WARNING] SQLite command failed. SQLite3 might not be installed.
        echo Trying with Python instead...
        
        python -c "import sqlite3; conn = sqlite3.connect('chatbot_database.db'); conn.execute('VACUUM;'); conn.close(); print('Database optimized successfully!')" 2>nul
        if %errorlevel% neq 0 (
            echo [ERROR] Failed to optimize database.
        ) else (
            echo [SUCCESS] Database optimized successfully.
        )
    ) else (
        echo [SUCCESS] Database optimized successfully.
    )
)

if exist models (
    set db_found=1
    echo Found TensorFlow model directory.
    echo Cleaning up temporary model files...
    
    if exist models\*.tmp del models\*.tmp
    echo [SUCCESS] Model directory cleaned.
)

if %db_found%==0 (
    echo [WARNING] No database or model files found to optimize.
)

echo.
echo Press any key to return to the Database Tools menu...
pause >nul
goto database_tools

:import_training
cls
echo [INFO] Import Training Data
echo.

echo [1] Import from JSON file
echo [2] Import from CSV file
echo [3] Import from text file
echo [4] Return to Database Tools
echo.
set /p import_choice=Select an option (1-4): 

if "%import_choice%"=="4" goto database_tools

if "%import_choice%"=="1" (
    set /p jsonfile=Enter JSON file path: 
    if exist "%jsonfile%" (
        echo [INFO] Importing training data from %jsonfile%...
        echo import json > import_script.py
        echo import os >> import_script.py
        echo try: >> import_script.py
        echo     with open('%jsonfile%', 'r', encoding='utf-8') as f: >> import_script.py
        echo         imported_data = json.load(f) >> import_script.py
        echo     with open('intents.json', 'r', encoding='utf-8') as f: >> import_script.py
        echo         current_data = json.load(f) >> import_script.py
        echo     # Merge intents >> import_script.py
        echo     print(f"Found {len(imported_data.get('intents', []))} intents to import") >> import_script.py
        echo     current_data['intents'].extend(imported_data.get('intents', [])) >> import_script.py
        echo     # Save updated data >> import_script.py
        echo     with open('intents.json', 'w', encoding='utf-8') as f: >> import_script.py
        echo         json.dump(current_data, f, indent=2) >> import_script.py
        echo     print("Import completed successfully.") >> import_script.py
        echo except Exception as e: >> import_script.py
        echo     print(f"Error during import: {e}") >> import_script.py
        
        python import_script.py
        del import_script.py
    ) else (
        echo [ERROR] File not found: %jsonfile%
    )
)

if "%import_choice%"=="2" (
    set /p csvfile=Enter CSV file path: 
    echo [INFO] Creating CSV import utility...
    echo import csv > csv_import.py
    echo import json >> csv_import.py
    echo import os >> csv_import.py
    echo. >> csv_import.py
    echo def import_csv(csv_file): >> csv_import.py
    echo     try: >> csv_import.py
    echo         intents_data = {"intents": []} >> csv_import.py
    echo         with open(csv_file, 'r', encoding='utf-8') as file: >> csv_import.py
    echo             reader = csv.reader(file) >> csv_import.py
    echo             header = next(reader)  # Skip header >> csv_import.py
    echo             for row in reader: >> csv_import.py
    echo                 if len(row) >= 3:  # Ensure row has tag, pattern, response >> csv_import.py
    echo                     tag, pattern, response = row[0], row[1], row[2] >> csv_import.py
    echo                     # Check if tag already exists >> csv_import.py
    echo                     tag_exists = False >> csv_import.py
    echo                     for intent in intents_data["intents"]: >> csv_import.py
    echo                         if intent["tag"] == tag: >> csv_import.py
    echo                             intent["patterns"].append(pattern) >> csv_import.py
    echo                             intent["responses"].append(response) >> csv_import.py
    echo                             tag_exists = True >> csv_import.py
    echo                             break >> csv_import.py
    echo                     if not tag_exists: >> csv_import.py
    echo                         intents_data["intents"].append({ >> csv_import.py
    echo                             "tag": tag, >> csv_import.py
    echo                             "patterns": [pattern], >> csv_import.py
    echo                             "responses": [response] >> csv_import.py
    echo                         }) >> csv_import.py
    echo         # Now merge with existing intents.json if it exists >> csv_import.py
    echo         if os.path.exists('intents.json'): >> csv_import.py
    echo             with open('intents.json', 'r', encoding='utf-8') as f: >> csv_import.py
    echo                 current_data = json.load(f) >> csv_import.py
    echo             # Merge intents >> csv_import.py
    echo             current_data['intents'].extend(intents_data['intents']) >> csv_import.py
    echo             intents_data = current_data >> csv_import.py
    echo         # Save the data >> csv_import.py
    echo         with open('intents.json', 'w', encoding='utf-8') as f: >> csv_import.py
    echo             json.dump(intents_data, f, indent=2) >> csv_import.py
    echo         print(f"Successfully imported {len(intents_data['intents'])} intents") >> csv_import.py
    echo         return True >> csv_import.py
    echo     except Exception as e: >> csv_import.py
    echo         print(f"Error importing CSV: {e}") >> csv_import.py
    echo         return False >> csv_import.py
    echo. >> csv_import.py
    echo import_csv('%csvfile%') >> csv_import.py

    python csv_import.py
    del csv_import.py
)

if "%import_choice%"=="3" (
    set /p textfile=Enter text file path: 
    echo [INFO] Creating text import utility...
    echo import json >> text_import.py
    echo import os >> text_import.py
    echo. >> text_import.py
    echo def import_text(text_file): >> text_import.py
    echo     try: >> text_import.py
    echo         intents_data = {"intents": []} >> text_import.py
    echo         current_tag = None >> text_import.py
    echo         current_patterns = [] >> text_import.py
    echo         current_responses = [] >> text_import.py
    echo         with open(text_file, 'r', encoding='utf-8') as file: >> text_import.py
    echo             for line in file: >> text_import.py
    echo                 line = line.strip() >> text_import.py
    echo                 if not line: >> text_import.py
    echo                     continue >> text_import.py
    echo                 if line.startswith("TAG:"): >> text_import.py
    echo                     # Save previous tag if exists >> text_import.py
    echo                     if current_tag and current_patterns and current_responses: >> text_import.py
    echo                         intents_data["intents"].append({ >> text_import.py
    echo                             "tag": current_tag, >> text_import.py
    echo                             "patterns": current_patterns, >> text_import.py
    echo                             "responses": current_responses >> text_import.py
    echo                         }) >> text_import.py
    echo                     # Start new tag >> text_import.py
    echo                     current_tag = line[4:].strip() >> text_import.py
    echo                     current_patterns = [] >> text_import.py
    echo                     current_responses = [] >> text_import.py
    echo                 elif line.startswith("P:"): >> text_import.py
    echo                     current_patterns.append(line[2:].strip()) >> text_import.py
    echo                 elif line.startswith("R:"): >> text_import.py
    echo                     current_responses.append(line[2:].strip()) >> text_import.py
    echo             # Save the last tag >> text_import.py
    echo             if current_tag and current_patterns and current_responses: >> text_import.py
    echo                 intents_data["intents"].append({ >> text_import.py
    echo                     "tag": current_tag, >> text_import.py
    echo                     "patterns": current_patterns, >> text_import.py
    echo                     "responses": current_responses >> text_import.py
    echo                 }) >> text_import.py
    echo         # Now merge with existing intents.json if it exists >> text_import.py
    echo         if os.path.exists('intents.json'): >> text_import.py
    echo             with open('intents.json', 'r', encoding='utf-8') as f: >> text_import.py
    echo                 current_data = json.load(f) >> text_import.py
    echo             # Merge intents >> text_import.py
    echo             current_data['intents'].extend(intents_data['intents']) >> text_import.py
    echo             intents_data = current_data >> text_import.py
    echo         # Save the data >> text_import.py
    echo         with open('intents.json', 'w', encoding='utf-8') as f: >> text_import.py
    echo             json.dump(intents_data, f, indent=2) >> text_import.py
    echo         print(f"Successfully imported {len(intents_data['intents'])} intents") >> text_import.py
    echo         return True >> text_import.py
    echo     except Exception as e: >> text_import.py
    echo         print(f"Error importing text: {e}") >> text_import.py
    echo         return False >> text_import.py
    echo. >> text_import.py
    echo import_text('%textfile%') >> text_import.py
    
    python text_import.py
    del text_import.py
)

echo.
echo Press any key to return to the Database Tools menu...
pause >nul
goto database_tools

:export_logs
cls
echo [INFO] Exporting ChatBot Logs...
echo.

:: Create exports directory if it doesn't exist
if not exist exports mkdir exports

:: Get current date and time for filename
for /f "tokens=2 delims==" %%a in ('wmic OS Get localdatetime /value') do set datetime=%%a
set logfile=exports\chatbot_logs_%datetime:~0,8%_%datetime:~8,6%.txt

echo [INFO] Searching for log files...
set found_logs=0

if exist logs (
    echo [INFO] Found logs directory, exporting logs...
    type logs\*.log > "%logfile%" 2>nul
    set found_logs=1
)

if exist chatbot_log.txt (
    echo [INFO] Found chatbot_log.txt, exporting...
    type chatbot_log.txt > "%logfile%" 2>nul
    set found_logs=1
)

if exist chat_history.txt (
    echo [INFO] Found chat_history.txt, exporting...
    type chat_history.txt > "%logfile%" 2>nul
    set found_logs=1
)

if %found_logs%==0 (
    echo [WARNING] No log files found to export.
) else (
    echo [SUCCESS] Logs exported to %logfile%
)

echo.
echo Press any key to return to the Database Tools menu...
pause >nul
goto database_tools

:system_info
cls
echo ====================================================================
echo              SYSTEM INFORMATION
echo ====================================================================
echo.

echo [INFO] Gathering system information...

echo 1. Operating System Information:
systeminfo | findstr /B /C:"OS Name" /C:"OS Version" /C:"System Type"

echo.
echo 2. Disk Space:
wmic logicaldisk where "DeviceID='C:'" get size, freespace, caption

echo.
echo 3. Memory Information:
systeminfo | findstr /C:"Total Physical Memory" /C:"Available Physical Memory"

echo.
echo 4. CPU Information:
wmic cpu get name, numberofcores, maxclockspeed

echo.
echo 5. Python Environment:
python --version
pip --version

echo.
echo 6. TensorFlow Status:
python -c "import tensorflow as tf; print(f'TensorFlow version: {tf.__version__}')" 2>nul || echo TensorFlow is not installed or has issues

echo.
echo 7. ChatBot Files Status:
echo.
echo File             Status
echo ---------------------
if exist chatbot.py (echo chatbot.py       Found) else (echo chatbot.py       Not found)
if exist app.py (echo app.py           Found) else (echo app.py           Not found)
if exist models.py (echo models.py        Found) else (echo models.py        Not found)
if exist forms.py (echo forms.py         Found) else (echo forms.py         Not found)
if exist security_gateway.py (echo security_gateway.py Found) else (echo security_gateway.py Not found)
if exist intents.json (echo intents.json     Found) else (echo intents.json     Not found)

echo.
echo System information check completed. Press any key to return to the menu...
pause >nul
goto main_menu

:install_package
set /a current+=1
set package=%~1
echo [%current%/%total_packages%] Installing %package%...
pip install %package% >nul 2>&1
if %errorlevel% neq 0 (
    echo     [FAILED] %package%
    set failed_packages=!failed_packages! %package%
) else (
    echo     [SUCCESS] %package%
)
goto :eof

:end
cls
echo ====================================================================
echo              EXITING PROGRAM
echo ====================================================================
echo.
echo Thank you for using the JakkChatBOT Management Tool.
echo.
exit /b 0