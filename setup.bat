@echo off
pip install -r requirements.txt
echo.
echo Checking TensorFlow installation...
pip show tensorflow
echo.
echo If you see a version number above, TensorFlow is installed.
echo If you see an error message, TensorFlow is not installed.
echo.
echo If TensorFlow is not installed, you can install it with:
echo pip install tensorflow
echo.
echo If you're having issues with TensorFlow, you might need to downgrade NumPy:
echo pip install numpy==1.24.3 --force-reinstall
echo.
echo You can now try running your chatbot with start.bat
echo Fixing NumPy compatibility issues...
pip install numpy==1.24.3 --force-reinstall
echo.
echo NumPy has been downgraded to 1.24.3
echo.
echo Verifying TensorFlow installation...
pip show tensorflow
echo.
echo If you're still having issues, you might need to reinstall TensorFlow:
echo pip install tensorflow --upgrade
echo.
echo You can now try running your chatbot again with start.bat
pause