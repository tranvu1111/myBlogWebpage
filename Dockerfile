#
# FROM python:3.11
# # Working directory
# WORKDIR /app
# # Copy requirements file and install dependencies
# COPY requirements.txt requirements.txt
# RUN pip install --no-cache-dir -r requirements.txt
# # Copy the rest of the project files
# COPY . .
# # Expose the server port
# EXPOSE 8080
# # Command to start the server
# CMD ["gunicorn", "-b", "0.0.0.0:8080", "app:app"]


FROM python:3.11
WORKDIR /app
COPY . /app
RUN pip install -r requirements.txt
CMD ["python", "main.py"]
