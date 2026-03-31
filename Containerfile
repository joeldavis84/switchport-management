# Use the Red Hat Universal Base Image 10 (Minimal)
FROM registry.access.redhat.com/ubi10/ubi-minimal

# Prevent Python from writing .pyc files and force stdout/stderr to be unbuffered
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# Set the working directory inside the container
WORKDIR /app

# Install Python 3, pip, and SSH client tools
# UBI Minimal uses 'microdnf' instead of 'dnf'
RUN microdnf install -y python3 python3-pip openssh-clients \
    && microdnf clean all

# Copy requirements and install dependencies
COPY requirements.txt .
RUN pip3 install --no-cache-dir -r requirements.txt \
    && pip3 install --no-cache-dir gunicorn

# Copy the rest of the application code
COPY . .

# Create the SSH directory with strict permissions
# Keys will be mounted here at runtime
RUN mkdir -p /root/.ssh && chmod 700 /root/.ssh

# Create a directory for the SQLite database so it can be persisted via a volume mount
RUN mkdir -p /app/instance

# Expose the port the app runs on
EXPOSE 5000

# Run the application using Gunicorn with the --preload flag
#CMD ["gunicorn", "--bind", "0.0.0.0:5000", "--workers", "4", "--threads", "2", "--preload", "run:app"]
CMD ["/app/entrypoint.sh"]
