# Use the Red Hat Universal Base Image 10 (Minimal)
FROM registry.access.redhat.com/ubi10/ubi-minimal

# Prevent Python from writing .pyc files and force stdout/stderr to be unbuffered
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# Set the working directory inside the container
WORKDIR /app

# Install Python 3, pip, SSH client tools, and nginx (reverse proxy on port 80)
# UBI Minimal uses 'microdnf' instead of 'dnf'
RUN microdnf install -y python3 python3-pip openssh-clients nginx \
    && microdnf clean all \
    && rm -f /etc/nginx/conf.d/default.conf /etc/nginx/conf.d/default.conf.rpmsave 2>/dev/null || true

# Copy requirements and install dependencies
COPY requirements.txt .
RUN pip3 install --no-cache-dir -r requirements.txt \
    && pip3 install --no-cache-dir gunicorn

# Nginx site: proxy to Gunicorn on 127.0.0.1:5000
COPY nginx/conf.d/app.conf /etc/nginx/conf.d/app.conf

# Copy the rest of the application code
COPY . .

RUN chmod +x /app/entrypoint.sh

# Create the SSH directory with strict permissions
# Keys will be mounted here at runtime
RUN mkdir -p /root/.ssh && chmod 700 /root/.ssh

# Create a directory for the SQLite database so it can be persisted via a volume mount
RUN mkdir -p /app/instance

# TLS PEM (cert + optional key) mounted at runtime — see nginx/conf.d/app.conf
RUN mkdir -p /app/pki && chmod 755 /app/pki

# HTTP redirects to HTTPS; TLS on 443 (Gunicorn only on 127.0.0.1:5000)
EXPOSE 80 443

# Run the application using Gunicorn with the --preload flag
#CMD ["gunicorn", "--bind", "0.0.0.0:5000", "--workers", "4", "--threads", "2", "--preload", "run:app"]
CMD ["/app/entrypoint.sh"]
